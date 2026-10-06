//! Retry rules (§6.5) for SDK calls: retry 429 and transient 5xx with
//! jittered exponential backoff; never retry other 4xx. A 409 (etag
//! conflict) is surfaced so read-modify-write callers can re-read.

use std::time::Duration;

use google_cloud_gax::error::rpc::Code;
use google_cloud_gax::error::Error;
use google_cloud_gax::exponential_backoff::{ExponentialBackoff, ExponentialBackoffBuilder};
use google_cloud_gax::retry_policy::{RetryPolicy, RetryPolicyExt};
use google_cloud_gax::retry_result::RetryResult;
use google_cloud_gax::retry_state::RetryState;

#[derive(Clone, Debug)]
pub struct OrgmoveRetry;

/// Whether the failure means the request was rejected before being processed
/// (so retrying is safe even for non-idempotent calls).
fn throttled(e: &Error) -> bool {
    e.status()
        .is_some_and(|s| s.code == Code::ResourceExhausted)
        || e.http_status_code() == Some(429)
}

fn transient(e: &Error) -> bool {
    e.is_io()
        || e.status().is_some_and(|s| s.code == Code::Unavailable)
        || matches!(e.http_status_code(), Some(500 | 502 | 503 | 504))
}

impl RetryPolicy for OrgmoveRetry {
    fn on_error(&self, state: &RetryState, error: Error) -> RetryResult {
        if error.is_transient_and_before_rpc() || throttled(&error) {
            return RetryResult::Continue(error);
        }
        if state.idempotent && transient(&error) {
            return RetryResult::Continue(error);
        }
        RetryResult::Permanent(error)
    }
}

/// The policy handed to every SDK client: bounded attempts and elapsed time.
pub fn policy() -> impl RetryPolicy + 'static {
    OrgmoveRetry
        .with_attempt_limit(6)
        .with_time_limit(Duration::from_secs(120))
}

pub fn backoff() -> ExponentialBackoff {
    ExponentialBackoffBuilder::new()
        .with_initial_delay(Duration::from_millis(500))
        .with_maximum_delay(Duration::from_secs(30))
        .with_scaling(2.0)
        .build()
        .expect("static backoff parameters are valid")
}

#[cfg(test)]
mod tests {
    use super::*;
    use google_cloud_gax::error::rpc::Status;

    fn state(idempotent: bool) -> RetryState {
        RetryState::new(idempotent)
    }
    fn svc(code: Code) -> Error {
        Error::service(Status::default().set_code(code))
    }

    #[test]
    fn retries_429_even_when_not_idempotent() {
        let r = OrgmoveRetry.on_error(&state(false), svc(Code::ResourceExhausted));
        assert!(matches!(r, RetryResult::Continue(_)));
        let r = OrgmoveRetry.on_error(
            &state(false),
            Error::http(429, Default::default(), bytes::Bytes::new()),
        );
        assert!(matches!(r, RetryResult::Continue(_)));
    }

    #[test]
    fn retries_5xx_only_when_idempotent() {
        let e = || Error::http(503, Default::default(), bytes::Bytes::new());
        assert!(matches!(
            OrgmoveRetry.on_error(&state(true), e()),
            RetryResult::Continue(_)
        ));
        assert!(matches!(
            OrgmoveRetry.on_error(&state(false), e()),
            RetryResult::Permanent(_)
        ));
    }

    #[test]
    fn never_retries_other_4xx_or_conflicts() {
        for c in [
            Code::PermissionDenied,
            Code::NotFound,
            Code::InvalidArgument,
            Code::Aborted,
            Code::AlreadyExists,
        ] {
            assert!(
                matches!(
                    OrgmoveRetry.on_error(&state(true), svc(c)),
                    RetryResult::Permanent(_)
                ),
                "{c:?}"
            );
        }
        let e = Error::http(409, Default::default(), bytes::Bytes::new());
        assert!(matches!(
            OrgmoveRetry.on_error(&state(true), e),
            RetryResult::Permanent(_)
        ));
    }
}
