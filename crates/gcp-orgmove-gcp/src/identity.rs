//! Cloud Identity Groups lookup. The official SDK has no Cloud Identity
//! client, so this uses plain `reqwest` with the same credentials and the
//! same retry rules as the SDK calls (429 and transient 5xx only).

use std::time::Duration;

use gcp_orgmove_core::{Error, ErrorKind, Result};
use google_cloud_auth::credentials::Credentials;
use reqwest::StatusCode;

use crate::auth::auth_headers;

pub const DEFAULT_BASE: &str = "https://cloudidentity.googleapis.com";

#[derive(Debug, Clone, Copy)]
pub struct Backoff {
    pub attempts: u32,
    pub initial: Duration,
    pub max: Duration,
}

impl Default for Backoff {
    fn default() -> Self {
        Self {
            attempts: 6,
            initial: Duration::from_millis(500),
            max: Duration::from_secs(30),
        }
    }
}

fn retryable(s: StatusCode) -> bool {
    s == StatusCode::TOO_MANY_REQUESTS || matches!(s.as_u16(), 500 | 502 | 503 | 504)
}

fn jittered(d: Duration) -> Duration {
    let n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|t| t.subsec_nanos())
        .unwrap_or(0);
    d + d.mul_f64(f64::from(n % 250) / 1000.0)
}

/// Does a group with this email exist and resolve?
pub async fn group_exists(
    http: &reqwest::Client,
    creds: &Credentials,
    base: &str,
    backoff: Backoff,
    email: &str,
) -> Result<bool> {
    let url = format!("{}/v1/groups:lookup", base.trim_end_matches('/'));
    let mut delay = backoff.initial;
    for attempt in 1..=backoff.attempts.max(1) {
        let headers = auth_headers(creds).await?;
        let resp = http
            .get(&url)
            .headers(headers)
            .query(&[("groupKey.id", email)])
            .send()
            .await;
        let status = match resp {
            Ok(r) => r,
            Err(e) if attempt < backoff.attempts && (e.is_connect() || e.is_timeout()) => {
                tokio::time::sleep(jittered(delay)).await;
                delay = (delay * 2).min(backoff.max);
                continue;
            }
            Err(e) => {
                return Err(Error::internal(format!(
                    "Cloud Identity request failed: {e}"
                )))
            }
        };
        let code = status.status();
        if code.is_success() {
            return Ok(true);
        }
        if code == StatusCode::NOT_FOUND {
            return Ok(false);
        }
        if retryable(code) && attempt < backoff.attempts {
            tokio::time::sleep(jittered(delay)).await;
            delay = (delay * 2).min(backoff.max);
            continue;
        }
        let body = status.text().await.unwrap_or_default();
        let kind = match code {
            StatusCode::UNAUTHORIZED => ErrorKind::Unauthenticated,
            StatusCode::FORBIDDEN => ErrorKind::PermissionDenied,
            StatusCode::TOO_MANY_REQUESTS => ErrorKind::QuotaExceeded,
            _ => ErrorKind::Internal,
        };
        let mut e = Error::new(
            kind,
            format!(
                "group {email}: Cloud Identity returned {code}: {}",
                body.chars().take(200).collect::<String>()
            ),
        )
        .with_resource(format!("groups/{email}"));
        if kind == ErrorKind::PermissionDenied {
            e = e.with_hint("enable the Cloud Identity API and grant groups.lookup access, or run with --skip groups");
        }
        return Err(e);
    }
    unreachable!("loop returns on the last attempt")
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn creds() -> Credentials {
        google_cloud_auth::credentials::anonymous::Builder::new().build()
    }
    fn fast() -> Backoff {
        Backoff {
            attempts: 4,
            initial: Duration::from_millis(1),
            max: Duration::from_millis(2),
        }
    }

    #[tokio::test]
    async fn found_and_not_found() {
        let s = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/groups:lookup"))
            .and(query_param("groupKey.id", "eng@example.com"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"name": "groups/123"})),
            )
            .mount(&s)
            .await;
        Mock::given(method("GET"))
            .and(query_param("groupKey.id", "gone@example.com"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&s)
            .await;
        let h = reqwest::Client::new();
        assert!(
            group_exists(&h, &creds(), &s.uri(), fast(), "eng@example.com")
                .await
                .unwrap()
        );
        assert!(
            !group_exists(&h, &creds(), &s.uri(), fast(), "gone@example.com")
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn retries_429_then_succeeds() {
        let s = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(429))
            .up_to_n_times(2)
            .mount(&s)
            .await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .mount(&s)
            .await;
        assert!(group_exists(
            &reqwest::Client::new(),
            &creds(),
            &s.uri(),
            fast(),
            "a@b.com"
        )
        .await
        .unwrap());
    }

    #[tokio::test]
    async fn gives_up_after_the_attempt_limit_as_quota_exceeded() {
        let s = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(429))
            .expect(4)
            .mount(&s)
            .await;
        let e = group_exists(
            &reqwest::Client::new(),
            &creds(),
            &s.uri(),
            fast(),
            "a@b.com",
        )
        .await
        .unwrap_err();
        assert_eq!(e.kind, ErrorKind::QuotaExceeded);
    }

    #[tokio::test]
    async fn does_not_retry_403_and_maps_it() {
        let s = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(403))
            .expect(1)
            .mount(&s)
            .await;
        let e = group_exists(
            &reqwest::Client::new(),
            &creds(),
            &s.uri(),
            fast(),
            "a@b.com",
        )
        .await
        .unwrap_err();
        assert_eq!(e.kind, ErrorKind::PermissionDenied);
        assert!(e.hint.unwrap().contains("--skip groups"));
    }
}
