//! Map SDK errors onto core error kinds (§9.6).

use gcp_orgmove_core::{Error, ErrorKind};
use google_cloud_gax::error::rpc::Code;

/// Convert an SDK error for `resource` (used in messages and hints).
pub fn map_err(e: google_cloud_gax::error::Error, resource: impl std::fmt::Display) -> Error {
    let kind = classify(&e);
    let detail = e
        .status()
        .map(|s| s.message.clone())
        .filter(|m| !m.is_empty())
        .unwrap_or_else(|| e.to_string());
    let mut err =
        Error::new(kind, format!("{resource}: {detail}")).with_resource(resource.to_string());
    match kind {
        ErrorKind::PermissionDenied => {
            err = err.with_hint("check the roles listed under 'Required permissions' and that the API is enabled on the quota project");
        }
        ErrorKind::Unauthenticated => {
            err = err.with_hint("re-authenticate, e.g. `gcloud auth application-default login`");
        }
        _ => {}
    }
    err
}

fn classify(e: &google_cloud_gax::error::Error) -> ErrorKind {
    if e.is_authentication() {
        return ErrorKind::Unauthenticated;
    }
    if let Some(s) = e.status() {
        return match s.code {
            Code::PermissionDenied => ErrorKind::PermissionDenied,
            Code::Unauthenticated => ErrorKind::Unauthenticated,
            Code::NotFound => ErrorKind::NotFound,
            Code::Aborted | Code::AlreadyExists => ErrorKind::Conflict,
            Code::ResourceExhausted => ErrorKind::QuotaExceeded,
            Code::FailedPrecondition => ErrorKind::PolicyViolation,
            Code::InvalidArgument | Code::OutOfRange => ErrorKind::InvalidInput,
            _ => ErrorKind::Internal,
        };
    }
    match e.http_status_code() {
        Some(401) => ErrorKind::Unauthenticated,
        Some(403) => ErrorKind::PermissionDenied,
        Some(404) => ErrorKind::NotFound,
        Some(409) => ErrorKind::Conflict,
        Some(412) => ErrorKind::PolicyViolation,
        Some(429) => ErrorKind::QuotaExceeded,
        Some(400) => ErrorKind::InvalidInput,
        _ if e.is_exhausted() => ErrorKind::QuotaExceeded,
        _ => ErrorKind::Internal,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use google_cloud_gax::error::rpc::Status;
    use google_cloud_gax::error::Error as GaxError;

    fn svc(code: Code) -> GaxError {
        GaxError::service(Status::default().set_code(code).set_message("m"))
    }

    #[test]
    fn maps_status_codes() {
        let cases = [
            (Code::PermissionDenied, ErrorKind::PermissionDenied),
            (Code::Unauthenticated, ErrorKind::Unauthenticated),
            (Code::NotFound, ErrorKind::NotFound),
            (Code::Aborted, ErrorKind::Conflict),
            (Code::AlreadyExists, ErrorKind::Conflict),
            (Code::ResourceExhausted, ErrorKind::QuotaExceeded),
            (Code::FailedPrecondition, ErrorKind::PolicyViolation),
            (Code::InvalidArgument, ErrorKind::InvalidInput),
            (Code::Internal, ErrorKind::Internal),
        ];
        for (code, kind) in cases {
            assert_eq!(map_err(svc(code), "projects/x").kind, kind, "{code:?}");
        }
    }

    #[test]
    fn http_status_fallback_and_message() {
        let e = GaxError::http(403, Default::default(), bytes::Bytes::new());
        let m = map_err(e, "projects/x-proj");
        assert_eq!(m.kind, ErrorKind::PermissionDenied);
        assert_eq!(m.resource.as_deref(), Some("projects/x-proj"));
        assert!(m.hint.is_some());
        assert_eq!(map_err(svc(Code::NotFound), "r").message, "r: m");
    }
}
