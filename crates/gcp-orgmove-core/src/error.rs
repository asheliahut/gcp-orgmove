//! Typed errors with machine-readable kinds and exit-code mapping (§3.2, §9.6).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorKind {
    InvalidInput,
    Unauthenticated,
    PermissionDenied,
    NotFound,
    Conflict,
    QuotaExceeded,
    PolicyViolation,
    /// Plan contains blockers or unaccepted gaps.
    Blocked,
    /// Plan is too old, manifest changed, or live parent drifted.
    StalePlan,
    /// Some projects failed during apply/rollback.
    PartialFailure,
    /// A smoke test failed after a move.
    SmokeFailed,
    Internal,
}

impl ErrorKind {
    /// Process exit code per §3.2.
    pub fn exit_code(self) -> u8 {
        match self {
            ErrorKind::InvalidInput => 2,
            ErrorKind::Unauthenticated | ErrorKind::PermissionDenied => 3,
            ErrorKind::Blocked => 4,
            ErrorKind::StalePlan => 5,
            ErrorKind::PartialFailure => 6,
            ErrorKind::SmokeFailed => 7,
            ErrorKind::NotFound
            | ErrorKind::Conflict
            | ErrorKind::QuotaExceeded
            | ErrorKind::PolicyViolation
            | ErrorKind::Internal => 1,
        }
    }

    /// Whether a retry with backoff can plausibly succeed.
    pub fn is_retryable(self) -> bool {
        matches!(self, ErrorKind::QuotaExceeded)
    }
}

#[derive(Debug, Clone, thiserror::Error)]
#[error("{message}")]
pub struct Error {
    pub kind: ErrorKind,
    pub message: String,
    /// The failing resource, e.g. `projects/my-app-prod`.
    pub resource: Option<String>,
    /// Suggested next command for the user.
    pub hint: Option<String>,
}

impl Error {
    pub fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            resource: None,
            hint: None,
        }
    }
    pub fn with_resource(mut self, r: impl ToString) -> Self {
        self.resource = Some(r.to_string());
        self
    }
    pub fn with_hint(mut self, h: impl Into<String>) -> Self {
        self.hint = Some(h.into());
        self
    }
    pub fn exit_code(&self) -> u8 {
        self.kind.exit_code()
    }
    pub fn internal(msg: impl Into<String>) -> Self {
        Self::new(ErrorKind::Internal, msg)
    }
    pub fn invalid(msg: impl Into<String>) -> Self {
        Self::new(ErrorKind::InvalidInput, msg)
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::internal(format!("I/O error: {e}"))
    }
}
impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::invalid(format!("JSON error: {e}"))
    }
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_code_table() {
        use ErrorKind::*;
        let table = [
            (InvalidInput, 2),
            (Unauthenticated, 3),
            (PermissionDenied, 3),
            (Blocked, 4),
            (StalePlan, 5),
            (PartialFailure, 6),
            (SmokeFailed, 7),
            (Internal, 1),
            (NotFound, 1),
            (Conflict, 1),
            (QuotaExceeded, 1),
            (PolicyViolation, 1),
        ];
        for (k, code) in table {
            assert_eq!(k.exit_code(), code, "{k:?}");
        }
    }

    #[test]
    fn carries_resource_and_hint() {
        let e = Error::new(ErrorKind::PermissionDenied, "denied")
            .with_resource("projects/x-project")
            .with_hint("gcp-orgmove plan");
        assert_eq!(e.resource.as_deref(), Some("projects/x-project"));
        assert_eq!(e.exit_code(), 3);
    }
}
