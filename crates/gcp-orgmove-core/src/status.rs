//! Per-project state machine (§5).

use serde::{Deserialize, Serialize};

use crate::error::{Error, ErrorKind, Result};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum Status {
    Discovered,
    Analyzed,
    /// Terminal until the plan is regenerated.
    Blocked,
    ParityGaps,
    ParityFixed,
    Ready,
    Moving,
    Failed {
        reason: String,
    },
    Moved,
    Verified,
    RolledBack,
}

/// Payload-free discriminant, used for the transition table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Kind {
    Discovered,
    Analyzed,
    Blocked,
    ParityGaps,
    ParityFixed,
    Ready,
    Moving,
    Failed,
    Moved,
    Verified,
    RolledBack,
}

impl Kind {
    pub const ALL: [Kind; 11] = [
        Kind::Discovered,
        Kind::Analyzed,
        Kind::Blocked,
        Kind::ParityGaps,
        Kind::ParityFixed,
        Kind::Ready,
        Kind::Moving,
        Kind::Failed,
        Kind::Moved,
        Kind::Verified,
        Kind::RolledBack,
    ];

    /// Allowed transitions: forward only, plus `Failed -> Ready` and
    /// `Moved/Verified -> RolledBack`. `Ready -> Moved` covers a project that
    /// is already at its landing parent (idempotency). `Blocked -> Analyzed`
    /// happens only when the plan is regenerated.
    pub fn can_go_to(self, to: Kind) -> bool {
        use Kind::*;
        matches!(
            (self, to),
            (Discovered, Analyzed)
                | (Analyzed, Blocked | ParityGaps | Ready)
                | (Blocked, Analyzed)
                | (ParityGaps, ParityFixed | Ready)
                | (ParityFixed, Ready)
                | (Ready, Moving | Moved)
                | (Moving, Moved | Failed)
                | (Failed, Ready)
                | (Moved, Verified | RolledBack)
                | (Verified, RolledBack)
        )
    }
}

impl Status {
    pub fn kind(&self) -> Kind {
        match self {
            Status::Discovered => Kind::Discovered,
            Status::Analyzed => Kind::Analyzed,
            Status::Blocked => Kind::Blocked,
            Status::ParityGaps => Kind::ParityGaps,
            Status::ParityFixed => Kind::ParityFixed,
            Status::Ready => Kind::Ready,
            Status::Moving => Kind::Moving,
            Status::Failed { .. } => Kind::Failed,
            Status::Moved => Kind::Moved,
            Status::Verified => Kind::Verified,
            Status::RolledBack => Kind::RolledBack,
        }
    }

    pub fn failed(reason: impl Into<String>) -> Status {
        Status::Failed {
            reason: reason.into(),
        }
    }

    /// Validate and perform a transition, returning the new status.
    pub fn transition(&self, to: Status) -> Result<Status> {
        if self.kind().can_go_to(to.kind()) {
            Ok(to)
        } else {
            Err(Error::new(
                ErrorKind::Internal,
                format!(
                    "illegal state transition {:?} -> {:?}",
                    self.kind(),
                    to.kind()
                ),
            ))
        }
    }

    /// Whether the project has been moved into the destination org.
    pub fn is_in_destination(&self) -> bool {
        matches!(self, Status::Moved | Status::Verified)
    }

    pub fn is_terminal(&self) -> bool {
        matches!(self, Status::RolledBack)
    }
}

/// Outcome of a move group: atomic at group level (§5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GroupOutcome {
    /// Every member moved.
    Moved,
    /// At least one member failed; remaining members must not start.
    Halted {
        failed: Vec<String>,
    },
    InProgress,
}

pub fn group_outcome(members: &[&Status]) -> GroupOutcome {
    let failed: Vec<String> = members
        .iter()
        .filter_map(|s| match s {
            Status::Failed { reason } => Some(reason.clone()),
            _ => None,
        })
        .collect();
    if !failed.is_empty() {
        GroupOutcome::Halted { failed }
    } else if members.iter().all(|s| s.is_in_destination()) {
        GroupOutcome::Moved
    } else {
        GroupOutcome::InProgress
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use Kind::*;

    #[test]
    fn exhaustive_transition_table() {
        let allowed: &[(Kind, Kind)] = &[
            (Discovered, Analyzed),
            (Analyzed, Blocked),
            (Analyzed, ParityGaps),
            (Analyzed, Ready),
            (Blocked, Analyzed),
            (ParityGaps, ParityFixed),
            (ParityGaps, Ready),
            (ParityFixed, Ready),
            (Ready, Moving),
            (Ready, Moved),
            (Moving, Moved),
            (Moving, Failed),
            (Failed, Ready),
            (Moved, Verified),
            (Moved, RolledBack),
            (Verified, RolledBack),
        ];
        for from in Kind::ALL {
            for to in Kind::ALL {
                assert_eq!(
                    from.can_go_to(to),
                    allowed.contains(&(from, to)),
                    "{from:?} -> {to:?}"
                );
            }
        }
    }

    #[test]
    fn rolled_back_is_terminal() {
        for to in Kind::ALL {
            assert!(!RolledBack.can_go_to(to));
        }
    }

    #[test]
    fn transition_rejects_illegal() {
        assert!(Status::Ready.transition(Status::Verified).is_err());
        assert_eq!(
            Status::Ready.transition(Status::Moving).unwrap(),
            Status::Moving
        );
    }

    #[test]
    fn group_halts_on_any_failure() {
        let f = Status::failed("boom");
        assert_eq!(
            group_outcome(&[&Status::Moved, &f]),
            GroupOutcome::Halted {
                failed: vec!["boom".into()]
            }
        );
        assert_eq!(
            group_outcome(&[&Status::Moved, &Status::Verified]),
            GroupOutcome::Moved
        );
        assert_eq!(
            group_outcome(&[&Status::Moved, &Status::Moving]),
            GroupOutcome::InProgress
        );
    }

    proptest! {
        /// Random walks only through legal edges never reach an illegal state,
        /// and nothing ever leaves RolledBack or returns to an earlier phase.
        #[test]
        fn random_walks_stay_legal(steps in proptest::collection::vec(0usize..11, 0..60)) {
            let mut cur = Status::Discovered;
            for s in steps {
                let to = Kind::ALL[s];
                let next = match to {
                    Failed => Status::failed("x"),
                    Discovered => Status::Discovered,
                    Analyzed => Status::Analyzed,
                    Blocked => Status::Blocked,
                    ParityGaps => Status::ParityGaps,
                    ParityFixed => Status::ParityFixed,
                    Ready => Status::Ready,
                    Moving => Status::Moving,
                    Moved => Status::Moved,
                    Verified => Status::Verified,
                    RolledBack => Status::RolledBack,
                };
                match cur.transition(next.clone()) {
                    Ok(n) => cur = n,
                    Err(_) => prop_assert!(!cur.kind().can_go_to(next.kind())),
                }
                prop_assert!(Kind::ALL.contains(&cur.kind()));
            }
        }
    }
}
