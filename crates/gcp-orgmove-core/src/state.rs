//! State file (§4.3): per-project progress, original parents, applied
//! remediations with prior values, policy backups and in-flight operations.
//!
//! Persistence rules:
//! * every mutation goes through [`StateStore::update`], which applies the
//!   change to a copy, writes it atomically (temp file + fsync + rename +
//!   directory fsync) and only then publishes it;
//! * a single writer task serializes updates, so transitions never race;
//! * `<state>.lock` is held exclusively for the life of the store.

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, oneshot};

use crate::error::{Error, ErrorKind, Result};
use crate::finding::Remediation;
use crate::ids::*;
use crate::manifest::SmokePhase;
use crate::model::{IamPolicy, OrgPolicy};
use crate::status::Status;

pub const STATE_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectState {
    pub status: Status,
    pub updated_at: DateTime<Utc>,
    /// Recorded durably *before* the move is attempted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub original_parent: Option<Parent>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub landing_parent: Option<Parent>,
    /// Name of an in-flight long-running operation, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
}

/// Backup of one constraint we changed, enough to restore it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyBackup {
    pub scope: Scope,
    pub constraint: String,
    /// The policy as it was before; `None` if no policy was set on the scope.
    pub prior: Option<OrgPolicy>,
    /// The value we added; restoration removes only this value if the policy
    /// was changed by someone else in the meantime.
    pub added_value: String,
    /// True while the constraint is still modified (not yet restored).
    pub modified: bool,
}

/// The value a remediation overwrote, for reversal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PriorValue {
    Iam {
        scope: Scope,
        policy: IamPolicy,
    },
    PolicyOverride {
        project: ProjectId,
        prior: Option<OrgPolicy>,
    },
    Labels {
        project: ProjectId,
        labels: BTreeMap<String, String>,
    },
    /// Created from nothing (custom roles): reversal deletes.
    CreatedRole {
        name: RoleName,
    },
    /// Added a binding to an existing policy; reversal removes exactly it.
    AddedBinding {
        scope: Scope,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppliedRemediation {
    pub finding: Option<String>,
    pub project: ProjectId,
    pub remediation: Remediation,
    pub prior: Vec<PriorValue>,
    pub applied_at: DateTime<Utc>,
    #[serde(default)]
    pub reverted: bool,
    /// Set by `parity prune` when the superseded access was removed.
    #[serde(default)]
    pub pruned: bool,
}

/// Access removed by `parity prune`, kept so a rollback can put it back.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrunedRecord {
    pub project: ProjectId,
    pub scope: Resource,
    pub binding: crate::model::Binding,
    pub reason: String,
    pub at: DateTime<Utc>,
    #[serde(default)]
    pub restored: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SmokeResult {
    pub project: Option<ProjectId>,
    pub name: String,
    pub phase: SmokePhase,
    pub passed: bool,
    pub duration_ms: u64,
    pub output: String,
    pub at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifyResult {
    pub passed: bool,
    pub detail: String,
    pub at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub version: u32,
    #[serde(default)]
    pub manifest_sha256: String,
    #[serde(default)]
    pub projects: BTreeMap<ProjectId, ProjectState>,
    #[serde(default)]
    pub policy_backups: BTreeMap<String, PolicyBackup>,
    #[serde(default)]
    pub applied: Vec<AppliedRemediation>,
    #[serde(default)]
    pub pruned: Vec<PrunedRecord>,
    #[serde(default)]
    pub smoke_results: Vec<SmokeResult>,
    /// `parity verify` outcome per project (precondition for prune).
    #[serde(default)]
    pub parity_verify: BTreeMap<ProjectId, VerifyResult>,
    /// `verify` (structural) outcome per project.
    #[serde(default)]
    pub verify: BTreeMap<ProjectId, VerifyResult>,
    /// Effective-IAM snapshots for probed principals taken before the move.
    #[serde(default)]
    pub iam_snapshots: BTreeMap<String, Vec<crate::model::GrantKey>>,
}

impl Default for State {
    fn default() -> Self {
        Self {
            version: STATE_VERSION,
            manifest_sha256: String::new(),
            projects: BTreeMap::new(),
            policy_backups: BTreeMap::new(),
            applied: vec![],
            pruned: vec![],
            smoke_results: vec![],
            parity_verify: BTreeMap::new(),
            verify: BTreeMap::new(),
            iam_snapshots: BTreeMap::new(),
        }
    }
}

impl State {
    pub fn project(&self, id: &ProjectId) -> Option<&ProjectState> {
        self.projects.get(id)
    }

    /// Ensure a project entry exists (starting at `Discovered`).
    pub fn ensure_project(&mut self, id: &ProjectId) -> &mut ProjectState {
        self.projects
            .entry(id.clone())
            .or_insert_with(|| ProjectState {
                status: Status::Discovered,
                updated_at: Utc::now(),
                original_parent: None,
                landing_parent: None,
                operation: None,
                group: None,
            })
    }

    /// Validated status transition; stamps `updated_at`.
    pub fn set_status(&mut self, id: &ProjectId, to: Status) -> Result<()> {
        let p = self.ensure_project(id);
        p.status = p
            .status
            .transition(to)
            .map_err(|e| e.with_resource(format!("projects/{id}")))?;
        p.updated_at = Utc::now();
        Ok(())
    }

    /// Constraints still modified (need restoring).
    pub fn pending_constraints(&self) -> impl Iterator<Item = (&String, &PolicyBackup)> {
        self.policy_backups.iter().filter(|(_, b)| b.modified)
    }

    pub fn from_json_bytes(b: &[u8]) -> Result<State> {
        let s: State = serde_json::from_slice(b)
            .map_err(|e| Error::invalid(format!("state file is invalid: {e}")))?;
        if s.version > STATE_VERSION {
            return Err(Error::invalid(format!(
                "state version {} is newer than this tool supports ({STATE_VERSION})",
                s.version
            )));
        }
        // Migration hook: older versions are upgraded in place here.
        Ok(s)
    }

    pub fn to_json_bytes(&self) -> Result<Vec<u8>> {
        let mut b = serde_json::to_vec_pretty(self)?;
        b.push(b'\n');
        Ok(b)
    }
}

/// Atomic write: temp file in the same directory, fsync, rename, fsync dir.
pub fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut tmp = tempfile::NamedTempFile::new_in(dir)?;
    tmp.write_all(bytes)?;
    tmp.as_file().sync_all()?;
    tmp.persist(path).map_err(|e| Error::from(e.error))?;
    #[cfg(unix)]
    File::open(dir)?.sync_all()?;
    Ok(())
}

/// Exclusive lock on `<state>.lock`, released on drop.
#[derive(Debug)]
pub struct StateLock {
    file: File,
    path: PathBuf,
}

impl StateLock {
    pub fn lock_path(state: &Path) -> PathBuf {
        let mut s = state.as_os_str().to_owned();
        s.push(".lock");
        PathBuf::from(s)
    }

    pub fn acquire(state: &Path) -> Result<StateLock> {
        let path = Self::lock_path(state);
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)?;
        if file.try_lock_exclusive().is_err() {
            let mut holder = String::new();
            let _ = file.read_to_string(&mut holder);
            let holder = holder.trim();
            return Err(Error::new(
                ErrorKind::Internal,
                format!(
                    "another gcp-orgmove run holds {} (pid {})",
                    path.display(),
                    if holder.is_empty() { "unknown" } else { holder }
                ),
            )
            .with_hint("wait for it to finish, or remove the lock file if that process is gone"));
        }
        file.set_len(0)?;
        write!(file, "{}", std::process::id())?;
        file.sync_all()?;
        Ok(StateLock { file, path })
    }
}

impl Drop for StateLock {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&self.file);
        let _ = &self.path;
    }
}

type Update = Box<dyn FnOnce(&mut State) -> Result<()> + Send>;

enum Msg {
    Update(Update, oneshot::Sender<Result<()>>),
    Snapshot(oneshot::Sender<State>),
    Shutdown,
}

/// Cloneable handle to the single writer task.
#[derive(Clone)]
pub struct StateHandle {
    tx: mpsc::Sender<Msg>,
}

/// Owns the lock and the writer task.
pub struct StateStore {
    handle: StateHandle,
    _lock: StateLock,
    task: tokio::task::JoinHandle<()>,
}

impl StateStore {
    /// Open (or create in memory; first write creates the file) and lock.
    pub async fn open(path: &Path) -> Result<StateStore> {
        let lock = StateLock::acquire(path)?;
        let state = match std::fs::read(path) {
            Ok(b) => State::from_json_bytes(&b)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => State::default(),
            Err(e) => return Err(e.into()),
        };
        let (tx, mut rx) = mpsc::channel::<Msg>(64);
        let path = path.to_path_buf();
        let task = tokio::spawn(async move {
            let mut state = state;
            while let Some(msg) = rx.recv().await {
                match msg {
                    Msg::Shutdown => break,
                    Msg::Snapshot(reply) => {
                        let _ = reply.send(state.clone());
                    }
                    Msg::Update(f, reply) => {
                        let mut next = state.clone();
                        let res = f(&mut next).and_then(|()| {
                            let bytes = next.to_json_bytes()?;
                            atomic_write(&path, &bytes)
                        });
                        if res.is_ok() {
                            state = next;
                        }
                        let _ = reply.send(res);
                    }
                }
            }
        });
        Ok(StateStore {
            handle: StateHandle { tx },
            _lock: lock,
            task,
        })
    }

    pub fn handle(&self) -> StateHandle {
        self.handle.clone()
    }

    /// Stop the writer after queued updates are flushed.
    pub async fn close(self) {
        let StateStore {
            handle,
            task,
            _lock,
        } = self;
        // Queued updates are processed first (FIFO); the task then exits even
        // if cloned handles are still alive.
        let _ = handle.tx.send(Msg::Shutdown).await;
        let _ = task.await;
    }
}

impl StateHandle {
    /// Apply `f` to a copy of the state and persist it durably before
    /// returning. If `f` fails nothing is written.
    pub async fn update<F>(&self, f: F) -> Result<()>
    where
        F: FnOnce(&mut State) -> Result<()> + Send + 'static,
    {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(Msg::Update(Box::new(f), tx))
            .await
            .map_err(|_| Error::internal("state writer stopped"))?;
        rx.await
            .map_err(|_| Error::internal("state writer stopped"))?
    }

    pub async fn snapshot(&self) -> Result<State> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(Msg::Snapshot(tx))
            .await
            .map_err(|_| Error::internal("state writer stopped"))?;
        rx.await
            .map_err(|_| Error::internal("state writer stopped"))
    }

    pub async fn set_status(&self, id: &ProjectId, to: Status) -> Result<()> {
        let id = id.clone();
        self.update(move |s| s.set_status(&id, to)).await
    }
}

/// Read a state file without locking (for read-only commands like `status`).
pub fn read_state(path: &Path) -> Result<State> {
    match std::fs::read(path) {
        Ok(b) => State::from_json_bytes(&b),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(State::default()),
        Err(e) => Err(e.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pid(s: &str) -> ProjectId {
        s.parse().unwrap()
    }

    #[tokio::test]
    async fn update_persists_before_returning() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("orgmove.state.json");
        let store = StateStore::open(&path).await.unwrap();
        let h = store.handle();
        h.update(|s| {
            s.ensure_project(&pid("my-app-prod"));
            Ok(())
        })
        .await
        .unwrap();
        // File on disk already reflects the update.
        let on_disk = read_state(&path).unwrap();
        assert!(on_disk.projects.contains_key(&pid("my-app-prod")));
        store.close().await;
    }

    #[tokio::test]
    async fn failed_update_writes_nothing_and_keeps_state() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.json");
        let store = StateStore::open(&path).await.unwrap();
        let h = store.handle();
        h.set_status(&pid("my-app-prod"), Status::Analyzed)
            .await
            .unwrap();
        // Illegal: Analyzed -> Verified
        assert!(h
            .set_status(&pid("my-app-prod"), Status::Verified)
            .await
            .is_err());
        let snap = h.snapshot().await.unwrap();
        assert_eq!(snap.projects[&pid("my-app-prod")].status, Status::Analyzed);
        assert_eq!(
            read_state(&path).unwrap().projects[&pid("my-app-prod")].status,
            Status::Analyzed
        );
        store.close().await;
    }

    #[tokio::test]
    async fn second_open_gets_lock_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.json");
        let first = StateStore::open(&path).await.unwrap();
        let err = StateStore::open(&path)
            .await
            .err()
            .expect("lock must be held");
        assert!(
            err.message.contains("another gcp-orgmove run"),
            "{}",
            err.message
        );
        assert!(err.message.contains(&std::process::id().to_string()));
        first.close().await;
        // Released after close.
        StateStore::open(&path).await.unwrap().close().await;
    }

    #[test]
    fn atomic_write_replaces_whole_file_and_leaves_no_temp() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.json");
        atomic_write(&path, b"old").unwrap();
        atomic_write(&path, b"new").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"new");
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn interrupted_write_leaves_old_file_valid() {
        // A crash before rename leaves only a stray temp file; the real
        // file is untouched and still parses.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.json");
        atomic_write(&path, &State::default().to_json_bytes().unwrap()).unwrap();
        let stray = tempfile::NamedTempFile::new_in(dir.path()).unwrap();
        std::fs::write(stray.path(), b"{ half written").unwrap();
        assert!(read_state(&path).is_ok());
    }

    #[test]
    fn rejects_newer_state_version() {
        let s = State {
            version: 99,
            ..State::default()
        };
        let err = State::from_json_bytes(&s.to_json_bytes().unwrap()).unwrap_err();
        assert_eq!(err.exit_code(), 2);
    }

    #[test]
    fn pending_constraints_lists_only_modified() {
        let mut s = State::default();
        let mk = |m| PolicyBackup {
            scope: "organizations/1".parse().unwrap(),
            constraint: "c".into(),
            prior: None,
            added_value: "v".into(),
            modified: m,
        };
        s.policy_backups.insert("a".into(), mk(true));
        s.policy_backups.insert("b".into(), mk(false));
        assert_eq!(s.pending_constraints().count(), 1);
    }
}
