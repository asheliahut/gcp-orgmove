//! Smoke tests (§6.7.2): user-defined shell commands that gate progression.
//!
//! Commands run via `sh -c` with the user's environment, minus the tool's
//! own token. They get `ORGMOVE_PROJECT` and `ORGMOVE_PHASE` so a test can
//! target the project that just moved. Exit 0 passes; anything else, or a
//! timeout, fails. A timed-out command's whole process group is killed.

use std::time::Instant;

use async_trait::async_trait;
use chrono::Utc;
use tokio::process::Command;

use crate::apply::ApplyHooks;
use crate::error::{Error, ErrorKind, Result};
use crate::ids::ProjectId;
use crate::manifest::{SmokePhase, SmokeTest};
use crate::state::{SmokeResult, StateHandle};

/// Never passed to smoke tests.
pub const SCRUBBED_ENV: &[&str] = &["GCP_ORGMOVE_TOKEN"];
const OUTPUT_LIMIT: usize = 2048;

fn truncate(mut s: String) -> String {
    if s.len() > OUTPUT_LIMIT {
        let mut cut = OUTPUT_LIMIT;
        while !s.is_char_boundary(cut) {
            cut -= 1;
        }
        s.truncate(cut);
        s.push_str("…[truncated]");
    }
    s
}

fn phase_name(p: SmokePhase) -> &'static str {
    match p {
        SmokePhase::Before => "before",
        SmokePhase::After => "after",
    }
}

#[cfg(unix)]
async fn kill_group(pid: u32) {
    // Negative pid = the whole process group (the child leads its own group).
    let _ = Command::new("kill")
        .args(["-KILL", "--", &format!("-{pid}")])
        .output()
        .await;
}
#[cfg(not(unix))]
async fn kill_group(_pid: u32) {}

/// Run one smoke test.
pub async fn run_test(
    test: &SmokeTest,
    phase: SmokePhase,
    project: Option<&ProjectId>,
) -> SmokeResult {
    let started = Instant::now();
    let mut cmd = Command::new("sh");
    cmd.arg("-c")
        .arg(&test.run)
        .env("ORGMOVE_PHASE", phase_name(phase))
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);
    for var in SCRUBBED_ENV {
        cmd.env_remove(var);
    }
    if let Some(p) = project {
        cmd.env("ORGMOVE_PROJECT", p.as_str());
    }
    #[cfg(unix)]
    cmd.process_group(0);

    let (passed, output) = match cmd.spawn() {
        Err(e) => (false, format!("cannot start command: {e}")),
        Ok(child) => {
            let pid = child.id();
            match tokio::time::timeout(test.timeout.0, child.wait_with_output()).await {
                Ok(Ok(out)) => {
                    let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
                    text.push_str(&String::from_utf8_lossy(&out.stderr));
                    let code = out
                        .status
                        .code()
                        .map(|c| format!("exit {c}"))
                        .unwrap_or_else(|| "killed by signal".into());
                    (
                        out.status.success(),
                        if out.status.success() {
                            text
                        } else {
                            format!("{code}: {text}")
                        },
                    )
                }
                Ok(Err(e)) => (false, format!("cannot wait for command: {e}")),
                Err(_) => {
                    if let Some(pid) = pid {
                        kill_group(pid).await;
                    }
                    (false, format!("timed out after {}", test.timeout))
                }
            }
        }
    };
    SmokeResult {
        project: project.cloned(),
        name: test.name.clone(),
        phase,
        passed,
        duration_ms: started.elapsed().as_millis() as u64,
        output: truncate(output.trim().to_string()),
        at: Utc::now(),
    }
}

/// Run every test configured for `phase`; stops at the first failure.
pub async fn run_phase(
    tests: &[SmokeTest],
    phase: SmokePhase,
    project: Option<&ProjectId>,
) -> Vec<SmokeResult> {
    let mut out = vec![];
    for t in tests.iter().filter(|t| t.phase.contains(&phase)) {
        let r = run_test(t, phase, project).await;
        let failed = !r.passed;
        out.push(r);
        if failed {
            break;
        }
    }
    out
}

/// `apply` hooks that run the manifest's smoke tests and record the results.
pub struct SmokeHooks {
    pub tests: Vec<SmokeTest>,
    pub state: StateHandle,
}

impl SmokeHooks {
    async fn run_and_record(&self, phase: SmokePhase, project: Option<&ProjectId>) -> Result<()> {
        let results = run_phase(&self.tests, phase, project).await;
        let failure = results.iter().find(|r| !r.passed).cloned();
        let recorded = results;
        self.state
            .update(move |s| {
                s.smoke_results.extend(recorded);
                Ok(())
            })
            .await?;
        match failure {
            None => Ok(()),
            Some(f) => Err(Error::new(
                ErrorKind::SmokeFailed,
                format!(
                    "smoke test {:?} ({}) failed: {}",
                    f.name,
                    phase_name(phase),
                    f.output
                ),
            )),
        }
    }
}

#[async_trait]
impl ApplyHooks for SmokeHooks {
    async fn before_moves(&self) -> Result<()> {
        self.run_and_record(SmokePhase::Before, None).await
    }
    async fn after_move(&self, project: &ProjectId) -> Result<()> {
        self.run_and_record(SmokePhase::After, Some(project)).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::HumanDuration;
    use std::time::Duration;

    fn t(name: &str, run: &str, secs: u64) -> SmokeTest {
        SmokeTest {
            name: name.into(),
            run: run.into(),
            timeout: HumanDuration(Duration::from_secs(secs)),
            phase: vec![SmokePhase::Before, SmokePhase::After],
        }
    }

    #[tokio::test]
    async fn exit_zero_passes_and_nonzero_fails_with_output() {
        let ok = run_test(&t("ok", "echo hello", 5), SmokePhase::Before, None).await;
        assert!(ok.passed);
        assert!(ok.output.contains("hello"));
        let bad = run_test(
            &t("bad", "echo boom >&2; exit 3", 5),
            SmokePhase::Before,
            None,
        )
        .await;
        assert!(!bad.passed);
        assert!(bad.output.contains("exit 3") && bad.output.contains("boom"));
    }

    #[tokio::test]
    async fn timeout_fails_and_kills_the_whole_process_group() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("survived");
        // A grandchild that would create the marker if it outlived the test.
        let cmd = format!("(sleep 2; touch {}) & sleep 30", marker.display());
        let started = Instant::now();
        let r = run_test(&t("slow", &cmd, 1), SmokePhase::After, None).await;
        assert!(!r.passed);
        assert!(r.output.contains("timed out after 1s"), "{}", r.output);
        assert!(started.elapsed() < Duration::from_secs(10));
        tokio::time::sleep(Duration::from_millis(2500)).await;
        assert!(
            !marker.exists(),
            "grandchild must have been killed with the group"
        );
    }

    #[tokio::test]
    async fn tool_token_is_scrubbed_but_the_rest_of_the_env_is_kept() {
        std::env::set_var("GCP_ORGMOVE_TOKEN", "supersecret");
        std::env::set_var("ORGMOVE_TEST_KEEP", "kept");
        let r = run_test(
            &t("env", r#"test -z "$GCP_ORGMOVE_TOKEN" && echo "token=[$GCP_ORGMOVE_TOKEN] keep=$ORGMOVE_TEST_KEEP""#, 5),
            SmokePhase::Before,
            None,
        )
        .await;
        std::env::remove_var("GCP_ORGMOVE_TOKEN");
        assert!(r.passed, "{}", r.output);
        assert!(r.output.contains("keep=kept"));
        assert!(!r.output.contains("supersecret"));
    }

    #[tokio::test]
    async fn project_and_phase_are_exported() {
        let p: ProjectId = "proj-aaaa".parse().unwrap();
        let r = run_test(
            &t("vars", r#"echo "$ORGMOVE_PROJECT/$ORGMOVE_PHASE""#, 5),
            SmokePhase::After,
            Some(&p),
        )
        .await;
        assert_eq!(r.output, "proj-aaaa/after");
        assert_eq!(r.project, Some(p));
    }

    #[tokio::test]
    async fn long_output_is_truncated() {
        let r = run_test(
            &t("big", "yes x | head -c 100000", 10),
            SmokePhase::Before,
            None,
        )
        .await;
        assert!(r.output.len() < OUTPUT_LIMIT + 32);
        assert!(r.output.ends_with("[truncated]"));
    }

    #[tokio::test]
    async fn phases_are_filtered_and_run_stops_at_first_failure() {
        let mut only_after = t("only-after", "true", 5);
        only_after.phase = vec![SmokePhase::After];
        let tests = [
            t("a", "true", 5),
            t("b", "exit 1", 5),
            t("c", "true", 5),
            only_after,
        ];
        let before = run_phase(&tests, SmokePhase::Before, None).await;
        let names: Vec<_> = before.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(
            names,
            ["a", "b"],
            "c never runs after b failed; only-after is not a before test"
        );
        let after = run_phase(&tests[3..], SmokePhase::After, None).await;
        assert_eq!(after.len(), 1);
    }

    #[tokio::test]
    async fn missing_binary_is_a_failure_not_a_crash() {
        let r = run_test(
            &t("nope", "definitely-not-a-command-xyz", 5),
            SmokePhase::Before,
            None,
        )
        .await;
        assert!(!r.passed);
    }
}
