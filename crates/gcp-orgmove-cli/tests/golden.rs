//! Golden `--format json` output for every command. The JSON envelope is a
//! stable interface (`schema_version`); a diff here means a breaking change.
//! Volatile fields (timestamps, durations, temp paths) are scrubbed.

mod common;

use common::*;
use gcp_orgmove_core::fake::FakeGcp;
use serde_json::Value;

fn scrub(v: &mut Value, dir: &str) {
    match v {
        Value::Object(m) => {
            for (k, val) in m.iter_mut() {
                if matches!(
                    k.as_str(),
                    "generated_at" | "updated_at" | "at" | "applied_at"
                ) {
                    *val = Value::String("[timestamp]".into());
                } else if k == "duration_ms" {
                    *val = Value::from(0);
                } else if k == "manifest_sha256" {
                    *val = Value::String("[sha256]".into());
                } else {
                    scrub(val, dir);
                }
            }
        }
        Value::Array(a) => a.iter_mut().for_each(|x| scrub(x, dir)),
        Value::String(s) => *s = s.replace(dir, "<dir>"),
        _ => {}
    }
}

async fn golden(g: &FakeGcp, dir: &std::path::Path, args: &[&str]) -> String {
    let mut full = vec!["--format", "json"];
    full.extend_from_slice(args);
    let r = cli(g, dir, &full).await;
    let code = r.code.unwrap_or_else(|e| panic!("{args:?} failed: {e}"));
    assert!(code == 0 || code == 4, "{args:?} exited {code}: {}", r.out);
    let mut v: Value = serde_json::from_str(&r.out)
        .unwrap_or_else(|e| panic!("{args:?} did not print one JSON document ({e}): {}", r.out));
    assert_eq!(v["schema_version"], 1);
    scrub(&mut v, &dir.display().to_string());
    serde_json::to_string_pretty(&v).unwrap()
}

fn rich_world() -> FakeGcp {
    let g = world();
    g.grant(
        "organizations/111",
        "roles/compute.viewer",
        "group:eng@x.com",
    );
    g.group("eng@x.com");
    g
}

#[tokio::test]
async fn every_command_has_a_stable_json_shape() {
    let dir = tempfile::tempdir().unwrap();
    let g = rich_world();
    let d = dir.path();

    insta::assert_snapshot!(
        "init",
        golden(
            &g,
            d,
            &["init", "--source-org", "111", "--destination-org", "222"]
        )
        .await
    );
    write_manifest(d);
    insta::assert_snapshot!("discover", golden(&g, d, &["discover"]).await);
    insta::assert_snapshot!("plan", golden(&g, d, &["plan"]).await);
    insta::assert_snapshot!(
        "parity_fix_dry_run",
        golden(&g, d, &["parity", "fix"]).await
    );
    let fixed = golden(&g, d, &["parity", "fix", "--yes"]).await;
    insta::assert_snapshot!("parity_fix", fixed);
    insta::assert_snapshot!("parity_check", golden(&g, d, &["parity", "check"]).await);
    insta::assert_snapshot!("apply_dry_run", golden(&g, d, &["apply"]).await);
    insta::assert_snapshot!("apply", golden(&g, d, &["apply", "--yes"]).await);
    insta::assert_snapshot!("status", golden(&g, d, &["status"]).await);
    insta::assert_snapshot!("verify", golden(&g, d, &["verify"]).await);
    insta::assert_snapshot!("parity_verify", golden(&g, d, &["parity", "verify"]).await);
    insta::assert_snapshot!("parity_prune", golden(&g, d, &["parity", "prune"]).await);
    insta::assert_snapshot!(
        "rollback_dry_run",
        golden(&g, d, &["rollback", "--all"]).await
    );
    insta::assert_snapshot!(
        "rollback",
        golden(&g, d, &["rollback", "--all", "--yes"]).await
    );
}
