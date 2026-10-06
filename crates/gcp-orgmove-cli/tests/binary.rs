use assert_cmd::Command;
use predicates::prelude::*;

fn cmd() -> Command {
    Command::cargo_bin("gcp-orgmove").unwrap()
}

#[test]
fn help_lists_every_command() {
    let out = cmd().arg("--help").assert().success();
    let text = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    for c in [
        "init", "discover", "plan", "parity", "apply", "verify", "rollback", "status",
    ] {
        assert!(text.contains(c), "--help is missing {c}");
    }
}

#[test]
fn global_options_work_after_the_subcommand() {
    cmd()
        .args(["plan", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--strict"));
    cmd()
        .args(["status", "--concurrency", "99"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("99"));
}

#[test]
fn usage_errors_exit_2() {
    cmd().arg("bogus").assert().code(2);
    cmd().args(["--format", "xml", "status"]).assert().code(2);
}

#[test]
fn missing_manifest_is_exit_2_with_a_hint() {
    let dir = tempfile::tempdir().unwrap();
    cmd()
        .current_dir(dir.path())
        .env_remove("GOOGLE_APPLICATION_CREDENTIALS")
        .env("GCP_ORGMOVE_TOKEN", "unused")
        .args(["--token-source", "env", "plan"])
        .assert()
        .code(2)
        .stderr(
            predicate::str::contains("cannot read manifest")
                .and(predicate::str::contains("hint: run `gcp-orgmove init`")),
        );
}

#[test]
fn status_needs_no_credentials_and_handles_missing_state() {
    let dir = tempfile::tempdir().unwrap();
    cmd()
        .current_dir(dir.path())
        .env_remove("GOOGLE_APPLICATION_CREDENTIALS")
        .env("HOME", dir.path())
        .arg("status")
        .assert()
        .success()
        .stdout(predicate::str::contains("No project state recorded yet"));
}

#[test]
fn missing_env_token_is_exit_3() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("orgmove.yaml"),
        "version: 1\nsource_org: \"1\"\ndestination_org: \"2\"\nprojects:\n  - id: proj-aaaa\n",
    )
    .unwrap();
    cmd()
        .current_dir(dir.path())
        .env_remove("GCP_ORGMOVE_TOKEN")
        .args(["--token-source", "env", "plan"])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("GCP_ORGMOVE_TOKEN"));
}

#[test]
fn version_includes_the_crate_version_and_commit() {
    let out = cmd().arg("--version").assert().success();
    let text = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    assert!(text.starts_with("gcp-orgmove "), "{text}");
    assert!(text.contains(env!("CARGO_PKG_VERSION")), "{text}");
    assert!(
        text.contains('(') && text.contains(')'),
        "commit is embedded: {text}"
    );
}

fn project_dir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("orgmove.yaml"),
        "version: 1\nsource_org: \"1\"\ndestination_org: \"2\"\nprojects:\n  - id: proj-aaaa\n",
    )
    .unwrap();
    dir
}

#[test]
fn a_bad_auth_spec_is_a_usage_error() {
    let dir = project_dir();
    for args in [
        vec!["--source-auth", "kerberos", "plan"],
        vec!["--destination-auth", "adc:", "plan"],
        vec!["--token-source", "token:abc", "plan"],
    ] {
        cmd()
            .current_dir(dir.path())
            .args(&args)
            .assert()
            .code(2)
            .stderr(predicate::str::contains("auth spec").or(predicate::str::contains("expected")));
    }
}

#[test]
fn each_side_names_its_own_missing_variable() {
    let dir = project_dir();
    cmd()
        .current_dir(dir.path())
        .env("GCP_ORGMOVE_TOKEN", "x")
        .args([
            "--token-source",
            "env",
            "--destination-auth",
            "env:ORGMOVE_NO_DEST_TOKEN",
            "plan",
        ])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("ORGMOVE_NO_DEST_TOKEN is not set"));
    cmd()
        .current_dir(dir.path())
        .args([
            "--source-auth",
            "env:ORGMOVE_NO_SRC_TOKEN",
            "--destination-auth",
            "env:ORGMOVE_NO_DEST_TOKEN",
            "plan",
        ])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("ORGMOVE_NO_SRC_TOKEN is not set"));
}

#[test]
fn a_missing_credentials_file_is_named() {
    let dir = project_dir();
    cmd()
        .current_dir(dir.path())
        .env("GCP_ORGMOVE_TOKEN", "x")
        .args([
            "--token-source",
            "env",
            "--destination-auth",
            "adc:/definitely/not/here.json",
            "plan",
        ])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("/definitely/not/here.json"));
}

#[test]
fn move_as_must_be_source_or_destination() {
    let dir = project_dir();
    cmd()
        .current_dir(dir.path())
        .args(["--move-as", "both", "plan"])
        .assert()
        .code(2);
}

#[test]
fn help_documents_the_per_org_options() {
    let out = cmd().arg("--help").assert().success();
    let text = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    for flag in [
        "--source-auth",
        "--destination-auth",
        "--source-quota-project",
        "--destination-quota-project",
        "--move-as",
    ] {
        assert!(text.contains(flag), "--help is missing {flag}");
    }
}
