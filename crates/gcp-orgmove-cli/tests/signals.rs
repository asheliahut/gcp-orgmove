//! Delivers a real SIGINT to this process and checks the handler sets the flag.

#![cfg(unix)]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

#[tokio::test]
async fn a_real_sigint_sets_the_cancel_flag_without_killing_the_process() {
    let cancel = Arc::new(AtomicBool::new(false));
    gcp_orgmove_cli::signals::install(cancel.clone());
    // Give the handler a moment to register before signalling.
    tokio::time::sleep(Duration::from_millis(200)).await;
    let status = std::process::Command::new("kill")
        .args(["-INT", &std::process::id().to_string()])
        .status()
        .expect("kill is available");
    assert!(status.success());
    for _ in 0..200 {
        if cancel.load(Ordering::SeqCst) {
            return; // still alive, flag set: the handler replaced the default action
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("SIGINT did not set the cancel flag");
}
