//! Interrupt handling (§6.5, §9.5).
//!
//! First SIGINT/SIGTERM: set the cancel flag. `apply` and `rollback` then stop
//! starting new work, finish polling operations already in flight, and restore
//! the org-policy constraints. Second signal: give up at once; the state file
//! still records which constraints are modified, so the next run repairs them.

use std::future::Future;
use std::sync::atomic::Ordering;

use gcp_orgmove_core::apply::CancelFlag;

pub const ABORT_EXIT_CODE: i32 = 130;

/// The signal loop, with the waiter and the abort action injected so it can
/// be tested without delivering real signals.
pub async fn cancel_loop<W, Fut>(cancel: CancelFlag, mut wait: W, on_abort: impl Fn())
where
    W: FnMut() -> Fut,
    Fut: Future<Output = ()>,
{
    loop {
        wait().await;
        if cancel.swap(true, Ordering::SeqCst) {
            eprintln!("aborting; the next run restores any constraints still modified");
            on_abort();
            return;
        }
        eprintln!("interrupt received: finishing in-flight operations and restoring constraints (press again to abort)");
    }
}

/// Wait for SIGINT (or SIGTERM on unix).
#[cfg(unix)]
async fn next_signal(term: &mut Option<tokio::signal::unix::Signal>) {
    let term_fut = async {
        match term.as_mut() {
            Some(t) => {
                t.recv().await;
            }
            None => std::future::pending::<()>().await,
        }
    };
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        () = term_fut => {}
    }
}

/// Install the real handler. A second signal exits the process with 130.
pub fn install(cancel: CancelFlag) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        #[cfg(unix)]
        {
            let term =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).ok();
            let term = std::sync::Arc::new(tokio::sync::Mutex::new(term));
            cancel_loop(
                cancel,
                || {
                    let term = term.clone();
                    async move {
                        let mut guard = term.lock().await;
                        next_signal(&mut guard).await;
                    }
                },
                || std::process::exit(ABORT_EXIT_CODE),
            )
            .await;
        }
        #[cfg(not(unix))]
        {
            cancel_loop(
                cancel,
                || async {
                    let _ = tokio::signal::ctrl_c().await;
                },
                || std::process::exit(ABORT_EXIT_CODE),
            )
            .await;
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize};
    use std::sync::Arc;
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn first_signal_cancels_second_aborts() {
        let cancel: CancelFlag = Arc::new(AtomicBool::new(false));
        let aborted = Arc::new(AtomicUsize::new(0));
        let (tx, rx) = mpsc::channel::<()>(4);
        let rx = Arc::new(tokio::sync::Mutex::new(rx));
        let (c2, a2) = (cancel.clone(), aborted.clone());
        let task = tokio::spawn(async move {
            cancel_loop(
                c2,
                || {
                    let rx = rx.clone();
                    async move {
                        rx.lock().await.recv().await;
                    }
                },
                move || {
                    a2.fetch_add(1, Ordering::SeqCst);
                },
            )
            .await;
        });
        assert!(!cancel.load(Ordering::SeqCst));
        tx.send(()).await.unwrap();
        for _ in 0..200 {
            if cancel.load(Ordering::SeqCst) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        assert!(cancel.load(Ordering::SeqCst), "first signal sets the flag");
        assert_eq!(aborted.load(Ordering::SeqCst), 0, "...and does not abort");
        tx.send(()).await.unwrap();
        task.await.unwrap();
        assert_eq!(aborted.load(Ordering::SeqCst), 1, "second signal aborts");
    }
}
