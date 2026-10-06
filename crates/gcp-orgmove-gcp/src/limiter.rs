//! Bounded concurrency with AIMD back-off (§9.5).
//!
//! At most `max` calls are in flight. Each throttling response (429 /
//! `QuotaExceeded`) halves the effective limit; each full window of
//! successes adds one back, up to `max`.

use std::future::Future;
use std::sync::{Arc, Mutex};

use gcp_orgmove_core::{ErrorKind, Result};
use tokio::sync::Semaphore;

/// Hard cap from the spec (§3.1).
pub const HARD_CAP: usize = 16;

#[derive(Debug)]
struct Window {
    limit: usize,
    ok_streak: usize,
}

#[derive(Debug, Clone)]
pub struct Limiter {
    sem: Arc<Semaphore>,
    max: usize,
    win: Arc<Mutex<Window>>,
}

impl Limiter {
    pub fn new(concurrency: usize) -> Self {
        let max = concurrency.clamp(1, HARD_CAP);
        Self {
            sem: Arc::new(Semaphore::new(max)),
            max,
            win: Arc::new(Mutex::new(Window {
                limit: max,
                ok_streak: 0,
            })),
        }
    }

    /// Current effective concurrency.
    pub fn effective(&self) -> usize {
        self.win.lock().unwrap().limit
    }

    pub async fn run<T, F>(&self, fut: F) -> Result<T>
    where
        F: Future<Output = Result<T>>,
    {
        let permit = self.sem.acquire().await.expect("semaphore is never closed");
        let res = fut.await;
        drop(permit);
        match &res {
            Err(e) if e.kind == ErrorKind::QuotaExceeded => self.throttled().await,
            Ok(_) => self.succeeded(),
            Err(_) => {}
        }
        res
    }

    async fn throttled(&self) {
        let shrink = {
            let mut w = self.win.lock().unwrap();
            w.ok_streak = 0;
            let new = (w.limit / 2).max(1);
            let shrink = w.limit - new;
            w.limit = new;
            shrink
        };
        if shrink > 0 {
            // Hold the permits back so fewer calls can be in flight.
            if let Ok(p) = self.sem.acquire_many(shrink as u32).await {
                p.forget();
            }
        }
    }

    fn succeeded(&self) {
        let grow = {
            let mut w = self.win.lock().unwrap();
            w.ok_streak += 1;
            if w.ok_streak >= w.limit && w.limit < self.max {
                w.ok_streak = 0;
                w.limit += 1;
                true
            } else {
                false
            }
        };
        if grow {
            self.sem.add_permits(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gcp_orgmove_core::Error;
    use std::sync::atomic::{AtomicUsize, Ordering};

    async fn ok() -> Result<()> {
        Ok(())
    }
    async fn throttle() -> Result<()> {
        Err(Error::new(ErrorKind::QuotaExceeded, "429"))
    }

    #[test]
    fn caps_at_hard_limit() {
        assert_eq!(Limiter::new(100).effective(), HARD_CAP);
        assert_eq!(Limiter::new(0).effective(), 1);
    }

    #[tokio::test]
    async fn throttling_halves_and_successes_recover() {
        let l = Limiter::new(8);
        let _ = l.run(throttle()).await;
        assert_eq!(l.effective(), 4);
        let _ = l.run(throttle()).await;
        let _ = l.run(throttle()).await;
        let _ = l.run(throttle()).await;
        assert_eq!(l.effective(), 1);
        for _ in 0..40 {
            l.run(ok()).await.unwrap();
        }
        assert!(l.effective() > 1, "recovers additively");
        assert!(l.effective() <= 8);
    }

    #[tokio::test]
    async fn other_errors_do_not_shrink() {
        let l = Limiter::new(8);
        let _ = l
            .run(async { Err::<(), _>(Error::new(ErrorKind::NotFound, "x")) })
            .await;
        assert_eq!(l.effective(), 8);
    }

    #[tokio::test]
    async fn enforces_the_bound() {
        let l = Limiter::new(3);
        let (cur, peak) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
        let tasks: Vec<_> = (0..20)
            .map(|_| {
                let (l, cur, peak) = (l.clone(), cur.clone(), peak.clone());
                tokio::spawn(async move {
                    l.run(async {
                        let n = cur.fetch_add(1, Ordering::SeqCst) + 1;
                        peak.fetch_max(n, Ordering::SeqCst);
                        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                        cur.fetch_sub(1, Ordering::SeqCst);
                        Ok(())
                    })
                    .await
                })
            })
            .collect();
        for t in tasks {
            t.await.unwrap().unwrap();
        }
        assert!(peak.load(Ordering::SeqCst) <= 3);
    }

    #[tokio::test]
    async fn still_makes_progress_at_limit_one() {
        let l = Limiter::new(2);
        for _ in 0..5 {
            let _ = l.run(throttle()).await;
        }
        assert_eq!(l.effective(), 1);
        l.run(ok()).await.unwrap();
    }
}
