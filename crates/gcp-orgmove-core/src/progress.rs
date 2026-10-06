//! Progress reporting without a UI: engines emit [`Event`]s to an
//! [`Observer`]; the CLI turns them into progress bars. Core stays free of
//! terminal concerns, and tests can record what was reported.

use std::fmt::Debug;
use std::sync::{Arc, Mutex};

/// One thing the engine wants to tell the user about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// A new stage with `total` units of work. Any earlier stage is finished.
    Phase { name: String, total: u64 },
    /// Work on `detail` has started (no progress yet).
    Working(String),
    /// One unit of work finished.
    Tick(String),
    /// The current stage is over (always sent, including on error or cancel).
    End,
}

pub trait Observer: Send + Sync + Debug {
    fn event(&self, e: Event);
}

pub type SharedObserver = Arc<dyn Observer>;

/// Discards everything. The default everywhere.
#[derive(Debug, Default, Clone, Copy)]
pub struct Silent;

impl Observer for Silent {
    fn event(&self, _: Event) {}
}

pub fn silent() -> SharedObserver {
    Arc::new(Silent)
}

/// Convenience emitters so call sites stay short.
pub trait ObserverExt {
    fn phase(&self, name: &str, total: usize);
    fn working(&self, detail: impl ToString);
    fn tick(&self, detail: impl ToString);
    fn end(&self);
}

impl ObserverExt for dyn Observer {
    fn phase(&self, name: &str, total: usize) {
        self.event(Event::Phase {
            name: name.to_string(),
            total: total as u64,
        });
    }
    fn working(&self, detail: impl ToString) {
        self.event(Event::Working(detail.to_string()));
    }
    fn tick(&self, detail: impl ToString) {
        self.event(Event::Tick(detail.to_string()));
    }
    fn end(&self) {
        self.event(Event::End);
    }
}

/// Ends the current stage when dropped, so `End` is sent exactly once even on
/// early return, error, cancel or panic.
pub struct PhaseGuard {
    obs: SharedObserver,
}

impl PhaseGuard {
    pub fn start(obs: &SharedObserver, name: &str, total: usize) -> Self {
        obs.phase(name, total);
        Self { obs: obs.clone() }
    }
}

impl Drop for PhaseGuard {
    fn drop(&mut self) {
        self.obs.end();
    }
}

/// For long functions with several sequential stages: each [`Stages::begin`]
/// starts a new stage (which implicitly finishes the previous one), and
/// dropping the value sends `End`, even on an early `?` return.
pub struct Stages {
    obs: SharedObserver,
}

impl Stages {
    pub fn new(obs: &SharedObserver) -> Self {
        Self { obs: obs.clone() }
    }
    pub fn begin(&self, name: &str, total: usize) {
        self.obs.phase(name, total);
    }
}

impl Drop for Stages {
    fn drop(&mut self) {
        self.obs.end();
    }
}

/// Records events (for tests).
#[derive(Debug, Default)]
pub struct Recorder {
    events: Mutex<Vec<Event>>,
}

impl Recorder {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }
    pub fn events(&self) -> Vec<Event> {
        self.events.lock().unwrap().clone()
    }
    pub fn count(&self, f: impl Fn(&Event) -> bool) -> usize {
        self.events().iter().filter(|e| f(e)).count()
    }
    pub fn ticks(&self) -> usize {
        self.count(|e| matches!(e, Event::Tick(_)))
    }
    pub fn ends(&self) -> usize {
        self.count(|e| matches!(e, Event::End))
    }
    pub fn phases(&self) -> Vec<(String, u64)> {
        self.events()
            .into_iter()
            .filter_map(|e| match e {
                Event::Phase { name, total } => Some((name, total)),
                _ => None,
            })
            .collect()
    }
}

impl Observer for Recorder {
    fn event(&self, e: Event) {
        self.events.lock().unwrap().push(e);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guard_sends_end_once_even_on_early_exit() {
        let rec = Recorder::new();
        let obs: SharedObserver = rec.clone();
        {
            let _g = PhaseGuard::start(&obs, "moving", 3);
            obs.tick("a");
        }
        assert_eq!(rec.phases(), vec![("moving".to_string(), 3)]);
        assert_eq!((rec.ticks(), rec.ends()), (1, 1));
    }

    #[test]
    fn guard_ends_on_panic() {
        let rec = Recorder::new();
        let obs: SharedObserver = rec.clone();
        let o2 = obs.clone();
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let _g = PhaseGuard::start(&o2, "x", 1);
            panic!("boom");
        }));
        assert!(r.is_err());
        assert_eq!(rec.ends(), 1);
    }

    #[test]
    fn silent_discards() {
        let s = silent();
        s.phase("p", 1);
        s.tick("t");
        s.end();
    }
}
