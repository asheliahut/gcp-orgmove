//! indicatif progress bars driven by engine [`Event`]s.
//!
//! Bars draw on **stderr** and are hidden unless a person is watching a
//! terminal (stderr is a TTY, not `-q`, not `--format json`), so stdout stays a
//! clean table or a single JSON document and piped runs print nothing extra.

use std::sync::Mutex;
use std::time::Duration;

use gcp_orgmove_core::progress::{Event, Observer};
use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle};

const BAR_TEMPLATE: &str =
    "{spinner:.green} {prefix} [{bar:20.cyan/blue}] {pos}/{len} {elapsed} {wide_msg}";
const SPINNER_TEMPLATE: &str = "{spinner:.green} {prefix} {elapsed} {wide_msg}";

#[derive(Debug)]
pub struct IndicatifObserver {
    target: fn() -> ProgressDrawTarget,
    current: Mutex<Option<ProgressBar>>,
}

fn stderr_target() -> ProgressDrawTarget {
    ProgressDrawTarget::stderr()
}
fn hidden_target() -> ProgressDrawTarget {
    ProgressDrawTarget::hidden()
}

/// What the current bar shows (for tests).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BarState {
    pub prefix: String,
    pub pos: u64,
    pub len: Option<u64>,
    pub message: String,
}

impl IndicatifObserver {
    pub fn new(visible: bool) -> Self {
        Self {
            target: if visible {
                stderr_target
            } else {
                hidden_target
            },
            current: Mutex::new(None),
        }
    }

    pub fn state(&self) -> Option<BarState> {
        self.current.lock().unwrap().as_ref().map(|b| BarState {
            prefix: b.prefix(),
            pos: b.position(),
            len: b.length(),
            message: b.message(),
        })
    }

    fn style(determinate: bool) -> ProgressStyle {
        let template = if determinate {
            BAR_TEMPLATE
        } else {
            SPINNER_TEMPLATE
        };
        ProgressStyle::with_template(template)
            .unwrap_or_else(|_| ProgressStyle::default_bar())
            .progress_chars("=> ")
    }

    fn finish_current(&self) {
        if let Some(bar) = self.current.lock().unwrap().take() {
            bar.finish_and_clear();
        }
    }
}

impl Observer for IndicatifObserver {
    fn event(&self, e: Event) {
        match e {
            Event::Phase { name, total } => {
                self.finish_current();
                let bar = if total > 0 {
                    ProgressBar::with_draw_target(Some(total), (self.target)())
                } else {
                    ProgressBar::with_draw_target(None, (self.target)())
                };
                bar.set_style(Self::style(total > 0));
                bar.set_prefix(name);
                bar.enable_steady_tick(Duration::from_millis(120));
                *self.current.lock().unwrap() = Some(bar);
            }
            Event::Working(detail) => {
                if let Some(bar) = self.current.lock().unwrap().as_ref() {
                    bar.set_message(detail);
                }
            }
            Event::Tick(detail) => {
                if let Some(bar) = self.current.lock().unwrap().as_ref() {
                    bar.inc(1);
                    bar.set_message(detail);
                }
            }
            Event::End => self.finish_current(),
        }
    }
}

impl Drop for IndicatifObserver {
    fn drop(&mut self) {
        self.finish_current();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gcp_orgmove_core::progress::ObserverExt;
    use std::sync::Arc;

    fn obs() -> Arc<IndicatifObserver> {
        Arc::new(IndicatifObserver::new(false))
    }

    #[test]
    fn tracks_phase_position_and_message() {
        let o = obs();
        let dynobs: &dyn Observer = &*o;
        dynobs.phase("Moving projects", 3);
        assert_eq!(
            o.state().unwrap(),
            BarState {
                prefix: "Moving projects".into(),
                pos: 0,
                len: Some(3),
                message: String::new()
            }
        );
        dynobs.working("moving proj-a");
        assert_eq!(o.state().unwrap().message, "moving proj-a");
        dynobs.tick("proj-a moved");
        dynobs.tick("proj-b moved");
        let st = o.state().unwrap();
        assert_eq!((st.pos, st.message.as_str()), (2, "proj-b moved"));
    }

    #[test]
    fn a_new_phase_replaces_the_old_and_end_clears() {
        let o = obs();
        let dynobs: &dyn Observer = &*o;
        dynobs.phase("one", 2);
        dynobs.tick("x");
        dynobs.phase("two", 0);
        let st = o.state().unwrap();
        assert_eq!(
            (st.prefix.as_str(), st.pos, st.len),
            ("two", 0, None),
            "indeterminate phase is a spinner"
        );
        dynobs.end();
        assert!(o.state().is_none());
        dynobs.end(); // idempotent
        dynobs.tick("stray"); // no bar: ignored, no panic
    }

    #[test]
    fn hidden_bars_still_track_state_but_draw_nothing() {
        let o = IndicatifObserver::new(false);
        o.event(Event::Phase {
            name: "p".into(),
            total: 1,
        });
        o.event(Event::Tick("t".into()));
        assert_eq!(o.state().unwrap().pos, 1);
        assert!(matches!((o.target)(), t if t.is_hidden()));
    }

    #[test]
    fn visible_observers_target_stderr_not_stdout() {
        let o = IndicatifObserver::new(true);
        // A visible target is not hidden when attached to a real terminal; in
        // tests stderr is not a TTY, so indicatif hides it itself. What matters
        // is that we never use the stdout target.
        let t = (o.target)();
        let dbg = format!("{t:?}");
        assert!(!dbg.contains("Stdout"), "{dbg}");
    }

    #[test]
    fn the_templates_are_valid() {
        // with_template errors would silently fall back to the default style.
        for template in [BAR_TEMPLATE, SPINNER_TEMPLATE] {
            assert!(ProgressStyle::with_template(template).is_ok(), "{template}");
        }
    }
}
