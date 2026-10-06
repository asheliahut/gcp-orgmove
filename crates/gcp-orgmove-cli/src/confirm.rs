//! Interactive confirmation (§7 "Dry-run by default").
//!
//! A mutating command prints what it would do, then (only in an interactive
//! terminal) asks before doing it. Prompts go to stderr so stdout stays clean.

use std::io::{BufRead, IsTerminal, Write};

use gcp_orgmove_core::Result;

pub trait Confirm: Sync {
    /// Ask `question`. `strict` demands the full word `yes` (destructive steps);
    /// otherwise `y`/`yes` is enough. Anything else, or EOF, means no.
    fn confirm(&self, question: &str, strict: bool) -> Result<bool>;
}

/// Interpret an answer line.
pub fn parse_answer(input: &str, strict: bool) -> bool {
    let a = input.trim().to_ascii_lowercase();
    if strict {
        a == "yes"
    } else {
        a == "y" || a == "yes"
    }
}

/// Reads the answer from stdin, prompting on stderr.
pub struct StdinConfirm;

impl Confirm for StdinConfirm {
    fn confirm(&self, question: &str, strict: bool) -> Result<bool> {
        let hint = if strict {
            "type 'yes' to continue"
        } else {
            "y/N"
        };
        let mut err = std::io::stderr().lock();
        let _ = write!(err, "{question} [{hint}]: ");
        let _ = err.flush();
        drop(err);
        let mut line = String::new();
        match std::io::stdin().lock().read_line(&mut line) {
            Ok(0) | Err(_) => Ok(false),
            Ok(_) => Ok(parse_answer(&line, strict)),
        }
    }
}

/// Always declines (used when nothing can be asked).
pub struct NeverConfirm;

impl Confirm for NeverConfirm {
    fn confirm(&self, _: &str, _: bool) -> Result<bool> {
        Ok(false)
    }
}

/// Can we show a preview and read an answer?
pub fn stdio_is_interactive() -> bool {
    std::io::stdin().is_terminal() && std::io::stderr().is_terminal()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn answers() {
        for (input, strict, want) in [
            ("y\n", false, true),
            ("Y", false, true),
            ("yes", false, true),
            (" YES \n", false, true),
            ("n", false, false),
            ("", false, false),
            ("sure", false, false),
            ("y", true, false),
            ("yes", true, true),
            ("YES\n", true, true),
            ("yep", true, false),
        ] {
            assert_eq!(
                parse_answer(input, strict),
                want,
                "{input:?} strict={strict}"
            );
        }
    }

    #[test]
    fn never_declines() {
        assert!(!NeverConfirm.confirm("ok?", false).unwrap());
    }
}
