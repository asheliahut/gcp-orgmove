//! Output: tables for people, stable JSON for machines.

use std::io::Write;

use comfy_table::{presets::UTF8_FULL_CONDENSED, ContentArrangement, Table};
use serde::Serialize;

use crate::cli::Format;

/// Version of the `--format json` envelope; bump on breaking changes.
pub const JSON_SCHEMA_VERSION: u32 = 1;

pub struct Printer<'a> {
    pub format: Format,
    pub quiet: bool,
    pub out: &'a mut dyn Write,
}

#[derive(Serialize)]
struct Envelope<'a, T: Serialize> {
    schema_version: u32,
    command: &'a str,
    data: &'a T,
}

impl<'a> Printer<'a> {
    pub fn new(format: Format, quiet: bool, out: &'a mut dyn Write) -> Self {
        Self { format, quiet, out }
    }

    pub fn is_json(&self) -> bool {
        self.format == Format::Json
    }

    /// Informational line (suppressed by -q and in JSON mode).
    pub fn info(&mut self, line: impl AsRef<str>) {
        if !self.quiet && !self.is_json() {
            let _ = writeln!(self.out, "{}", line.as_ref());
        }
    }

    /// A table in table mode. In JSON mode nothing is printed here; the
    /// command emits its single JSON document via [`Printer::json`].
    pub fn table(&mut self, headers: &[&str], rows: Vec<Vec<String>>) {
        if self.quiet || self.is_json() {
            return;
        }
        let mut t = Table::new();
        t.load_preset(UTF8_FULL_CONDENSED)
            .set_content_arrangement(ContentArrangement::Dynamic);
        t.set_header(headers);
        for r in rows {
            t.add_row(r);
        }
        let _ = writeln!(self.out, "{t}");
    }

    /// The command's one JSON document (JSON mode only).
    pub fn json<T: Serialize>(&mut self, command: &str, data: &T) {
        if self.is_json() {
            let env = Envelope {
                schema_version: JSON_SCHEMA_VERSION,
                command,
                data,
            };
            let _ = writeln!(
                self.out,
                "{}",
                serde_json::to_string_pretty(&env).expect("serializable")
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_envelope_is_versioned() {
        let mut buf = vec![];
        Printer::new(Format::Json, false, &mut buf)
            .json("plan", &serde_json::json!({"projects": 2}));
        let v: serde_json::Value = serde_json::from_slice(&buf).unwrap();
        assert_eq!(v["schema_version"], 1);
        assert_eq!(v["command"], "plan");
        assert_eq!(v["data"]["projects"], 2);
    }

    #[test]
    fn table_mode_prints_table_json_mode_does_not() {
        let mut buf = vec![];
        Printer::new(Format::Table, false, &mut buf).table(&["ID"], vec![vec!["proj-aaaa".into()]]);
        assert!(String::from_utf8(buf).unwrap().contains("proj-aaaa"));
        let mut buf = vec![];
        let mut p = Printer::new(Format::Json, false, &mut buf);
        p.table(&["ID"], vec![vec!["x".into()]]);
        p.info("hello");
        assert!(buf.is_empty());
    }

    #[test]
    fn quiet_suppresses_info() {
        let mut buf = vec![];
        Printer::new(Format::Table, true, &mut buf).info("hello");
        assert!(buf.is_empty());
    }
}
