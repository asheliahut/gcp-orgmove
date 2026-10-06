//! Comment-preserving edits to the manifest (for `discover --write-manifest`).
//!
//! The manifest is user-authored, so it is never re-serialized: new projects
//! are inserted as text into the `projects:` block, leaving everything else
//! (comments, ordering, overrides) untouched.

/// Insert `- id: <id>` entries for each of `ids` (already deduplicated against
/// the manifest by the caller) at the end of the top-level `projects:` list.
pub fn add_projects(text: &str, ids: &[String]) -> String {
    if ids.is_empty() {
        return text.to_string();
    }
    let new_items: String = ids.iter().map(|id| format!("  - id: {id}\n")).collect();
    let lines: Vec<&str> = text.split_inclusive('\n').collect();

    let Some(start) = lines.iter().position(|l| is_key(l, "projects")) else {
        let mut out = text.to_string();
        if !out.is_empty() && !out.ends_with('\n') {
            out.push('\n');
        }
        out.push_str("projects:\n");
        out.push_str(&new_items);
        return out;
    };

    // `projects: []` (or any inline value) is replaced by a block list.
    let head = lines[start].trim_end();
    let inline = head.trim_start_matches("projects:").trim();
    let inline = inline.split('#').next().unwrap_or("").trim();
    if !inline.is_empty() {
        let mut out: String = lines[..start].concat();
        out.push_str("projects:\n");
        out.push_str(&new_items);
        out.push_str(&lines[start + 1..].concat());
        return out;
    }

    // Find the end of the block: the last non-blank line that is indented or a
    // list item, before the next top-level key.
    let mut end = start + 1;
    let mut last_content = start;
    while end < lines.len() {
        let l = lines[end];
        let t = l.trim_end();
        if t.is_empty() {
            end += 1;
            continue;
        }
        let indented = l.starts_with(' ') || l.starts_with('\t') || l.starts_with('-');
        let comment = t.trim_start().starts_with('#');
        if indented {
            if !comment {
                last_content = end;
            }
            end += 1;
        } else if comment {
            end += 1;
        } else {
            break;
        }
    }
    let insert_at = last_content + 1;
    let mut out: String = lines[..insert_at].concat();
    if !out.ends_with('\n') {
        out.push('\n');
    }
    out.push_str(&new_items);
    out.push_str(&lines[insert_at..].concat());
    out
}

fn is_key(line: &str, key: &str) -> bool {
    line.strip_prefix(key)
        .is_some_and(|rest| rest.starts_with(':'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn appends_to_existing_block_and_keeps_comments() {
        let text = "version: 1\n# keep me\nprojects:\n  - id: my-app-prod\n    destination_folder: \"44\"  # override\n  - id: my-app-dev\n\nlimits:\n  batch_size: 2\n";
        let out = add_projects(text, &ids(&["new-proj-a", "new-proj-b"]));
        assert!(out.contains("# keep me"));
        assert!(out.contains("destination_folder: \"44\"  # override"));
        let expected = "projects:\n  - id: my-app-prod\n    destination_folder: \"44\"  # override\n  - id: my-app-dev\n  - id: new-proj-a\n  - id: new-proj-b\n\nlimits:";
        assert!(out.contains(expected), "{out}");
    }

    #[test]
    fn replaces_inline_empty_list() {
        let out = add_projects(
            "version: 1\nprojects: []\nlimits: {}\n",
            &ids(&["new-proj-a"]),
        );
        assert_eq!(
            out,
            "version: 1\nprojects:\n  - id: new-proj-a\nlimits: {}\n"
        );
    }

    #[test]
    fn adds_block_when_missing() {
        let out = add_projects("version: 1\n", &ids(&["new-proj-a"]));
        assert_eq!(out, "version: 1\nprojects:\n  - id: new-proj-a\n");
        let out = add_projects("version: 1", &ids(&["new-proj-a"]));
        assert!(out.starts_with("version: 1\nprojects:"));
    }

    #[test]
    fn block_at_end_of_file_without_trailing_newline() {
        let out = add_projects("projects:\n  - id: my-app-dev", &ids(&["new-proj-a"]));
        assert_eq!(out, "projects:\n  - id: my-app-dev\n  - id: new-proj-a\n");
    }

    #[test]
    fn no_ids_is_a_noop() {
        assert_eq!(add_projects("anything", &[]), "anything");
    }

    #[test]
    fn result_still_parses_as_a_manifest() {
        let text = "version: 1\nsource_org: \"1\"\ndestination_org: \"2\"\nprojects:\n  - id: my-app-dev\n";
        let out = add_projects(text, &ids(&["new-proj-a"]));
        let m = gcp_orgmove_core::Manifest::parse(&out).unwrap().manifest;
        assert_eq!(m.projects.len(), 2);
    }
}
