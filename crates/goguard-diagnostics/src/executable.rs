//! Executable edit generation — unified diff patches and built-in Rust file apply.
//!
//! This module generates portable unified diffs from [`TextEdit`]s and can apply
//! (or revert) those edits directly via Rust I/O, with no shell dependency.

use crate::full::TextEdit;
use serde::Serialize;
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

/// A portable patch for a single file.
#[derive(Debug, Clone, Serialize)]
pub struct FilePatch {
    pub file: String,
    pub description: String,
    pub unified_diff: String,
}

/// Result of applying a single edit.
#[derive(Debug, Clone, Serialize)]
pub struct ApplyResult {
    pub file: String,
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Generate a unified diff patch for each text edit.
///
/// Each patch includes `--- a/file` / `+++ b/file` headers and standard
/// `@@ -start,count +start,count @@` hunk headers.
pub fn generate_patches(edits: &[TextEdit]) -> Vec<FilePatch> {
    edits.iter().map(generate_single_patch).collect()
}

/// Combine all patches into one string, separated by newlines.
pub fn generate_combined_patch(edits: &[TextEdit]) -> String {
    let patches = generate_patches(edits);
    patches
        .iter()
        .map(|p| p.unified_diff.as_str())
        .collect::<Vec<_>>()
        .join("\n")
}

/// Apply edits directly via Rust I/O. Returns a result per edit.
pub fn apply_edits(edits: &[TextEdit]) -> Vec<ApplyResult> {
    edits
        .iter()
        .map(|edit| match apply_single_edit(edit) {
            Ok(()) => ApplyResult {
                file: edit.file.clone(),
                success: true,
                error: None,
            },
            Err(msg) => ApplyResult {
                file: edit.file.clone(),
                success: false,
                error: Some(msg),
            },
        })
        .collect()
}

/// Revert edits by swapping `old_text` and `new_text`, then applying.
///
/// This only works when `old_text` is non-empty (the original content is known).
pub fn revert_edits(edits: &[TextEdit]) -> Vec<ApplyResult> {
    let reversed: Vec<TextEdit> = edits
        .iter()
        .map(|e| TextEdit {
            file: e.file.clone(),
            range: e.range.clone(),
            old_text: e.new_text.clone(),
            new_text: e.old_text.clone(),
        })
        .collect();
    apply_edits(&reversed)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Apply a single text edit: read file, replace text at line range, write back.
fn apply_single_edit(edit: &TextEdit) -> Result<(), String> {
    let path = Path::new(&edit.file);
    let content =
        fs::read_to_string(path).map_err(|e| format!("failed to read {}: {}", edit.file, e))?;

    let has_trailing_newline = content.ends_with('\n');
    let mut lines: Vec<&str> = content.lines().collect();

    let start = edit.range.start_line as usize;
    let end = edit.range.end_line as usize;

    if start == 0 || end == 0 {
        return Err("line numbers are 1-based; 0 is invalid".into());
    }
    if start > lines.len() || end > lines.len() {
        return Err(format!(
            "line range {}-{} is out of bounds (file has {} lines)",
            start,
            end,
            lines.len()
        ));
    }
    if start > end {
        return Err(format!(
            "start_line ({}) must be <= end_line ({})",
            start, end
        ));
    }

    // Verify old_text matches if provided (non-empty).
    if !edit.old_text.is_empty() {
        let actual: String = lines[start - 1..end].to_vec().join("\n");
        if actual != edit.old_text {
            return Err(format!(
                "old_text mismatch at lines {}-{}: expected {:?}, found {:?}",
                start, end, edit.old_text, actual
            ));
        }
    }

    // Build replacement lines.
    let new_lines: Vec<&str> = edit.new_text.lines().collect();

    // Replace the range.
    let mut result: Vec<&str> = Vec::with_capacity(lines.len());
    result.extend_from_slice(&lines[..start - 1]);
    result.extend_from_slice(&new_lines);
    result.extend_from_slice(&lines[end..]);
    lines = result;

    let mut output = lines.join("\n");
    if has_trailing_newline {
        output.push('\n');
    }

    fs::write(path, &output).map_err(|e| format!("failed to write {}: {}", edit.file, e))?;

    Ok(())
}

/// Generate a unified-diff patch for a single edit.
fn generate_single_patch(edit: &TextEdit) -> FilePatch {
    let old_lines = split_lines(&edit.old_text);
    let new_lines = split_lines(&edit.new_text);

    let start = edit.range.start_line;
    let old_count = if edit.old_text.is_empty() {
        edit.range.end_line - start + 1
    } else {
        old_lines.len() as u32
    };
    let new_count = new_lines.len() as u32;

    let mut diff = String::new();

    // File headers.
    diff.push_str(&format!("--- a/{}\n", edit.file));
    diff.push_str(&format!("+++ b/{}\n", edit.file));

    // Hunk header.
    diff.push_str(&format!(
        "@@ -{},{} +{},{} @@\n",
        start, old_count, start, new_count
    ));

    // Old lines.
    let effective_old = if edit.old_text.is_empty() {
        // When old_text is empty we don't have line content to show, but we
        // can still represent the deletion as old_count empty removals.
        // However, the more useful semantic is that old_text was not captured,
        // so we just emit the new lines as additions.
        vec![]
    } else {
        old_lines
    };

    for line in &effective_old {
        diff.push_str(&format!("-{}\n", line));
    }
    for line in &new_lines {
        diff.push_str(&format!("+{}\n", line));
    }

    FilePatch {
        file: edit.file.clone(),
        description: format!(
            "Edit lines {}-{} of {}",
            edit.range.start_line, edit.range.end_line, edit.file
        ),
        unified_diff: diff,
    }
}

/// Split text into lines, handling the empty-string edge case.
fn split_lines(text: &str) -> Vec<&str> {
    if text.is_empty() {
        vec![]
    } else {
        text.lines().collect()
    }
}

/// An executable shell command for a single text edit.
#[derive(Debug, Clone, Serialize)]
pub struct ExecutableEdit {
    /// Human-readable description of what the command does.
    pub description: String,
    /// The shell command to execute (e.g., `sed -i '' ...`).
    pub command: String,
    /// The file affected.
    pub file: String,
}

/// Generate executable shell commands for each text edit.
///
/// For single-line replacements, generates `sed -i ''` commands.
/// For multi-line or complex edits, generates heredoc-based `patch` commands.
/// All commands are designed to be idempotent where possible.
pub fn generate_shell_commands(edits: &[TextEdit]) -> Vec<ExecutableEdit> {
    edits.iter().map(generate_single_command).collect()
}

/// Generate a combined bash script that applies all edits.
///
/// Includes `set -e` for fail-fast, comments for each edit, and the commands.
pub fn generate_apply_script(edits: &[TextEdit]) -> String {
    let mut script = String::new();
    script.push_str("#!/bin/bash\n");
    script.push_str("# Auto-generated by GoGuard\n");
    script.push_str("set -e\n\n");

    for (i, edit) in edits.iter().enumerate() {
        let cmd = generate_single_command(edit);
        script.push_str(&format!("# Edit {}: {}\n", i + 1, cmd.description));
        script.push_str(&cmd.command);
        script.push('\n');
        script.push('\n');
    }

    script
}

fn generate_single_command(edit: &TextEdit) -> ExecutableEdit {
    let file = &edit.file;
    let start = edit.range.start_line;
    let end = edit.range.end_line;

    let old_lines: Vec<&str> = if edit.old_text.is_empty() {
        vec![]
    } else {
        edit.old_text.lines().collect()
    };
    let new_lines: Vec<&str> = edit.new_text.lines().collect();

    // Single-line to single-line → simple sed
    if old_lines.len() <= 1 && new_lines.len() <= 1 && !edit.old_text.is_empty() {
        let sed_old = sed_escape(&edit.old_text);
        let sed_new = sed_escape(&edit.new_text);
        return ExecutableEdit {
            description: format!("Replace line {} in {}", start, file),
            command: format!("sed -i '' '{}s|{}|{}|' '{}'", start, sed_old, sed_new, file),
            file: file.clone(),
        };
    }

    // Multi-line or complex: use sed line deletion + insertion
    // Strategy: delete old lines, insert new content
    let mut parts = Vec::new();

    // Delete old lines
    if start <= end && !edit.old_text.is_empty() {
        if start == end {
            parts.push(format!("sed -i '' '{}d' '{}'", start, file));
        } else {
            parts.push(format!("sed -i '' '{},{}d' '{}'", start, end, file));
        }
    }

    // Insert new lines at the position (use i\ command at start line,
    // or a\ after previous line if we deleted)
    if !edit.new_text.is_empty() {
        let insert_at = start.saturating_sub(1);
        if insert_at == 0 {
            // Insert at the very beginning of file
            parts.push(format!(
                "sed -i '' '1i\\\n{}' '{}'",
                sed_insert_escape(&edit.new_text),
                file
            ));
        } else {
            parts.push(format!(
                "sed -i '' '{}a\\\n{}' '{}'",
                insert_at,
                sed_insert_escape(&edit.new_text),
                file
            ));
        }
    }

    let command = parts.join(" && ");

    ExecutableEdit {
        description: format!("Edit lines {}-{} in {}", start, end, file),
        command,
        file: file.clone(),
    }
}

/// Escape a string for use inside sed s|pattern|replacement| delimiters.
fn sed_escape(s: &str) -> String {
    s.replace('|', "\\|")
        .replace('\\', "\\\\")
        .replace('&', "\\&")
        .replace('\n', "\\n")
}

/// Escape a string for use in sed insert/append commands (a\, i\).
fn sed_insert_escape(s: &str) -> String {
    // Each newline in the text needs to be escaped as \<newline> for sed
    s.replace('\\', "\\\\").replace('\n', "\\\n")
}

/// Group edits by file path, preserving order within each file.
#[allow(dead_code)]
fn group_edits_by_file(edits: &[TextEdit]) -> BTreeMap<&str, Vec<&TextEdit>> {
    let mut map: BTreeMap<&str, Vec<&TextEdit>> = BTreeMap::new();
    for edit in edits {
        map.entry(edit.file.as_str()).or_default().push(edit);
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::full::{EditRange, TextEdit};

    fn make_edit(
        file: &str,
        start_line: u32,
        end_line: u32,
        old_text: &str,
        new_text: &str,
    ) -> TextEdit {
        TextEdit {
            file: file.into(),
            range: EditRange {
                start_line,
                end_line,
            },
            old_text: old_text.into(),
            new_text: new_text.into(),
        }
    }

    #[test]
    fn test_generate_patches_single_line() {
        let edit = make_edit(
            "handler.go",
            16,
            16,
            "\t\thttp.Error(w, \"not found\", 404)",
            "\t\thttp.Error(w, \"not found\", 404)\n\t\treturn",
        );

        let patches = generate_patches(&[edit]);
        assert_eq!(patches.len(), 1);

        let diff = &patches[0].unified_diff;
        assert!(diff.contains("--- a/handler.go"), "missing --- header");
        assert!(diff.contains("+++ b/handler.go"), "missing +++ header");
        assert!(diff.contains("@@ -16,1 +16,2 @@"), "incorrect @@ header");
        assert!(
            diff.contains("-\t\thttp.Error(w, \"not found\", 404)"),
            "missing old line with - prefix"
        );
        assert!(
            diff.contains("+\t\thttp.Error(w, \"not found\", 404)"),
            "missing new line with + prefix"
        );
        assert!(
            diff.contains("+\t\treturn"),
            "missing added return line with + prefix"
        );
    }

    #[test]
    fn test_generate_patches_multiline() {
        let edit = make_edit("main.go", 10, 12, "line10\nline11\nline12", "new10\nnew11");

        let patches = generate_patches(&[edit]);
        assert_eq!(patches.len(), 1);

        let diff = &patches[0].unified_diff;
        // 3 old lines -> 2 new lines
        assert!(
            diff.contains("@@ -10,3 +10,2 @@"),
            "incorrect @@ header for multiline edit: {}",
            diff
        );
        assert!(diff.contains("-line10"));
        assert!(diff.contains("-line11"));
        assert!(diff.contains("-line12"));
        assert!(diff.contains("+new10"));
        assert!(diff.contains("+new11"));
    }

    #[test]
    fn test_combined_patch_multiple_files() {
        let edits = vec![
            make_edit("a.go", 5, 5, "old_a", "new_a"),
            make_edit("b.go", 3, 3, "old_b", "new_b"),
        ];

        let combined = generate_combined_patch(&edits);
        assert!(combined.contains("--- a/a.go"), "missing a.go patch");
        assert!(combined.contains("+++ b/a.go"), "missing a.go patch");
        assert!(combined.contains("--- a/b.go"), "missing b.go patch");
        assert!(combined.contains("+++ b/b.go"), "missing b.go patch");
        assert!(combined.contains("-old_a"));
        assert!(combined.contains("+new_a"));
        assert!(combined.contains("-old_b"));
        assert!(combined.contains("+new_b"));
    }

    #[test]
    fn test_apply_edits_roundtrip() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let file_path = dir.path().join("test.go");

        let original = "package main\n\nfunc main() {\n\tfmt.Println(\"hello\")\n}\n";
        fs::write(&file_path, original).unwrap();

        let path_str = file_path.to_str().unwrap();
        let edit = make_edit(
            path_str,
            4,
            4,
            "\tfmt.Println(\"hello\")",
            "\tfmt.Println(\"goodbye\")",
        );

        let results = apply_edits(&[edit]);
        assert_eq!(results.len(), 1);
        assert!(results[0].success, "apply failed: {:?}", results[0].error);

        let content = fs::read_to_string(&file_path).unwrap();
        assert!(
            content.contains("goodbye"),
            "file should contain new text: {}",
            content
        );
        assert!(
            !content.contains("hello"),
            "file should not contain old text: {}",
            content
        );
        // Trailing newline preserved.
        assert!(
            content.ends_with('\n'),
            "trailing newline should be preserved"
        );
    }

    #[test]
    fn test_revert_edits() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let file_path = dir.path().join("revert.go");

        let original = "package main\n\nvar x = 1\n";
        fs::write(&file_path, original).unwrap();

        let path_str = file_path.to_str().unwrap();
        let edit = make_edit(path_str, 3, 3, "var x = 1", "var x = 2");

        // Apply.
        let results = apply_edits(std::slice::from_ref(&edit));
        assert!(results[0].success);
        let changed = fs::read_to_string(&file_path).unwrap();
        assert!(changed.contains("var x = 2"));

        // Revert.
        let revert_results = revert_edits(&[edit]);
        assert!(
            revert_results[0].success,
            "revert failed: {:?}",
            revert_results[0].error
        );
        let reverted = fs::read_to_string(&file_path).unwrap();
        assert_eq!(reverted, original, "file should be back to original");
    }

    // ── Shell command generation tests ──

    #[test]
    fn test_generate_shell_command_single_line() {
        let edit = make_edit(
            "handler.go",
            16,
            16,
            "http.Error(w, \"not found\", 404)",
            "http.Error(w, \"not found\", 404)\n\t\treturn",
        );
        let cmds = generate_shell_commands(&[edit]);
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].file, "handler.go");
        assert!(
            cmds[0].command.contains("handler.go"),
            "command should reference file"
        );
        assert!(
            cmds[0].command.contains("sed"),
            "should use sed: {}",
            cmds[0].command
        );
    }

    #[test]
    fn test_generate_shell_command_simple_replacement() {
        let edit = make_edit("main.go", 5, 5, "var x = 1", "var x = 2");
        let cmds = generate_shell_commands(&[edit]);
        assert_eq!(cmds.len(), 1);
        // Single-line to single-line should be a simple sed s|old|new|
        assert!(
            cmds[0].command.contains("s|"),
            "simple replacement should use sed s|: {}",
            cmds[0].command
        );
        assert!(cmds[0].command.contains("var x = 1"));
        assert!(cmds[0].command.contains("var x = 2"));
    }

    #[test]
    fn test_generate_shell_command_multiline() {
        let edit = make_edit(
            "handler.go",
            10,
            12,
            "line10\nline11\nline12",
            "new10\nnew11",
        );
        let cmds = generate_shell_commands(&[edit]);
        assert_eq!(cmds.len(), 1);
        // Multi-line should use delete + insert
        assert!(
            cmds[0].command.contains("sed"),
            "should use sed for multi-line: {}",
            cmds[0].command
        );
        assert!(
            cmds[0].description.contains("10"),
            "description should mention start line"
        );
    }

    #[test]
    fn test_generate_apply_script() {
        let edits = vec![
            make_edit("a.go", 5, 5, "old_a", "new_a"),
            make_edit("b.go", 3, 3, "old_b", "new_b"),
        ];
        let script = generate_apply_script(&edits);
        assert!(
            script.starts_with("#!/bin/bash"),
            "should start with shebang"
        );
        assert!(
            script.contains("set -e"),
            "should have fail-fast: {}",
            script
        );
        assert!(
            script.contains("Auto-generated by GoGuard"),
            "should have GoGuard header"
        );
        assert!(script.contains("a.go"), "should reference first file");
        assert!(script.contains("b.go"), "should reference second file");
        assert!(
            script.contains("# Edit 1:"),
            "should have numbered comments"
        );
        assert!(
            script.contains("# Edit 2:"),
            "should have numbered comments"
        );
    }

    #[test]
    fn test_generate_shell_command_special_chars() {
        // Test that pipe characters in code are properly escaped
        let edit = make_edit("main.go", 3, 3, "x | y", "x || y");
        let cmds = generate_shell_commands(&[edit]);
        assert_eq!(cmds.len(), 1);
        // The sed command uses | as delimiter, so | in content must be escaped
        assert!(
            cmds[0].command.contains("\\|"),
            "pipe in code should be escaped: {}",
            cmds[0].command
        );
    }

    #[test]
    fn test_executable_edit_serialization() {
        let cmd = ExecutableEdit {
            description: "Replace line 5 in main.go".into(),
            command: "sed -i '' '5s|old|new|' 'main.go'".into(),
            file: "main.go".into(),
        };
        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains("description"));
        assert!(json.contains("command"));
        assert!(json.contains("file"));
    }

    #[test]
    fn test_apply_nonexistent_file() {
        let edit = make_edit("/tmp/goguard_does_not_exist_xyz_42.go", 1, 1, "old", "new");

        let results = apply_edits(&[edit]);
        assert_eq!(results.len(), 1);
        assert!(!results[0].success, "should fail for nonexistent file");
        assert!(results[0].error.is_some(), "should have error message");
        assert!(
            results[0]
                .error
                .as_ref()
                .unwrap()
                .contains("failed to read"),
            "error should mention read failure: {:?}",
            results[0].error
        );
    }
}
