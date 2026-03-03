use crate::contract::CheckStatus;
use crate::verification::RawResult;
use regex::Regex;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

pub(crate) fn resolve_path(path: &str, working_dir: Option<&str>) -> PathBuf {
    match (working_dir, Path::new(path).is_absolute()) {
        (Some(wd), false) => Path::new(wd).join(path),
        _ => Path::new(path).to_path_buf(),
    }
}

pub(crate) fn add_working_dir_hint_if_needed(
    result: &mut RawResult,
    path: &str,
    working_dir: Option<&str>,
) {
    if working_dir.is_none()
        && !Path::new(path).is_absolute()
        && result.status == CheckStatus::Failed
    {
        if result.message.contains("No such file")
            || result.message.contains("NOT found")
            || result.message.contains("Cannot read file")
        {
            let hint = format!(
                "\n\n💡 HINT: The file path '{path}' appears to be relative, but no 'working_dir' \
was set. The server resolves paths from its own working directory, not your project. \
Add 'working_dir' to this check to specify the project root:\n\n\
  \"working_dir\": \"/absolute/path/to/your/project\""
            );
            if let Some(details) = &mut result.details {
                details.push_str(&hint);
            } else {
                result.details = Some(hint);
            }
        }
    }
}

pub(crate) fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}... [truncated]", &s[..max_len])
    }
}

/// Shell-escape a string for use in `sh -c`.
pub(crate) fn shell_escape(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Extract the number immediately before a keyword in a string.
/// E.g., "5 passed" → Some(5), "12 failed" → Some(12)
pub(crate) fn extract_before_keyword(text: &str, keyword: &str) -> Option<usize> {
    static RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(\d+)\s+([a-zA-Z]+)").unwrap());
    RE.captures_iter(text)
        .find(|c| c.get(2).map_or(false, |m| m.as_str() == keyword))
        .and_then(|c| c.get(1))
        .and_then(|m| m.as_str().parse().ok())
}

/// Extract first number from a string.
pub(crate) fn extract_first_number(text: &str) -> Option<usize> {
    static RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(\d+)").unwrap());
    RE.captures(text)
        .and_then(|c| c.get(1))
        .and_then(|m| m.as_str().parse().ok())
}
