use crate::contract::CheckStatus;
use crate::verification::helpers::{add_working_dir_hint_if_needed, resolve_path};
use crate::verification::RawResult;
use regex::Regex;

pub(crate) fn check_file_exists(path: &str, working_dir: Option<&str>) -> RawResult {
    let effective_path = resolve_path(path, working_dir);
    let exists = effective_path.exists();
    let mut result = RawResult {
        status: if exists {
            CheckStatus::Passed
        } else {
            CheckStatus::Failed
        },
        message: if exists {
            format!("File exists: {path}")
        } else {
            format!("File NOT found: {path}")
        },
        details: None,
    };
    add_working_dir_hint_if_needed(&mut result, path, working_dir);
    result
}

pub(crate) fn check_file_contains_patterns(
    path: &str,
    patterns: &[String],
    working_dir: Option<&str>,
) -> RawResult {
    let effective_path = resolve_path(path, working_dir);
    let content = match std::fs::read_to_string(&effective_path) {
        Ok(c) => c,
        Err(e) => {
            let mut result = RawResult {
                status: CheckStatus::Failed,
                message: format!("Cannot read file '{path}': {e}"),
                details: None,
            };
            add_working_dir_hint_if_needed(&mut result, path, working_dir);
            return result;
        }
    };

    let mut missing = Vec::new();
    for pattern in patterns {
        match Regex::new(pattern) {
            Ok(re) => {
                if !re.is_match(&content) {
                    missing.push(pattern.clone());
                }
            }
            Err(e) => {
                missing.push(format!("{pattern} (invalid regex: {e})"));
            }
        }
    }

    if missing.is_empty() {
        RawResult {
            status: CheckStatus::Passed,
            message: format!("All {} required patterns found in {path}", patterns.len()),
            details: None,
        }
    } else {
        RawResult {
            status: CheckStatus::Failed,
            message: format!(
                "{} of {} patterns missing in {path}",
                missing.len(),
                patterns.len()
            ),
            details: Some(format!("Missing patterns:\n{}", missing.join("\n"))),
        }
    }
}

pub(crate) fn check_file_excludes_patterns(
    path: &str,
    patterns: &[String],
    working_dir: Option<&str>,
) -> RawResult {
    let effective_path = resolve_path(path, working_dir);
    let content = match std::fs::read_to_string(&effective_path) {
        Ok(c) => c,
        Err(e) => {
            let mut result = RawResult {
                status: CheckStatus::Failed,
                message: format!("Cannot read file '{path}': {e}"),
                details: None,
            };
            add_working_dir_hint_if_needed(&mut result, path, working_dir);
            return result;
        }
    };

    let mut found = Vec::new();
    for pattern in patterns {
        match Regex::new(pattern) {
            Ok(re) => {
                if let Some(m) = re.find(&content) {
                    found.push(format!("{pattern} (found at offset {})", m.start()));
                }
            }
            Err(e) => {
                found.push(format!("{pattern} (invalid regex: {e})"));
            }
        }
    }

    if found.is_empty() {
        RawResult {
            status: CheckStatus::Passed,
            message: format!(
                "None of the {} forbidden patterns found in {path}",
                patterns.len()
            ),
            details: None,
        }
    } else {
        RawResult {
            status: CheckStatus::Failed,
            message: format!("{} forbidden pattern(s) found in {path}", found.len()),
            details: Some(format!("Found:\n{}", found.join("\n"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_file_contains_patterns_with_working_dir() {
        let dir = std::env::temp_dir().join("verify_mcp_test_wd");
        fs::create_dir_all(&dir).unwrap();
        let file_path = dir.join("test_file.txt");
        fs::write(&file_path, "hello world\nthis is a test").unwrap();

        let wd = dir.to_str().unwrap();
        let rel_path = "test_file.txt";
        let patterns = vec!["hello".to_string(), "test".to_string()];

        // 1. With working_dir
        let result = check_file_contains_patterns(rel_path, &patterns, Some(wd));
        assert_eq!(result.status, CheckStatus::Passed);

        // 2. Without working_dir, should fail and have hint
        let result_no_wd = check_file_contains_patterns(rel_path, &patterns, None);
        assert_eq!(result_no_wd.status, CheckStatus::Failed);
        assert!(result_no_wd.details.unwrap().contains("💡 HINT:"));

        fs::remove_dir_all(dir).unwrap();
    }
}
