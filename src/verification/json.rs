use crate::contract::CheckStatus;
use crate::verification::helpers::{add_working_dir_hint_if_needed, resolve_path, truncate};
use crate::verification::RawResult;
use regex::Regex;

pub(crate) fn check_json_schema(input: Option<&str>, schema_str: &str) -> RawResult {
    let input = match input {
        Some(i) => i,
        None => {
            return RawResult {
                status: CheckStatus::Failed,
                message: "No input provided for JSON schema validation".into(),
                details: Some("Pass the JSON to validate in the 'input' field".into()),
            }
        }
    };

    let instance: serde_json::Value = match serde_json::from_str(input) {
        Ok(v) => v,
        Err(e) => {
            return RawResult {
                status: CheckStatus::Failed,
                message: format!("Input is not valid JSON: {e}"),
                details: Some(truncate(input, 500)),
            }
        }
    };

    let schema: serde_json::Value = match serde_json::from_str(schema_str) {
        Ok(v) => v,
        Err(e) => {
            return RawResult {
                status: CheckStatus::Failed,
                message: format!("Schema is not valid JSON: {e}"),
                details: None,
            }
        }
    };

    // Simple structural validation (full jsonschema crate can be added later)
    match validate_json_structure(&instance, &schema) {
        Ok(()) => RawResult {
            status: CheckStatus::Passed,
            message: "JSON validates against schema".into(),
            details: None,
        },
        Err(errors) => RawResult {
            status: CheckStatus::Failed,
            message: format!("JSON schema validation failed: {} error(s)", errors.len()),
            details: Some(errors.join("\n")),
        },
    }
}

/// Simple structural JSON validation (type checking + required fields).
pub(crate) fn validate_json_structure(
    instance: &serde_json::Value,
    schema: &serde_json::Value,
) -> Result<(), Vec<String>> {
    let mut errors = Vec::new();

    // Check type
    if let Some(expected_type) = schema.get("type").and_then(|t| t.as_str()) {
        let actual_type = match instance {
            serde_json::Value::Null => "null",
            serde_json::Value::Bool(_) => "boolean",
            serde_json::Value::Number(n) => {
                if n.is_i64() || n.is_u64() {
                    "integer"
                } else {
                    "number"
                }
            }
            serde_json::Value::String(_) => "string",
            serde_json::Value::Array(_) => "array",
            serde_json::Value::Object(_) => "object",
        };

        // "integer" is also a valid "number"
        let type_ok =
            actual_type == expected_type || (expected_type == "number" && actual_type == "integer");

        if !type_ok {
            errors.push(format!(
                "Expected type '{expected_type}', got '{actual_type}'"
            ));
        }
    }

    // Check required fields for objects
    if let (Some(required), Some(obj)) = (
        schema.get("required").and_then(|r| r.as_array()),
        instance.as_object(),
    ) {
        for req in required {
            if let Some(field) = req.as_str() {
                if !obj.contains_key(field) {
                    errors.push(format!("Missing required field: '{field}'"));
                }
            }
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

pub(crate) fn check_json_registry_consistency(
    json_path: &str,
    id_field: &str,
    source_path: &str,
    reference_pattern: Option<&str>,
    working_dir: Option<&str>,
) -> RawResult {
    let effective_json_path = resolve_path(json_path, working_dir);
    // Read and parse JSON
    let json_content = match std::fs::read_to_string(&effective_json_path) {
        Ok(c) => c,
        Err(e) => {
            let mut result = RawResult {
                status: CheckStatus::Failed,
                message: format!("Cannot read JSON file '{json_path}': {e}"),
                details: None,
            };
            add_working_dir_hint_if_needed(&mut result, json_path, working_dir);
            return result;
        }
    };

    let json_data: serde_json::Value = match serde_json::from_str(&json_content) {
        Ok(v) => v,
        Err(e) => {
            return RawResult {
                status: CheckStatus::Failed,
                message: format!("Invalid JSON in '{json_path}': {e}"),
                details: None,
            }
        }
    };

    // Extract all values for the given id_field at any depth
    let mut ids = Vec::new();
    extract_field_values(&json_data, id_field, &mut ids);

    if ids.is_empty() {
        return RawResult {
            status: CheckStatus::Failed,
            message: format!("No '{id_field}' fields found in {json_path}"),
            details: Some(format!(
                "Expected to find fields named '{id_field}' in the JSON structure"
            )),
        };
    }

    // Read source file
    let effective_source_path = resolve_path(source_path, working_dir);
    let source_content = match std::fs::read_to_string(&effective_source_path) {
        Ok(c) => c,
        Err(e) => {
            let mut result = RawResult {
                status: CheckStatus::Failed,
                message: format!("Cannot read source file '{source_path}': {e}"),
                details: None,
            };
            add_working_dir_hint_if_needed(&mut result, source_path, working_dir);
            return result;
        }
    };

    // Check each ID against source
    let mut missing = Vec::new();
    let mut found = Vec::new();

    for id in &ids {
        let is_referenced = if let Some(pattern) = reference_pattern {
            // Replace {} with the actual ID in the pattern
            let concrete_pattern = pattern.replace("{}", id);
            match Regex::new(&concrete_pattern) {
                Ok(re) => re.is_match(&source_content),
                Err(_) => source_content.contains(id),
            }
        } else {
            // Simple string containment
            source_content.contains(id)
        };

        if is_referenced {
            found.push(id.clone());
        } else {
            missing.push(id.clone());
        }
    }

    let passed = missing.is_empty();

    let mut details = format!(
        "Checked {total} ID(s) from {json_path} against {source_path}\n\
         Found: {found_n}, Missing: {missing_n}\n",
        total = ids.len(),
        found_n = found.len(),
        missing_n = missing.len(),
    );

    if !missing.is_empty() {
        details.push_str("\nMissing IDs (in JSON but not in source):\n");
        for (i, id) in missing.iter().enumerate() {
            if i >= 30 {
                details.push_str(&format!("  ... and {} more\n", missing.len() - 30));
                break;
            }
            details.push_str(&format!("  - \"{id}\"\n"));
        }
    }

    RawResult {
        status: if passed {
            CheckStatus::Passed
        } else {
            CheckStatus::Failed
        },
        message: if passed {
            format!(
                "All {} ID(s) from {json_path} found in {source_path}",
                ids.len()
            )
        } else {
            format!(
                "{} of {} ID(s) from {json_path} NOT found in {source_path}",
                missing.len(),
                ids.len()
            )
        },
        details: Some(details),
    }
}

/// Recursively extract all string values for a given field name from JSON.
pub(crate) fn extract_field_values(value: &serde_json::Value, field: &str, results: &mut Vec<String>) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, val) in map {
                if key == field {
                    if let Some(s) = val.as_str() {
                        results.push(s.to_string());
                    }
                }
                extract_field_values(val, field, results);
            }
        }
        serde_json::Value::Array(arr) => {
            for item in arr {
                extract_field_values(item, field, results);
            }
        }
        _ => {}
    }
}
