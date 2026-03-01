use crate::contract::Check;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateVariables {
    #[serde(default)]
    pub required: HashMap<String, String>,
    #[serde(default)]
    pub optional: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateDefinition {
    pub id: String,
    pub name: String,
    pub description: String,
    pub language: String,
    pub source: String,
    pub source_contract_id: Option<String>,
    pub variables: TemplateVariables,
    pub checks_json: String,
    pub created_at: String,
    pub usage_count: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateSummary {
    pub name: String,
    pub description: String,
    pub language: String,
    pub source: String,
    pub usage_count: i64,
    pub variables: TemplateVariables,
}

pub fn instantiate_template(
    template: &TemplateDefinition,
    variables: &HashMap<String, String>,
) -> Result<(Vec<Check>, String, String), String> {
    // 1. Check required variables
    let mut missing_msg = String::new();
    let mut missing_keys = Vec::new();
    for (req, desc) in &template.variables.required {
        if !variables.contains_key(req) {
            missing_msg.push_str(&format!("  - {}: {}\n", req, desc));
            missing_keys.push(req.clone());
        }
    }

    if !missing_msg.is_empty() {
        let provided: Vec<_> = variables.keys().cloned().collect();
        return Err(format!(
            "Template '{}' instantiation failed:\n\nMissing required variables:\n{}\nProvided variables: {}",
            template.name,
            missing_msg.trim_end(),
            provided.join(", ")
        ));
    }

    // 2. Parse checks_json
    let mut checks_val: Value = serde_json::from_str(&template.checks_json)
        .map_err(|e| format!("Invalid checks_json in template: {}", e))?;

    // 3. Process _condition
    if let Value::Array(arr) = &mut checks_val {
        arr.retain(|check| {
            if let Value::Object(obj) = check {
                if let Some(Value::String(cond_var)) = obj.get("_condition") {
                    // Retain only if variables contains this key
                    variables.contains_key(cond_var)
                } else {
                    true
                }
            } else {
                true
            }
        });

        // Remove _condition from all remaining checks
        for check in arr.iter_mut() {
            if let Value::Object(obj) = check {
                obj.remove("_condition");
            }
        }
    } else {
        return Err("checks_json must be an array".into());
    }

    // 4. Substitute variables recursively
    substitute_variables(&mut checks_val, variables);

    // 5. Deserialize to Vec<Check>
    let checks: Vec<Check> = serde_json::from_value(checks_val)
        .map_err(|e| format!("Failed to deserialize checks after substitution: {}", e))?;

    Ok((
        checks,
        template.description.clone(),
        template.language.clone(),
    ))
}

fn substitute_variables(val: &mut Value, variables: &HashMap<String, String>) {
    // Regex to find {{var}} or {{var:default}}
    let re = Regex::new(r"\{\{([^}:]+)(?::([^}]+))?\}\}").unwrap();

    match val {
        Value::String(s) => {
            let mut result = s.clone();

            result = re
                .replace_all(&result, |caps: &regex::Captures| {
                    let var_name = caps.get(1).unwrap().as_str();
                    let default_val = caps.get(2).map(|m| m.as_str());

                    if let Some(val) = variables.get(var_name) {
                        val.to_string()
                    } else if let Some(def) = default_val {
                        def.to_string()
                    } else {
                        // Leave it as is if not found and no default, though required vars should be checked earlier
                        caps.get(0).unwrap().as_str().to_string()
                    }
                })
                .into_owned();

            // Try to convert to a number if requested
            // We just attempt parsing it. If it succeeds and matches logic, we make it a number.
            // But we should only do it if the original string was an exact match, or just any purely numeric result.
            // Let's just try parsing to i64 if it's purely digits.
            if result.chars().all(|c| c.is_ascii_digit()) && !result.is_empty() {
                if let Ok(num) = result.parse::<i64>() {
                    *val = Value::Number(serde_json::Number::from(num));
                    return;
                }
            }

            *val = Value::String(result);
        }
        Value::Array(arr) => {
            for item in arr.iter_mut() {
                substitute_variables(item, variables);
            }
        }
        Value::Object(obj) => {
            for (_, v) in obj.iter_mut() {
                substitute_variables(v, variables);
            }
        }
        _ => {}
    }
}

pub fn parameterize_contract(checks_json: &str, path_mapping: &HashMap<String, String>) -> String {
    let mut sorted_keys: Vec<&String> = path_mapping.keys().collect();
    // Sort by length descending, then alphabetically for stability
    sorted_keys.sort_by(|a, b| b.len().cmp(&a.len()).then(a.cmp(b)));

    let mut result = checks_json.to_string();
    for key in sorted_keys {
        let var_name = &path_mapping[key];
        let placeholder = format!("{{{{{}}}}}", var_name);
        result = result.replace(key, &placeholder);
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn dummy_template(checks_json: Value) -> TemplateDefinition {
        let mut required = HashMap::new();
        required.insert("req1".to_string(), "A required var".to_string());

        TemplateDefinition {
            id: "123".into(),
            name: "test_tmpl".into(),
            description: "Test".into(),
            language: "python".into(),
            source: "builtin".into(),
            source_contract_id: None,
            variables: TemplateVariables {
                required,
                optional: HashMap::new(),
            },
            checks_json: serde_json::to_string(&checks_json).unwrap(),
            created_at: "".into(),
            usage_count: 0,
        }
    }

    #[test]
    fn test_simple_substitution() {
        let tmpl = dummy_template(json!([{
            "name": "check1",
            "check_type": {
                "type": "command_succeeds",
                "command": "echo {{req1}}"
            },
            "severity": "error"
        }]));

        let mut vars = HashMap::new();
        vars.insert("req1".to_string(), "hello_world".to_string());

        let (checks, _, _) = instantiate_template(&tmpl, &vars).unwrap();
        if let crate::contract::CheckType::CommandSucceeds { command, .. } = &checks[0].check_type {
            assert_eq!(command, "echo hello_world");
        } else {
            panic!("Wrong check type");
        }
    }

    #[test]
    fn test_default_value() {
        let tmpl = dummy_template(json!([{
            "name": "check1",
            "check_type": {
                "type": "command_succeeds",
                "command": "echo {{opt1:default_val}}"
            },
            "severity": "error"
        }]));

        let mut vars = HashMap::new();
        vars.insert("req1".to_string(), "val".to_string());

        let (checks, _, _) = instantiate_template(&tmpl, &vars).unwrap();
        if let crate::contract::CheckType::CommandSucceeds { command, .. } = &checks[0].check_type {
            assert_eq!(command, "echo default_val");
        } else {
            panic!("Wrong check type");
        }
    }

    #[test]
    fn test_missing_required_variable() {
        let tmpl = dummy_template(json!([]));
        let vars = HashMap::new();

        let err = instantiate_template(&tmpl, &vars).unwrap_err();
        assert!(err.contains("Missing required variables"));
        assert!(err.contains("req1"));
    }

    #[test]
    fn test_condition_included() {
        let tmpl = dummy_template(json!([{
            "name": "check1",
            "check_type": { "type": "command_succeeds", "command": "echo 1" },
            "severity": "error",
            "_condition": "opt1"
        }]));

        let mut vars = HashMap::new();
        vars.insert("req1".to_string(), "val".to_string());
        vars.insert("opt1".to_string(), "set".to_string());

        let (checks, _, _) = instantiate_template(&tmpl, &vars).unwrap();
        assert_eq!(checks.len(), 1);
    }

    #[test]
    fn test_condition_excluded() {
        let tmpl = dummy_template(json!([{
            "name": "check1",
            "check_type": { "type": "command_succeeds", "command": "echo 1" },
            "severity": "error",
            "_condition": "opt1"
        }]));

        let mut vars = HashMap::new();
        vars.insert("req1".to_string(), "val".to_string());
        // opt1 is NOT set

        let (checks, _, _) = instantiate_template(&tmpl, &vars).unwrap();
        assert_eq!(checks.len(), 0);
    }

    #[test]
    fn test_numeric_conversion() {
        let tmpl = dummy_template(json!([{
            "name": "check1",
            "check_type": {
                "type": "pytest_result",
                "test_path": "tests",
                "min_passed": "{{min_tests:1}}"
            },
            "severity": "error"
        }]));

        let mut vars = HashMap::new();
        vars.insert("req1".to_string(), "val".to_string());

        let (checks, _, _) = instantiate_template(&tmpl, &vars).unwrap();
        if let crate::contract::CheckType::PytestResult { min_passed, .. } = &checks[0].check_type {
            assert_eq!(*min_passed, Some(1));
        } else {
            panic!("Wrong check type");
        }
    }
}
