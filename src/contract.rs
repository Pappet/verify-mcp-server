//! Contract definitions for agent output verification.
//!
//! A contract is a set of expectations defined *before* work begins.
//! After the agent produces a result, the contract is checked against it.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ── Contract Definition ─────────────────────────────────────────────

/// A verification contract: expectations that must be met.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contract {
    /// Unique contract ID.
    pub id: String,
    /// Human-readable description of what this contract verifies.
    pub description: String,
    /// The task the agent is supposed to accomplish.
    pub task: String,
    /// Individual checks that must pass.
    pub checks: Vec<Check>,
    /// When the contract was created.
    pub created_at: DateTime<Utc>,
    /// Current status of verification.
    pub status: ContractStatus,
    /// Results of individual checks after verification.
    #[serde(default)]
    pub results: Vec<CheckResult>,
}

/// A single verifiable check within a contract.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Check {
    /// Human-readable name for this check.
    pub name: String,
    /// What kind of verification to perform.
    pub check_type: CheckType,
    /// Severity if this check fails.
    #[serde(default = "default_severity")]
    pub severity: Severity,
}

fn default_severity() -> Severity {
    Severity::Error
}

/// The types of verification checks available.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CheckType {
    /// Run a shell command; verify exit code is 0.
    CommandSucceeds {
        command: String,
        #[serde(default)]
        working_dir: Option<String>,
        /// Optional timeout in seconds (default: 30).
        #[serde(default = "default_timeout")]
        timeout_secs: u64,
    },

    /// Run a command and check that stdout matches a pattern.
    CommandOutputMatches {
        command: String,
        /// Regex pattern the stdout must match.
        pattern: String,
        #[serde(default)]
        working_dir: Option<String>,
        #[serde(default = "default_timeout")]
        timeout_secs: u64,
    },

    /// Check that a file exists.
    FileExists {
        path: String,
    },

    /// Check that a file contains required patterns.
    FileContainsPatterns {
        path: String,
        /// Regex patterns that must all be found.
        required_patterns: Vec<String>,
    },

    /// Check that a file does NOT contain forbidden patterns.
    FileExcludesPatterns {
        path: String,
        /// Regex patterns that must NOT be found.
        forbidden_patterns: Vec<String>,
    },

    /// Validate JSON string against a JSON Schema.
    JsonSchemaValid {
        /// The JSON Schema to validate against (as JSON string).
        schema: String,
    },

    /// Check that a numeric value is within a range.
    ValueInRange {
        min: Option<f64>,
        max: Option<f64>,
    },

    /// Check that the number of lines changed is within bounds.
    DiffSizeLimit {
        /// Maximum number of lines added.
        max_additions: Option<usize>,
        /// Maximum number of lines removed.
        max_deletions: Option<usize>,
    },

    /// Custom assertion: agent provides a boolean claim with evidence.
    /// The server records it but flags unverified claims.
    Assertion {
        /// What is being asserted.
        claim: String,
    },

    // ── Python-Specific Checks ──────────────────────────────────

    /// Run mypy or pyright and parse structured results.
    PythonTypeCheck {
        /// Files or directories to check (e.g. "ecs/systems/ai_system.py" or "ecs/").
        paths: Vec<String>,
        /// Type checker to use: "mypy" (default) or "pyright".
        #[serde(default = "default_type_checker")]
        checker: String,
        /// Extra flags (e.g. ["--ignore-missing-imports", "--strict"]).
        #[serde(default)]
        extra_args: Vec<String>,
        #[serde(default)]
        working_dir: Option<String>,
        #[serde(default = "default_type_check_timeout")]
        timeout_secs: u64,
    },

    /// Run pytest and parse structured results (pass/fail/skip counts, failure details).
    PytestResult {
        /// Test path or expression (e.g. "tests/verify_ai_system.py" or "tests/ -k combat").
        test_path: String,
        /// Minimum number of tests that must pass (0 = just don't fail).
        #[serde(default)]
        min_passed: Option<usize>,
        /// Maximum allowed failures (default: 0).
        #[serde(default)]
        max_failures: Option<usize>,
        /// Maximum allowed skips.
        #[serde(default)]
        max_skipped: Option<usize>,
        #[serde(default)]
        working_dir: Option<String>,
        #[serde(default = "default_type_check_timeout")]
        timeout_secs: u64,
    },

    /// Detect circular imports in Python modules.
    PythonImportGraph {
        /// Root module/package to analyze (e.g. "ecs" or "services").
        root_path: String,
        /// If true, any circular import is an error. If false, just report.
        #[serde(default = "default_true")]
        fail_on_circular: bool,
        #[serde(default)]
        working_dir: Option<String>,
    },

    /// Check that all IDs referenced in a JSON data file exist
    /// in a corresponding Python registry/factory source file.
    JsonRegistryConsistency {
        /// Path to the JSON data file (e.g. "assets/data/entities.json").
        json_path: String,
        /// JSONPath-like key to extract IDs from (e.g. "id" or "template_id").
        /// Extracts all values for this key at any depth.
        id_field: String,
        /// Path to the Python source that should reference these IDs.
        source_path: String,
        /// Optional: regex pattern that should wrap each ID in the source.
        /// Use `{}` as placeholder for the ID. Default: just checks the ID string appears.
        #[serde(default)]
        reference_pattern: Option<String>,
    },
}

fn default_timeout() -> u64 {
    30
}

fn default_type_checker() -> String {
    "mypy".into()
}

fn default_type_check_timeout() -> u64 {
    120
}

fn default_true() -> bool {
    true
}

/// How severe a check failure is.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Contract fails immediately.
    Error,
    /// Recorded but contract can still pass.
    Warning,
    /// Informational only.
    Info,
}

// ── Verification Results ────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ContractStatus {
    /// Contract defined, not yet verified.
    Pending,
    /// All error-level checks passed.
    Passed,
    /// At least one error-level check failed.
    Failed,
    /// Verification is currently running.
    Running,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckResult {
    /// Name of the check.
    pub check_name: String,
    /// Did it pass?
    pub passed: bool,
    /// Severity of this check.
    pub severity: Severity,
    /// Human-readable explanation of the result.
    pub message: String,
    /// Detailed output (e.g., command stdout/stderr).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
    /// How long the check took in milliseconds.
    pub duration_ms: u64,
}

// ── Summary ─────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct ContractSummary {
    pub id: String,
    pub description: String,
    pub task: String,
    pub status: ContractStatus,
    pub num_checks: usize,
    pub created_at: DateTime<Utc>,
}
