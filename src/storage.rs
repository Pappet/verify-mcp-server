//! SQLite-backed persistent storage for contracts, results, and audit trail.
//!
//! Database location: `~/.local/share/verify-mcp/verify.db`
//! (respects XDG_DATA_HOME if set)

use crate::contract::*;
use crate::templates::*;
use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{debug, info};

// ── Database Path ───────────────────────────────────────────────────

fn db_path() -> PathBuf {
    let base = std::env::var("XDG_DATA_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
            PathBuf::from(home).join(".local").join("share")
        });
    let dir = base.join("verify-mcp");
    std::fs::create_dir_all(&dir).ok();
    dir.join("verify.db")
}

// ── Audit Event Types ───────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditEventType {
    ContractCreated,
    VerificationStarted,
    VerificationPassed,
    VerificationFailed,
    ContractDeleted,
    ContractRejected,
}

impl AuditEventType {
    fn as_str(&self) -> &'static str {
        match self {
            Self::ContractCreated => "contract_created",
            Self::VerificationStarted => "verification_started",
            Self::VerificationPassed => "verification_passed",
            Self::VerificationFailed => "verification_failed",
            Self::ContractDeleted => "contract_deleted",
            Self::ContractRejected => "contract_rejected",
        }
    }

    fn from_str(s: &str) -> Self {
        match s {
            "contract_created" => Self::ContractCreated,
            "verification_started" => Self::VerificationStarted,
            "verification_passed" => Self::VerificationPassed,
            "verification_failed" => Self::VerificationFailed,
            "contract_deleted" => Self::ContractDeleted,
            "contract_rejected" => Self::ContractRejected,
            _ => Self::ContractCreated,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditEvent {
    pub id: i64,
    pub contract_id: String,
    pub event_type: AuditEventType,
    pub details: Option<String>,
    pub created_at: String,
}

// ── Query Result Types ──────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct HistoryEntry {
    pub id: String,
    pub description: String,
    pub task: String,
    pub status: String,
    pub num_checks: usize,
    pub passed_checks: usize,
    pub failed_checks: usize,
    pub total_duration_ms: u64,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Serialize)]
pub struct VerificationStats {
    pub total_contracts: usize,
    pub total_passed: usize,
    pub total_failed: usize,
    pub total_pending: usize,
    pub pass_rate_percent: f64,
    pub total_checks_run: usize,
    pub total_check_failures: usize,
    pub most_common_failures: Vec<FailureFrequency>,
    pub avg_verification_duration_ms: u64,
    pub period_days: i64,
    pub agents: Vec<AgentStats>,
}

#[derive(Debug, Serialize)]
pub struct AgentStats {
    pub id: String,
    pub trust_score: f64,
}

#[derive(Debug, Serialize)]
pub struct FailureFrequency {
    pub check_name: String,
    pub failure_count: usize,
    pub last_failure: String,
}

// ── Persistent Store ────────────────────────────────────────────────

/// SQLite-backed contract store with audit trail.
#[derive(Clone)]
pub struct Storage {
    conn: Arc<Mutex<Connection>>,
}

impl Storage {
    /// Open or create the database.
    pub fn open() -> Result<Self, String> {
        let path = db_path();
        info!("Opening database at {}", path.display());

        let conn = Connection::open(&path)
            .map_err(|e| format!("Failed to open database at {}: {e}", path.display()))?;

        // Enable WAL mode for better concurrent read performance
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")
            .map_err(|e| format!("Failed to set pragmas: {e}"))?;

        let storage = Self {
            conn: Arc::new(Mutex::new(conn)),
        };
        storage.init_schema_sync()?;
        storage.seed_builtin_templates()?;

        Ok(storage)
    }

    fn init_schema_sync(&self) -> Result<(), String> {
        // We need to run this synchronously during construction
        // Use try_lock since we know we're the only holder at init time
        let conn = self
            .conn
            .try_lock()
            .map_err(|e| format!("Lock error: {e}"))?;

        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS agents (
                id              TEXT PRIMARY KEY,
                trust_score     REAL NOT NULL DEFAULT 100.0
            );

            CREATE TABLE IF NOT EXISTS contracts (
                id              TEXT PRIMARY KEY,
                description     TEXT NOT NULL,
                task            TEXT NOT NULL,
                agent_id        TEXT NOT NULL,
                language        TEXT NOT NULL,
                checks_json     TEXT NOT NULL,
                status          TEXT NOT NULL DEFAULT 'pending',
                created_at      TEXT NOT NULL,
                updated_at      TEXT NOT NULL,
                workspace_hash  TEXT
            );

            CREATE TABLE IF NOT EXISTS check_results (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                contract_id     TEXT NOT NULL REFERENCES contracts(id) ON DELETE CASCADE,
                check_name      TEXT NOT NULL,
                status          TEXT NOT NULL,
                severity        TEXT NOT NULL,
                message         TEXT NOT NULL,
                details         TEXT,
                duration_ms     INTEGER NOT NULL,
                created_at      TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS audit_events (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                contract_id     TEXT NOT NULL,
                event_type      TEXT NOT NULL,
                details         TEXT,
                created_at      TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS templates (
                id TEXT PRIMARY KEY,
                name TEXT UNIQUE NOT NULL,
                description TEXT,
                language TEXT NOT NULL,
                source TEXT NOT NULL,
                source_contract_id TEXT,
                variables_json TEXT NOT NULL,
                checks_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                usage_count INTEGER DEFAULT 0
            );

            CREATE INDEX IF NOT EXISTS idx_check_results_contract
                ON check_results(contract_id);
            CREATE INDEX IF NOT EXISTS idx_audit_events_contract
                ON audit_events(contract_id);
            CREATE INDEX IF NOT EXISTS idx_audit_events_type
                ON audit_events(event_type);
            CREATE INDEX IF NOT EXISTS idx_contracts_status
                ON contracts(status);
            CREATE INDEX IF NOT EXISTS idx_contracts_agent
                ON contracts(agent_id);
            CREATE INDEX IF NOT EXISTS idx_contracts_created
                ON contracts(created_at);
            ",
        )
        .map_err(|e| format!("Failed to initialize schema: {e}"))?;

        debug!("Database schema initialized");
        Ok(())
    }

    // ── Contract CRUD ───────────────────────────────────────────

    /// Create a new contract and return its ID.
    pub async fn create_contract(
        &self,
        id: &str,
        description: &str,
        task: &str,
        agent_id: &str,
        language: &str,
        checks: &[Check],
    ) -> Result<(), String> {
        let conn = self.conn.lock().await;
        let now = Utc::now().to_rfc3339();
        let checks_json =
            serde_json::to_string(checks).map_err(|e| format!("Serialize checks: {e}"))?;

        // Ensure agent exists
        conn.execute(
            "INSERT INTO agents (id, trust_score) VALUES (?1, 100.0)
             ON CONFLICT(id) DO NOTHING",
            params![agent_id],
        )
        .map_err(|e| format!("Insert agent: {e}"))?;

        conn.execute(
            "INSERT INTO contracts (id, description, task, agent_id, language, checks_json, status, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'pending', ?7, ?7)",
            params![id, description, task, agent_id, language, checks_json, now],
        )
        .map_err(|e| format!("Insert contract: {e}"))?;

        self.log_event_sync(&conn, id, AuditEventType::ContractCreated, None)?;
        Ok(())
    }

    /// Create a rejected contract for audit purposes.
    ///
    /// Unlike `create_contract`, this accepts raw JSON for checks (since parsing
    /// may have failed) and stores the contract with status `rejected`.
    pub async fn create_rejected_contract(
        &self,
        id: &str,
        description: &str,
        task: &str,
        agent_id: &str,
        language: &str,
        checks_json: &str,
        rejection_reason: &str,
    ) -> Result<(), String> {
        let conn = self.conn.lock().await;
        let now = Utc::now().to_rfc3339();

        // Ensure agent exists
        conn.execute(
            "INSERT INTO agents (id, trust_score) VALUES (?1, 100.0)
             ON CONFLICT(id) DO NOTHING",
            params![agent_id],
        )
        .map_err(|e| format!("Insert agent: {e}"))?;

        conn.execute(
            "INSERT INTO contracts (id, description, task, agent_id, language, checks_json, status, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'rejected', ?7, ?7)",
            params![id, description, task, agent_id, language, checks_json, now],
        )
        .map_err(|e| format!("Insert rejected contract: {e}"))?;

        self.log_event_sync(
            &conn,
            id,
            AuditEventType::ContractRejected,
            Some(rejection_reason),
        )?;
        Ok(())
    }

    /// Get a contract by ID.
    pub async fn get_contract(&self, id: &str) -> Result<Option<Contract>, String> {
        let conn = self.conn.lock().await;
        self.get_contract_sync(&conn, id)
    }

    fn get_contract_sync(&self, conn: &Connection, id: &str) -> Result<Option<Contract>, String> {
        let mut stmt = conn
            .prepare(
                "SELECT id, description, task, agent_id, language, checks_json, status, created_at, workspace_hash
                 FROM contracts WHERE id = ?1",
            )
            .map_err(|e| format!("Prepare: {e}"))?;

        let contract = stmt
            .query_row(params![id], |row| {
                let checks_json: String = row.get(5)?;
                let status_str: String = row.get(6)?;
                let created_str: String = row.get(7)?;
                let workspace_hash: Option<String> = row.get(8)?;

                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    checks_json,
                    status_str,
                    created_str,
                    workspace_hash,
                ))
            })
            .optional()
            .map_err(|e| format!("Query contract: {e}"))?;

        match contract {
            None => Ok(None),
            Some((
                id,
                description,
                task,
                agent_id,
                language,
                checks_json,
                status_str,
                created_str,
                workspace_hash,
            )) => {
                let checks: Vec<Check> = serde_json::from_str(&checks_json)
                    .map_err(|e| format!("Deserialize checks: {e}"))?;
                let status = match status_str.as_str() {
                    "passed" => ContractStatus::Passed,
                    "failed" => ContractStatus::Failed,
                    "running" => ContractStatus::Running,
                    "review_required" => ContractStatus::ReviewRequired,
                    "rejected" => ContractStatus::Rejected,
                    _ => ContractStatus::Pending,
                };
                let created_at = DateTime::parse_from_rfc3339(&created_str)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now());

                // Load check results
                let results = self.get_results_sync(conn, &id)?;

                Ok(Some(Contract {
                    id,
                    description,
                    task,
                    agent_id,
                    language,
                    checks,
                    created_at,
                    status,
                    results,
                    workspace_hash,
                }))
            }
        }
    }

    /// Update contract status and store check results.
    pub async fn update_results(
        &self,
        id: &str,
        status: ContractStatus,
        results: &[CheckResult],
        new_workspace_hash: Option<String>,
    ) -> Result<(), String> {
        let conn = self.conn.lock().await;

        // Fetch old contract state to check for penalties
        let old_contract = self.get_contract_sync(&conn, id)?;
        if let Some(old) = &old_contract {
            let flaky_penalty = std::env::var("VERIFY_TRUST_PENALTY_FLAKY")
                .ok()
                .and_then(|v| v.parse::<f64>().ok())
                .unwrap_or(-5.0);
            let trial_penalty = std::env::var("VERIFY_TRUST_PENALTY_TRIAL")
                .ok()
                .and_then(|v| v.parse::<f64>().ok())
                .unwrap_or(-1.0);
            let max_retries = std::env::var("VERIFY_TRUST_MAX_RETRIES")
                .ok()
                .and_then(|v| v.parse::<i64>().ok())
                .unwrap_or(3);

            if status == ContractStatus::Failed {
                if old.status == ContractStatus::Passed && old.workspace_hash == new_workspace_hash
                {
                    // Flaky / Fake test detected - severe penalty
                    conn.execute(
                        "UPDATE agents SET trust_score = trust_score + ?1 WHERE id = ?2",
                        params![flaky_penalty, old.agent_id],
                    )
                    .map_err(|e| format!("Update agent score: {e}"))?;
                } else {
                    // Check for consecutive failures
                    let mut stmt = conn.prepare(
                        "SELECT event_type FROM audit_events WHERE contract_id = ?1 ORDER BY created_at DESC LIMIT ?2"
                    ).map_err(|e| format!("Prepare consecutive check: {e}"))?;

                    let rows = stmt
                        .query_map(params![id, max_retries], |row| row.get::<_, String>(0))
                        .map_err(|e| format!("Query consecutive: {e}"))?;

                    let mut recent_failures = 0;
                    for row in rows {
                        if let Ok(evt) = row {
                            if evt == "verification_failed" || evt == "verification_started" {
                                if evt == "verification_failed" {
                                    recent_failures += 1;
                                }
                            } else {
                                break;
                            }
                        }
                    }

                    if recent_failures >= max_retries as usize {
                        // Trial and error detected
                        conn.execute(
                            "UPDATE agents SET trust_score = trust_score + ?1 WHERE id = ?2",
                            params![trial_penalty, old.agent_id],
                        )
                        .map_err(|e| format!("Update agent score: {e}"))?;
                    }
                }
            }
        }

        let now = Utc::now().to_rfc3339();
        let status_str = status_to_str(&status);

        if status == ContractStatus::Passed {
            conn.execute(
                "UPDATE contracts SET status = ?1, updated_at = ?2, workspace_hash = ?3 WHERE id = ?4",
                params![status_str, now, new_workspace_hash, id],
            )
            .map_err(|e| format!("Update status with hash: {e}"))?;
        } else {
            conn.execute(
                "UPDATE contracts SET status = ?1, updated_at = ?2 WHERE id = ?3",
                params![status_str, now, id],
            )
            .map_err(|e| format!("Update status: {e}"))?;
        }

        // Delete old results for this contract (re-runs overwrite)
        conn.execute(
            "DELETE FROM check_results WHERE contract_id = ?1",
            params![id],
        )
        .map_err(|e| format!("Delete old results: {e}"))?;

        // Insert new results
        let mut stmt = conn
            .prepare(
                "INSERT INTO check_results
                 (contract_id, check_name, status, severity, message, details, duration_ms, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            )
            .map_err(|e| format!("Prepare insert result: {e}"))?;

        for r in results {
            stmt.execute(params![
                id,
                r.check_name,
                check_status_to_str(&r.status),
                severity_to_str(&r.severity),
                r.message,
                r.details,
                r.duration_ms as i64,
                now,
            ])
            .map_err(|e| format!("Insert result: {e}"))?;
        }

        // Audit event
        let event_type = match status {
            ContractStatus::Passed => AuditEventType::VerificationPassed,
            ContractStatus::Failed => AuditEventType::VerificationFailed,
            _ => AuditEventType::VerificationStarted,
        };
        let detail = format!(
            "{} passed, {} failed, {} unverified",
            results
                .iter()
                .filter(|r| r.status == CheckStatus::Passed)
                .count(),
            results
                .iter()
                .filter(|r| r.status == CheckStatus::Failed)
                .count(),
            results
                .iter()
                .filter(|r| r.status == CheckStatus::Unverified)
                .count(),
        );
        self.log_event_sync(&conn, id, event_type, Some(&detail))?;

        Ok(())
    }

    /// Set status to Running.
    pub async fn set_running(&self, id: &str) -> Result<(), String> {
        let conn = self.conn.lock().await;
        let now = Utc::now().to_rfc3339();
        conn.execute(
            "UPDATE contracts SET status = 'running', updated_at = ?1 WHERE id = ?2",
            params![now, id],
        )
        .map_err(|e| format!("Set running: {e}"))?;
        self.log_event_sync(&conn, id, AuditEventType::VerificationStarted, None)?;
        Ok(())
    }

    /// List active (non-deleted) contracts.
    pub async fn list_contracts(&self) -> Result<Vec<ContractSummary>, String> {
        let conn = self.conn.lock().await;
        let mut stmt = conn
            .prepare(
                "SELECT id, description, task, agent_id, language, status, checks_json, created_at, workspace_hash
                 FROM contracts ORDER BY created_at DESC",
            )
            .map_err(|e| format!("Prepare list: {e}"))?;

        let rows = stmt
            .query_map([], |row| {
                let checks_json: String = row.get(6)?;
                let created_str: String = row.get(7)?;
                let workspace_hash: Option<String> = row.get(8)?;
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    checks_json,
                    created_str,
                    workspace_hash,
                ))
            })
            .map_err(|e| format!("Query list: {e}"))?;

        let mut summaries = Vec::new();
        for row in rows {
            let (
                id,
                description,
                task,
                agent_id,
                language,
                status_str,
                checks_json,
                created_str,
                workspace_hash,
            ) = row.map_err(|e| format!("Row error: {e}"))?;
            let checks: Vec<Check> = serde_json::from_str(&checks_json).unwrap_or_default();
            let status = str_to_status(&status_str);
            let created_at = DateTime::parse_from_rfc3339(&created_str)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now());

            summaries.push(ContractSummary {
                id,
                description,
                task,
                agent_id,
                language,
                status,
                num_checks: checks.len(),
                created_at,
                workspace_hash,
            });
        }
        Ok(summaries)
    }

    /// Delete a contract (and cascade to results/events).
    pub async fn delete_contract(&self, id: &str) -> Result<bool, String> {
        let conn = self.conn.lock().await;
        self.log_event_sync(&conn, id, AuditEventType::ContractDeleted, None)?;
        let changed = conn
            .execute("DELETE FROM contracts WHERE id = ?1", params![id])
            .map_err(|e| format!("Delete contract: {e}"))?;
        Ok(changed > 0)
    }

    // ── History & Stats Queries ─────────────────────────────────

    /// Get verification history with optional filters.
    pub async fn get_history(
        &self,
        limit: usize,
        status_filter: Option<&str>,
        days: Option<i64>,
    ) -> Result<Vec<HistoryEntry>, String> {
        let conn = self.conn.lock().await;

        let mut sql = String::from(
            "SELECT c.id, c.description, c.task, c.status, c.checks_json,
                    c.created_at, c.updated_at
             FROM contracts c WHERE 1=1",
        );
        let mut param_values: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();

        if let Some(status) = status_filter {
            sql.push_str(&format!(" AND c.status = ?{}", param_values.len() + 1));
            param_values.push(Box::new(status.to_string()));
        }

        if let Some(d) = days {
            sql.push_str(&format!(" AND c.created_at >= ?{}", param_values.len() + 1));
            let cutoff = (Utc::now() - chrono::Duration::days(d)).to_rfc3339();
            param_values.push(Box::new(cutoff));
        }

        sql.push_str(&format!(
            " ORDER BY c.created_at DESC LIMIT ?{}",
            param_values.len() + 1
        ));
        param_values.push(Box::new(limit as i64));

        let mut stmt = conn
            .prepare(&sql)
            .map_err(|e| format!("Prepare history: {e}"))?;

        let params_ref: Vec<&dyn rusqlite::types::ToSql> =
            param_values.iter().map(|p| p.as_ref()).collect();

        let rows = stmt
            .query_map(params_ref.as_slice(), |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                ))
            })
            .map_err(|e| format!("Query history: {e}"))?;

        let mut entries = Vec::new();
        for row in rows {
            let (id, description, task, status, checks_json, created_at, updated_at) =
                row.map_err(|e| format!("Row: {e}"))?;

            let checks: Vec<Check> = serde_json::from_str(&checks_json).unwrap_or_default();

            // Load results for this contract
            let results = self.get_results_sync(&conn, &id)?;
            let passed_checks = results
                .iter()
                .filter(|r| r.status == CheckStatus::Passed)
                .count();
            let failed_checks = results
                .iter()
                .filter(|r| r.status == CheckStatus::Failed)
                .count();
            let total_duration_ms: u64 = results.iter().map(|r| r.duration_ms).sum();

            entries.push(HistoryEntry {
                id,
                description,
                task,
                status,
                num_checks: checks.len(),
                passed_checks,
                failed_checks,
                total_duration_ms,
                created_at,
                updated_at,
            });
        }
        Ok(entries)
    }

    /// Get aggregate verification statistics.
    pub async fn get_stats(&self, days: Option<i64>) -> Result<VerificationStats, String> {
        let conn = self.conn.lock().await;
        let period = days.unwrap_or(30);
        let cutoff = (Utc::now() - chrono::Duration::days(period)).to_rfc3339();

        // Contract counts by status
        let mut stmt = conn
            .prepare(
                "SELECT status, COUNT(*) FROM contracts
                 WHERE created_at >= ?1 GROUP BY status",
            )
            .map_err(|e| format!("Prepare stats: {e}"))?;

        let mut total_passed = 0usize;
        let mut total_failed = 0usize;
        let mut total_pending = 0usize;

        let rows = stmt
            .query_map(params![cutoff], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, usize>(1)?))
            })
            .map_err(|e| format!("Query stats: {e}"))?;

        for row in rows {
            let (status, count) = row.map_err(|e| format!("Row: {e}"))?;
            match status.as_str() {
                "passed" => total_passed = count,
                "failed" => total_failed = count,
                "pending" | "running" => total_pending += count,
                _ => {}
            }
        }

        let total_contracts = total_passed + total_failed + total_pending;
        let completed = total_passed + total_failed;
        let pass_rate = if completed > 0 {
            (total_passed as f64 / completed as f64) * 100.0
        } else {
            0.0
        };

        // Check-level stats
        let (total_checks_run, total_check_failures, avg_duration) = conn
            .query_row(
                "SELECT COUNT(*), SUM(CASE WHEN status != 'passed' THEN 1 ELSE 0 END), AVG(duration_ms)
                 FROM check_results cr
                 JOIN contracts c ON cr.contract_id = c.id
                 WHERE c.created_at >= ?1",
                params![cutoff],
                |row| {
                    Ok((
                        row.get::<_, usize>(0)?,
                        row.get::<_, usize>(1).unwrap_or(0),
                        row.get::<_, f64>(2).unwrap_or(0.0),
                    ))
                },
            )
            .map_err(|e| format!("Check stats: {e}"))?;

        // Most commonly failing checks
        let mut stmt = conn
            .prepare(
                "SELECT cr.check_name, COUNT(*) as cnt, MAX(cr.created_at)
                 FROM check_results cr
                 JOIN contracts c ON cr.contract_id = c.id
                 WHERE cr.status = 'failed' AND c.created_at >= ?1
                 GROUP BY cr.check_name
                 ORDER BY cnt DESC
                 LIMIT 10",
            )
            .map_err(|e| format!("Prepare failures: {e}"))?;

        let failure_rows = stmt
            .query_map(params![cutoff], |row| {
                Ok(FailureFrequency {
                    check_name: row.get(0)?,
                    failure_count: row.get(1)?,
                    last_failure: row.get(2)?,
                })
            })
            .map_err(|e| format!("Query failures: {e}"))?;

        let most_common_failures: Vec<FailureFrequency> =
            failure_rows.filter_map(|r| r.ok()).collect();

        // Agent stats
        let mut stmt = conn
            .prepare("SELECT id, trust_score FROM agents ORDER BY trust_score DESC")
            .map_err(|e| format!("Prepare agents: {e}"))?;
        let agent_rows = stmt
            .query_map([], |row| {
                Ok(AgentStats {
                    id: row.get(0)?,
                    trust_score: row.get(1)?,
                })
            })
            .map_err(|e| format!("Query agents: {e}"))?;

        let agents: Vec<AgentStats> = agent_rows.filter_map(|r| r.ok()).collect();

        Ok(VerificationStats {
            total_contracts,
            total_passed,
            total_failed,
            total_pending,
            pass_rate_percent: (pass_rate * 10.0).round() / 10.0,
            total_checks_run,
            total_check_failures,
            most_common_failures,
            avg_verification_duration_ms: avg_duration as u64,
            period_days: period,
            agents,
        })
    }

    /// Get audit events for a contract.
    pub async fn get_audit_events(
        &self,
        contract_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<AuditEvent>, String> {
        let conn = self.conn.lock().await;

        let (sql, params_vec): (String, Vec<Box<dyn rusqlite::types::ToSql>>) =
            if let Some(cid) = contract_id {
                (
                    "SELECT id, contract_id, event_type, details, created_at
                     FROM audit_events WHERE contract_id = ?1
                     ORDER BY created_at DESC LIMIT ?2"
                        .into(),
                    vec![
                        Box::new(cid.to_string()) as Box<dyn rusqlite::types::ToSql>,
                        Box::new(limit as i64),
                    ],
                )
            } else {
                (
                    "SELECT id, contract_id, event_type, details, created_at
                     FROM audit_events ORDER BY created_at DESC LIMIT ?1"
                        .into(),
                    vec![Box::new(limit as i64) as Box<dyn rusqlite::types::ToSql>],
                )
            };

        let mut stmt = conn
            .prepare(&sql)
            .map_err(|e| format!("Prepare audit: {e}"))?;
        let params_ref: Vec<&dyn rusqlite::types::ToSql> =
            params_vec.iter().map(|p| p.as_ref()).collect();

        let rows = stmt
            .query_map(params_ref.as_slice(), |row| {
                let event_type_str: String = row.get(2)?;
                Ok(AuditEvent {
                    id: row.get(0)?,
                    contract_id: row.get(1)?,
                    event_type: AuditEventType::from_str(&event_type_str),
                    details: row.get(3)?,
                    created_at: row.get(4)?,
                })
            })
            .map_err(|e| format!("Query audit: {e}"))?;

        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("Collect audit: {e}"))
    }

    // ── Internal Helpers ────────────────────────────────────────

    fn get_results_sync(
        &self,
        conn: &Connection,
        contract_id: &str,
    ) -> Result<Vec<CheckResult>, String> {
        let mut stmt = conn
            .prepare(
                "SELECT check_name, status, severity, message, details, duration_ms
                 FROM check_results WHERE contract_id = ?1
                 ORDER BY id ASC",
            )
            .map_err(|e| format!("Prepare results: {e}"))?;

        let rows = stmt
            .query_map(params![contract_id], |row| {
                let status_str: String = row.get(1)?;
                let severity_str: String = row.get(2)?;
                Ok(CheckResult {
                    check_name: row.get(0)?,
                    status: str_to_check_status(&status_str),
                    severity: str_to_severity(&severity_str),
                    message: row.get(3)?,
                    details: row.get(4)?,
                    duration_ms: row.get::<_, i64>(5)? as u64,
                })
            })
            .map_err(|e| format!("Query results: {e}"))?;

        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("Collect results: {e}"))
    }

    fn log_event_sync(
        &self,
        conn: &Connection,
        contract_id: &str,
        event_type: AuditEventType,
        details: Option<&str>,
    ) -> Result<(), String> {
        let now = Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO audit_events (contract_id, event_type, details, created_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![contract_id, event_type.as_str(), details, now],
        )
        .map_err(|e| format!("Log event: {e}"))?;
        Ok(())
    }

    // ── Templates ───────────────────────────────────────────────

    pub async fn list_templates(&self) -> Result<Vec<TemplateSummary>, String> {
        let conn = self.conn.lock().await;
        let mut stmt = conn
            .prepare(
                "SELECT name, description, language, source, usage_count, variables_json
             FROM templates
             ORDER BY usage_count DESC",
            )
            .map_err(|e| format!("Prepare list_templates: {e}"))?;

        let rows = stmt
            .query_map([], |row| {
                let variables_json: String = row.get(5)?;
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                    variables_json,
                ))
            })
            .map_err(|e| format!("Query list_templates: {e}"))?;

        let mut summaries = Vec::new();
        for row in rows {
            let (name, description, language, source, usage_count, variables_json) =
                row.map_err(|e| format!("Row: {e}"))?;

            let variables: TemplateVariables = serde_json::from_str(&variables_json)
                .unwrap_or_else(|_| TemplateVariables {
                    required: Default::default(),
                    optional: Default::default(),
                });

            summaries.push(TemplateSummary {
                name,
                description,
                language,
                source,
                usage_count,
                variables,
            });
        }

        Ok(summaries)
    }

    pub async fn get_template(&self, name: &str) -> Result<Option<TemplateDefinition>, String> {
        let conn = self.conn.lock().await;
        let mut stmt = conn.prepare(
            "SELECT id, name, description, language, source, source_contract_id, variables_json, checks_json, created_at, usage_count
             FROM templates WHERE name = ?1",
        ).map_err(|e| format!("Prepare get_template: {e}"))?;

        let template = stmt
            .query_row(params![name], |row| {
                let variables_json: String = row.get(6)?;
                let checks_json: String = row.get(7)?;
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    variables_json,
                    checks_json,
                    row.get::<_, String>(8)?,
                    row.get::<_, i64>(9)?,
                ))
            })
            .optional()
            .map_err(|e| format!("Query get_template: {e}"))?;

        match template {
            None => Ok(None),
            Some((
                id,
                name,
                description,
                language,
                source,
                source_contract_id,
                variables_json,
                checks_json,
                created_at,
                usage_count,
            )) => {
                let variables: TemplateVariables = serde_json::from_str(&variables_json)
                    .unwrap_or_else(|_| TemplateVariables {
                        required: Default::default(),
                        optional: Default::default(),
                    });

                Ok(Some(TemplateDefinition {
                    id,
                    name,
                    description,
                    language,
                    source,
                    source_contract_id,
                    variables,
                    checks_json,
                    created_at,
                    usage_count,
                }))
            }
        }
    }

    pub async fn save_template(&self, template: &TemplateDefinition) -> Result<(), String> {
        let conn = self.conn.lock().await;
        self.save_template_sync(&conn, template)
    }

    fn save_template_sync(
        &self,
        conn: &Connection,
        template: &TemplateDefinition,
    ) -> Result<(), String> {
        let conflict_clause = if template.source == "builtin" {
            "ON CONFLICT(name) DO NOTHING"
        } else {
            "ON CONFLICT(name) DO UPDATE SET 
             description=excluded.description, 
             variables_json=excluded.variables_json, 
             checks_json=excluded.checks_json"
        };

        let variables_json = serde_json::to_string(&template.variables).unwrap_or_default();

        let sql = format!(
            "INSERT INTO templates 
            (id, name, description, language, source, source_contract_id, variables_json, checks_json, created_at, usage_count)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10) {}",
            conflict_clause
        );

        conn.execute(
            &sql,
            params![
                template.id,
                template.name,
                template.description,
                template.language,
                template.source,
                template.source_contract_id,
                variables_json,
                template.checks_json,
                template.created_at,
                template.usage_count
            ],
        )
        .map_err(|e| format!("Insert template: {e}"))?;

        Ok(())
    }

    pub async fn increment_template_usage(&self, name: &str) -> Result<(), String> {
        let conn = self.conn.lock().await;
        conn.execute(
            "UPDATE templates SET usage_count = usage_count + 1 WHERE name = ?1",
            params![name],
        )
        .map_err(|e| format!("Increment usage_count: {e}"))?;
        Ok(())
    }

    fn seed_builtin_templates(&self) -> Result<(), String> {
        let conn = self
            .conn
            .try_lock()
            .map_err(|e| format!("Lock error in seed: {e}"))?;

        let builtin_jsons = vec![
            r#"{
              "name": "python_new_endpoint",
              "description": "New API endpoint with type checking and tests",
              "language": "python",
              "source": "builtin",
              "variables_json": {
                "required": {
                  "working_dir": "Absolute path to project root",
                  "module_path": "Path to the module file, e.g. src/app.py",
                  "test_path": "Path to test file, e.g. tests/test_app.py"
                },
                "optional": {
                  "endpoint_pattern": "Route pattern to verify, e.g. /api/users",
                  "min_tests": "Minimum passing tests (default: 1)"
                }
              },
              "checks_json": [
                {
                  "name": "endpoint_exists",
                  "check_type": {
                    "type": "file_contains_patterns",
                    "path": "{{module_path}}",
                    "required_patterns": ["{{endpoint_pattern}}"],
                    "working_dir": "{{working_dir}}"
                  },
                  "_condition": "endpoint_pattern"
                },
                {
                  "name": "type_check",
                  "check_type": {
                    "type": "python_type_check",
                    "paths": ["{{module_path}}"],
                    "checker": "mypy",
                    "extra_args": ["--ignore-missing-imports"],
                    "working_dir": "{{working_dir}}"
                  }
                },
                {
                  "name": "tests_pass",
                  "check_type": {
                    "type": "pytest_result",
                    "test_path": "{{test_path}}",
                    "min_passed": "{{min_tests:1}}",
                    "working_dir": "{{working_dir}}"
                  }
                }
              ]
            }"#,
            r#"{
              "name": "python_bugfix",
              "description": "Bugfix with type checking and regression test",
              "language": "python",
              "source": "builtin",
              "variables_json": {
                "required": {
                  "working_dir": "Absolute path to project root",
                  "test_path": "Path to test file, e.g. tests/test_bugfix.py"
                },
                "optional": {
                  "source_dir": "Source directory to type-check (default: src/)",
                  "min_tests": "Minimum passing tests (default: 1)"
                }
              },
              "checks_json": [
                {
                  "name": "type_check",
                  "check_type": {
                    "type": "python_type_check",
                    "paths": ["{{source_dir:src/}}"],
                    "checker": "mypy",
                    "extra_args": ["--ignore-missing-imports"],
                    "working_dir": "{{working_dir}}"
                  }
                },
                {
                  "name": "tests_pass",
                  "check_type": {
                    "type": "pytest_result",
                    "test_path": "{{test_path}}",
                    "min_passed": "{{min_tests:1}}",
                    "working_dir": "{{working_dir}}"
                  }
                }
              ]
            }"#,
            r#"{
              "name": "python_new_module",
              "description": "New Python module with import safety, type checking and tests",
              "language": "python",
              "source": "builtin",
              "variables_json": {
                "required": {
                  "working_dir": "Absolute path to project root",
                  "module_path": "Path to the new module, e.g. src/billing.py",
                  "test_path": "Path to test file, e.g. tests/test_billing.py"
                },
                "optional": {
                  "min_tests": "Minimum passing tests (default: 1)"
                }
              },
              "checks_json": [
                {
                  "name": "module_created",
                  "check_type": {
                    "type": "file_exists",
                    "path": "{{module_path}}",
                    "working_dir": "{{working_dir}}"
                  }
                },
                {
                  "name": "type_check",
                  "check_type": {
                    "type": "python_type_check",
                    "paths": ["{{module_path}}"],
                    "checker": "mypy",
                    "extra_args": ["--ignore-missing-imports"],
                    "working_dir": "{{working_dir}}"
                  }
                },
                {
                  "name": "tests_pass",
                  "check_type": {
                    "type": "pytest_result",
                    "test_path": "{{test_path}}",
                    "min_passed": "{{min_tests:1}}",
                    "working_dir": "{{working_dir}}"
                  }
                }
              ]
            }"#,
            r#"{
              "name": "rust_feature",
              "description": "New Rust feature with build and test verification",
              "language": "rust",
              "source": "builtin",
              "variables_json": {
                "required": {
                  "working_dir": "Absolute path to Rust project root (where Cargo.toml is)"
                },
                "optional": {}
              },
              "checks_json": [
                {
                  "name": "builds_clean",
                  "check_type": {
                    "type": "command_succeeds",
                    "command": "cargo build --release",
                    "working_dir": "{{working_dir}}",
                    "timeout_secs": 120
                  }
                },
                {
                  "name": "tests_pass",
                  "check_type": {
                    "type": "command_succeeds",
                    "command": "cargo test",
                    "working_dir": "{{working_dir}}",
                    "timeout_secs": 120
                  }
                }
              ]
            }"#,
            r#"{
              "name": "html_template_change",
              "description": "HTML/CSS/template change — no forced test requirements",
              "language": "html",
              "source": "builtin",
              "variables_json": {
                "required": {
                  "working_dir": "Absolute path to project root",
                  "template_path": "Path to the template file, e.g. src/templates/history.html"
                },
                "optional": {
                  "expected_pattern": "Regex pattern that must be present after the change"
                }
              },
              "checks_json": [
                {
                  "name": "change_verified",
                  "check_type": {
                    "type": "file_contains_patterns",
                    "path": "{{template_path}}",
                    "required_patterns": ["{{expected_pattern}}"],
                    "working_dir": "{{working_dir}}"
                  },
                  "_condition": "expected_pattern"
                }
              ]
            }"#,
        ];

        let now = Utc::now().to_rfc3339();

        for json_str in builtin_jsons {
            #[derive(Deserialize)]
            struct BuiltinTemplate {
                name: String,
                description: String,
                language: String,
                source: String,
                variables_json: TemplateVariables,
                checks_json: serde_json::Value,
            }

            let parsed: BuiltinTemplate = serde_json::from_str(json_str)
                .map_err(|e| format!("Failed to parse builtin template: {}", e))?;

            let id = uuid::Uuid::new_v4().to_string();
            let def = TemplateDefinition {
                id,
                name: parsed.name,
                description: parsed.description,
                language: parsed.language,
                source: parsed.source,
                source_contract_id: None,
                variables: parsed.variables_json,
                checks_json: serde_json::to_string(&parsed.checks_json).unwrap(),
                created_at: now.clone(),
                usage_count: 0,
            };

            self.save_template_sync(&conn, &def)?;
        }

        Ok(())
    }
}

// ── Conversion Helpers ──────────────────────────────────────────────

fn status_to_str(status: &ContractStatus) -> &'static str {
    match status {
        ContractStatus::Pending => "pending",
        ContractStatus::Passed => "passed",
        ContractStatus::Failed => "failed",
        ContractStatus::Running => "running",
        ContractStatus::ReviewRequired => "review_required",
        ContractStatus::Rejected => "rejected",
    }
}

fn str_to_status(s: &str) -> ContractStatus {
    match s {
        "passed" => ContractStatus::Passed,
        "failed" => ContractStatus::Failed,
        "running" => ContractStatus::Running,
        "review_required" => ContractStatus::ReviewRequired,
        "rejected" => ContractStatus::Rejected,
        _ => ContractStatus::Pending,
    }
}

fn check_status_to_str(status: &CheckStatus) -> &'static str {
    match status {
        CheckStatus::Passed => "passed",
        CheckStatus::Failed => "failed",
        CheckStatus::Unverified => "unverified",
    }
}

fn str_to_check_status(s: &str) -> CheckStatus {
    match s {
        "passed" => CheckStatus::Passed,
        "failed" => CheckStatus::Failed,
        "unverified" => CheckStatus::Unverified,
        _ => CheckStatus::Failed,
    }
}

fn severity_to_str(s: &Severity) -> &'static str {
    match s {
        Severity::Error => "error",
        Severity::Warning => "warning",
        Severity::Info => "info",
    }
}

fn str_to_severity(s: &str) -> Severity {
    match s {
        "warning" => Severity::Warning,
        "info" => Severity::Info,
        _ => Severity::Error,
    }
}
