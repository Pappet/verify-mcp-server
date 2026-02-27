# Project Overview: verify-mcp-server

## What Is This?

A **Rust-based MCP (Model Context Protocol) server** that provides **contract-based verification** for AI agents. It solves the "blind trust" problem — where AI agents accept tool outputs without checking them — by letting agents define expectations *before* work and verify results *after*.

> [!TIP]
> You are already using this server! It's the `verify` MCP server that powers `verify_create_contract`, `verify_run_contract`, and other verification tools.

---

## Project Stats

| Property | Value |
|---|---|
| **Language** | Rust (edition 2021) |
| **Version** | 0.1.0 |
| **License** | MIT |
| **Tests** | ✅ 18 passing unit tests |
| **Build** | ✅ Compiles (with 4 dead code warnings in `storage.rs` for future audit events) |
| **Binary** | `target/release/verify-mcp-server` |
| **Persistence** | SQLite at `~/.local/share/verify-mcp/verify.db` |

---

## Architectural Decisions

This project is built around several core design decisions to ensure safety, reliability, and precision when evaluating agent outputs.

### 1. Three-Tier Command Security
Agents have a tendency to run unsafe commands (e.g., `rm -rf`, unexpected network calls) or chain commands in ways that bypass monitoring.
- **Whitelisting**: Basic commands (`cargo`, `python`, `pytest`, `grep`) are allowed by default if they do not contain dangerous characters.
- **Pattern Blocking**: Any payload containing shell-injection patterns (`&&`, `||`, `$()`, `>`, etc.) is immediately rejected unless inside an allowed context.
- **Sandboxing**: Unknown or explicitly sandboxed commands (`"sandbox": true`) run in short-lived, ephemeral **Podman** containers with severe restrictions (no network, 512MB RAM limit, 2 CPU limit).

### 2. Precise Assertion Handling (`CheckStatus`)
Originally, agents could arbitrarily claim an assertion was "passed" (`passed: true`), breaking the trustless model.
- We introduced a 3-state `CheckStatus` enum (`Passed`, `Failed`, `Unverified`). 
- If an agent provides an assertion with evidence, it is logged as `Unverified`.
- Contracts containing `Unverified` checks cannot achieve a `Passed` status. Instead, they result in `ContractStatus::ReviewRequired`. This prevents false confidence while still capturing agent insights.

### 3. Local SQLite Persistence
Instead of appending to JSON files or using an external database, the server uses a bundled `rusqlite` implementation. 
- It maintains structured trails of all created contracts, executions, and check results.
- **No Migration Framework**: Because this is a local developer tool, if schema changes are required (e.g., adding `status` instead of `passed`), the database file (`~/.local/share/verify-mcp/verify.db`) is safely wiped and re-created rather than bloating the system with a heavy versioned migration tool like SeaORM/Diesel-migrations.

---

## Source Files

### [main.rs](file:///home/peter/Projekte/verify-mcp-server/src/main.rs)
Entry point. Sets up tracing (to stderr per MCP spec), opens SQLite storage, and runs the stdio JSON-RPC loop. Handles `initialize`, `tools/list`, `tools/call`, and `ping` methods.

### [protocol.rs](file:///home/peter/Projekte/verify-mcp-server/src/protocol.rs)
MCP protocol types: `JsonRpcRequest`, `JsonRpcResponse`, `ToolDefinition`, `ToolResult`, etc. Implements the JSON-RPC 2.0 subset needed for an MCP tool server.

### [contract.rs](file:///home/peter/Projekte/verify-mcp-server/src/contract.rs)
Data model for contracts and checks. Defines:
- `Contract` — a set of expectations with metadata
- `Check` — a single verifiable check with severity
- `CheckType` — the 12 supported check types (commands, files, JSON schema, pytest, import graph, etc.)
- `CheckResult` — contains a `CheckStatus` (`Passed`, `Failed`, `Unverified`).
- `ContractStatus` — Overall health (`Pending`, `Running`, `Passed`, `Failed`, `ReviewRequired`).

### [tools.rs](file:///home/peter/Projekte/verify-mcp-server/src/tools.rs)
MCP tool definitions and call handlers. Exposes 8 tools (`verify_create_contract`, `verify_run_contract`, etc.). Analyzes check outcomes to enforce the `ReviewRequired` verdict.

### [verification.rs](file:///home/peter/Projekte/verify-mcp-server/src/verification.rs)
The verification engine. Implements all 12 check evaluation mechanisms, mapping command and regex evaluations into strict `CheckStatus` results. Evaluates python types and tracks graph loops and missing items.

### [storage.rs](file:///home/peter/Projekte/verify-mcp-server/src/storage.rs)
SQLite-backed persistence. Stores contracts, check results (using the text mapping of `status`), and a full, queryable audit trail (including unused scaffolded `AuditEvent` hooks for future use).

### [sandbox.rs](file:///home/peter/Projekte/verify-mcp-server/src/sandbox.rs)
Implements the 3-tier security policies and regex filters to deny destructive behaviors, returning verdicts on whether a command is whitelisted, blocked, or must be containerized.

---

## Dependencies

| Crate | Purpose |
|---|---|
| `serde` + `serde_json` | JSON serialization |
| `tokio` | Async runtime + process spawning |
| `uuid` | Contract ID generation |
| `chrono` | Timestamps |
| `regex` | Pattern matching in checks |
| `rusqlite` (bundled) | SQLite storage |
| `tracing` + `tracing-subscriber` | Structured logging |
| `thiserror` | Error handling |

---

## Additional References

- [README.md](file:///home/peter/Projekte/verify-mcp-server/README.md) — The Quick Start guide and entry point.
- [CLAUDE_roguelike_verification_v2.md](file:///home/peter/Projekte/verify-mcp-server/CLAUDE_roguelike_verification_v2.md) — A comprehensive verification template tailored for a roguelike Python/ECS project.
