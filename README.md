# verify-mcp-server 🔍

**Contract-based verification for AI agents.**

An MCP (Model Context Protocol) server that addresses the "blind trust" problem in agentic AI systems where agents delegate tasks and accept results without verifying them. This server forces agents to mathematically and robustly prove their work using explicit contracts.

For full architectural details, source code breakdowns, and historical design decisions, see the [PROJECT_OVERVIEW.md](PROJECT_OVERVIEW.md).

## The Problem

```
Agent A: "Write a function to sort users by age"
Agent B: "Done! Here's the code"
Agent A: "Great, shipping it!" ← No verification!
```

Agents currently:
- Accept nested tool outputs at face value.
- Do not confirm if code compiles or tests pass before reporting completion.
- Propagate hallucinations through multi-agent steps.

## The Solution: Contracts

```
1. DEFINE expectations (contract) → before work
2. DO the work                    → agent acts
3. VERIFY against contract        → automated checks & metrics
4. DECIDE based on evidence       → Passed / Failed / Review Required
```

Contracts implement a rigorous definition of done. If an agent asserts something without computational proof, it is marked as `Unverified` and forces a human to review the task (`ReviewRequired`).

## Quick Start

### 1. Build

```bash
cargo build --release
```

### 2. Configure in your Client

Add to your MCP configuration (e.g. `~/.config/claude/claude_desktop_config.json` or cursor config):

```json
{
  "mcpServers": {
    "verify": {
      "command": "/path/to/verify-mcp-server/target/release/verify-mcp-server",
      "env": {
        "RUST_LOG": "verify_mcp_server=info"
      }
    }
  }
}
```

### 3. Usage Example

Define expectations before starting work using `verify_create_contract`:

```json
{
  "description": "Adding user sort function",
  "task": "Add a sort_users_by_age() function",
  "agent_id": "cli-user",
  "language": "python",
  "checks": [
    {
      "name": "type_check",
      "check_type": {
        "type": "python_type_check",
        "paths": ["services/user_service.py"],
        "checker": "mypy",
        "extra_args": ["--ignore-missing-imports"],
        "working_dir": "."
      }
    },
    {
      "name": "tests_pass",
      "check_type": {
        "type": "pytest_result",
        "test_path": "tests/test_user_service.py -v",
        "min_passed": 3,
        "max_failures": 0,
        "working_dir": "."
      }
    }
  ]
}
```

> **Note:** `agent_id` and `language` are mandatory. The server enforces language-specific meta-validation — Python tasks must include `python_type_check` and `pytest_result`, Rust tasks must include `cargo test`. Use `bypass_meta_validation_reason` for non-code changes like templates or config edits.

Execute the work and verify using `verify_run_contract`. You'll receive a detailed verdict:

```json
{
  "status": "passed",
  "verdict": "✓ ALL CHECKS PASSED",
  "summary": {
    "total_checks": 2,
    "passed": 2,
    "failed": 0,
    "unverified": 0,
    "warnings": 0
  }
}
```

### 4. Using Templates

Instead of defining checks from scratch every time, use templates:

```bash
# List available templates
verify_list_templates

# Create a contract from a template
verify_create_from_template {
  "template_name": "python_bugfix",
  "agent_id": "my-agent",
  "variables": {
    "working_dir": "/path/to/project",
    "test_path": "tests/test_fix.py"
  }
}
```

Once a contract passes, promote it to a reusable template with `verify_promote_to_template`.

### 5. Debugging & Audit Trails

If an agent or a review process gets stuck, you can pull up the history and audit trails:
- Use `verify_history` to browse past operations.
- Use `verify_stats` to see aggregate pass rates, most common failures, and agent trust scores.
- Use `verify_get_audit_trail` with a specific `contract_id` to trace the exact lifecycle of a task and identify how often an agent failed before succeeding.

## Tools

The server exposes 12 MCP tools:

| Tool | Description |
|---|---|
| `verify_create_contract` | Define a verification contract before starting work |
| `verify_run_contract` | Execute all checks and get a verification report |
| `verify_quick_check` | Run a single ad-hoc check without a full contract |
| `verify_list_contracts` | List all active contracts with status |
| `verify_get_report` | Get detailed results for a contract |
| `verify_delete_contract` | Remove a contract |
| `verify_history` | Browse past contracts with filters |
| `verify_stats` | Aggregate statistics, pass rates, and agent trust scores |
| `verify_get_audit_trail` | Full lifecycle trace for a contract |
| `verify_list_templates` | List available contract templates |
| `verify_create_from_template` | Create a contract from a template with variable substitution |
| `verify_promote_to_template` | Promote a passed contract into a reusable template |

## Check Types

The server supports 17 check types for comprehensive verification:

| Check Type | Description |
|---|---|
| `command_succeeds` | Run a shell command, verify exit code 0 |
| `command_output_matches` | Run a command, match stdout against regex |
| `file_exists` | Verify a file exists |
| `file_contains_patterns` | Verify regex patterns are present in a file |
| `file_excludes_patterns` | Verify regex patterns are absent from a file |
| `ast_query` | Tree-sitter based semantic AST analysis |
| `json_schema_valid` | Validate JSON against a schema |
| `value_in_range` | Check a numeric value is within bounds |
| `diff_size_limit` | Verify diff size stays within limits |
| `assertion` | Agent-provided claim (always marked Unverified) |
| `python_type_check` | Structured mypy/pyright type checking |
| `pytest_result` | Structured pytest with pass/fail/skip thresholds |
| `python_import_graph` | Circular import detection with architecture rules |
| `json_registry_consistency` | Verify JSON IDs exist in Python registries |
| `typescript_type_check` | Run tsc --noEmit to check TypeScript types |
| `jest_vitest_result` | Run and parse Jest/Vitest JSON test reports |
| `css_html_consistency` | Ensure all HTML classes in a file exist in the CSS file |

## Safety Features

### Contract Creation Safeguards

Contracts go through multiple validation stages before being accepted:

1. **Check Parsing** — All checks are deserialized with targeted error messages. If a field name is wrong (e.g. `path` vs `paths`), the agent gets a specific hint showing exactly which fields are required, with a copy-paste example.

2. **Meta-Validation** — Language-specific minimum standards are enforced (e.g. Python tasks must have type checks and tests, JS tasks must have tests, TS tasks must have type checks and tests). Can be bypassed with `bypass_meta_validation_reason` for non-code changes.

3. **Dry-Run Validation** — Before a contract is stored, all regex patterns are compiled, working directories are verified, and AST queries are checked for balanced brackets. Invalid contracts are rejected immediately with actionable diagnostics.

4. **Rejected Contract Auditing** — Even rejected contracts are stored in the database for audit purposes, so patterns of repeated mistakes can be tracked.

### Security & Sandboxing

Commands executed by the server are strictly validated through a three-tier security model:

- **Whitelisted:** Safe commands (`python`, `cargo`, `pytest`, `mypy`, etc.) run directly on the host.
- **Blocked:** Shell injection patterns (`&&`, `||`, `;`, `|`, `rm`, `sudo`, etc.) are rejected with actionable suggestions (e.g. "Use `working_dir` instead of `cd ... &&`").
- **Sandboxed:** Unknown commands run in ephemeral Podman containers with no network, limited RAM and CPU.

The validation is **quote-aware** — semicolons inside quoted strings (e.g. `python -c "import x; y"`) are correctly recognized as safe Python code, not shell injection.

Configure sandbox constraints via environment variables:

| Variable | Default | Description |
|---|---|---|
| `VERIFY_SANDBOX_IMAGE` | `ubuntu:24.04` | Container image |
| `VERIFY_SANDBOX_MEMORY` | `512m` | Memory limit |
| `VERIFY_SANDBOX_CPUS` | `2.0` | CPU limit |
| `VERIFY_SANDBOX_NETWORK` | `false` | Network access |
| `VERIFY_SANDBOX_MOUNT_MODE` | `rw` | Mount mode (rw/ro) |

### Agent Trust Scores

The server tracks agent reliability through trust scores. Agents start at 100.0 and receive penalties for:

- **Flaky results:** A contract that was `Passed` suddenly fails with the same workspace hash → severe penalty.
- **Trial-and-error:** Repeated consecutive failures on the same contract → penalty after N retries.

Trust scores are visible in `verify_stats` output and can be tuned via environment variables (`VERIFY_TRUST_PENALTY_FLAKY`, `VERIFY_TRUST_PENALTY_TRIAL`, `VERIFY_TRUST_MAX_RETRIES`).

## Persistence

All contracts, check results, templates, and audit events are stored in a local SQLite file:
`~/.local/share/verify-mcp/verify.db`

The database uses WAL mode for better concurrent read performance and foreign key constraints for referential integrity.

## License

MIT
