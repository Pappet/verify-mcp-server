# verify-mcp-server 🔍

**Contract-based verification for AI agents.**

An MCP (Model Context Protocol) server that addresses the "blind trust" problem in agentic AI systems: agents delegate tasks and accept results without verification. This server provides a structured way for agents to define expectations *before* doing work and verify results *after*.

Inspired by the [DeepMind research](https://deepmind.google/discover/blog/) on agent verification failures.

## The Problem

```
Agent A: "Write a function to sort users by age"
Agent B: "Done! Here's the code"
Agent A: "Great, shipping it!" ← No verification!
```

Agents currently:
- Accept tool outputs at face value
- Don't check if code compiles or tests pass
- Don't verify outputs match the original intent
- Propagate hallucinations through multi-agent chains

## The Solution: Contracts

```
1. DEFINE expectations (contract) → before work
2. DO the work                    → agent does its thing
3. VERIFY against contract        → automated checks
4. DECIDE based on evidence       → pass/fail with details
```

## Quick Start

### Build

```bash
cargo build --release
```

### Configure in Claude Code / Cursor / etc.

Add to your MCP configuration (e.g. `~/.config/claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "verify": {
      "command": "/path/to/verify-mcp-server"
    }
  }
}
```

### Enable debug logging

```bash
RUST_LOG=verify_mcp_server=debug verify-mcp-server
```

### Sandbox Configuration (optional)

Commands executed by the server are validated through a security layer. Unknown or risky commands are automatically sandboxed in a [Podman](https://podman.io/) container. Configure via environment variables:

| Variable | Default | Description |
|---|---|---|
| `VERIFY_SANDBOX_IMAGE` | `ubuntu:24.04` | Container image for sandboxed execution |
| `VERIFY_SANDBOX_MEMORY` | `512m` | Container memory limit |
| `VERIFY_SANDBOX_CPUS` | `2` | Container CPU limit |
| `VERIFY_SANDBOX_NETWORK` | `false` | Allow network access in containers |
| `VERIFY_SANDBOX_MOUNT_MODE` | `rw` | Working dir mount mode (`rw`, `ro`, `overlay`) |

> **Note**: The default `ubuntu:24.04` image doesn't include dev tools. For sandboxed execution of `pytest`, `cargo`, etc., set `VERIFY_SANDBOX_IMAGE` to a custom image with your toolchain.

## Tools

### `verify_create_contract`

Define expectations before starting work.

```json
{
  "description": "Adding user sort function",
  "task": "Add a sort_users_by_age() function to users.py",
  "checks": [
    {
      "name": "file_exists",
      "check_type": { "type": "file_exists", "path": "src/users.py" }
    },
    {
      "name": "code_compiles",
      "check_type": {
        "type": "command_succeeds",
        "command": "python -m py_compile src/users.py"
      }
    },
    {
      "name": "tests_pass",
      "check_type": {
        "type": "command_succeeds",
        "command": "pytest tests/test_users.py -v",
        "timeout_secs": 60
      }
    },
    {
      "name": "function_defined",
      "check_type": {
        "type": "file_contains_patterns",
        "path": "src/users.py",
        "required_patterns": ["def sort_users_by_age"]
      }
    },
    {
      "name": "no_unsafe_patterns",
      "check_type": {
        "type": "file_excludes_patterns",
        "path": "src/users.py",
        "forbidden_patterns": ["eval\\(", "exec\\(", "import os"]
      },
      "severity": "warning"
    }
  ]
}
```

### `verify_run_contract`

Execute all checks and get a verdict.

```json
{
  "contract_id": "uuid-from-create",
  "input": "optional data for schema/range/diff checks"
}
```

Returns:
```json
{
  "status": "passed",
  "verdict": "✓ ALL CHECKS PASSED",
  "summary": {
    "total_checks": 5,
    "passed": 5,
    "failed": 0,
    "warnings": 0,
    "total_duration_ms": 342
  },
  "checks": [...]
}
```

### `verify_quick_check`

Run a single check without a full contract. Good for ad-hoc verification during work.

```json
{
  "check": {
    "name": "rust_compiles",
    "check_type": {
      "type": "command_succeeds",
      "command": "cargo check",
      "working_dir": "/home/user/my-project"
    }
  }
}
```

### `verify_list_contracts`

List all active contracts with their status.

### `verify_get_report`

Get a detailed markdown report for a contract.

### `verify_delete_contract`

Clean up completed contracts.

### `verify_history`

Browse verification history across sessions. Shows past contracts with outcomes, filterable by status and time period.

```json
{
  "limit": 10,
  "status": "failed",
  "days": 7
}
```

Returns: contract IDs, descriptions, pass/fail counts, durations — useful for understanding patterns.

### `verify_stats`

Get aggregate verification statistics for a time period.

```json
{
  "days": 30
}
```

Returns:
```
Verification Stats (last 30 days)
══════════════════════════════════
Contracts: 47 total (38 passed, 9 failed, 0 pending)
Pass rate: 80.9%
Checks run: 284 total (23 failures)
Avg duration: 412ms per check

Most frequently failing checks:
  1. all_tests_pass (6 failures, last: 2026-02-25)
  2. no_print_statements (3 failures, last: 2026-02-27)
```

## Security

The server implements a three-tier security model for command execution:

### Command Whitelisting

All agent-provided commands are validated before execution. The base command is checked against a whitelist of known-safe tools:

- **Allowed**: `python`, `pytest`, `mypy`, `cargo`, `rustc`, `npm`, `go`, `ruff`, `grep`, `cat`, `echo`, and 20+ more
- **Blocked**: Commands containing dangerous patterns like `;`, `&&`, `||`, `|`, `` ` ``, `$()`, `rm`, `curl`, `wget`, `sudo`, `chmod`, `>`, `>>`, etc.
- **Sandboxed**: Unknown commands that pass pattern checks run inside a Podman container

```
✓ "cargo check"                  → Allowed (whitelisted)
✓ "python -m pytest tests/"     → Allowed (whitelisted)
✗ "cargo check && rm -rf /"     → Denied  (dangerous pattern: &&)
✗ "curl https://evil.com"       → Denied  (dangerous pattern: curl)
⎔ "my-custom-tool --check"      → Sandboxed (unknown command)
```

### Container Sandboxing

Commands can be force-sandboxed by setting `"sandbox": true` on a check. Unknown commands are automatically sandboxed. Sandboxed commands run in ephemeral [Podman](https://podman.io/) containers with:

- **Memory limit**: 512 MB (configurable)
- **CPU limit**: 2 CPUs (configurable)
- **PID limit**: 256 processes
- **Network**: Disabled by default
- **Working directory**: Bind-mounted from the host

### Internal Command Exemption

Server-generated commands (e.g., for `python_type_check`, `pytest_result`, `python_import_graph`) bypass dangerous-pattern checks since they are constructed by the server itself and cannot contain agent-injected payloads.

## Persistence

All contracts, check results, and audit events are stored in SQLite at:

```
~/.local/share/verify-mcp/verify.db
```

(Respects `XDG_DATA_HOME` if set.)

This means:
- Contracts survive server restarts
- History is queryable across sessions
- Audit trail tracks every create/run/pass/fail/delete event
- Statistics accumulate over time for trend analysis

## Check Types

| Type | Purpose | Needs `input`? | `sandbox`? |
|------|---------|----------------|------------|
| `command_succeeds` | Run command, verify exit 0 | No | Yes |
| `command_output_matches` | Run command, match stdout regex | No | Yes |
| `file_exists` | Check file exists | No | No |
| `file_contains_patterns` | Required regex patterns in file | No | No |
| `file_excludes_patterns` | Forbidden regex patterns in file | No | No |
| `json_schema_valid` | Validate JSON against schema | Yes (JSON) | No |
| `value_in_range` | Numeric range check | Yes (number) | No |
| `diff_size_limit` | Limit additions/deletions | Yes (diff) | No |
| `assertion` | Agent claim (flagged as unverified) | Yes (evidence) | No |
| `python_type_check` | Run mypy/pyright with structured results | No | No |
| `pytest_result` | Run pytest with pass/fail/skip thresholds | No | No |
| `python_import_graph` | Detect circular imports in Python packages | No | No |
| `json_registry_consistency` | Verify JSON IDs exist in Python source | No | No |

For `command_succeeds` and `command_output_matches`, you can set `"sandbox": true` to force execution inside a container:

```json
{
  "name": "untrusted_check",
  "check_type": {
    "type": "command_succeeds",
    "command": "some-tool --check",
    "sandbox": true
  }
}

### Python-Specific Check Details

#### `python_type_check`

Run mypy or pyright and get structured error counts instead of just exit codes:

```json
{
  "name": "type_check",
  "check_type": {
    "type": "python_type_check",
    "paths": ["ecs/systems/", "services/"],
    "checker": "mypy",
    "extra_args": ["--ignore-missing-imports"],
    "working_dir": "."
  }
}
```

#### `pytest_result`

Run pytest with thresholds on pass/fail/skip counts:

```json
{
  "name": "tests_with_thresholds",
  "check_type": {
    "type": "pytest_result",
    "test_path": "tests/ -v",
    "min_passed": 40,
    "max_failures": 0,
    "max_skipped": 5,
    "working_dir": "."
  }
}
```

Returns structured data:
```
Results: 52 passed, 0 failed, 0 errors, 2 skipped

All thresholds met ✓
```

#### `python_import_graph`

Detect circular imports by analyzing `import` and `from ... import` statements via AST:

```json
{
  "name": "no_circular_imports",
  "check_type": {
    "type": "python_import_graph",
    "root_path": "ecs",
    "fail_on_circular": true,
    "working_dir": "."
  }
}
```

Returns:
```
Import graph: 18 modules, 47 import edges

Circular imports (1):
  1. ecs.systems.combat_system → ecs.components → ecs.systems.combat_system
```

#### `json_registry_consistency`

Verify that every ID in a JSON data file is referenced in a Python source file:

```json
{
  "name": "all_entities_registered",
  "check_type": {
    "type": "json_registry_consistency",
    "json_path": "assets/data/entities.json",
    "id_field": "id",
    "source_path": "entities/entity_registry.py"
  }
}
```

Optionally, specify a pattern for how IDs should appear in the source (use `{}` as placeholder):

```json
{
  "name": "items_have_factory",
  "check_type": {
    "type": "json_registry_consistency",
    "json_path": "assets/data/items.json",
    "id_field": "id",
    "source_path": "entities/item_factory.py",
    "reference_pattern": "\"{}\"" 
  }
}
```

## Example Workflow: Rust Project

```
Agent: "I need to add a new endpoint to the API"

1. verify_create_contract:
   - cargo check succeeds
   - cargo test succeeds
   - cargo clippy has no warnings
   - new file exists at src/routes/users.rs
   - file contains "pub async fn"
   - no unwrap() in production code
   - diff is under 200 lines

2. Agent writes the code...

3. verify_run_contract:
   → ✓ cargo check: passed (1203ms)
   → ✓ cargo test: passed (4521ms)
   → ⚠ clippy: 2 warnings (severity: warning)
   → ✓ file exists: passed
   → ✓ function found: passed
   → ✗ unwrap check: FAILED - found unwrap() at line 42
   → ✓ diff size: +87 -12 within limits

   VERDICT: ✗ CONTRACT FAILED
   → Agent must fix unwrap() before proceeding
```

## Architecture

```
┌──────────────┐     stdio/JSON-RPC      ┌──────────────────┐
│  AI Agent    │ ◄──────────────────────► │  verify-mcp      │
│  (Claude,    │                          │  server           │
│   Cursor,    │  1. Create contract      │                  │
│   custom)    │  2. Do work              │  ┌────────────┐  │
│              │  3. Run verification     │  │ Contract   │  │
│              │  4. Get verdict          │  │ Store      │  │
└──────────────┘                          │  └────────────┘  │
                                          │  ┌────────────┐  │
                                          │  │ Verify     │  │
                                          │  │ Engine     │  │
                                          │  └────────────┘  │
                                          │  ┌────────────┐  │
                                          │  │ Sandbox    │  │
                                          │  │ (Security) │  │
                                          │  └────────────┘  │
                                          └──────────────────┘
```

## Future Ideas

- **Tree-sitter AST analysis**: Verify code structure, not just text patterns
- **LLM-powered semantic review**: Use a second model as adversarial reviewer
- **Git integration**: Auto-generate diff checks from staged changes
- **Contract templates**: Pre-built contracts for common languages/frameworks
- **Multi-agent trust scores**: Track which agents produce reliable results
- **Overlay mount mode**: Run sandboxed commands with disposable filesystem overlays

## License

MIT
