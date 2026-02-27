# verify-mcp-server 🔍

**Contract-based verification for AI agents.**

An MCP (Model Context Protocol) server that addresses the "blind trust" problem in agentic AI systems where agents delegate tasks and accept results without verifying them. This server forces agents to mathematically and robustly prove their work using explicit contracts.

For full architectural details, source code breakdowns, and historical design decisions, see the [PROJECT_OVERVIEW.md](file:///home/peter/Projekte/verify-mcp-server/PROJECT_OVERVIEW.md).

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
      "command": "/path/to/verify-mcp-server/target/release/verify-mcp-server"
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
  "checks": [
    {
      "name": "tests_pass",
      "check_type": {
        "type": "command_succeeds",
        "command": "cargo test"
      }
    }
  ]
}
```

Execute the work and verify using `verify_run_contract`. You'll receive a detailed verdict:

```json
{
  "status": "passed",
  "verdict": "✓ ALL CHECKS PASSED",
  "summary": {
    "total_checks": 1,
    "passed": 1,
    "failed": 0,
    "unverified": 0,
    "warnings": 0
  }
}
```

## Security & Sandboxing

Commands executed by the server are strictly validated. Unknown or risky commands are either blocked entirely or automatically sandboxed in an ephemeral **Podman** container. 

You can configure sandbox constraints via environment variables (e.g., `VERIFY_SANDBOX_MEMORY`, `VERIFY_SANDBOX_CPUS`). See [PROJECT_OVERVIEW.md](file:///home/peter/Projekte/verify-mcp-server/PROJECT_OVERVIEW.md) for deeper details on whitelisting limits.

## Persistence

All contracts, check results, and audit events are stored securely in a local SQLite file resulting in state capable of surviving resets:
`~/.local/share/verify-mcp/verify.db`

## License

MIT
