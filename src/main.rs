//! verify-mcp-server: Contract-based verification for AI agents.
//!
//! An MCP server that helps agents verify their own work through
//! pre-defined contracts. Addresses the "blind trust" problem where
//! agents accept results without validation.
//!
//! ## Usage
//!
//! ```json
//! {
//!   "mcpServers": {
//!     "verify": {
//!       "command": "verify-mcp-server"
//!     }
//!   }
//! }
//! ```

mod contract;
mod protocol;
mod sandbox;
mod storage;
mod templates;
mod tools;
mod verification;

use protocol::*;
use serde_json::{json, Value};
use storage::Storage;
use tokio::io::{self, AsyncBufReadExt, AsyncWriteExt, BufReader};
use tracing::{debug, error, info};

const SERVER_NAME: &str = "verify-mcp-server";
const SERVER_VERSION: &str = env!("CARGO_PKG_VERSION");
const PROTOCOL_VERSION: &str = "2024-11-05";

#[tokio::main]
async fn main() {
    // Log to stderr (MCP requirement: stdout is for JSON-RPC only)
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("verify_mcp_server=info".parse().unwrap()),
        )
        .with_writer(std::io::stderr)
        .with_target(false)
        .init();

    info!("{SERVER_NAME} v{SERVER_VERSION} starting...");

    let store = match Storage::open() {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to open database: {e}");
            std::process::exit(1);
        }
    };

    if let Err(e) = run_stdio_loop(store).await {
        error!("Fatal error: {e}");
        std::process::exit(1);
    }
}

/// Main stdio loop: read JSON-RPC messages from stdin, write responses to stdout.
async fn run_stdio_loop(store: Storage) -> Result<(), Box<dyn std::error::Error>> {
    let stdin = io::stdin();
    let mut stdout = io::stdout();
    let reader = BufReader::new(stdin);
    let mut lines = reader.lines();

    while let Some(line) = lines.next_line().await? {
        let line = line.trim().to_string();
        if line.is_empty() {
            continue;
        }

        debug!("← {line}");

        let request: JsonRpcRequest = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                let err_response =
                    JsonRpcResponse::error(None, -32700, format!("Parse error: {e}"));
                write_response(&mut stdout, &err_response).await?;
                continue;
            }
        };

        let response = handle_request(&request, &store).await;

        // Notifications (no id) don't get a response
        if request.id.is_none() {
            debug!("Notification '{}' handled (no response)", request.method);
            continue;
        }

        if let Some(response) = response {
            write_response(&mut stdout, &response).await?;
        }
    }

    info!("stdin closed, shutting down.");
    Ok(())
}

async fn handle_request(request: &JsonRpcRequest, store: &Storage) -> Option<JsonRpcResponse> {
    let id = request.id.clone();

    match request.method.as_str() {
        // ── Lifecycle ───────────────────────────────────────────
        "initialize" => {
            info!("Client connected, initializing...");
            let result = InitializeResult {
                protocol_version: PROTOCOL_VERSION.into(),
                capabilities: ServerCapabilities {
                    tools: ToolsCapability {
                        list_changed: false,
                    },
                },
                server_info: ServerInfo {
                    name: SERVER_NAME.into(),
                    version: SERVER_VERSION.into(),
                },
            };
            Some(JsonRpcResponse::success(
                id,
                serde_json::to_value(result).unwrap(),
            ))
        }

        // Client sends this as notification after receiving initialize result
        "notifications/initialized" => {
            info!("Client initialized successfully.");
            None // notification, no response
        }

        // ── Tools ───────────────────────────────────────────────
        "tools/list" => {
            let tools = tools::tool_definitions();
            let result = ToolsListResult { tools };
            Some(JsonRpcResponse::success(
                id,
                serde_json::to_value(result).unwrap(),
            ))
        }

        "tools/call" => {
            let params: ToolCallParams = match request
                .params
                .as_ref()
                .and_then(|p| serde_json::from_value(p.clone()).ok())
            {
                Some(p) => p,
                None => {
                    return Some(JsonRpcResponse::error(
                        id,
                        -32602,
                        "Invalid params: expected {name, arguments}",
                    ))
                }
            };

            let args = params
                .arguments
                .unwrap_or(Value::Object(Default::default()));
            info!("Tool call: {}", params.name);

            let result = tools::handle_tool_call(&params.name, &args, store).await;

            Some(JsonRpcResponse::success(
                id,
                serde_json::to_value(result).unwrap(),
            ))
        }

        // ── Ping ────────────────────────────────────────────────
        "ping" => Some(JsonRpcResponse::success(id, json!({}))),

        // ── Unknown ─────────────────────────────────────────────
        other => {
            debug!("Unknown method: {other}");
            Some(JsonRpcResponse::method_not_found(id, other))
        }
    }
}

async fn write_response(
    stdout: &mut io::Stdout,
    response: &JsonRpcResponse,
) -> Result<(), Box<dyn std::error::Error>> {
    let json = serde_json::to_string(response)?;
    debug!("→ {json}");
    stdout.write_all(json.as_bytes()).await?;
    stdout.write_all(b"\n").await?;
    stdout.flush().await?;
    Ok(())
}
