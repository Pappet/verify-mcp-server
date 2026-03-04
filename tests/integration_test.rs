use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;
use serde_json::json;

async fn send_msg(stdin: &mut tokio::process::ChildStdin, msg: serde_json::Value) {
    let mut msg_str = serde_json::to_string(&msg).unwrap();
    msg_str.push('\n');
    stdin.write_all(msg_str.as_bytes()).await.unwrap();
    stdin.flush().await.unwrap();
}

async fn recv_msg(reader: &mut tokio::io::Lines<BufReader<tokio::process::ChildStdout>>) -> serde_json::Value {
    // Wait for a JSON line. Exclude any non-JSON or debug output if there happen to be any, though stdio should be clean.
    loop {
        let line = reader.next_line().await.unwrap().expect("Unexpected EOF while waiting for response");
        if line.trim().is_empty() {
            continue;
        }
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&line) {
            return val;
        } else {
            // If it's invalid JSON from the server, we might want to panic, but let's see.
            panic!("Server returned invalid JSON: {}", line);
        }
    }
}

#[tokio::test]
async fn test_json_rpc_integration() {
    let temp_dir = tempfile::tempdir().unwrap();
    
    let mut child = Command::new(env!("CARGO_BIN_EXE_verify-mcp-server"))
        .env("XDG_DATA_HOME", temp_dir.path())
        .env("RUST_LOG", "error") // Keep stdout clean
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        // Route stderr to null to avoid clutter, or leave mapped
        .stderr(Stdio::null())
        .spawn()
        .expect("Failed to spawn verify-mcp-server");

    let mut stdin = child.stdin.take().expect("Failed to open stdin");
    let stdout = child.stdout.take().expect("Failed to open stdout");
    let mut reader = BufReader::new(stdout).lines();

    // 1. initialize
    send_msg(&mut stdin, json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {
                "name": "integration-test",
                "version": "1.0.0"
            }
        }
    })).await;

    let init_resp = recv_msg(&mut reader).await;
    assert_eq!(init_resp["id"], 1);
    assert!(init_resp["result"].get("protocolVersion").is_some(), "Expected protocolVersion in initialize response");
    assert!(init_resp["result"].get("serverInfo").is_some(), "Expected serverInfo in initialize response");
    assert!(init_resp["result"].get("capabilities").is_some(), "Expected capabilities in initialize response");

    // 2. notifications/initialized
    send_msg(&mut stdin, json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized"
    })).await;

    // 3. tools/list -> Response mit 12 Tools (or more)
    send_msg(&mut stdin, json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list",
        "params": {}
    })).await;

    let list_resp = recv_msg(&mut reader).await;
    assert_eq!(list_resp["id"], 2);
    let tools = list_resp["result"]["tools"].as_array().expect("Tools should be an array");
    assert!(tools.len() >= 12, "Expected at least 12 tools, got: {}", tools.len());

    // 4. tools/call mit verify_create_contract
    send_msg(&mut stdin, json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "verify_create_contract",
            "arguments": {
                "agent_id": "integration_tester",
                "description": "Integration test contract",
                "task": "Test contract creation via RPC",
                "language": "python",
                "bypass_meta_validation_reason": "Not real code",
                "checks": [
                    {
                        "name": "dummy_check",
                        "severity": "info",
                        "check_type": {
                            "type": "command_succeeds",
                            "command": "echo ok",
                            "working_dir": "."
                        }
                    }
                ]
            }
        }
    })).await;

    let create_resp = recv_msg(&mut reader).await;
    assert_eq!(create_resp["id"], 3);
    
    // Server wraps tools/call results in { content: [ { type: "text", text: "..." } ], isError: false }
    let content = create_resp["result"]["content"].as_array().expect("Expected content array");
    let text = content[0]["text"].as_str().expect("Expected text field");
    
    // DEBUG PRINT
    eprintln!("verify_create_contract response text: {}", text);

    let create_result_json: serde_json::Value = serde_json::from_str(text)
        .unwrap_or_else(|e| panic!("Contract result text should be JSON. Raw text was: '{}', Error: {}", text, e));
    let contract_id = create_result_json["contract_id"].as_str().expect("Expected contract_id in create response");

    // 5. tools/call mit verify_list_contracts -> Response enthält den erstellten Contract
    send_msg(&mut stdin, json!({
        "jsonrpc": "2.0",
        "id": 4,
        "method": "tools/call",
        "params": {
            "name": "verify_list_contracts",
            "arguments": {}
        }
    })).await;

    let list_contracts_resp = recv_msg(&mut reader).await;
    assert_eq!(list_contracts_resp["id"], 4);
    let lcontent = list_contracts_resp["result"]["content"].as_array().expect("Expected content array");
    let ltext = lcontent[0]["text"].as_str().unwrap();
    eprintln!("verify_list_contracts response text: {}", ltext);
    let ljson: serde_json::Value = serde_json::from_str(ltext).unwrap();
    let contracts = ljson["contracts"].as_array().expect("Expected contracts array");
    assert!(contracts.iter().any(|c| c["id"] == contract_id || c["contract_id"] == contract_id || c["uuid"] == contract_id), "Listed contracts should contain the newly created contract_id. Contracts list: {:?}", contracts);

    // 6. tools/call mit verify_delete_contract -> Response bestätigt Löschung
    send_msg(&mut stdin, json!({
        "jsonrpc": "2.0",
        "id": 5,
        "method": "tools/call",
        "params": {
            "name": "verify_delete_contract",
            "arguments": {
                "contract_id": contract_id
            }
        }
    })).await;

    let del_resp = recv_msg(&mut reader).await;
    assert_eq!(del_resp["id"], 5);
    let dcontent = del_resp["result"]["content"].as_array().expect("Expected content array");
    let dtext = dcontent[0]["text"].as_str().unwrap();
    assert!(dtext.contains("deleted") || dtext.contains("Deleted"), "Delete response should confirm deletion");

    // 7. ping -> Response {}
    send_msg(&mut stdin, json!({
        "jsonrpc": "2.0",
        "id": 6,
        "method": "ping"
    })).await;

    let ping_resp = recv_msg(&mut reader).await;
    assert_eq!(ping_resp["id"], 6);
    assert_eq!(ping_resp["result"], json!({}));

    // Fehler-Pfade:
    // 8. Ungültiges JSON -> Parse-Error Response (-32700)
    let bad_json_str = "{invalid json\n".as_bytes();
    stdin.write_all(bad_json_str).await.unwrap();
    stdin.flush().await.unwrap();

    let parse_err_resp = recv_msg(&mut reader).await;
    assert_eq!(parse_err_resp["error"]["code"], -32700, "Expected parse error code -32700");

    // 9. Unbekannte Methode -> Method Not Found (-32601)
    send_msg(&mut stdin, json!({
        "jsonrpc": "2.0",
        "id": 8,
        "method": "unknown/method"
    })).await;

    let unk_resp = recv_msg(&mut reader).await;
    assert_eq!(unk_resp["id"], 8);
    assert_eq!(unk_resp["error"]["code"], -32601, "Expected method not found code -32601");

    // 10. tools/call ohne name -> Invalid Params (-32602)
    send_msg(&mut stdin, json!({
        "jsonrpc": "2.0",
        "id": 9,
        "method": "tools/call",
        "params": {
            // Missing name here
            "arguments": {}
        }
    })).await;

    let invalid_resp = recv_msg(&mut reader).await;
    assert_eq!(invalid_resp["id"], 9);
    assert_eq!(invalid_resp["error"]["code"], -32602, "Expected invalid params code -32602");

    // Teste dass der Server bei stdin-Close sauber beendet
    drop(stdin);

    let status = child.wait().await.expect("Failed to wait on child");
    assert!(status.success(), "Server should exit cleanly with success on stdin close");
}
