# OpenFang Fork Integration Guide

## Overview

ShieldAGI extends OpenFang by adding 14 custom security tools as native Rust implementations in the `openfang-runtime` crate. This guide explains how to integrate the `shieldagi-tools` crate into your OpenFang fork.

## Step 1: Fork OpenFang

```bash
git clone https://github.com/RightNow-AI/openfang.git shieldagi-openfang
cd shieldagi-openfang
git checkout -b shieldagi/tools-integration
```

## Step 2: Add ShieldAGI Tools Crate

Copy the `tools/` directory from the ShieldAGI repo into the OpenFang workspace:

```bash
cp -r /path/to/shieldagi/tools crates/shieldagi-tools
```

Add to the workspace `Cargo.toml`:
```toml
[workspace]
members = [
    # ... existing crates
    "crates/shieldagi-tools",
]
```

Add dependency in `crates/openfang-runtime/Cargo.toml`:
```toml
[dependencies]
shieldagi-tools = { path = "../shieldagi-tools" }
```

## Step 3: Register Tools in Runtime

Edit `crates/openfang-runtime/src/tool_runner.rs`:

```rust
use shieldagi_tools::{get_shieldagi_tools, execute_shieldagi_tool};

// In the tool registration section, add:
pub fn register_tools() -> Vec<ToolDefinition> {
    let mut tools = builtin_tools(); // existing tools

    // Register ShieldAGI security tools
    for shield_tool in get_shieldagi_tools() {
        tools.push(ToolDefinition {
            name: shield_tool.name,
            description: shield_tool.description,
            input_schema: shield_tool.input_schema,
        });
    }

    tools
}

// In the tool execution dispatch, add:
async fn execute_tool(name: &str, input: &serde_json::Value) -> Result<String, String> {
    // Check ShieldAGI tools first
    if name.starts_with("nmap_") || name.starts_with("sqlmap_") ||
       name.starts_with("xss_") || name.starts_with("csrf_") ||
       name.starts_with("ssrf_") || name.starts_with("semgrep_") ||
       name.starts_with("secret_") || name.starts_with("rls_") ||
       name.starts_with("header_") || name.starts_with("dep_") ||
       name.starts_with("brute_") || name.starts_with("idor_") ||
       name.starts_with("path_") || name.starts_with("log_") {
        return execute_shieldagi_tool(name, input).await;
    }

    // Fall through to existing tool dispatch
    match name {
        // ... existing tools
    }
}
```

## Step 4: Copy Agent Templates

```bash
cp -r /path/to/shieldagi/agents/* agents/
cp -r /path/to/shieldagi/hands/* hands/  # If hands/ exists in OpenFang root
```

## Step 5: Build and Test

```bash
cargo build --workspace --lib
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

## Step 6: Run ShieldAGI

```bash
# Initialize with Anthropic API key
openfang init  # Select claude-opus-4-6

# Start daemon
openfang start

# Spawn agents
openfang agent spawn recon-scout
openfang agent spawn code-auditor
openfang agent spawn attack-executor
openfang agent spawn vuln-reporter
openfang agent spawn shield-remediator

# Activate monitoring Hands
openfang hand activate sentinel
openfang hand activate dep-guardian
# incident-responder activates automatically on sentinel alerts

# Start a scan
openfang chat recon-scout
> "Scan https://github.com/user/target-repo"
```

## Architecture Notes

### Tool Execution Flow
1. Agent requests tool via LLM function call
2. OpenFang runtime matches tool name to `execute_shieldagi_tool()`
3. Tool function wraps the underlying binary (nmap, sqlmap, etc.)
4. Binary executes inside the Docker sandbox (via `shell` tool or direct)
5. Output is parsed from XML/JSON into structured response
6. Agent receives structured data and continues reasoning

### Knowledge Graph Integration
All agents store findings via the built-in `knowledge_store` tool. This uses OpenFang's SQLite + vector embeddings backend:
- Recon Scout stores: attack surface data
- Code Auditor stores: static analysis findings
- Attack Executor stores: exploitation results with PoCs
- Vuln Reporter stores: compiled vulnerability report
- Shield Remediator queries: all stored data for remediation context

### Sandbox Isolation
The Attack Executor runs all exploitation tools inside `shieldagi-sandbox` Docker network:
- `internal: true` — no internet access from sandbox
- Tools connect only to `shieldagi-vulnapp` and `shieldagi-vulndb`
- No access to host network or other Docker networks
- Resource limits: 4 CPU, 4GB RAM per container
