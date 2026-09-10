#!/usr/bin/env node
/**
 * NOSIH MCP — Entry Point.
 *
 * Security-first multi-MCP proxy server.
 * Connects to multiple downstream MCP servers and enforces
 * NOSIH policy on every tool call.
 *
 * Usage:
 *   npx nosih-mcp                            # stdio, default config
 *   npx nosih-mcp --sse --port 3200         # SSE remote
 *   npx nosih-mcp --config ./config.json     # custom config
 *
 * @module @nosih/mcp
 */

import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { randomUUID } from "node:crypto";
import { loadConfig } from "./config.js";
import { NosihMCPServer } from "./server.js";

const NOSIH_MCP_VERSION = "0.1.1";

let activeServer: NosihMCPServer | null = null;
let trajectoryFlushed = false;

function printHelp(): void {
  console.log(`NOSIH MCP ${NOSIH_MCP_VERSION}

Security-first multi-MCP proxy server with NOSIH policy enforcement.

Usage:
  nosih-mcp [options]

Options:
  --help, -h              Show this help text and exit
  --version, -v           Show version and exit
  --stdio                 Use stdio transport (default)
  --sse                   Use streamable HTTP transport
  --port <port>           HTTP port for --sse (default: 3200)
  --config <path>         Path to nosih-mcp JSON config

Environment:
  NOSIH_MCP_CONFIG         Path to a nosih-mcp JSON config file
  NOSIH_MCP_POLICY         Enforcement posture: permissive, cautious, or strict
  NOSIH_MCP_TRANSPORT      Transport mode: stdio or sse
  NOSIH_MCP_PORT           Port used when transport is sse
`);
}

function handleMetaFlags(argv: readonly string[]): boolean {
  if (argv.includes("--help") || argv.includes("-h")) {
    printHelp();
    return true;
  }
  if (argv.includes("--version") || argv.includes("-v")) {
    console.log(NOSIH_MCP_VERSION);
    return true;
  }
  return false;
}

async function flushTrajectory(outcome: "success" | "failure" | "partial" | "timeout"): Promise<void> {
  if (!activeServer || trajectoryFlushed) return;
  try {
    const filePath = await activeServer.finalizeTrajectory(outcome);
    trajectoryFlushed = true;
    console.error(`  Trajectory: ${filePath}`);
  } catch (err) {
    console.error("  Failed to flush trajectory:", err);
  }
}

async function main(): Promise<void> {
  if (handleMetaFlags(process.argv.slice(2))) {
    return;
  }

  const config = loadConfig();

  // Banner
  console.error("╔══════════════════════════════════════╗");
  console.error("║   🛡️  NOSIH MCP — Security Proxy      ║");
  console.error("║   Multi-MCP Policy Enforcement       ║");
  console.error("╚══════════════════════════════════════╝");
  console.error(`  Transport: ${config.transport}`);
  console.error(`  Servers:   ${Object.keys(config.servers).length} configured`);
  console.error(`  Policy:    ${config.defaultPolicy}`);
  console.error("");

  // Create and initialize server
  const nosihMCP = new NosihMCPServer(config);
  activeServer = nosihMCP;
  await nosihMCP.initialize();

  const identity = nosihMCP.getIdentity();
  if (identity) {
    console.error(`  Agent:     ${identity.publicKey.slice(0, 16)}...`);
    console.error(`  Token:     ${identity.defaultToken.tokenId.slice(0, 8)}...`);
  }

  const servers = nosihMCP.downstream.listServers();
  const connected = servers.filter((s) => s.status === "connected");
  console.error(`  Connected: ${connected.length}/${servers.length} servers`);

  const nosihToolCount = nosihMCP.getNosihToolCount();
  const totalTools = connected.reduce((sum, s) => sum + s.toolCount, 0);
  console.error(`  Tools:     ${totalTools} aggregated + ${nosihToolCount} NOSIH built-in`);
  console.error("");

  // Connect transport
  if (config.transport === "stdio") {
    const transport = new StdioServerTransport();
    await nosihMCP.server.connect(transport);
    console.error("  ✓ Listening on stdio");
  } else {
    // Streamable HTTP transport (SSE + HTTP POST)
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: () => randomUUID(),
    });

    await nosihMCP.server.connect(transport);

    const httpServer = createServer(async (req: IncomingMessage, res: ServerResponse) => {
      const url = req.url ?? "/";

      // Health check endpoint
      if (url === "/health" && req.method === "GET") {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ status: "ok", transport: "streamable-http" }));
        return;
      }

      // MCP endpoint — handle GET (SSE) and POST (JSON-RPC)
      if (url === "/mcp" || url === "/") {
        await transport.handleRequest(req, res);
        return;
      }

      res.writeHead(404);
      res.end("Not found");
    });

    httpServer.listen(config.port, () => {
      console.error(`  ✓ Streamable HTTP on http://localhost:${config.port}/mcp`);
      console.error(`  ✓ Health check at  http://localhost:${config.port}/health`);
    });
  }

  // Graceful shutdown
  process.on("SIGINT", async () => {
    console.error("\n  Shutting down...");
    await flushTrajectory("success");
    await nosihMCP.dispose();
    process.exit(0);
  });

  process.on("SIGTERM", async () => {
    await flushTrajectory("success");
    await nosihMCP.dispose();
    process.exit(0);
  });
}

main().catch(async (err) => {
  console.error("Fatal error:", err);
  await flushTrajectory("failure");
  if (activeServer) {
    await activeServer.dispose();
  }
  process.exit(1);
});
