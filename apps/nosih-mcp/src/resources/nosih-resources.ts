/**
 * NOSIH MCP — MCP Resources.
 *
 * Exposes NOSIH data (ledger events, tokens, server info, approvals)
 * as browseable MCP resources.
 *
 * @module @nosih/mcp/resources/nosih-resources
 */

import type { NosihCapabilityToken } from "@pshkv/core";
import type { ApprovalQueue } from "@pshkv/gate-policy-gateway";
import type { LedgerWriter } from "@pshkv/gate-evidence-ledger";
import type { DownstreamManager } from "../downstream.js";

/** Context needed by resource handlers. */
export interface ResourceContext {
  readonly downstream: DownstreamManager;
  readonly approvalQueue: ApprovalQueue;
  readonly ledger: LedgerWriter;
  readonly tokenStore: Map<string, NosihCapabilityToken>;
}

/** MCP Resource definition. */
export interface MCPResource {
  readonly uri: string;
  readonly name: string;
  readonly description: string;
  readonly mimeType: string;
}

/**
 * Get the list of all NOSIH resources.
 */
export function getNosihResources(): MCPResource[] {
  return [
    {
      uri: "nosih://ledger/recent",
      name: "Recent Ledger Events",
      description: "Last 50 events from the NOSIH evidence ledger",
      mimeType: "application/json",
    },
    {
      uri: "nosih://tokens/active",
      name: "Active Tokens",
      description: "All active capability tokens",
      mimeType: "application/json",
    },
    {
      uri: "nosih://approvals/pending",
      name: "Pending Approvals",
      description: "Currently pending approval requests",
      mimeType: "application/json",
    },
    {
      uri: "nosih://servers/list",
      name: "Connected Servers",
      description: "All downstream MCP servers and their status",
      mimeType: "application/json",
    },
    {
      uri: "nosih://policy/decisions",
      name: "Recent Decisions",
      description: "Recent policy decisions with outcomes",
      mimeType: "application/json",
    },
    {
      uri: "nosih://ledger/event/{eventId}",
      name: "Ledger Event Detail",
      description: "Single ledger event by event ID",
      mimeType: "application/json",
    },
    {
      uri: "nosih://tokens/{tokenId}",
      name: "Token Detail",
      description: "Single capability token with full details and delegation chain",
      mimeType: "application/json",
    },
  ];
}

/**
 * Read a NOSIH resource by URI.
 */
export function readNosihResource(
  uri: string,
  ctx: ResourceContext,
): { contents: Array<{ uri: string; mimeType: string; text: string }> } | undefined {
  if (uri === "nosih://ledger/recent") {
    const events = ctx.ledger.getAll().slice(-50);
    const serialized = events.map((e) => ({
      ...e,
      sequenceNumber: e.sequenceNumber.toString(),
    }));
    return {
      contents: [{
        uri,
        mimeType: "application/json",
        text: JSON.stringify(serialized, null, 2),
      }],
    };
  }

  if (uri === "nosih://tokens/active") {
    const tokens = Array.from(ctx.tokenStore.values());
    return {
      contents: [{
        uri,
        mimeType: "application/json",
        text: JSON.stringify(tokens, null, 2),
      }],
    };
  }

  if (uri === "nosih://approvals/pending") {
    const pending = ctx.approvalQueue.getPending();
    return {
      contents: [{
        uri,
        mimeType: "application/json",
        text: JSON.stringify(pending, null, 2),
      }],
    };
  }

  if (uri === "nosih://servers/list") {
    const servers = ctx.downstream.listServers();
    return {
      contents: [{
        uri,
        mimeType: "application/json",
        text: JSON.stringify(servers, null, 2),
      }],
    };
  }

  if (uri === "nosih://policy/decisions") {
    // Extract policy.evaluated events from ledger
    const events = ctx.ledger.getAll()
      .filter((e) => e.eventType === "policy.evaluated")
      .slice(-50);
    const serialized = events.map((e) => ({
      ...e,
      sequenceNumber: e.sequenceNumber.toString(),
    }));
    return {
      contents: [{
        uri,
        mimeType: "application/json",
        text: JSON.stringify(serialized, null, 2),
      }],
    };
  }

  // ── Dynamic resources ──

  // nosih://servers/{name}/tools
  const serverToolsMatch = uri.match(/^nosih:\/\/servers\/([^/]+)\/tools$/);
  if (serverToolsMatch) {
    const serverName = serverToolsMatch[1]!;
    const servers = ctx.downstream.listServers();
    const server = servers.find((s) => s.name === serverName);
    if (!server) return undefined;

    return {
      contents: [{
        uri,
        mimeType: "application/json",
        text: JSON.stringify(server, null, 2),
      }],
    };
  }

  // nosih://ledger/event/{eventId}
  const eventMatch = uri.match(/^nosih:\/\/ledger\/event\/(.+)$/);
  if (eventMatch) {
    const eventId = eventMatch[1]!;
    const event = ctx.ledger.getAll().find((e) => e.eventId === eventId);
    if (!event) return undefined;

    return {
      contents: [{
        uri,
        mimeType: "application/json",
        text: JSON.stringify({
          ...event,
          sequenceNumber: event.sequenceNumber.toString(),
        }, null, 2),
      }],
    };
  }

  // nosih://tokens/{tokenId}
  const tokenMatch = uri.match(/^nosih:\/\/tokens\/([^/]+)$/);
  if (tokenMatch) {
    const tokenId = tokenMatch[1]!;
    if (tokenId === "active") return undefined; // already handled above
    const token = ctx.tokenStore.get(tokenId);
    if (!token) return undefined;

    return {
      contents: [{
        uri,
        mimeType: "application/json",
        text: JSON.stringify(token, null, 2),
      }],
    };
  }

  return undefined;
}
