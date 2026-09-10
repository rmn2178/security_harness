/**
 * NOSIH MCP — Server.
 *
 * The main MCP server that aggregates tools from downstream servers,
 * enforces NOSIH policy on every call, and exposes built-in NOSIH tools
 * for approval workflows, audit trail, and server management.
 *
 * @module @nosih/mcp/server
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import {
  ListToolsRequestSchema,
  CallToolRequestSchema,
  ListResourcesRequestSchema,
  ReadResourceRequestSchema,
  ListPromptsRequestSchema,
  ListResourceTemplatesRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import type { NosihCapabilityToken } from "@pshkv/core";
import { PolicyGateway } from "@pshkv/gate-policy-gateway";
import { ApprovalQueue } from "@pshkv/gate-policy-gateway";
import { RevocationStore } from "@pshkv/gate-capability-tokens";
import { LedgerWriter } from "@pshkv/gate-evidence-ledger";
import { DownstreamManager } from "./downstream.js";
import { ToolAggregator, parseNamespace } from "./aggregator.js";
import { PolicyEnforcer } from "./enforcer.js";
import { createAgentIdentity, type AgentIdentity } from "./identity.js";
import {
  getNosihToolDefinitions,
  handleNosihTool,
  isNosihTool,
  type NosihToolContext,
} from "./tools/nosih-tools.js";
import {
  getInterfaceToolDefinitions,
  handleInterfaceTool,
  isInterfaceTool,
  type InterfaceToolContext,
} from "./tools/interface-tools.js";
import {
  getDelegationToolDefinitions,
  handleDelegationTool,
  isDelegationTool,
  type DelegationToolContext,
} from "./tools/delegation-tools.js";
import { InterfaceStateManager, DelegationTree } from "@pshkv/interface-bridge";
import {
  getNosihResources,
  readNosihResource,
  type ResourceContext,
} from "./resources/nosih-resources.js";
import type { NosihMCPConfig } from "./config.js";
import {
  TrajectoryRecorder,
  type TrajectoryOutcome,
} from "./trajectory.js";

/** NOSIH MCP Server — the security-first multi-MCP proxy. */
export class NosihMCPServer {
  readonly server: Server;
  readonly downstream: DownstreamManager;
  readonly aggregator: ToolAggregator;
  readonly tokenStore: Map<string, NosihCapabilityToken>;
  readonly revocationStore: RevocationStore;
  readonly ledger: LedgerWriter;
  readonly gateway: PolicyGateway;
  readonly approvalQueue: ApprovalQueue;
  readonly trajectory: TrajectoryRecorder;
  readonly interfaceState: InterfaceStateManager;
  readonly delegationTree: DelegationTree;

  private identity: AgentIdentity | null = null;
  private enforcer: PolicyEnforcer | null = null;
  private readonly config: NosihMCPConfig;

  constructor(config: NosihMCPConfig) {
    this.config = config;

    // Create MCP Server
    this.server = new Server(
      { name: "nosih-mcp", version: "0.1.1" },
      {
        capabilities: {
          tools: {},
          resources: {},
          prompts: {},
        },
      },
    );

    // Initialize NOSIH components
    this.tokenStore = new Map();
    this.revocationStore = new RevocationStore();
    this.ledger = new LedgerWriter();
    this.approvalQueue = new ApprovalQueue({
      defaultTimeoutMs: config.approvalTimeoutMs,
    });
    this.trajectory = new TrajectoryRecorder({
      runId: process.env["PAPERCLIP_RUN_ID"] ?? `run-${Date.now()}`,
      agentId: process.env["PAPERCLIP_AGENT_ID"] ?? "unknown-agent",
      taskId: process.env["PAPERCLIP_TASK_ID"] ?? "unknown-task",
      model: process.env["OPENAI_MODEL"] ?? process.env["MODEL"] ?? "unknown-model",
      outputDir: process.env["NOSIH_TRAJECTORY_DIR"] ?? ".nosih/trajectories",
    });

    this.gateway = new PolicyGateway({
      resolveToken: (id) => this.tokenStore.get(id),
      revocationStore: this.revocationStore,
      emitLedgerEvent: (event) => {
        this.ledger.append({
          eventType: event.eventType as any,
          agentId: event.agentId,
          tokenId: event.tokenId,
          payload: event.payload,
        });
      },
    });

    // Initialize interface state manager
    this.interfaceState = new InterfaceStateManager(
      process.env["NOSIH_SESSION_ID"] ?? `session-${Date.now()}`,
    );

    // Initialize delegation tree
    this.delegationTree = new DelegationTree();

    // Initialize downstream & aggregator
    this.downstream = new DownstreamManager();
    this.aggregator = new ToolAggregator(this.downstream);

    // Register MCP handlers
    this.registerHandlers();
  }

  /**
   * Initialize the server: create identity, connect downstreams.
   */
  async initialize(): Promise<void> {
    // Create agent identity
    this.identity = createAgentIdentity(this.config.agentPrivateKey);

    // Store the default token
    this.tokenStore.set(
      this.identity.defaultToken.tokenId,
      this.identity.defaultToken,
    );

    // Create enforcer
    this.enforcer = new PolicyEnforcer(
      this.gateway,
      this.approvalQueue,
      this.downstream,
      this.identity.publicKey,
      this.identity.defaultToken.tokenId,
      this.trajectory,
    );

    // Connect to downstream servers
    await this.connectDownstreams();

    // Refresh tool aggregation
    this.aggregator.refresh();
  }

  /**
   * Get the agent identity (available after initialize()).
   */
  getIdentity(): AgentIdentity | null {
    return this.identity;
  }

  /**
   * Connect to all configured downstream servers.
   */
  private async connectDownstreams(): Promise<void> {
    const entries = Object.entries(this.config.servers);
    const results = await Promise.allSettled(
      entries.map(([name, config]) => this.downstream.addServer(name, config)),
    );

    for (let i = 0; i < results.length; i++) {
      const result = results[i]!;
      const name = entries[i]![0];
      if (result.status === "rejected") {
        console.error(`Failed to connect downstream "${name}": ${result.reason}`);
      }
    }
  }

  /**
   * Register all MCP request handlers.
   */
  private registerHandlers(): void {
    // tools/list — return aggregated tools + NOSIH built-in tools
    this.server.setRequestHandler(ListToolsRequestSchema, async () => {
      const downstreamTools = this.aggregator.toMCPToolsList();
      const nosihTools = getNosihToolDefinitions();
      const interfaceTools = getInterfaceToolDefinitions();
      const delegationTools = getDelegationToolDefinitions();
      return { tools: [...downstreamTools, ...nosihTools, ...interfaceTools, ...delegationTools] };
    });

    // prompts/list — NOSIH currently exposes no prompt templates
    this.server.setRequestHandler(ListPromptsRequestSchema, async () => {
      return { prompts: [] };
    });

    // tools/call — enforce policy then route
    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      const { name, arguments: args } = request.params;
      const toolArgs = (args ?? {}) as Record<string, unknown>;

      // Handle multi-agent delegation tools (no policy enforcement)
      if (isDelegationTool(name)) {
        return handleDelegationTool(name, toolArgs, this.getDelegationToolContext());
      }

      // Handle operator interface tools (no policy enforcement)
      if (isInterfaceTool(name)) {
        return handleInterfaceTool(name, toolArgs, this.getInterfaceToolContext());
      }

      // Handle built-in NOSIH tools (no policy enforcement)
      if (isNosihTool(name)) {
        return handleNosihTool(name, toolArgs, this.getToolContext());
      }

      // Parse namespace and enforce policy
      const parsed = parseNamespace(name);
      if (!parsed) {
        return {
          content: [{
            type: "text",
            text: `Invalid tool name "${name}". Use format: serverName__toolName`,
          }],
          isError: true,
        };
      }

      if (!this.enforcer) {
        return {
          content: [{
            type: "text",
            text: "Server not initialized. Call initialize() first.",
          }],
          isError: true,
        };
      }

      const result = await this.enforcer.enforce(parsed, toolArgs);

      if (result.allowed && result.result) {
        return result.result;
      }

      // Denied or escalated
      return {
        content: [{
          type: "text",
          text: result.denyReason ?? "Action denied by NOSIH policy",
        }],
        isError: true,
      };
    });

    // resources/list
    this.server.setRequestHandler(ListResourcesRequestSchema, async () => {
      return { resources: getNosihResources() };
    });

    // resources/templates/list — NOSIH currently exposes no resource templates
    this.server.setRequestHandler(ListResourceTemplatesRequestSchema, async () => {
      return { resourceTemplates: [] };
    });

    // resources/read
    this.server.setRequestHandler(ReadResourceRequestSchema, async (request) => {
      const result = readNosihResource(
        request.params.uri,
        this.getResourceContext(),
      );

      if (!result) {
        throw new Error(`Resource not found: ${request.params.uri}`);
      }

      return result;
    });
  }

  /**
   * Get the count of built-in NOSIH tools (including interface and delegation tools).
   */
  getNosihToolCount(): number {
    return getNosihToolDefinitions().length + getInterfaceToolDefinitions().length + getDelegationToolDefinitions().length;
  }

  async finalizeTrajectory(outcome: TrajectoryOutcome): Promise<string> {
    this.trajectory.markOutcome(outcome);
    return this.trajectory.flushToFile();
  }

  private getToolContext(): NosihToolContext {
    return {
      downstream: this.downstream,
      approvalQueue: this.approvalQueue,
      ledger: this.ledger,
      agentPublicKey: this.identity?.publicKey ?? "unknown",
      agentPrivateKey: this.identity?.privateKey ?? "",
      tokenId: this.identity?.defaultToken.tokenId ?? "unknown",
      tokenStore: this.tokenStore,
      revocationStore: this.revocationStore,
    };
  }

  private getInterfaceToolContext(): InterfaceToolContext {
    return {
      interfaceState: this.interfaceState,
      ledger: this.ledger,
      agentPublicKey: this.identity?.publicKey ?? "unknown",
    };
  }

  private getDelegationToolContext(): DelegationToolContext {
    return {
      agentPublicKey: this.identity?.publicKey ?? "unknown",
      agentPrivateKey: this.identity?.privateKey ?? "",
      tokenId: this.identity?.defaultToken.tokenId ?? "unknown",
      tokenStore: this.tokenStore,
      revocationStore: this.revocationStore,
      ledger: this.ledger,
      delegationTree: this.delegationTree,
    };
  }

  private getResourceContext(): ResourceContext {
    return {
      downstream: this.downstream,
      approvalQueue: this.approvalQueue,
      ledger: this.ledger,
      tokenStore: this.tokenStore,
    };
  }

  /**
   * Dispose all resources.
   */
  async dispose(): Promise<void> {
    this.approvalQueue.dispose();
    await this.downstream.dispose();
  }
}
