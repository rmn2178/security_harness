/**
 * NosihGovernanceHandler — LangChain callback handler for NOSIH Protocol.
 *
 * Intercepts tool calls before execution, validates against the
 * Policy Gateway, and logs evidence. Denied actions throw NosihDeniedError
 * (configurable).
 *
 * Compatible with LangChain JS/TS callback handler interface.
 * Implement the subset of BaseCallbackHandler methods we need.
 */

import type {
  NosihGovernanceConfig,
  NosihInterceptResult,
  NosihToolCallContext,
} from "./types.js";
import { intercept } from "./gateway-client.js";
import { NosihDeniedError } from "./errors.js";

/**
 * Default resource mapper: tool name → "tool:{toolName}".
 */
function defaultResourceMapper(toolName: string): string {
  return `tool:${toolName}`;
}

/**
 * Default action mapper: always "execute".
 */
function defaultActionMapper(_toolName: string): string {
  return "execute";
}

/**
 * NOSIH Governance Handler for LangChain.
 *
 * Implements the LangChain callback handler interface (handleToolStart).
 * Every tool invocation is intercepted by the NOSIH Policy Gateway.
 *
 * @example
 * ```typescript
 * import { NosihGovernanceHandler } from "@pshkv/integration-langchain";
 *
 * const handler = new NosihGovernanceHandler({
 *   gatewayUrl: "http://localhost:4100",
 *   agentId: "my-agent-pubkey-hex",
 * });
 *
 * // Attach to any LangChain chain or agent
 * const result = await chain.invoke(input, { callbacks: [handler] });
 * ```
 */
export class NosihGovernanceHandler {
  readonly name = "NosihGovernanceHandler";

  private config: NosihGovernanceConfig;
  private resourceMapper: (toolName: string) => string;
  private actionMapper: (toolName: string) => string;
  private interceptLog: NosihToolCallContext[] = [];

  constructor(config: NosihGovernanceConfig) {
    this.config = {
      throwOnDeny: true,
      logEvidence: true,
      timeoutMs: 5000,
      ...config,
    };
    this.resourceMapper =
      config.resourceMapper ?? defaultResourceMapper;
    this.actionMapper = config.actionMapper ?? defaultActionMapper;
  }

  /**
   * Called by LangChain before a tool is executed.
   *
   * Sends an intercept request to the NOSIH Policy Gateway.
   * If denied and throwOnDeny is true, throws NosihDeniedError.
   */
  async handleToolStart(
    tool: { name: string },
    input: string,
    runId: string,
    parentRunId?: string
  ): Promise<void> {
    const resource = this.resourceMapper(tool.name);
    const action = this.actionMapper(tool.name);

    const context: NosihToolCallContext = {
      toolName: tool.name,
      toolInput: input,
      runId,
      parentRunId,
      resource,
      action,
    };

    const result = await this.intercept(context);

    if (!result.approved && this.config.throwOnDeny) {
      throw new NosihDeniedError({
        toolName: tool.name,
        resource,
        reason: result.reason ?? "Policy gateway denied the action",
        tier: result.tier,
      });
    }
  }

  /**
   * Called by LangChain when a tool completes successfully.
   * Logs the successful execution to the evidence ledger.
   */
  async handleToolEnd(
    output: string,
    runId: string
  ): Promise<void> {
    // Evidence is logged by the gateway on intercept.
    // This hook is available for custom post-execution logging.
    void output;
    void runId;
  }

  /**
   * Called by LangChain when a tool errors.
   */
  async handleToolError(
    error: Error,
    runId: string
  ): Promise<void> {
    void error;
    void runId;
  }

  /**
   * Send an intercept request to the NOSIH gateway.
   */
  private async intercept(
    context: NosihToolCallContext
  ): Promise<NosihInterceptResult> {
    this.interceptLog.push(context);

    return intercept(this.config, {
      agentId: this.config.agentId,
      resource: context.resource,
      action: context.action,
      context: {
        toolName: context.toolName,
        toolInput: context.toolInput,
        runId: context.runId,
        parentRunId: context.parentRunId,
        source: "langchain",
      },
    });
  }

  /**
   * Get the log of all intercepted tool calls in this handler's lifetime.
   */
  getInterceptLog(): ReadonlyArray<NosihToolCallContext> {
    return this.interceptLog;
  }

  /**
   * Clear the intercept log.
   */
  clearLog(): void {
    this.interceptLog = [];
  }
}
