/**
 * @nosih/integration-langchain — NOSIH Protocol governance for LangChain.
 *
 * Provides a callback handler and tool wrapper that enforce
 * capability tokens on every LangChain tool invocation.
 *
 * Usage (LangChain JS/TS):
 *
 *   import { NosihGovernanceHandler } from "@pshkv/integration-langchain";
 *
 *   const handler = new NosihGovernanceHandler({
 *     gatewayUrl: "http://localhost:4100",
 *     agentId: "my-agent",
 *     token: capabilityToken,
 *   });
 *
 *   const agent = createReactAgent({ llm, tools, callbacks: [handler] });
 *
 * Every tool call will be intercepted by NOSIH's Policy Gateway.
 * Denied actions throw NosihDeniedError with the denial reason.
 *
 * @module @nosih/integration-langchain
 */

export { NosihGovernanceHandler } from "./handler.js";
export { nosihGovernedTool, wrapToolsWithGovernance } from "./tool-wrapper.js";
export { NosihDeniedError } from "./errors.js";
export type {
  NosihGovernanceConfig,
  NosihInterceptResult,
  NosihToolCallContext,
} from "./types.js";
