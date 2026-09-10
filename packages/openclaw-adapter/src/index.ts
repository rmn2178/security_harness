/**
 * @nosih/openclaw-adapter — NOSIH Protocol governance for OpenClaw.
 *
 * Injects capability token governance into every OpenClaw tool call,
 * MCP server call, and node action. Maps OpenClaw's tool system to
 * NOSIH's T0-T3 safety tiers with cross-system policy enforcement.
 *
 * @module @nosih/openclaw-adapter
 */

export { OpenClawAdapter } from "./adapter.js";
export {
  classifyToolCall,
  classifyMCPCall,
  classifyNodeAction,
} from "./tier-classifier.js";
export {
  SystemStateTracker,
  evaluateCrossSystemPolicies,
  DEFAULT_PHYSICAL_POLICIES,
} from "./cross-system.js";
export type {
  OpenClawToolCall,
  OpenClawMCPCall,
  OpenClawNodeAction,
  NosihTier,
  GovernanceResult,
  OpenClawAdapterConfig,
  CrossSystemPolicy,
} from "./types.js";
