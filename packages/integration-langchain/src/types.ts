/**
 * Type definitions for NOSIH LangChain integration.
 */

/** Configuration for the NOSIH governance handler. */
export interface NosihGovernanceConfig {
  /** URL of the NOSIH Protocol gateway server (e.g., "http://localhost:4100"). */
  gatewayUrl: string;

  /** Agent identifier (Ed25519 public key hex or friendly name). */
  agentId: string;

  /** Capability token (signed JWT-like token from the gateway). */
  token?: string;

  /** API key for admin-level operations (optional). */
  apiKey?: string;

  /** Whether to throw on denied actions. Default: true. */
  throwOnDeny?: boolean;

  /** Whether to log evidence to the ledger. Default: true. */
  logEvidence?: boolean;

  /** Custom resource mapper: maps tool name → NOSIH resource identifier. */
  resourceMapper?: (toolName: string) => string;

  /** Custom action mapper: maps tool name → NOSIH action identifier. */
  actionMapper?: (toolName: string) => string;

  /** Timeout for gateway requests in milliseconds. Default: 5000. */
  timeoutMs?: number;
}

/** Result of a NOSIH intercept call. */
export interface NosihInterceptResult {
  /** Whether the action was approved. */
  approved: boolean;

  /** Outcome: "approve", "deny", or "escalate". */
  outcome: "approve" | "deny" | "escalate";

  /** Reason for denial or escalation (if applicable). */
  reason?: string;

  /** Risk tier assigned to this action. */
  tier?: number;

  /** Evidence ledger entry ID (if logged). */
  evidenceId?: string;

  /** Full response from the gateway. */
  raw?: Record<string, unknown>;
}

/** Context passed to the tool call interceptor. */
export interface NosihToolCallContext {
  /** LangChain tool name. */
  toolName: string;

  /** Tool input (serialized). */
  toolInput: string;

  /** Run ID from LangChain. */
  runId: string;

  /** Parent run ID (if nested). */
  parentRunId?: string;

  /** Mapped NOSIH resource. */
  resource: string;

  /** Mapped NOSIH action. */
  action: string;
}
