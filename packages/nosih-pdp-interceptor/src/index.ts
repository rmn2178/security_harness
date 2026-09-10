/**
 * @nosih/nosih-pdp-interceptor — reference PDP adapter for SEP-1763 style MCP interceptors.
 *
 * Presents a small `evaluate()` interface that maps MCP host requests into
 * `PolicyGateway.intercept()` calls.
 */

export { NOSIHPDPInterceptor } from "./interceptor.js";
export type {
  GatePrerequisiteResult,
  GuardedExecutionOptions,
  GuardedExecutionResult,
  PDPDecision,
  PDPInterceptorCall,
  PDPInterceptorContext,
  PDPInterceptorRequest,
  NOSIHGatewayLike,
  NOSIHPDPInterceptorConfig,
} from "./types.js";
