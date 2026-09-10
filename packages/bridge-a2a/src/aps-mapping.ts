/**
 * NOSIH ↔ APS Interoperability Mapping.
 *
 * Defines the formal mapping between:
 *   - APS (Agent Passport System) DelegationScope — digital governance layer
 *   - NOSIH NosihPhysicalConstraints — physical governance layer
 *
 * These two protocols arrived at identical cryptographic primitives
 * (Ed25519, did:key, monotonic attenuation) independently. This module
 * is the "narrow waist" that connects them at the constraint layer.
 *
 * Key invariant: attenuation composes across protocols.
 *   scope(NOSIH_child) ⊆ scope(NOSIH_parent)
 *   scope(APS_child) ⊆ scope(APS_parent)
 *   scope(NOSIH_child) ⊆ scope(APS_digital_projection(APS_delegation))
 *
 * Ref: https://github.com/a2aproject/A2A/issues/1713#issuecomment-4186524108
 *      NOSIH ↔ APS cross-verification: packages/capability-tokens/__tests__/aps-crossverify.test.ts
 *
 * @module @nosih/bridge-a2a/aps-mapping
 */

import type {
  ISO8601,
  NosihCapabilityToken,
  NosihPhysicalConstraints,
} from "@pshkv/core";

// ─── APS Delegation Scope types ───────────────────────────────────────────────

/**
 * APS (Agent Passport System) DelegationScope.
 * Represents the digital governance layer of an APS delegation chain.
 *
 * Source: APS v1.32.0 specification (draft-pidlisnyi-aps-00, IETF Internet-Draft)
 * These fields are the APS analog to NOSIH's NosihPhysicalConstraints.
 */
export interface ApsDelegationScope {
  /**
   * Digital resource scope — what the agent is allowed to access/invoke.
   * E.g. ["logistics:dispatch", "inventory:read"]
   * Maps to NOSIH resource URI patterns.
   */
  readonly resourceScope: readonly string[];

  /**
   * Digital action verbs permitted.
   * E.g. ["read", "write"] — maps to NOSIH token.actions.
   */
  readonly allowedActions?: readonly string[];

  /**
   * Temporal validity window for the delegation.
   * Maps to NOSIH token.expiresAt (uses the `end` timestamp).
   */
  readonly temporalValidity?: {
    readonly start: ISO8601;
    readonly end: ISO8601;
  };

  /**
   * Spend limit in the domain's currency unit.
   * Maps to NOSIH rateLimit.maxCalls as a proxy for operation budget.
   * (Physical cost per action must be estimated by the deployment.)
   */
  readonly spendLimit?: number;

  /**
   * Data access terms — sensitivity classifications this delegation permits.
   * E.g. ["PII:none", "confidential:no"] — these become physical context
   * escalation factors in NOSIH (Δ_trust or Δ_novelty).
   */
  readonly dataAccessTerms?: readonly string[];

  /**
   * Attestation grade (0-3) from APS.
   * 0=self-attested, 1=peer-vouched, 2=infrastructure-attested, 3=legal-entity-attested
   * Maps to NOSIH tier escalation: grade < 2 → Δ_trust = +1
   */
  readonly attestationGrade?: 0 | 1 | 2 | 3;
}

/**
 * Result of mapping an APS delegation to a NOSIH constraint envelope.
 */
export interface ApsMappingResult {
  /**
   * The NOSIH resource URI pattern derived from APS resourceScope.
   * Uses the A2A URI scheme if the scope suggests agent-to-agent delegation.
   */
  readonly resource: string;

  /**
   * NOSIH token actions derived from APS allowedActions.
   */
  readonly actions: readonly string[];

  /**
   * Physical constraints derived from APS scope.
   * Physical-world limits (velocity, force, geofence) are NOT derivable from
   * APS — they must be set by the physical deployment operator.
   * This function returns what CAN be derived from APS fields.
   */
  readonly constraints: NosihPhysicalConstraints;

  /**
   * Recommended tier escalation based on APS attestation grade.
   * Low-grade attestations get +1 tier (higher scrutiny).
   */
  readonly tierEscalation: 0 | 1;

  /**
   * Warning messages about fields that require operator input.
   * Physical constraints (maxVelocityMps, geofence) cannot be inferred
   * from APS scope and MUST be set manually.
   */
  readonly warnings: readonly string[];
}

// ─── APS resource scope → NOSIH URI ────────────────────────────────────────────

/**
 * Map APS resource scope tokens to a NOSIH resource URI.
 *
 * APS uses domain-scoped identifiers like "logistics:dispatch".
 * NOSIH uses URI schemes like "a2a://warehouse.example.com/dispatch".
 *
 * This mapping is convention-based. Production deployments should
 * configure an explicit scope registry.
 */
function apsScopeToNosihResource(resourceScope: readonly string[]): string {
  if (resourceScope.length === 0) return "a2a://*";

  // If all scopes share a domain prefix, use it
  const domains = new Set(resourceScope.map((s) => s.split(":")[0]!));
  const paths = resourceScope.map((s) => s.split(":").slice(1).join("/")).filter(Boolean);

  if (domains.size === 1) {
    const domain = [...domains][0]!;
    if (paths.length === 1) {
      return `a2a://${domain}/${paths[0]!}`;
    }
    return `a2a://${domain}/*`;
  }

  // Multiple domains → wildcard
  return "a2a://*";
}

/**
 * Map APS allowedActions to NOSIH token actions.
 * APS uses REST-style verbs; NOSIH uses protocol-specific verbs.
 */
function apsActionsToNosihActions(apsActions?: readonly string[]): string[] {
  if (!apsActions || apsActions.length === 0) {
    return ["a2a.send"]; // default: basic task delegation
  }

  const mapping: Record<string, string> = {
    read: "a2a.get",
    write: "a2a.send",
    execute: "a2a.send",
    stream: "a2a.stream",
    cancel: "a2a.cancel",
    dispatch: "a2a.send",
  };

  const mapped = apsActions.map((a) => mapping[a.toLowerCase()] ?? `a2a.${a.toLowerCase()}`);
  return [...new Set(mapped)]; // deduplicate
}

// ─── Main mapping function ────────────────────────────────────────────────────

/**
 * Map an APS DelegationScope to NOSIH token fields.
 *
 * This is the formal mapping layer between the two protocols' constraint
 * dimensions. Digital constraints (spend limit, temporal validity) are
 * translated to their NOSIH analogs. Physical constraints (velocity, force,
 * geofence) CANNOT be derived from APS and must be set by the operator.
 *
 * @example
 * ```ts
 * // A delivery robot from Org B enters a warehouse governed by Org A
 * const apsScope = {
 *   resourceScope: ["logistics:dispatch", "inventory:read"],
 *   allowedActions: ["execute", "read"],
 *   spendLimit: 500,
 *   attestationGrade: 2,
 * };
 *
 * const { resource, actions, constraints, tierEscalation, warnings } =
 *   apsScopeToNosihMapping(apsScope);
 *
 * // Operator must ALSO set:
 * //   constraints.maxVelocityMps = 0.5  (human-shared workspace)
 * //   constraints.geofence = warehousePolygon
 * ```
 */
export function apsScopeToNosihMapping(scope: ApsDelegationScope): ApsMappingResult {
  const warnings: string[] = [];

  // Resource URI
  const resource = apsScopeToNosihResource(scope.resourceScope);

  // Actions
  const actions = apsActionsToNosihActions(scope.allowedActions);

  // Constraints — only what can be derived from APS fields
  const constraintsMutable: Record<string, unknown> = {};

  // spendLimit → rateLimit proxy
  if (scope.spendLimit !== undefined) {
    // Conservative default: 1 operation per $10 of spend limit
    // Operators should calibrate this to their actual cost model
    const estimatedMaxCalls = Math.max(1, Math.floor(scope.spendLimit / 10));
    constraintsMutable["rateLimit"] = {
      maxCalls: estimatedMaxCalls,
      windowMs: 3_600_000, // 1 hour window
    };
    warnings.push(
      `spendLimit=${scope.spendLimit} mapped to rateLimit.maxCalls=${estimatedMaxCalls} (1h window). ` +
      `Calibrate to actual cost-per-operation for your deployment.`
    );
  }

  // temporalValidity → timeWindow
  if (scope.temporalValidity) {
    constraintsMutable["timeWindow"] = {
      start: scope.temporalValidity.start,
      end: scope.temporalValidity.end,
    };
  }

  const constraints = constraintsMutable as NosihPhysicalConstraints;

  // Physical constraints — cannot be derived from APS
  warnings.push(
    "Physical constraints (maxVelocityMps, maxForceNewtons, geofence) cannot be derived from " +
    "APS DelegationScope. Set these manually based on your physical deployment context."
  );

  // Tier escalation based on APS attestation grade
  // Grade < 2 (not infrastructure-attested) → require higher scrutiny
  const tierEscalation: 0 | 1 =
    scope.attestationGrade === undefined || scope.attestationGrade < 2 ? 1 : 0;

  if (tierEscalation === 1) {
    warnings.push(
      `APS attestation grade ${scope.attestationGrade ?? "unknown"} < 2 → ` +
      `applying Δ_trust = +1 (tier escalation). Upgrade to infrastructure-attested (grade 2) ` +
      `to operate at base tier.`
    );
  }

  return { resource, actions, constraints, tierEscalation, warnings };
}

// ─── NOSIH token → APS attestation projection ─────────────────────────────────

/**
 * Project a NOSIH capability token into an APS-compatible attestation object.
 *
 * Used when a NOSIH-governed agent enters an APS-governed workflow.
 * The physical constraint fields (maxVelocityMps, geofence) are included
 * in dataAccessTerms as metadata — APS cannot enforce them, but the
 * receiving APS gateway can log and audit them.
 *
 * @example
 * ```ts
 * // Robot has NOSIH token, needs to interact with APS warehouse system
 * const apsProjection = nosihTokenToApsProjection(robotToken);
 * // apsProjection can be passed to APS importExternalAttestation()
 * ```
 */
export function nosihTokenToApsProjection(token: NosihCapabilityToken): {
  did: string;
  resourceScope: string[];
  allowedActions: string[];
  temporalValidity: { start: string; end: string };
  dataAccessTerms: string[];
  attestationGrade: 2; // NOSIH tokens are infrastructure-attested
  nosihPhysicalConstraints: NosihPhysicalConstraints; // APS preserves but doesn't enforce
} {
  // Convert did:key format (NOSIH stores subject as hex public key — derive DID)
  // Note: in practice, call keyToDid(token.subject) — imported separately to avoid circular dep
  const did = `nosih:subject:${token.subject}`; // placeholder; caller should use keyToDid()

  // Resource scope: NOSIH URI → APS domain:path format
  const resourceScope = [token.resource];

  // Actions: NOSIH verbs → APS verbs (reverse mapping)
  const actionReverseMap: Record<string, string> = {
    "a2a.send": "execute",
    "a2a.get": "read",
    "a2a.stream": "stream",
    "a2a.cancel": "cancel",
    call: "execute",
    publish: "write",
    subscribe: "read",
  };
  const allowedActions = token.actions.map(
    (a) => actionReverseMap[a] ?? a
  );

  // Physical constraints as APS data access terms (metadata only)
  const dataAccessTerms: string[] = [];
  if (token.constraints.maxVelocityMps !== undefined) {
    dataAccessTerms.push(`nosih:maxVelocityMps:${token.constraints.maxVelocityMps}`);
  }
  if (token.constraints.maxForceNewtons !== undefined) {
    dataAccessTerms.push(`nosih:maxForceNewtons:${token.constraints.maxForceNewtons}`);
  }
  if (token.constraints.geofence !== undefined) {
    dataAccessTerms.push("nosih:geofence:present");
  }
  if (token.constraints.requiresHumanPresence) {
    dataAccessTerms.push("nosih:requiresHumanPresence:true");
  }

  return {
    did,
    resourceScope,
    allowedActions,
    temporalValidity: {
      start: token.issuedAt,
      end: token.expiresAt,
    },
    dataAccessTerms,
    attestationGrade: 2, // NOSIH tokens are Ed25519-signed by infrastructure
    nosihPhysicalConstraints: token.constraints,
  };
}
