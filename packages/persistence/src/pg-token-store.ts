/**
 * NOSIH Persistence — PostgreSQL Token Store.
 *
 * @module @nosih/persistence/pg-token-store
 */

import type pg from "pg";
import type { NosihCapabilityToken, UUIDv7 } from "@pshkv/core";
import type { TokenStore } from "./interfaces.js";

function cleanField<T>(val: T | null | undefined): T | undefined {
  return val === null ? undefined : val;
}

/** Map a database row to a NosihCapabilityToken. */
function rowToToken(row: any): NosihCapabilityToken {
  return {
    tokenId: row.token_id,
    issuer: row.issuer,
    subject: row.subject,
    resource: row.resource,
    actions: typeof row.actions === "string" ? JSON.parse(row.actions) : row.actions,
    constraints: typeof row.constraints === "string" ? JSON.parse(row.constraints) : row.constraints,
    modelConstraints: cleanField(typeof row.model_constraints === "string" ? JSON.parse(row.model_constraints) : row.model_constraints),
    attestationRequirements: cleanField(typeof row.attestation_requirements === "string" ? JSON.parse(row.attestation_requirements) : row.attestation_requirements),
    verifiableComputeRequirements: cleanField(typeof row.verifiable_compute_requirements === "string" ? JSON.parse(row.verifiable_compute_requirements) : row.verifiable_compute_requirements),
    executionEnvelope: cleanField(typeof row.execution_envelope === "string" ? JSON.parse(row.execution_envelope) : row.execution_envelope),
    behavioralConstraints: cleanField(typeof row.behavioral_constraints === "string" ? JSON.parse(row.behavioral_constraints) : row.behavioral_constraints),
    passportId: cleanField(row.passport_id),
    delegationDepth: cleanField(row.delegation_depth),
    delegationChain: typeof row.delegation_chain === "string" ? JSON.parse(row.delegation_chain) : row.delegation_chain,
    issuedAt: row.issued_at,
    expiresAt: row.expires_at,
    revocable: row.revocable,
    revocationEndpoint: cleanField(row.revocation_endpoint),
    cryptoProfile: cleanField(row.crypto_profile),
    postQuantumSignatures: cleanField(typeof row.post_quantum_signatures === "string" ? JSON.parse(row.post_quantum_signatures) : row.post_quantum_signatures),
    signature: row.signature,
  };
}

export class PgTokenStore implements TokenStore {
  constructor(private readonly pool: pg.Pool) {}

  async store(token: NosihCapabilityToken): Promise<void> {
    await this.pool.query(
      `INSERT INTO nosih_tokens
        (token_id, issuer, subject, resource, actions, constraints,
         model_constraints, attestation_requirements, verifiable_compute_requirements,
         execution_envelope, behavioral_constraints, passport_id, delegation_depth,
         delegation_chain, issued_at, expires_at, revocable, revocation_endpoint,
         crypto_profile, post_quantum_signatures, signature)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21)
       ON CONFLICT (token_id) DO UPDATE SET
         issuer = EXCLUDED.issuer,
         subject = EXCLUDED.subject,
         resource = EXCLUDED.resource,
         actions = EXCLUDED.actions,
         constraints = EXCLUDED.constraints,
         model_constraints = EXCLUDED.model_constraints,
         attestation_requirements = EXCLUDED.attestation_requirements,
         verifiable_compute_requirements = EXCLUDED.verifiable_compute_requirements,
         execution_envelope = EXCLUDED.execution_envelope,
         behavioral_constraints = EXCLUDED.behavioral_constraints,
         passport_id = EXCLUDED.passport_id,
         delegation_depth = EXCLUDED.delegation_depth,
         delegation_chain = EXCLUDED.delegation_chain,
         issued_at = EXCLUDED.issued_at,
         expires_at = EXCLUDED.expires_at,
         revocable = EXCLUDED.revocable,
         revocation_endpoint = EXCLUDED.revocation_endpoint,
         crypto_profile = EXCLUDED.crypto_profile,
         post_quantum_signatures = EXCLUDED.post_quantum_signatures,
         signature = EXCLUDED.signature`,
      [
        token.tokenId,
        token.issuer,
        token.subject,
        token.resource,
        JSON.stringify(token.actions),
        JSON.stringify(token.constraints),
        JSON.stringify(token.modelConstraints),
        JSON.stringify(token.attestationRequirements),
        JSON.stringify(token.verifiableComputeRequirements),
        JSON.stringify(token.executionEnvelope),
        JSON.stringify(token.behavioralConstraints),
        token.passportId,
        token.delegationDepth,
        JSON.stringify(token.delegationChain),
        token.issuedAt,
        token.expiresAt,
        token.revocable,
        token.revocationEndpoint,
        token.cryptoProfile,
        JSON.stringify(token.postQuantumSignatures),
        token.signature,
      ],
    );
  }

  async get(tokenId: UUIDv7): Promise<NosihCapabilityToken | undefined> {
    const result = await this.pool.query(
      "SELECT * FROM nosih_tokens WHERE token_id = $1",
      [tokenId],
    );
    return result.rows.length > 0 ? rowToToken(result.rows[0]) : undefined;
  }

  async getBySubject(subject: string): Promise<readonly NosihCapabilityToken[]> {
    const result = await this.pool.query(
      "SELECT * FROM nosih_tokens WHERE subject = $1",
      [subject],
    );
    return result.rows.map(rowToToken);
  }

  async remove(tokenId: UUIDv7): Promise<boolean> {
    const result = await this.pool.query(
      "DELETE FROM nosih_tokens WHERE token_id = $1",
      [tokenId],
    );
    return (result.rowCount ?? 0) > 0;
  }

  async count(): Promise<number> {
    const result = await this.pool.query(
      "SELECT COUNT(*) AS cnt FROM nosih_tokens",
    );
    return parseInt(result.rows[0].cnt, 10);
  }
}
