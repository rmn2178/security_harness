-- NOSIH Protocol — Evidence Ledger PostgreSQL Schema
-- CRITICAL: NO UPDATE or DELETE permissions on this table.
-- This is an append-only, immutable audit log.

CREATE TABLE IF NOT EXISTS nosih_evidence_ledger (
    -- Primary key: monotonic sequence number
    sequence_number BIGSERIAL PRIMARY KEY,

    -- Event identity
    event_id UUID NOT NULL UNIQUE,

    -- Timestamp with microsecond precision
    timestamp TIMESTAMPTZ(6) NOT NULL DEFAULT NOW(),

    -- Event classification
    event_type TEXT NOT NULL CHECK (event_type IN (
        'agent.registered',
        'agent.capability.granted',
        'agent.capability.revoked',
        'request.received',
        'policy.evaluated',
        'approval.requested',
        'approval.granted',
        'approval.denied',
        'approval.timeout',
        'action.started',
        'action.completed',
        'action.failed',
        'action.rolledback',
        'safety.estop.triggered',
        'safety.geofence.violation',
        'safety.force.exceeded',
        'safety.human.detected',
        'safety.anomaly.detected',
        'capsule.purchased',
        'task.bid.placed',
        'payment.settled'
    )),

    -- Agent identity (Ed25519 public key, hex-encoded)
    agent_id TEXT NOT NULL CHECK (LENGTH(agent_id) = 64),

    -- Capability token used (if applicable)
    token_id UUID,

    -- Event payload (JSONB for queryability)
    payload JSONB NOT NULL DEFAULT '{}',

    -- Hash chain integrity
    previous_hash TEXT NOT NULL CHECK (LENGTH(previous_hash) = 64),
    hash TEXT NOT NULL UNIQUE CHECK (LENGTH(hash) = 64),

    -- Constraints
    CONSTRAINT positive_sequence CHECK (sequence_number > 0)
);

-- Indexes for common query patterns
CREATE INDEX IF NOT EXISTS idx_ledger_agent_id ON nosih_evidence_ledger(agent_id);
CREATE INDEX IF NOT EXISTS idx_ledger_event_type ON nosih_evidence_ledger(event_type);
CREATE INDEX IF NOT EXISTS idx_ledger_timestamp ON nosih_evidence_ledger(timestamp);
CREATE INDEX IF NOT EXISTS idx_ledger_token_id ON nosih_evidence_ledger(token_id);
CREATE INDEX IF NOT EXISTS idx_ledger_hash ON nosih_evidence_ledger(hash);

-- GIN index for JSONB payload queries
CREATE INDEX IF NOT EXISTS idx_ledger_payload ON nosih_evidence_ledger USING GIN (payload);

-- CRITICAL: Create a restricted role with INSERT-only permissions.
-- This role MUST be used by the application. No UPDATE or DELETE.
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'nosih_ledger_writer') THEN
        CREATE ROLE nosih_ledger_writer;
    END IF;
END
$$;

GRANT INSERT, SELECT ON nosih_evidence_ledger TO nosih_ledger_writer;
GRANT USAGE, SELECT ON SEQUENCE nosih_evidence_ledger_sequence_number_seq TO nosih_ledger_writer;

-- Explicitly REVOKE UPDATE and DELETE to enforce immutability
REVOKE UPDATE, DELETE ON nosih_evidence_ledger FROM nosih_ledger_writer;

COMMENT ON TABLE nosih_evidence_ledger IS
    'NOSIH Protocol Evidence Ledger — append-only, immutable audit log. '
    'NO UPDATE or DELETE operations permitted. Hash-chained for tamper detection.';
