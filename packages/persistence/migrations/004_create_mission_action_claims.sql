-- Atomic, append-only reservations for Mission Authority execution.

CREATE TABLE IF NOT EXISTS nosih_mission_action_claims (
  action_ref  TEXT PRIMARY KEY,
  manifest_id TEXT NOT NULL
    REFERENCES nosih_mission_manifests (manifest_id),
  effect_id   TEXT,
  claimed_at  TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_nosih_mission_action_claims_effect
  ON nosih_mission_action_claims (manifest_id, effect_id)
  WHERE effect_id IS NOT NULL;
