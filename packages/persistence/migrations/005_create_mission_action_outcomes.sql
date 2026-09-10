-- Append-only terminal outcomes for claimed Mission Authority actions.

CREATE TABLE IF NOT EXISTS nosih_mission_action_outcomes (
  action_ref  TEXT PRIMARY KEY
    REFERENCES nosih_mission_action_claims (action_ref),
  manifest_id TEXT NOT NULL
    REFERENCES nosih_mission_manifests (manifest_id),
  outcome     TEXT NOT NULL,
  completed_at TEXT NOT NULL,
  report      JSONB NOT NULL
);
