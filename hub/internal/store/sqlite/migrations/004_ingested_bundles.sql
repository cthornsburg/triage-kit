CREATE TABLE IF NOT EXISTS ingested_bundles (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  batch_id TEXT NOT NULL,
  bundle_id TEXT NOT NULL,
  case_uuid TEXT,
  first_seen_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(batch_id, bundle_id)
);

CREATE INDEX IF NOT EXISTS idx_ingested_bundles_case_uuid ON ingested_bundles(case_uuid);
