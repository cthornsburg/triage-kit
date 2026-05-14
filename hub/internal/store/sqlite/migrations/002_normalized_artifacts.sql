CREATE TABLE IF NOT EXISTS normalized_artifact_sets (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  artifact_key TEXT NOT NULL,
  source_path TEXT NOT NULL,
  output_path TEXT NOT NULL,
  record_count INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'ok',
  loaded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(case_id, artifact_key)
);

CREATE INDEX IF NOT EXISTS idx_normalized_artifact_sets_case_id ON normalized_artifact_sets(case_id);

CREATE TABLE IF NOT EXISTS normalized_records (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  artifact_key TEXT NOT NULL,
  record_index INTEGER NOT NULL,
  primary_label TEXT,
  secondary_label TEXT,
  raw_json TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(case_id, artifact_key, record_index)
);

CREATE INDEX IF NOT EXISTS idx_normalized_records_case_artifact ON normalized_records(case_id, artifact_key);
