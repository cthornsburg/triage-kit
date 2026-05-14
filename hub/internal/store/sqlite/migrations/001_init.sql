CREATE TABLE IF NOT EXISTS schema_migrations (
  name TEXT PRIMARY KEY,
  applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS case_imports (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  import_uuid TEXT NOT NULL UNIQUE,
  source_path TEXT NOT NULL,
  source_kind TEXT NOT NULL,
  batch_id TEXT,
  collector_name TEXT,
  collector_version TEXT,
  imported_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS cases (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  case_uuid TEXT NOT NULL UNIQUE,
  import_id INTEGER REFERENCES case_imports(id) ON DELETE SET NULL,
  case_id TEXT NOT NULL,
  batch_id TEXT,
  hostname TEXT,
  asset_label TEXT,
  collected_at TEXT,
  collector_version TEXT,
  status TEXT NOT NULL DEFAULT 'new',
  integrity_status TEXT NOT NULL DEFAULT 'pending',
  disposition TEXT,
  priority TEXT,
  escalated INTEGER NOT NULL DEFAULT 0,
  raw_case_path TEXT NOT NULL,
  normalized_case_path TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_cases_case_id ON cases(case_id);
CREATE INDEX IF NOT EXISTS idx_cases_hostname ON cases(hostname);
CREATE INDEX IF NOT EXISTS idx_cases_batch_id ON cases(batch_id);
CREATE INDEX IF NOT EXISTS idx_cases_status ON cases(status);

CREATE TABLE IF NOT EXISTS integrity_results (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  manifest_valid INTEGER NOT NULL DEFAULT 0,
  hashes_valid INTEGER NOT NULL DEFAULT 0,
  files_missing_count INTEGER NOT NULL DEFAULT 0,
  files_mismatched_count INTEGER NOT NULL DEFAULT 0,
  warnings_count INTEGER NOT NULL DEFAULT 0,
  errors_count INTEGER NOT NULL DEFAULT 0,
  summary_json TEXT,
  checked_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_integrity_results_case_id ON integrity_results(case_id);

CREATE TABLE IF NOT EXISTS host_contexts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  case_id INTEGER NOT NULL UNIQUE REFERENCES cases(id) ON DELETE CASCADE,
  hostname TEXT,
  username TEXT,
  domain TEXT,
  os_name TEXT,
  os_version TEXT,
  os_build TEXT,
  architecture TEXT,
  timezone TEXT,
  last_boot_time TEXT,
  uptime_seconds INTEGER,
  source_artifact_path TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS findings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  finding_key TEXT,
  category TEXT NOT NULL,
  title TEXT NOT NULL,
  severity TEXT,
  confidence TEXT,
  status TEXT NOT NULL DEFAULT 'open',
  evidence_path TEXT,
  evidence_ref TEXT,
  rationale TEXT,
  source TEXT NOT NULL DEFAULT 'analyst',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_findings_case_id ON findings(case_id);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);

CREATE TABLE IF NOT EXISTS analyst_notes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  note_type TEXT NOT NULL DEFAULT 'general',
  body TEXT NOT NULL,
  author TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_analyst_notes_case_id ON analyst_notes(case_id);

CREATE TABLE IF NOT EXISTS case_exports (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  export_format TEXT NOT NULL,
  export_path TEXT NOT NULL,
  export_status TEXT NOT NULL DEFAULT 'generated',
  generated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  metadata_json TEXT
);

CREATE INDEX IF NOT EXISTS idx_case_exports_case_id ON case_exports(case_id);
