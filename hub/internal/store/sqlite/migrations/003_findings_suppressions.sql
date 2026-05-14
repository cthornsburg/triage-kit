ALTER TABLE findings ADD COLUMN suppressed INTEGER NOT NULL DEFAULT 0;
ALTER TABLE findings ADD COLUMN suppression_reason TEXT;
