package model

import "time"

// BatchManifest mirrors the shared batch manifest schema.
type BatchManifest struct {
	SchemaVersion    string           `json:"schema_version"`
	BatchID          string           `json:"batch_id"`
	CreatedAt        time.Time        `json:"created_at"`
	ClosedAt         *time.Time       `json:"closed_at"`
	CollectorVersion string           `json:"collector_version"`
	MediaLabel       string           `json:"media_label"`
	OperatorID       *string          `json:"operator_id"`
	Notes            *string          `json:"notes"`
	Cases            []BatchCaseEntry `json:"cases"`
}

type BatchCaseEntry struct {
	BundleID     string    `json:"bundle_id"`
	Hostname     string    `json:"hostname"`
	RelativePath string    `json:"relative_path"`
	CollectedAt  time.Time `json:"collected_at"`
	Status       string    `json:"status"`
}
