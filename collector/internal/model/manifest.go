package model

import "time"

const SchemaVersion = "0.1.0"

// CollectorBundleManifest mirrors the shared collector bundle manifest schema.
type CollectorBundleManifest struct {
	SchemaVersion string           `json:"schema_version"`
	BundleID      string           `json:"bundle_id"`
	BatchID       string           `json:"batch_id"`
	CaseID        string           `json:"case_id"`
	CollectedAt   time.Time        `json:"collected_at"`
	Collector     CollectorInfo    `json:"collector"`
	Operator      OperatorInfo     `json:"operator"`
	TargetHost    TargetHostInfo   `json:"target_host"`
	Profile       ProfileInfo      `json:"profile"`
	Artifacts     []ArtifactRecord `json:"artifacts"`
	Summary       ManifestSummary  `json:"summary"`
}

type CollectorInfo struct {
	Name      string  `json:"name"`
	Version   string  `json:"version"`
	Mode      string  `json:"mode"`
	USBSerial *string `json:"usb_serial"`
}

type OperatorInfo struct {
	OperatorID string  `json:"operator_id"`
	Notes      *string `json:"notes"`
}

type TargetHostInfo struct {
	Hostname     string     `json:"hostname"`
	Username     string     `json:"username"`
	Domain       *string    `json:"domain"`
	OSFamily     string     `json:"os_family"`
	OSVersion    *string    `json:"os_version"`
	Architecture *string    `json:"architecture"`
	Timezone     *string    `json:"timezone"`
	BootTime     *time.Time `json:"boot_time"`
}

type ProfileInfo struct {
	Name                  string  `json:"name"`
	ArtifactPolicyVersion *string `json:"artifact_policy_version"`
}

type ArtifactRecord struct {
	ArtifactID      string   `json:"artifact_id"`
	Category        string   `json:"category"`
	RelativePath    string   `json:"relative_path"`
	Format          string   `json:"format"`
	SHA256          string   `json:"sha256"`
	SizeBytes       int64    `json:"size_bytes"`
	SourceCommand   string   `json:"source_command"`
	CollectionScope string   `json:"collection_scope"`
	CollectedAt     string   `json:"collected_at"`
	CollectorStatus string   `json:"collector_status"`
	Error           *string  `json:"error"`
	Notes           []string `json:"notes"`
	Tags            []string `json:"tags"`
}

type ManifestSummary struct {
	ArtifactCount int    `json:"artifact_count"`
	Errors        int    `json:"errors"`
	Warnings      int    `json:"warnings"`
	Status        string `json:"status,omitempty"`
}
