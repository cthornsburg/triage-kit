package app

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/chip/incident-response-kit/collector/internal/casebundle"
	"github.com/chip/incident-response-kit/collector/internal/checksum"
	"github.com/chip/incident-response-kit/collector/internal/collect"
	"github.com/chip/incident-response-kit/collector/internal/model"
	"github.com/chip/incident-response-kit/collector/internal/writejson"
)

const version = "1.0"

type Config struct {
	OutputDir  string
	BatchID    string
	Hostname   string
	OperatorID string
	MediaLabel string
	Notes      string
	Now        time.Time
}

func Run(cfg Config) error {
	if cfg.OutputDir == "" {
		return fmt.Errorf("output directory is required")
	}
	if cfg.Hostname == "" || cfg.OperatorID == "" {
		return fmt.Errorf("hostname and operator-id are required")
	}

	now := cfg.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}

	cfg.BatchID = collectionBatchID(cfg.BatchID, now)
	resolvedHostname := resolveHostLabel(cfg.Hostname)
	printBanner(cfg, resolvedHostname)
	layout, err := casebundle.Create(cfg.OutputDir, cfg.BatchID, resolvedHostname, now)
	if err != nil {
		return err
	}

	bundleID := stableBundleID(resolvedHostname, now)

	fmt.Fprintln(os.Stdout, "[SEKER] Preparing output folders...")
	artifacts, warnings, errors := collectArtifacts(context.Background(), layout.CaseDir, now, nil)
	manifest := buildCollectorManifest(cfg, now, resolvedHostname, bundleID, artifacts, warnings, errors)
	if err := writejson.File(filepath.Join(layout.CaseDir, "manifest.json"), manifest); err != nil {
		return err
	}

	batch := buildBatchManifest(filepath.Join(layout.BatchDir, "batch-manifest.json"), cfg, now, layout.RelativeCase, manifest)
	if err := writejson.File(filepath.Join(layout.BatchDir, "batch-manifest.json"), batch); err != nil {
		return err
	}

	if err := writeHashesFile(layout.CaseDir, artifacts); err != nil {
		return err
	}

	fmt.Fprintln(os.Stdout, "[SEKER] Finalizing manifest and hashes...")
	fmt.Fprintf(os.Stdout, "[SEKER] Collection complete. Bundle created at %s\n", layout.CaseDir)
	return nil
}

type collectorPhase struct {
	Phase     int
	Name      string
	Collector collect.Collector
}

func collectionPlan() []collectorPhase {
	return []collectorPhase{
		{Phase: 1, Name: "Identifying Host", Collector: collect.HostCollector{}},
		{Phase: 2, Name: "Collecting Process IDs", Collector: collect.ProcessCollector{}},
		{Phase: 3, Name: "Collecting Network Data", Collector: collect.NetworkCollector{}},
		{Phase: 4, Name: "Collecting Log Data", Collector: collect.LogsCollector{}},
		{Phase: 5, Name: "Identifying Processes", Collector: collect.ProcessDetailCollector{}},
		{Phase: 6, Name: "Persistence Checks", Collector: collect.PersistenceCollector{}},
		{Phase: 7, Name: "Security Status", Collector: collect.SecurityCollector{}},
		{Phase: 8, Name: "Software Inventory", Collector: collect.SoftwareCollector{}},
		{Phase: 9, Name: "Verifying Removable Media", Collector: collect.DeviceCollector{}},
	}
}

func collectArtifacts(ctx context.Context, caseDir string, now time.Time, initialWarnings []string) ([]model.ArtifactRecord, []string, []string) {
	collectors := collectionPlan()

	artifacts := make([]model.ArtifactRecord, 0, len(collectors)+2)
	warnings := append([]string{}, initialWarnings...)
	errors := make([]string, 0)
	phaseEvents := make([]string, 0, len(collectors)+1)

	for i, phase := range collectors {
		collectedAt := now.Add(time.Duration(i) * time.Second)
		phaseEvent := fmt.Sprintf("%d. %s", phase.Phase, phase.Name)
		phaseEvents = append(phaseEvents, phaseEvent)
		fmt.Fprintf(os.Stdout, "[SEKER] %s...\n", phaseEvent)
		records, _ := phase.Collector.Collect(ctx, caseDir, collectedAt)
		artifacts = append(artifacts, records...)
		errorNotes := make([]string, 0)
		warningNotes := make([]string, 0)
		for _, record := range records {
			switch record.CollectorStatus {
			case "partial":
				for _, note := range record.Notes {
					if strings.TrimSpace(note) != "" {
						warningNotes = append(warningNotes, note)
					}
				}
			case "error":
				if record.Error != nil && strings.TrimSpace(*record.Error) != "" {
					errorNotes = append(errorNotes, fmt.Sprintf("%s: %s", record.ArtifactID, strings.TrimSpace(*record.Error)))
				}
			}
		}
		warnings = append(warnings, warningNotes...)
		errors = append(errors, errorNotes...)
	}

	finalPhaseEvent := "Finalizing metadata, manifest, and hashes"
	phaseEvents = append(phaseEvents, finalPhaseEvent)
	collectorLogArtifact, collectorErrorsArtifact, metaWarnings, metaErrors := writeMetaArtifacts(caseDir, now.Add(time.Duration(len(collectors))*time.Second), warnings, errors, phaseEvents)
	artifacts = append(artifacts, collectorLogArtifact, collectorErrorsArtifact)
	warnings = append(warnings, metaWarnings...)
	errors = append(errors, metaErrors...)
	return artifacts, unique(warnings), unique(errors)
}

func buildCollectorManifest(cfg Config, now time.Time, resolvedHostname string, bundleID string, artifacts []model.ArtifactRecord, warnings []string, errors []string) model.CollectorBundleManifest {
	usbSerial := strings.TrimSpace(cfg.MediaLabel)
	if usbSerial == "" {
		usbSerial = "UNSPECIFIED"
	}
	notes := stringPtr(cfg.Notes)
	sysInfo := collect.CollectSystemInfo(context.Background())
	osVersion := runtime.Version()
	arch := runtime.GOARCH
	if sysInfo.OSVersion != "" {
		osVersion = sysInfo.OSVersion
	}
	if sysInfo.Architecture != "" {
		arch = sysInfo.Architecture
	}
	tz := now.Location().String()
	hostSnapshot, hostMetadataWarnings := collect.HostIdentitySnapshot(context.Background(), now)
	username := hostSnapshot.Username
	var domain *string
	if strings.TrimSpace(hostSnapshot.Domain) != "" {
		domain = stringPtr(hostSnapshot.Domain)
	}
	var bootTime *time.Time
	if strings.TrimSpace(hostSnapshot.BootTime) != "" {
		if parsedBootTime, err := time.Parse(time.RFC3339, hostSnapshot.BootTime); err == nil {
			bootTime = &parsedBootTime
		} else {
			hostMetadataWarnings = append(hostMetadataWarnings, "target_host.boot_time: failed to parse host identity boot_time")
		}
	}
	warnings = append(warnings, hostMetadataWarnings...)
	artifactPolicyVersion := "draft-skeleton"
	status := "ok"
	if len(errors) > 0 || len(warnings) > 0 {
		status = "partial"
	}

	return model.CollectorBundleManifest{
		SchemaVersion: model.SchemaVersion,
		BundleID:      bundleID,
		BatchID:       cfg.BatchID,
		CollectedAt:   now,
		Collector: model.CollectorInfo{
			Name:      "SEKER",
			Version:   version,
			Mode:      collectorMode(),
			USBSerial: &usbSerial,
		},
		Operator: model.OperatorInfo{
			OperatorID: cfg.OperatorID,
			Notes:      notes,
		},
		TargetHost: model.TargetHostInfo{
			Hostname:     resolvedHostname,
			Username:     username,
			Domain:       domain,
			OSFamily:     normalizeOS(runtime.GOOS),
			OSVersion:    &osVersion,
			Architecture: &arch,
			Timezone:     &tz,
			BootTime:     bootTime,
		},
		Profile: model.ProfileInfo{
			Name:                  profileName(),
			ArtifactPolicyVersion: &artifactPolicyVersion,
		},
		Artifacts: artifacts,
		Summary: model.ManifestSummary{
			ArtifactCount: len(artifacts),
			Errors:        len(errors),
			Warnings:      len(warnings),
			Status:        status,
		},
	}
}

func buildBatchManifest(batchManifestPath string, cfg Config, now time.Time, relativeCase string, manifest model.CollectorBundleManifest) model.BatchManifest {
	operatorID := cfg.OperatorID
	notes := stringPtr(cfg.Notes)
	batch := model.BatchManifest{
		SchemaVersion:    model.SchemaVersion,
		BatchID:          cfg.BatchID,
		CreatedAt:        now,
		CollectorVersion: version,
		MediaLabel:       cfg.MediaLabel,
		OperatorID:       &operatorID,
		Notes:            notes,
		Cases:            []model.BatchCaseEntry{},
	}
	if existing, err := loadBatchManifest(batchManifestPath); err == nil {
		batch = existing
		batch.SchemaVersion = model.SchemaVersion
		batch.BatchID = cfg.BatchID
		batch.CollectorVersion = version
		batch.MediaLabel = cfg.MediaLabel
		batch.OperatorID = &operatorID
		batch.Notes = notes
	}
	entry := model.BatchCaseEntry{
		BundleID:     manifest.BundleID,
		Hostname:     manifest.TargetHost.Hostname,
		RelativePath: relativeCase,
		CollectedAt:  manifest.CollectedAt,
		Status:       manifest.Summary.Status,
	}
	batch.Cases = upsertBatchCase(batch.Cases, entry)
	return batch
}

func stableBundleID(hostname string, collectedAt time.Time) string {
	return fmt.Sprintf("bundle-%s-%s", strings.ToLower(sanitizeIdentityPart(hostname)), collectedAt.UTC().Format("20060102-150405z"))
}

func collectionBatchID(configuredBatchID string, collectedAt time.Time) string {
	trimmed := strings.TrimSpace(configuredBatchID)
	if trimmed != "" {
		return trimmed
	}
	return "batch-" + collectedAt.UTC().Format("20060102-150405z")
}

func writeMetaArtifacts(caseDir string, collectedAt time.Time, warnings []string, errors []string, phaseEvents []string) (model.ArtifactRecord, model.ArtifactRecord, []string, []string) {
	logPath := filepath.Join(caseDir, "collector-log.txt")
	logLines := []string{"collector run complete", "collection phase order:"}
	logLines = append(logLines, phaseEvents...)
	logLines = append(logLines, "mode: read-only system information collection")
	if len(warnings) > 0 {
		logLines = append(logLines, fmt.Sprintf("warnings: %d", len(warnings)))
		logLines = append(logLines, warnings...)
	}
	if len(errors) > 0 {
		logLines = append(logLines, fmt.Sprintf("errors: %d", len(errors)))
		logLines = append(logLines, errors...)
	}
	logArtifact, logErr := writeSimpleArtifact(logPath, strings.Join(logLines, "\n")+"\n", "collector-log", "logs", "txt", "internal", "collector", collectedAt, []string{"collector", "log"})

	errorPath := filepath.Join(caseDir, "errors.json")
	errorPayload := struct {
		Warnings []manifestIssue `json:"warnings"`
		Errors   []manifestIssue `json:"errors"`
	}{Warnings: manifestIssues("warning", warnings), Errors: manifestIssues("error", errors)}
	errorArtifact, errorErr := writeJSONArtifact(errorPath, errorPayload, "errors", "logs", "json", "internal", "collector", collectedAt.Add(time.Second), []string{"collector", "errors"})

	metaWarnings := make([]string, 0)
	metaErrors := make([]string, 0)
	if logErr != nil {
		metaErrors = append(metaErrors, "collector-log: "+logErr.Error())
	}
	if errorErr != nil {
		metaErrors = append(metaErrors, "errors: "+errorErr.Error())
	}
	return logArtifact, errorArtifact, metaWarnings, metaErrors
}

type manifestIssue struct {
	Severity string `json:"severity"`
	Source   string `json:"source"`
	Message  string `json:"message"`
}

func manifestIssues(severity string, values []string) []manifestIssue {
	issues := make([]manifestIssue, 0, len(values))
	for _, value := range values {
		message := strings.TrimSpace(value)
		if message == "" {
			continue
		}
		source := "collector"
		if idx := strings.Index(message, ":"); idx > 0 {
			source = strings.TrimSpace(message[:idx])
			message = strings.TrimSpace(message[idx+1:])
		}
		issues = append(issues, manifestIssue{Severity: severity, Source: source, Message: message})
	}
	return issues
}

func writeHashesFile(caseDir string, artifacts []model.ArtifactRecord) error {
	var lines []string
	for _, artifact := range artifacts {
		if artifact.SHA256 == "" {
			continue
		}
		lines = append(lines, fmt.Sprintf("%s  %s", artifact.SHA256, artifact.RelativePath))
	}
	content := strings.Join(lines, "\n")
	if content != "" {
		content += "\n"
	}
	return os.WriteFile(filepath.Join(caseDir, "hashes.sha256"), []byte(content), 0o644)
}

func writeSimpleArtifact(path string, content string, artifactID string, category string, format string, sourceCommand string, scope string, collectedAt time.Time, tags []string) (model.ArtifactRecord, error) {
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		msg := err.Error()
		return model.ArtifactRecord{ArtifactID: artifactID, Category: category, RelativePath: relativeArtifactPath(path), Format: format, SourceCommand: sourceCommand, CollectionScope: scope, CollectedAt: collectedAt.Format(time.RFC3339), CollectorStatus: "error", Error: &msg, Tags: tags}, err
	}
	return artifactFromPath(path, artifactID, category, format, sourceCommand, scope, collectedAt, tags, nil, "ok")
}

func writeJSONArtifact(path string, value any, artifactID string, category string, format string, sourceCommand string, scope string, collectedAt time.Time, tags []string) (model.ArtifactRecord, error) {
	if err := writejson.File(path, value); err != nil {
		msg := err.Error()
		return model.ArtifactRecord{ArtifactID: artifactID, Category: category, RelativePath: relativeArtifactPath(path), Format: format, SourceCommand: sourceCommand, CollectionScope: scope, CollectedAt: collectedAt.Format(time.RFC3339), CollectorStatus: "error", Error: &msg, Tags: tags}, err
	}
	return artifactFromPath(path, artifactID, category, format, sourceCommand, scope, collectedAt, tags, nil, "ok")
}

func artifactFromPath(path string, artifactID string, category string, format string, sourceCommand string, scope string, collectedAt time.Time, tags []string, notes []string, status string) (model.ArtifactRecord, error) {
	hash, size, err := checksumFile(path)
	if err != nil {
		msg := err.Error()
		return model.ArtifactRecord{ArtifactID: artifactID, Category: category, RelativePath: relativeArtifactPath(path), Format: format, SourceCommand: sourceCommand, CollectionScope: scope, CollectedAt: collectedAt.Format(time.RFC3339), CollectorStatus: "error", Error: &msg, Tags: tags, Notes: notes}, err
	}
	return model.ArtifactRecord{ArtifactID: artifactID, Category: category, RelativePath: relativeArtifactPath(path), Format: format, SHA256: hash, SizeBytes: size, SourceCommand: sourceCommand, CollectionScope: scope, CollectedAt: collectedAt.Format(time.RFC3339), CollectorStatus: status, Tags: tags, Notes: notes}, nil
}

func checksumFile(path string) (string, int64, error) {
	return checksum.SHA256File(path)
}

func loadBatchManifest(path string) (model.BatchManifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return model.BatchManifest{}, err
	}
	var batch model.BatchManifest
	if err := json.Unmarshal(data, &batch); err != nil {
		return model.BatchManifest{}, err
	}
	return batch, nil
}

func upsertBatchCase(cases []model.BatchCaseEntry, entry model.BatchCaseEntry) []model.BatchCaseEntry {
	for i := range cases {
		if cases[i].RelativePath == entry.RelativePath || cases[i].BundleID == entry.BundleID {
			cases[i] = entry
			return cases
		}
	}
	return append(cases, entry)
}

func resolveHostLabel(value string) string {
	trimmed := strings.TrimSpace(value)
	lower := strings.ToLower(trimmed)
	if trimmed == "" || lower == "sample-host" || lower == "ws-local" {
		if host, err := os.Hostname(); err == nil && strings.TrimSpace(host) != "" {
			return host
		}
	}
	return trimmed
}

func printBanner(cfg Config, hostname string) {
	fmt.Fprintln(os.Stdout, "SEKER - System Information Collector")
	fmt.Fprintln(os.Stdout, "[SEKER] Read-only mode: no data on the host is altered by SEKER.")
	fmt.Fprintf(os.Stdout, "[SEKER] Host target: %s\n", hostname)
	fmt.Fprintf(os.Stdout, "[SEKER] Batch ID: %s\n", cfg.BatchID)
	fmt.Fprintln(os.Stdout, "[SEKER] Collection started. Please wait...")
}

func collectorLabel(collector collect.Collector) string {
	switch collector.(type) {
	case collect.HostCollector:
		return "host identity"
	case collect.ProcessCollector:
		return "process inventory"
	case collect.ProcessDetailCollector:
		return "process detail"
	case collect.NetworkCollector:
		return "network information"
	case collect.PersistenceCollector:
		return "persistence checks"
	case collect.LogsCollector:
		return "readable logs"
	case collect.SecurityCollector:
		return "security posture"
	case collect.SoftwareCollector:
		return "installed-program inventory"
	case collect.DeviceCollector:
		return "device/removable-media inventory"
	default:
		return "artifacts"
	}
}

func relativeArtifactPath(path string) string {
	clean := filepath.ToSlash(path)
	for _, marker := range []string{"host/", "processes/", "network/", "persistence/", "files/", "security/", "software/", "logs/", "devices/", "collector-log.txt", "errors.json"} {
		if idx := strings.Index(clean, marker); idx >= 0 {
			return clean[idx:]
		}
	}
	parts := strings.Split(clean, "/")
	if len(parts) >= 2 {
		return strings.Join(parts[len(parts)-2:], "/")
	}
	return filepath.ToSlash(filepath.Base(path))
}

func collectorMode() string {
	return "read-only-baseline"
}

func profileName() string {
	return "baseline-live"
}

func currentUserAndDomain() (string, *string, []string) {
	warnings := make([]string, 0)
	username := strings.TrimSpace(os.Getenv("USERNAME"))
	if username == "" {
		username = strings.TrimSpace(os.Getenv("USER"))
	}
	if username == "" {
		warnings = append(warnings, "target_host.username: unavailable from USERNAME/USER environment")
	}

	var domain *string
	for _, key := range []string{"USERDOMAIN", "DOMAIN", "HOSTDOMAIN"} {
		if value := strings.TrimSpace(os.Getenv(key)); value != "" {
			domain = stringPtr(value)
			break
		}
	}
	return username, domain, warnings
}

func normalizeOS(goos string) string {
	switch goos {
	case "darwin":
		return "macos"
	default:
		return goos
	}
}

func unique(values []string) []string {
	seen := map[string]struct{}{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func sanitizeIdentityPart(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "unknown-host"
	}
	replacer := strings.NewReplacer(" ", "-", "/", "-", "\\", "-", ":", "-", "_", "-")
	return replacer.Replace(value)
}

func stringPtr(value string) *string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil
	}
	return &trimmed
}
