package ingest

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	storesqlite "github.com/chip/incident-response-kit/hub/internal/store/sqlite"
)

type BatchManifest struct {
	SchemaVersion    string         `json:"schema_version"`
	BatchID          string         `json:"batch_id"`
	CreatedAt        string         `json:"created_at"`
	ClosedAt         *string        `json:"closed_at"`
	CollectorVersion string         `json:"collector_version"`
	MediaLabel       string         `json:"media_label"`
	OperatorID       string         `json:"operator_id"`
	Notes            *string        `json:"notes"`
	Cases            []BatchCaseRef `json:"cases"`
}

type BatchCaseRef struct {
	BundleID     string `json:"bundle_id"`
	CaseID       string `json:"case_id,omitempty"` // legacy collector-side value; not required for ingest
	Hostname     string `json:"hostname"`
	RelativePath string `json:"relative_path"`
	CollectedAt  string `json:"collected_at"`
	Status       string `json:"status"`
}

type BundleManifest struct {
	SchemaVersion string          `json:"schema_version"`
	BundleID      string          `json:"bundle_id"`
	BatchID       string          `json:"batch_id"`
	CaseID        string          `json:"case_id,omitempty"` // legacy collector-side value; not required for ingest
	CollectedAt   string          `json:"collected_at"`
	Collector     CollectorInfo   `json:"collector"`
	Operator      OperatorInfo    `json:"operator"`
	TargetHost    TargetHost      `json:"target_host"`
	Profile       ProfileInfo     `json:"profile"`
	Artifacts     []Artifact      `json:"artifacts"`
	Summary       BundleSummary   `json:"summary"`
	Raw           json.RawMessage `json:"-"`
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

type TargetHost struct {
	Hostname     string  `json:"hostname"`
	Username     string  `json:"username"`
	Domain       *string `json:"domain"`
	OSFamily     string  `json:"os_family"`
	OSVersion    *string `json:"os_version"`
	Architecture *string `json:"architecture"`
	Timezone     *string `json:"timezone"`
	BootTime     *string `json:"boot_time"`
}

type HostIdentity struct {
	BootTime      string `json:"boot_time"`
	UptimeSeconds *int64 `json:"uptime_seconds"`
}

type ProfileInfo struct {
	Name                  string  `json:"name"`
	ArtifactPolicyVersion *string `json:"artifact_policy_version"`
}

type Artifact struct {
	ArtifactID      string    `json:"artifact_id"`
	Category        string    `json:"category"`
	RelativePath    string    `json:"relative_path"`
	Format          string    `json:"format"`
	SHA256          string    `json:"sha256"`
	SizeBytes       int64     `json:"size_bytes"`
	SourceCommand   *string   `json:"source_command"`
	CollectionScope *string   `json:"collection_scope"`
	CollectedAt     string    `json:"collected_at"`
	CollectorStatus string    `json:"collector_status"`
	Error           *string   `json:"error"`
	Notes           *[]string `json:"notes"`
	Tags            []string  `json:"tags"`
}

type BundleSummary struct {
	ArtifactCount int    `json:"artifact_count"`
	Errors        int    `json:"errors"`
	Warnings      int    `json:"warnings"`
	Status        string `json:"status"`
}

type Importer struct {
	Store    *storesqlite.Store
	DataRoot string
}

type ImportOptions struct {
	AnalystCaseID string
}

type ImportResult struct {
	ImportedBatches int
	ImportedCases   int
	SkippedCases    int
	SourcePath      string
	BatchIDs        []string
}

func (i *Importer) ImportPath(ctx context.Context, sourcePath string) (ImportResult, error) {
	return i.ImportPathWithOptions(ctx, sourcePath, ImportOptions{})
}

func (i *Importer) ImportPathWithOptions(ctx context.Context, sourcePath string, opts ImportOptions) (ImportResult, error) {
	absPath, err := filepath.Abs(sourcePath)
	if err != nil {
		return ImportResult{}, fmt.Errorf("resolve source path: %w", err)
	}
	if err := i.Store.SeedKnownBundlesFromCases(ctx); err != nil {
		return ImportResult{}, err
	}

	batchDirs, err := discoverBatchDirs(absPath)
	if err != nil {
		return ImportResult{}, err
	}

	result := ImportResult{SourcePath: absPath}
	for _, batchDir := range batchDirs {
		batchResult, err := i.importBatch(ctx, batchDir, opts)
		if err != nil {
			return result, err
		}
		result.ImportedBatches++
		result.ImportedCases += batchResult.ImportedCases
		result.SkippedCases += batchResult.SkippedCases
		result.BatchIDs = append(result.BatchIDs, batchResult.BatchIDs...)
	}

	return result, nil
}

func discoverBatchDirs(sourcePath string) ([]string, error) {
	info, err := os.Stat(sourcePath)
	if err != nil {
		return nil, fmt.Errorf("stat source path: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("source path must be a directory: %s", sourcePath)
	}

	if fileExists(filepath.Join(sourcePath, "batch-manifest.json")) {
		return []string{sourcePath}, nil
	}

	if fileExists(filepath.Join(sourcePath, "manifest.json")) {
		return nil, fmt.Errorf("case-only ingest is not wired yet; point Thoth at a batch directory or the SEKER USB root")
	}

	collectionsDir := sourcePath
	if filepath.Base(sourcePath) != "collections" && dirExists(filepath.Join(sourcePath, "collections")) {
		collectionsDir = filepath.Join(sourcePath, "collections")
	}

	entries, err := os.ReadDir(collectionsDir)
	if err != nil {
		return nil, fmt.Errorf("read collections dir: %w", err)
	}

	var batchDirs []string
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		candidate := filepath.Join(collectionsDir, entry.Name())
		if fileExists(filepath.Join(candidate, "batch-manifest.json")) {
			batchDirs = append(batchDirs, candidate)
		}
	}
	if len(batchDirs) == 0 {
		return nil, fmt.Errorf("no SEKER batch directories found under %s", sourcePath)
	}
	sort.Strings(batchDirs)
	return batchDirs, nil
}

func (i *Importer) importBatch(ctx context.Context, batchDir string, opts ImportOptions) (ImportResult, error) {
	batchManifestPath := filepath.Join(batchDir, "batch-manifest.json")
	batchManifest, err := readBatchManifest(batchManifestPath)
	if err != nil {
		return ImportResult{}, err
	}

	importUUID, err := randomID("imp")
	if err != nil {
		return ImportResult{}, fmt.Errorf("generate import uuid: %w", err)
	}

	caseRefs, err := discoverCaseRefs(batchManifest, batchDir)
	if err != nil {
		return ImportResult{}, err
	}

	importResult := ImportResult{ImportedBatches: 1, BatchIDs: []string{batchManifest.BatchID}}
	newCaseRefs := make([]BatchCaseRef, 0, len(caseRefs))
	for _, caseRef := range caseRefs {
		bundleID := caseRef.BundleID
		if bundleID == "" {
			manifest, err := readBundleManifest(filepath.Join(batchDir, caseRef.RelativePath, "manifest.json"))
			if err != nil {
				return importResult, err
			}
			bundleID = manifest.BundleID
			caseRef.BundleID = manifest.BundleID
		}
		known, err := i.Store.HasIngestedBundle(ctx, batchManifest.BatchID, bundleID)
		if err != nil {
			return importResult, err
		}
		if known {
			importResult.SkippedCases++
			continue
		}
		newCaseRefs = append(newCaseRefs, caseRef)
	}
	if len(newCaseRefs) == 0 {
		return importResult, nil
	}

	stagedBatchDir := filepath.Join(i.DataRoot, "imports", importUUID, filepath.Base(batchDir))
	if err := stageBatchSubset(batchDir, stagedBatchDir, newCaseRefs); err != nil {
		return ImportResult{}, fmt.Errorf("stage batch %s: %w", batchDir, err)
	}

	importID, err := i.Store.InsertImport(ctx, storesqlite.ImportRecord{
		ImportUUID:       importUUID,
		SourcePath:       batchDir,
		SourceKind:       "batch",
		BatchID:          batchManifest.BatchID,
		CollectorVersion: batchManifest.CollectorVersion,
		CollectorName:    "SEKER",
	})
	if err != nil {
		return ImportResult{}, err
	}

	for _, caseRef := range newCaseRefs {
		if err := i.importCase(ctx, importID, batchManifest.BatchID, stagedBatchDir, caseRef, opts); err != nil {
			return importResult, err
		}
		importResult.ImportedCases++
	}

	return importResult, nil
}

func discoverCaseRefs(batchManifest BatchManifest, stagedBatchDir string) ([]BatchCaseRef, error) {
	if len(batchManifest.Cases) > 0 {
		return batchManifest.Cases, nil
	}

	entries, err := os.ReadDir(stagedBatchDir)
	if err != nil {
		return nil, fmt.Errorf("read staged batch dir: %w", err)
	}

	var refs []BatchCaseRef
	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), "case-") {
			continue
		}
		manifestPath := filepath.Join(stagedBatchDir, entry.Name(), "manifest.json")
		if !fileExists(manifestPath) {
			continue
		}
		manifest, err := readBundleManifest(manifestPath)
		if err != nil {
			return nil, err
		}
		refs = append(refs, BatchCaseRef{
			BundleID:     manifest.BundleID,
			Hostname:     manifest.TargetHost.Hostname,
			RelativePath: entry.Name(),
			CollectedAt:  manifest.CollectedAt,
			Status:       manifest.Summary.Status,
		})
	}
	if len(refs) == 0 {
		return nil, errors.New("batch contains no readable case manifests")
	}
	return refs, nil
}

func (i *Importer) importCase(ctx context.Context, importID int64, batchID, stagedBatchDir string, caseRef BatchCaseRef, opts ImportOptions) error {
	caseDir := filepath.Join(stagedBatchDir, caseRef.RelativePath)
	manifestPath := filepath.Join(caseDir, "manifest.json")
	manifest, err := readBundleManifest(manifestPath)
	if err != nil {
		return err
	}

	caseUUID, err := randomID("case")
	if err != nil {
		return fmt.Errorf("generate case uuid: %w", err)
	}

	caseRoot := filepath.Join(i.DataRoot, "cases", caseUUID)
	sourceRoot := filepath.Join(caseRoot, "source")
	normalizedRoot := filepath.Join(caseRoot, "normalized")
	if err := os.MkdirAll(normalizedRoot, 0o755); err != nil {
		return fmt.Errorf("create normalized dir: %w", err)
	}
	for _, subdir := range []string{"findings", "reports", "notes", "attachments"} {
		if err := os.MkdirAll(filepath.Join(caseRoot, subdir), 0o755); err != nil {
			return fmt.Errorf("create case workspace %s: %w", subdir, err)
		}
	}
	if err := copyDir(caseDir, sourceRoot); err != nil {
		return fmt.Errorf("copy case source into workspace: %w", err)
	}

	integrity := verifyCaseIntegrity(sourceRoot, manifest)
	integrityStatus := "failed"
	if integrity.ManifestValid && integrity.HashesValid && integrity.ErrorsCount == 0 {
		integrityStatus = "ok"
	} else if integrity.ManifestValid {
		integrityStatus = "partial"
	}

	casePK, err := i.Store.InsertCase(ctx, storesqlite.CaseRecord{
		CaseUUID:           caseUUID,
		ImportID:           importID,
		CaseID:             analystCaseID(manifest, opts),
		CollectionCaseID:   manifest.BundleID,
		BatchID:            batchID,
		Hostname:           manifest.TargetHost.Hostname,
		AssetLabel:         manifest.TargetHost.Hostname,
		CollectedAt:        manifest.CollectedAt,
		CollectorVersion:   manifest.Collector.Version,
		Status:             manifest.Summary.Status,
		IntegrityStatus:    integrityStatus,
		Disposition:        sql.NullString{},
		Priority:           sql.NullString{},
		Escalated:          false,
		RawCasePath:        sourceRoot,
		NormalizedCasePath: sql.NullString{String: normalizedRoot, Valid: true},
	})
	if err != nil {
		return err
	}

	osVersion := derefString(manifest.TargetHost.OSVersion)
	osName, osBuild := splitOSVersion(osVersion)
	hostIdentity := readHostIdentity(filepath.Join(sourceRoot, "host", "identity.json"))
	lastBootTime := firstNonEmpty(derefString(manifest.TargetHost.BootTime), hostIdentity.BootTime)
	uptimeSeconds := sql.NullInt64{}
	if hostIdentity.UptimeSeconds != nil {
		uptimeSeconds = sql.NullInt64{Int64: *hostIdentity.UptimeSeconds, Valid: true}
	}
	if err := i.Store.UpsertHostContext(ctx, storesqlite.HostContextRecord{
		CaseID:             casePK,
		Hostname:           manifest.TargetHost.Hostname,
		Username:           manifest.TargetHost.Username,
		Domain:             derefString(manifest.TargetHost.Domain),
		OSName:             osName,
		OSVersion:          osVersion,
		OSBuild:            osBuild,
		Architecture:       derefString(manifest.TargetHost.Architecture),
		Timezone:           derefString(manifest.TargetHost.Timezone),
		LastBootTime:       lastBootTime,
		UptimeSeconds:      uptimeSeconds,
		SourceArtifactPath: filepath.Join(sourceRoot, "host", "identity.json"),
	}); err != nil {
		return err
	}

	summaryBytes, err := json.Marshal(integrity)
	if err != nil {
		return fmt.Errorf("marshal integrity summary: %w", err)
	}
	if err := i.Store.InsertIntegrityResult(ctx, storesqlite.IntegrityResultRecord{
		CaseID:               casePK,
		ManifestValid:        integrity.ManifestValid,
		HashesValid:          integrity.HashesValid,
		FilesMissingCount:    integrity.FilesMissingCount,
		FilesMismatchedCount: integrity.FilesMismatchedCount,
		WarningsCount:        integrity.WarningsCount,
		ErrorsCount:          integrity.ErrorsCount,
		SummaryJSON:          string(summaryBytes),
	}); err != nil {
		return err
	}
	if err := i.Store.RememberIngestedBundle(ctx, manifest.BatchID, manifest.BundleID, caseUUID); err != nil {
		return err
	}

	return nil
}

type IntegritySummary struct {
	ManifestValid        bool     `json:"manifest_valid"`
	HashesValid          bool     `json:"hashes_valid"`
	FilesMissingCount    int      `json:"files_missing_count"`
	FilesMismatchedCount int      `json:"files_mismatched_count"`
	WarningsCount        int      `json:"warnings_count"`
	ErrorsCount          int      `json:"errors_count"`
	MissingFiles         []string `json:"missing_files,omitempty"`
	MismatchedFiles      []string `json:"mismatched_files,omitempty"`
	HashListEntries      int      `json:"hash_list_entries"`
	ManifestArtifacts    int      `json:"manifest_artifacts"`
	ManifestStatus       string   `json:"manifest_status"`
	BundleID             string   `json:"bundle_id"`
	CaseID               string   `json:"case_id"`
	BatchID              string   `json:"batch_id"`
}

func verifyCaseIntegrity(caseDir string, manifest BundleManifest) IntegritySummary {
	summary := IntegritySummary{
		ManifestValid:     manifest.BundleID != "" && manifest.BatchID != "",
		WarningsCount:     manifest.Summary.Warnings,
		ErrorsCount:       manifest.Summary.Errors,
		ManifestArtifacts: len(manifest.Artifacts),
		ManifestStatus:    manifest.Summary.Status,
		BundleID:          manifest.BundleID,
		CaseID:            manifest.BundleID,
		BatchID:           manifest.BatchID,
	}

	for _, artifact := range manifest.Artifacts {
		if !fileExists(filepath.Join(caseDir, filepath.FromSlash(artifact.RelativePath))) {
			summary.FilesMissingCount++
			summary.MissingFiles = append(summary.MissingFiles, artifact.RelativePath)
		}
	}
	for _, required := range []string{"manifest.json", "hashes.sha256", "errors.json", "collector-log.txt"} {
		if !fileExists(filepath.Join(caseDir, required)) {
			summary.FilesMissingCount++
			summary.MissingFiles = append(summary.MissingFiles, required)
		}
	}

	entries, mismatches, err := verifyHashes(filepath.Join(caseDir, "hashes.sha256"), caseDir)
	if err == nil {
		summary.HashesValid = len(mismatches) == 0
		summary.HashListEntries = entries
		summary.FilesMismatchedCount = len(mismatches)
		summary.MismatchedFiles = mismatches
	} else {
		summary.HashesValid = false
		summary.FilesMissingCount++
		summary.MissingFiles = append(summary.MissingFiles, "hashes.sha256")
	}

	if summary.FilesMissingCount > 0 {
		summary.HashesValid = false
	}

	return summary
}

func verifyHashes(hashFilePath, caseDir string) (int, []string, error) {
	content, err := os.ReadFile(hashFilePath)
	if err != nil {
		return 0, nil, err
	}

	lines := strings.Split(strings.TrimSpace(string(content)), "\n")
	var mismatches []string
	entries := 0
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		expectedHash := strings.ToLower(parts[0])
		relPath := strings.Join(parts[1:], " ")
		entries++
		actualHash, err := fileSHA256(filepath.Join(caseDir, filepath.FromSlash(relPath)))
		if err != nil || actualHash != expectedHash {
			mismatches = append(mismatches, relPath)
		}
	}
	return entries, mismatches, nil
}

func fileSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func readBatchManifest(path string) (BatchManifest, error) {
	var manifest BatchManifest
	if err := readJSON(path, &manifest); err != nil {
		return BatchManifest{}, fmt.Errorf("read batch manifest %s: %w", path, err)
	}
	return manifest, nil
}

func readBundleManifest(path string) (BundleManifest, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return BundleManifest{}, fmt.Errorf("read bundle manifest %s: %w", path, err)
	}
	var manifest BundleManifest
	if err := json.Unmarshal(content, &manifest); err != nil {
		return BundleManifest{}, fmt.Errorf("parse bundle manifest %s: %w", path, err)
	}
	manifest.Raw = content
	return manifest, nil
}

func readJSON(path string, target any) error {
	content, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(content, target)
}

func copyDir(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)

		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}

		if d.Type()&os.ModeSymlink != 0 {
			return nil
		}

		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}

		srcFile, err := os.Open(path)
		if err != nil {
			return err
		}
		defer srcFile.Close()

		info, err := d.Info()
		if err != nil {
			return err
		}

		dstFile, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, info.Mode().Perm())
		if err != nil {
			return err
		}
		defer dstFile.Close()

		_, err = io.Copy(dstFile, srcFile)
		return err
	})
}

func stageBatchSubset(srcBatchDir, dstBatchDir string, caseRefs []BatchCaseRef) error {
	if err := os.MkdirAll(dstBatchDir, 0o755); err != nil {
		return err
	}
	for _, name := range []string{"batch-manifest.json"} {
		src := filepath.Join(srcBatchDir, name)
		if fileExists(src) {
			if err := copyFile(src, filepath.Join(dstBatchDir, name)); err != nil {
				return err
			}
		}
	}
	for _, caseRef := range caseRefs {
		src := filepath.Join(srcBatchDir, caseRef.RelativePath)
		dst := filepath.Join(dstBatchDir, caseRef.RelativePath)
		if err := copyDir(src, dst); err != nil {
			return err
		}
	}
	return nil
}

func copyFile(src, dst string) error {
	content, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	info, err := os.Stat(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, content, info.Mode().Perm())
}

func randomID(prefix string) (string, error) {
	bytes := make([]byte, 8)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return prefix + "-" + hex.EncodeToString(bytes), nil
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func dirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func derefString(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func readHostIdentity(path string) HostIdentity {
	var host HostIdentity
	content, err := os.ReadFile(path)
	if err != nil {
		return host
	}
	_ = json.Unmarshal(content, &host)
	return host
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func splitOSVersion(value string) (string, string) {
	if value == "" {
		return "", ""
	}
	buildIndex := strings.Index(strings.ToLower(value), "build ")
	if buildIndex == -1 {
		return value, ""
	}
	return strings.TrimSpace(value[:buildIndex]), strings.TrimSpace(value[buildIndex:])
}

func analystCaseID(manifest BundleManifest, opts ImportOptions) string {
	if value := strings.TrimSpace(opts.AnalystCaseID); value != "" {
		return value
	}
	if value := strings.TrimSpace(manifest.TargetHost.Hostname); value != "" {
		return value
	}
	return manifest.BundleID
}
