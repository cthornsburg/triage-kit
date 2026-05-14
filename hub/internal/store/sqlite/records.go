package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

type CaseSummary struct {
	ID                 int64
	CaseUUID           string
	CaseID             string
	CollectionCaseID   string
	BatchID            string
	AssetLabel         string
	Hostname           string
	OSVersion          string
	OSBuild            string
	CollectedAt        string
	Status             string
	IntegrityStatus    string
	WarningsCount      int
	ErrorsCount        int
	CollectorVersion   string
	RawCasePath        string
	NormalizedCasePath string
}

type ArtifactSetSummary struct {
	ArtifactKey string
	SourcePath  string
	OutputPath  string
	RecordCount int
	Status      string
}

type NormalizedRecord struct {
	ArtifactKey    string
	RecordIndex    int
	PrimaryLabel   string
	SecondaryLabel string
	RawJSON        string
}

type FindingRecord struct {
	Title             string
	Category          string
	Severity          string
	Confidence        string
	Status            string
	Evidence          string
	Rationale         string
	Source            string
	Suppressed        bool
	SuppressionReason string
}

type ImportRecord struct {
	ImportUUID       string
	SourcePath       string
	SourceKind       string
	BatchID          string
	CollectorName    string
	CollectorVersion string
}

type CaseRecord struct {
	CaseUUID           string
	ImportID           int64
	CaseID             string
	CollectionCaseID   string
	BatchID            string
	Hostname           string
	AssetLabel         string
	CollectedAt        string
	CollectorVersion   string
	Status             string
	IntegrityStatus    string
	Disposition        sql.NullString
	Priority           sql.NullString
	Escalated          bool
	RawCasePath        string
	NormalizedCasePath sql.NullString
}

type HostContextRecord struct {
	CaseID             int64
	Hostname           string
	Username           string
	Domain             string
	OSName             string
	OSVersion          string
	OSBuild            string
	Architecture       string
	Timezone           string
	LastBootTime       string
	UptimeSeconds      sql.NullInt64
	SourceArtifactPath string
}

type IntegrityResultRecord struct {
	CaseID               int64
	ManifestValid        bool
	HashesValid          bool
	FilesMissingCount    int
	FilesMismatchedCount int
	WarningsCount        int
	ErrorsCount          int
	SummaryJSON          string
}

func (s *Store) InsertImport(ctx context.Context, record ImportRecord) (int64, error) {
	result, err := s.DB.ExecContext(ctx, `
		INSERT INTO case_imports (
			import_uuid, source_path, source_kind, batch_id, collector_name, collector_version
		) VALUES (?, ?, ?, ?, ?, ?)
	`, record.ImportUUID, record.SourcePath, record.SourceKind, record.BatchID, record.CollectorName, record.CollectorVersion)
	if err != nil {
		return 0, fmt.Errorf("insert import: %w", err)
	}
	return result.LastInsertId()
}

func (s *Store) InsertCase(ctx context.Context, record CaseRecord) (int64, error) {
	escalated := 0
	if record.Escalated {
		escalated = 1
	}

	result, err := s.DB.ExecContext(ctx, `
		INSERT INTO cases (
			case_uuid, import_id, case_id, collection_case_id, batch_id, hostname, asset_label,
			collected_at, collector_version, status, integrity_status,
			disposition, priority, escalated, raw_case_path, normalized_case_path
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		record.CaseUUID,
		record.ImportID,
		record.CaseID,
		record.CollectionCaseID,
		record.BatchID,
		record.Hostname,
		record.AssetLabel,
		record.CollectedAt,
		record.CollectorVersion,
		record.Status,
		record.IntegrityStatus,
		record.Disposition,
		record.Priority,
		escalated,
		record.RawCasePath,
		record.NormalizedCasePath,
	)
	if err != nil {
		return 0, fmt.Errorf("insert case: %w", err)
	}
	return result.LastInsertId()
}

func (s *Store) UpsertHostContext(ctx context.Context, record HostContextRecord) error {
	_, err := s.DB.ExecContext(ctx, `
		INSERT INTO host_contexts (
			case_id, hostname, username, domain, os_name, os_version,
			os_build, architecture, timezone, last_boot_time, uptime_seconds, source_artifact_path
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(case_id) DO UPDATE SET
			hostname = excluded.hostname,
			username = excluded.username,
			domain = excluded.domain,
			os_name = excluded.os_name,
			os_version = excluded.os_version,
			os_build = excluded.os_build,
			architecture = excluded.architecture,
			timezone = excluded.timezone,
			last_boot_time = excluded.last_boot_time,
			uptime_seconds = excluded.uptime_seconds,
			source_artifact_path = excluded.source_artifact_path,
			updated_at = CURRENT_TIMESTAMP
	`, record.CaseID, record.Hostname, record.Username, record.Domain, record.OSName, record.OSVersion, record.OSBuild, record.Architecture, record.Timezone, record.LastBootTime, record.UptimeSeconds, record.SourceArtifactPath)
	if err != nil {
		return fmt.Errorf("upsert host context: %w", err)
	}
	return nil
}

func (s *Store) InsertIntegrityResult(ctx context.Context, record IntegrityResultRecord) error {
	manifestValid := 0
	if record.ManifestValid {
		manifestValid = 1
	}
	hashesValid := 0
	if record.HashesValid {
		hashesValid = 1
	}

	_, err := s.DB.ExecContext(ctx, `
		INSERT INTO integrity_results (
			case_id, manifest_valid, hashes_valid, files_missing_count,
			files_mismatched_count, warnings_count, errors_count, summary_json
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`, record.CaseID, manifestValid, hashesValid, record.FilesMissingCount, record.FilesMismatchedCount, record.WarningsCount, record.ErrorsCount, record.SummaryJSON)
	if err != nil {
		return fmt.Errorf("insert integrity result: %w", err)
	}
	return nil
}

func (s *Store) ListCaseSummaries(ctx context.Context) ([]CaseSummary, error) {
	rows, err := s.DB.QueryContext(ctx, `
		SELECT
			c.id,
			c.case_uuid,
			c.case_id,
			COALESCE(c.collection_case_id, ''),
			COALESCE(c.batch_id, ''),
			COALESCE(c.asset_label, ''),
			COALESCE(c.hostname, ''),
			COALESCE(hc.os_version, ''),
			COALESCE(hc.os_build, ''),
			COALESCE(c.collected_at, ''),
			c.status,
			c.integrity_status,
			COALESCE(ir.warnings_count, 0),
			COALESCE(ir.errors_count, 0),
			COALESCE(c.collector_version, ''),
			c.raw_case_path,
			COALESCE(c.normalized_case_path, '')
		FROM cases c
		LEFT JOIN host_contexts hc ON hc.case_id = c.id
		LEFT JOIN integrity_results ir ON ir.id = (
			SELECT id FROM integrity_results WHERE case_id = c.id ORDER BY id DESC LIMIT 1
		)
		ORDER BY c.collected_at DESC, c.id DESC
	`)
	if err != nil {
		return nil, fmt.Errorf("list case summaries: %w", err)
	}
	defer rows.Close()

	var summaries []CaseSummary
	for rows.Next() {
		var summary CaseSummary
		if err := rows.Scan(
			&summary.ID,
			&summary.CaseUUID,
			&summary.CaseID,
			&summary.CollectionCaseID,
			&summary.BatchID,
			&summary.AssetLabel,
			&summary.Hostname,
			&summary.OSVersion,
			&summary.OSBuild,
			&summary.CollectedAt,
			&summary.Status,
			&summary.IntegrityStatus,
			&summary.WarningsCount,
			&summary.ErrorsCount,
			&summary.CollectorVersion,
			&summary.RawCasePath,
			&summary.NormalizedCasePath,
		); err != nil {
			return nil, fmt.Errorf("scan case summary: %w", err)
		}
		summaries = append(summaries, summary)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate case summaries: %w", err)
	}

	return summaries, nil
}

func (s *Store) UpdateCaseLabel(ctx context.Context, caseUUID, label string) error {
	_, err := s.DB.ExecContext(ctx, `UPDATE cases SET asset_label = ?, updated_at = CURRENT_TIMESTAMP WHERE case_uuid = ?`, label, caseUUID)
	if err != nil {
		return fmt.Errorf("update case label: %w", err)
	}
	return nil
}

func (s *Store) HasIngestedBundle(ctx context.Context, batchID, bundleID string) (bool, error) {
	var count int
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(1) FROM ingested_bundles WHERE batch_id = ? AND bundle_id = ?`, batchID, bundleID).Scan(&count); err != nil {
		return false, fmt.Errorf("check ingested bundle: %w", err)
	}
	return count > 0, nil
}

func (s *Store) RememberIngestedBundle(ctx context.Context, batchID, bundleID, caseUUID string) error {
	_, err := s.DB.ExecContext(ctx, `
		INSERT INTO ingested_bundles (batch_id, bundle_id, case_uuid)
		VALUES (?, ?, ?)
		ON CONFLICT(batch_id, bundle_id) DO UPDATE SET case_uuid = COALESCE(ingested_bundles.case_uuid, excluded.case_uuid)
	`, batchID, bundleID, caseUUID)
	if err != nil {
		return fmt.Errorf("remember ingested bundle: %w", err)
	}
	return nil
}

func (s *Store) SeedKnownBundlesFromCases(ctx context.Context) error {
	rows, err := s.DB.QueryContext(ctx, `SELECT case_uuid, raw_case_path FROM cases WHERE raw_case_path IS NOT NULL AND raw_case_path != ''`)
	if err != nil {
		return fmt.Errorf("query existing case paths: %w", err)
	}
	defer rows.Close()

	type manifestKey struct {
		BundleID string `json:"bundle_id"`
		BatchID  string `json:"batch_id"`
	}

	for rows.Next() {
		var caseUUID string
		var rawCasePath string
		if err := rows.Scan(&caseUUID, &rawCasePath); err != nil {
			return fmt.Errorf("scan existing case path: %w", err)
		}
		manifestPath := filepath.Join(rawCasePath, "manifest.json")
		content, err := os.ReadFile(manifestPath)
		if err != nil {
			continue
		}
		var key manifestKey
		if err := json.Unmarshal(content, &key); err != nil {
			continue
		}
		if key.BatchID == "" || key.BundleID == "" {
			continue
		}
		if err := s.RememberIngestedBundle(ctx, key.BatchID, key.BundleID, caseUUID); err != nil {
			return err
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate existing case paths: %w", err)
	}
	return nil
}

func (s *Store) ReplaceNormalizedArtifactSet(ctx context.Context, caseID int64, summary ArtifactSetSummary, records []NormalizedRecord) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin normalized artifact transaction: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	if _, err = tx.ExecContext(ctx, `DELETE FROM normalized_records WHERE case_id = ? AND artifact_key = ?`, caseID, summary.ArtifactKey); err != nil {
		return fmt.Errorf("delete existing normalized records: %w", err)
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM normalized_artifact_sets WHERE case_id = ? AND artifact_key = ?`, caseID, summary.ArtifactKey); err != nil {
		return fmt.Errorf("delete existing normalized artifact set: %w", err)
	}

	if _, err = tx.ExecContext(ctx, `
		INSERT INTO normalized_artifact_sets (case_id, artifact_key, source_path, output_path, record_count, status)
		VALUES (?, ?, ?, ?, ?, ?)
	`, caseID, summary.ArtifactKey, summary.SourcePath, summary.OutputPath, summary.RecordCount, summary.Status); err != nil {
		return fmt.Errorf("insert normalized artifact set: %w", err)
	}

	for _, record := range records {
		if _, err = tx.ExecContext(ctx, `
			INSERT INTO normalized_records (case_id, artifact_key, record_index, primary_label, secondary_label, raw_json)
			VALUES (?, ?, ?, ?, ?, ?)
		`, caseID, record.ArtifactKey, record.RecordIndex, record.PrimaryLabel, record.SecondaryLabel, record.RawJSON); err != nil {
			return fmt.Errorf("insert normalized record: %w", err)
		}
	}

	if err = tx.Commit(); err != nil {
		return fmt.Errorf("commit normalized artifact transaction: %w", err)
	}
	return nil
}

func (s *Store) ListArtifactSets(ctx context.Context, caseUUID string) ([]ArtifactSetSummary, error) {
	rows, err := s.DB.QueryContext(ctx, `
		SELECT nas.artifact_key, nas.source_path, nas.output_path, nas.record_count, nas.status
		FROM normalized_artifact_sets nas
		JOIN cases c ON c.id = nas.case_id
		WHERE c.case_uuid = ?
		ORDER BY nas.artifact_key
	`, caseUUID)
	if err != nil {
		return nil, fmt.Errorf("list artifact sets: %w", err)
	}
	defer rows.Close()

	var items []ArtifactSetSummary
	for rows.Next() {
		var item ArtifactSetSummary
		if err := rows.Scan(&item.ArtifactKey, &item.SourcePath, &item.OutputPath, &item.RecordCount, &item.Status); err != nil {
			return nil, fmt.Errorf("scan artifact set: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate artifact sets: %w", err)
	}
	return items, nil
}

func (s *Store) ListNormalizedRecords(ctx context.Context, caseUUID, artifactKey string, limit int) ([]NormalizedRecord, error) {
	return s.ListNormalizedRecordsPage(ctx, caseUUID, artifactKey, limit, 0)
}

func (s *Store) ListNormalizedRecordsPage(ctx context.Context, caseUUID, artifactKey string, limit, offset int) ([]NormalizedRecord, error) {
	if limit <= 0 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	rows, err := s.DB.QueryContext(ctx, `
		SELECT nr.artifact_key, nr.record_index, COALESCE(nr.primary_label, ''), COALESCE(nr.secondary_label, ''), nr.raw_json
		FROM normalized_records nr
		JOIN cases c ON c.id = nr.case_id
		WHERE c.case_uuid = ? AND nr.artifact_key = ?
		ORDER BY nr.record_index ASC
		LIMIT ?
		OFFSET ?
	`, caseUUID, artifactKey, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("list normalized records: %w", err)
	}
	defer rows.Close()

	var records []NormalizedRecord
	for rows.Next() {
		var record NormalizedRecord
		if err := rows.Scan(&record.ArtifactKey, &record.RecordIndex, &record.PrimaryLabel, &record.SecondaryLabel, &record.RawJSON); err != nil {
			return nil, fmt.Errorf("scan normalized record: %w", err)
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate normalized records: %w", err)
	}
	return records, nil
}

func (s *Store) CountNormalizedRecords(ctx context.Context, caseUUID, artifactKey string) (int, error) {
	var count int
	if err := s.DB.QueryRowContext(ctx, `
		SELECT COUNT(1)
		FROM normalized_records nr
		JOIN cases c ON c.id = nr.case_id
		WHERE c.case_uuid = ? AND nr.artifact_key = ?
	`, caseUUID, artifactKey).Scan(&count); err != nil {
		return 0, fmt.Errorf("count normalized records: %w", err)
	}
	return count, nil
}

func (s *Store) ReplaceRuleFindings(ctx context.Context, caseID int64, findings []FindingRecord) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin findings transaction: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	if _, err = tx.ExecContext(ctx, `DELETE FROM findings WHERE case_id = ? AND source = 'rule-engine'`, caseID); err != nil {
		return fmt.Errorf("delete existing rule findings: %w", err)
	}

	for _, finding := range findings {
		suppressed := 0
		if finding.Suppressed {
			suppressed = 1
		}
		if _, err = tx.ExecContext(ctx, `
			INSERT INTO findings (case_id, category, title, severity, confidence, status, evidence_ref, rationale, source, suppressed, suppression_reason)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		`, caseID, finding.Category, finding.Title, finding.Severity, finding.Confidence, finding.Status, finding.Evidence, finding.Rationale, finding.Source, suppressed, finding.SuppressionReason); err != nil {
			return fmt.Errorf("insert finding: %w", err)
		}
	}

	if err = tx.Commit(); err != nil {
		return fmt.Errorf("commit findings transaction: %w", err)
	}
	return nil
}

func (s *Store) ListFindings(ctx context.Context, caseUUID string, includeSuppressed bool) ([]FindingRecord, error) {
	whereSuppressed := "AND COALESCE(f.suppressed, 0) = 0"
	if includeSuppressed {
		whereSuppressed = ""
	}

	rows, err := s.DB.QueryContext(ctx, `
		SELECT f.title, f.category, COALESCE(f.severity,''), COALESCE(f.confidence,''), f.status, COALESCE(f.evidence_ref,''), COALESCE(f.rationale,''), f.source, COALESCE(f.suppressed, 0), COALESCE(f.suppression_reason, '')
		FROM findings f
		JOIN cases c ON c.id = f.case_id
		WHERE c.case_uuid = ?
		`+whereSuppressed+`
		ORDER BY 
			CASE f.severity WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,
			f.title ASC
	`, caseUUID)
	if err != nil {
		return nil, fmt.Errorf("list findings: %w", err)
	}
	defer rows.Close()

	var findings []FindingRecord
	for rows.Next() {
		var finding FindingRecord
		var suppressed int
		if err := rows.Scan(&finding.Title, &finding.Category, &finding.Severity, &finding.Confidence, &finding.Status, &finding.Evidence, &finding.Rationale, &finding.Source, &suppressed, &finding.SuppressionReason); err != nil {
			return nil, fmt.Errorf("scan finding: %w", err)
		}
		finding.Suppressed = suppressed != 0
		findings = append(findings, finding)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate findings: %w", err)
	}
	return findings, nil
}
