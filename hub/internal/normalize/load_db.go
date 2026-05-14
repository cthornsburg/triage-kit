package normalize

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"

	storesqlite "github.com/chip/incident-response-kit/hub/internal/store/sqlite"
)

func LoadNormalizedArtifacts(ctx context.Context, store *storesqlite.Store, caseSummary storesqlite.CaseSummary, result CaseNormalizationResult) error {
	keys := make([]string, 0, len(result.Artifacts))
	for key := range result.Artifacts {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	for _, key := range keys {
		artifact := result.Artifacts[key]
		records, err := loadArtifactRecords(key, artifact.OutputPath)
		if err != nil {
			return fmt.Errorf("load artifact %s into db: %w", key, err)
		}
		if err := store.ReplaceNormalizedArtifactSet(ctx, caseSummary.ID, storesqlite.ArtifactSetSummary{
			ArtifactKey: key,
			SourcePath:  artifact.SourcePath,
			OutputPath:  artifact.OutputPath,
			RecordCount: len(records),
			Status:      artifact.Status,
		}, records); err != nil {
			return fmt.Errorf("store artifact %s in db: %w", key, err)
		}
	}

	return nil
}

func loadArtifactRecords(artifactKey, path string) ([]storesqlite.NormalizedRecord, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var payload any
	if err := json.Unmarshal(content, &payload); err != nil {
		return nil, err
	}

	switch typed := payload.(type) {
	case []any:
		records := make([]storesqlite.NormalizedRecord, 0, len(typed))
		for idx, item := range typed {
			raw, err := json.Marshal(item)
			if err != nil {
				return nil, err
			}
			primary, secondary := labelsForRecord(item)
			records = append(records, storesqlite.NormalizedRecord{
				ArtifactKey:    artifactKey,
				RecordIndex:    idx,
				PrimaryLabel:   primary,
				SecondaryLabel: secondary,
				RawJSON:        string(raw),
			})
		}
		return records, nil
	default:
		raw, err := json.Marshal(typed)
		if err != nil {
			return nil, err
		}
		primary, secondary := labelsForRecord(typed)
		return []storesqlite.NormalizedRecord{{
			ArtifactKey:    artifactKey,
			RecordIndex:    0,
			PrimaryLabel:   primary,
			SecondaryLabel: secondary,
			RawJSON:        string(raw),
		}}, nil
	}
}

func labelsForRecord(record any) (string, string) {
	item, ok := record.(map[string]any)
	if !ok {
		return "", ""
	}
	primaryCandidates := []string{"hostname", "image_name", "taskname", "task_name", "name", "record_name", "destination", "local_address", "event_id", "display_name", "friendly_name", "drive_letter", "mounted_device", "profile_name", "device_description"}
	secondaryCandidates := []string{"publisher", "display_version", "scope", "pid", "state", "full_name", "date", "gateway", "foreign_address", "user_name", "task_to_run", "classification", "evidence_type", "confidence", "device_id", "instance_id"}
	return firstString(item, primaryCandidates...), firstString(item, secondaryCandidates...)
}

func firstString(item map[string]any, keys ...string) string {
	for _, key := range keys {
		value, ok := item[key]
		if !ok || value == nil {
			continue
		}
		switch typed := value.(type) {
		case string:
			if typed != "" {
				return typed
			}
		case float64:
			return fmt.Sprintf("%.0f", typed)
		}
	}
	return ""
}
