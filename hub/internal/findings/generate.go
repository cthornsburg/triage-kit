package findings

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	storesqlite "github.com/chip/incident-response-kit/hub/internal/store/sqlite"
)

func GenerateCaseFindings(ctx context.Context, store *storesqlite.Store, summary storesqlite.CaseSummary) ([]storesqlite.FindingRecord, error) {
	var findings []storesqlite.FindingRecord

	autoruns, err := store.ListNormalizedRecords(ctx, summary.CaseUUID, "persistence_hkcu_run", 1000)
	if err != nil {
		return nil, err
	}
	findings = append(findings, findUserProfileAutorunFindings(autoruns)...)

	startupEntries, err := store.ListNormalizedRecords(ctx, summary.CaseUUID, "persistence_startup_folder", 1000)
	if err != nil {
		return nil, err
	}
	findings = append(findings, findStartupFolderFindings(startupEntries)...)

	tasks, err := store.ListNormalizedRecords(ctx, summary.CaseUUID, "scheduled_tasks", 5000)
	if err != nil {
		return nil, err
	}
	findings = append(findings, findUserProfileScheduledTaskFindings(tasks)...)

	powershellEvents, err := store.ListNormalizedRecords(ctx, summary.CaseUUID, "logs_powershell", 5000)
	if err != nil {
		return nil, err
	}
	findings = append(findings, findPowerShellScriptBlockFindings(powershellEvents)...)
	applySuppressions(findings)

	if err := store.ReplaceRuleFindings(ctx, summary.ID, findings); err != nil {
		return nil, err
	}

	return findings, nil
}

func findUserProfileAutorunFindings(records []storesqlite.NormalizedRecord) []storesqlite.FindingRecord {
	var findings []storesqlite.FindingRecord
	for _, record := range records {
		item := parseRecord(record.RawJSON)
		name := asString(item["name"])
		value := asString(item["value"])
		lower := strings.ToLower(value)
		if strings.Contains(lower, `\users\`) || strings.Contains(lower, `appdata\`) {
			findings = append(findings, storesqlite.FindingRecord{
				Title:      fmt.Sprintf("User-profile autorun: %s", name),
				Category:   "persistence",
				Severity:   "medium",
				Confidence: "medium",
				Status:     "open",
				Evidence:   fmt.Sprintf("artifact=persistence_hkcu_run record_index=%d name=%q value=%q", record.RecordIndex, name, value),
				Rationale:  "HKCU Run entry launches from a user-writable profile/AppData path. That is often legitimate, but it is worth analyst review during triage.",
				Source:     "rule-engine",
			})
		}
	}
	return findings
}

func findStartupFolderFindings(records []storesqlite.NormalizedRecord) []storesqlite.FindingRecord {
	var findings []storesqlite.FindingRecord
	for _, record := range records {
		item := parseRecord(record.RawJSON)
		name := asString(item["name"])
		if strings.EqualFold(name, "desktop.ini") || name == "" {
			continue
		}
		findings = append(findings, storesqlite.FindingRecord{
			Title:      fmt.Sprintf("Startup-folder item present: %s", name),
			Category:   "persistence",
			Severity:   "medium",
			Confidence: "low",
			Status:     "open",
			Evidence:   fmt.Sprintf("artifact=persistence_startup_folder record_index=%d name=%q full_name=%q", record.RecordIndex, name, firstNonEmpty(asString(item["full_name"]), asString(item["fullname"]))),
			Rationale:  "Non-default startup-folder entries are a common persistence location. This is not inherently malicious, but it should be reviewed in context.",
			Source:     "rule-engine",
		})
	}
	return findings
}

func findUserProfileScheduledTaskFindings(records []storesqlite.NormalizedRecord) []storesqlite.FindingRecord {
	var findings []storesqlite.FindingRecord
	for _, record := range records {
		item := parseRecord(record.RawJSON)
		taskName := asString(item["TaskName"])
		taskToRun := asString(item["Task To Run"])
		lower := strings.ToLower(taskToRun)
		if strings.Contains(lower, `\users\`) || strings.Contains(lower, `%localappdata%`) || strings.Contains(lower, `\appdata\`) {
			findings = append(findings, storesqlite.FindingRecord{
				Title:      fmt.Sprintf("User-profile scheduled task: %s", taskName),
				Category:   "persistence",
				Severity:   "medium",
				Confidence: "low",
				Status:     "open",
				Evidence:   fmt.Sprintf("artifact=scheduled_tasks record_index=%d task_name=%q command=%q", record.RecordIndex, taskName, taskToRun),
				Rationale:  "Scheduled tasks that execute from user-profile paths deserve review because that pathing is also common for persistence and updater abuse.",
				Source:     "rule-engine",
			})
		}
	}
	return findings
}

func findPowerShellScriptBlockFindings(records []storesqlite.NormalizedRecord) []storesqlite.FindingRecord {
	count := 0
	var indexes []string
	for _, record := range records {
		item := parseRecord(record.RawJSON)
		if asString(item["event_id"]) == "4104" {
			count++
			indexes = append(indexes, fmt.Sprintf("%d", record.RecordIndex))
		}
	}
	if count == 0 {
		return nil
	}
	return []storesqlite.FindingRecord{{
		Title:      fmt.Sprintf("PowerShell script block activity observed (%d event(s))", count),
		Category:   "execution",
		Severity:   "medium",
		Confidence: "medium",
		Status:     "open",
		Evidence:   fmt.Sprintf("artifact=logs_powershell event_id=4104 count=%d record_indexes=%s", count, strings.Join(indexes, ",")),
		Rationale:  "PowerShell 4104 events indicate script block logging captured executed PowerShell content. That is not automatically bad, but it is worth analyst review during triage.",
		Source:     "rule-engine",
	}}
}

func parseRecord(raw string) map[string]any {
	var item map[string]any
	_ = json.Unmarshal([]byte(raw), &item)
	return item
}

func asString(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	default:
		return ""
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func applySuppressions(findings []storesqlite.FindingRecord) {
	for idx := range findings {
		finding := &findings[idx]
		if reason, ok := suppressionReason(*finding); ok {
			finding.Suppressed = true
			finding.SuppressionReason = reason
		}
	}
}

func suppressionReason(finding storesqlite.FindingRecord) (string, bool) {
	title := strings.ToLower(finding.Title)
	evidence := strings.ToLower(finding.Evidence)

	if strings.Contains(title, "user-profile autorun: discord") ||
		strings.Contains(title, "user-profile autorun: grammarly") ||
		strings.Contains(title, "user-profile autorun: com.squirrel.slack.slack") ||
		strings.Contains(title, "user-profile autorun: ciscomeetingdaemon") {
		return "Known common collaboration/productivity autorun; hidden by default to reduce noise.", true
	}

	if strings.Contains(title, "startup-folder item present: aorus engine.lnk") ||
		strings.Contains(title, "startup-folder item present: send to onenote.lnk") {
		return "Known common consumer/application startup item; hidden by default to reduce noise.", true
	}

	if strings.Contains(title, "user-profile scheduled task") &&
		(strings.Contains(evidence, "onedrive") || strings.Contains(evidence, "zoom")) {
		return "Known common updater/startup scheduled task; hidden by default to reduce noise.", true
	}

	return "", false
}
