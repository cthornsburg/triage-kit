package collect

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/chip/incident-response-kit/collector/internal/checksum"
	"github.com/chip/incident-response-kit/collector/internal/model"
)

// SoftwareCollector collects installed-program inventory from Windows uninstall registry keys.
type SoftwareCollector struct{}

type installedProgram struct {
	DisplayName       string `json:"display_name"`
	Publisher         string `json:"publisher,omitempty"`
	DisplayVersion    string `json:"display_version,omitempty"`
	InstallDate       string `json:"install_date,omitempty"`
	InstallDateStatus string `json:"install_date_status"`
	InstallLocation   string `json:"install_location,omitempty"`
	InstallSource     string `json:"install_source,omitempty"`
	UninstallString   string `json:"uninstall_string,omitempty"`
	QuietUninstall    string `json:"quiet_uninstall_string,omitempty"`
	Scope             string `json:"scope"`
	SourceHive        string `json:"source_hive"`
	SourcePath        string `json:"source_path"`
	SourceKeyName     string `json:"source_key_name"`
}

var compactDatePattern = regexp.MustCompile(`^\d{8}$`)

func installDateStatus(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "missing"
	}
	if compactDatePattern.MatchString(value) {
		return "present_yyyymmdd_unverified"
	}
	return "present_unreliable_format"
}

func writeSoftwareJSON(caseDir string, programs []installedProgram, collectedAt time.Time, status string, notes []string, errPtr *string) (model.ArtifactRecord, []string) {
	relativePath := "software/installed-programs.json"
	artifactPath := filepath.Join(caseDir, filepath.FromSlash(relativePath))
	data, err := json.MarshalIndent(programs, "", "  ")
	if err != nil {
		msg := err.Error()
		return softwareRecord(collectedAt, statusOrError(status), 0, "", &msg, notes), append(notes, msg)
	}
	if err := os.WriteFile(artifactPath, append(data, '\n'), 0o644); err != nil {
		msg := err.Error()
		return softwareRecord(collectedAt, statusOrError(status), 0, "", &msg, notes), append(notes, msg)
	}
	hash, size, err := checksum.SHA256File(artifactPath)
	if err != nil {
		msg := err.Error()
		return softwareRecord(collectedAt, statusOrError(status), 0, "", &msg, notes), append(notes, msg)
	}
	return softwareRecord(collectedAt, status, size, hash, errPtr, notes), notes
}

func statusOrError(status string) string {
	if status == "error" {
		return status
	}
	return "error"
}

func softwareRecord(collectedAt time.Time, status string, size int64, hash string, errPtr *string, notes []string) model.ArtifactRecord {
	return model.ArtifactRecord{
		ArtifactID:      "software-installed-programs",
		Category:        "software",
		RelativePath:    "software/installed-programs.json",
		Format:          "json",
		SHA256:          hash,
		SizeBytes:       size,
		SourceCommand:   `Windows uninstall registry hives: HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall; HKLM\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall; HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall`,
		CollectionScope: "system-readable",
		CollectedAt:     collectedAt.Format(time.RFC3339),
		CollectorStatus: status,
		Error:           errPtr,
		Notes:           notes,
		Tags:            []string{"software", "installed-programs", "uninstall-registry"},
	}
}
