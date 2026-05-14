package collect

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/chip/incident-response-kit/collector/internal/checksum"
	"github.com/chip/incident-response-kit/collector/internal/model"
)

// LogsCollector is Windows-first and targets readable baseline event-log slices without elevation.
type LogsCollector struct{}

type logSpec struct {
	ArtifactID string
	Path       string
	Format     string
	Command    string
	Args       []string
	Notes      []string
	Tags       []string
}

func (LogsCollector) Collect(ctx context.Context, caseDir string, collectedAt time.Time) ([]model.ArtifactRecord, []string) {
	specs, warnings := logSpecs()
	if len(specs) == 0 {
		msg := "readable log collection is not implemented for this platform"
		return []model.ArtifactRecord{{
			ArtifactID:      "logs-collection",
			Category:        "logs",
			RelativePath:    "logs/",
			Format:          "txt",
			SourceCommand:   "unsupported-platform",
			CollectionScope: "best-effort",
			CollectedAt:     collectedAt.Format(time.RFC3339),
			CollectorStatus: "error",
			Error:           &msg,
			Notes:           []string{msg},
			Tags:            []string{"logs"},
		}}, []string{msg}
	}

	artifacts := make([]model.ArtifactRecord, 0, len(specs))
	allWarnings := append([]string{}, warnings...)
	for i, spec := range specs {
		record, notes := runLogSpec(ctx, caseDir, spec, collectedAt.Add(time.Duration(i)*time.Second))
		artifacts = append(artifacts, record)
		allWarnings = append(allWarnings, notes...)
	}
	return artifacts, allWarnings
}

func runLogSpec(ctx context.Context, caseDir string, spec logSpec, collectedAt time.Time) (model.ArtifactRecord, []string) {
	relativePath := filepath.ToSlash(spec.Path)
	artifactPath := filepath.Join(caseDir, filepath.FromSlash(relativePath))
	cmd := exec.CommandContext(ctx, spec.Command, spec.Args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	output, err := cmd.Output()
	if err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		notes := append([]string{}, spec.Notes...)
		notes = append(notes, fmt.Sprintf("%s: %s", spec.ArtifactID, msg))
		return model.ArtifactRecord{
			ArtifactID:      spec.ArtifactID,
			Category:        "logs",
			RelativePath:    relativePath,
			Format:          spec.Format,
			SourceCommand:   sourceCommand(spec.Command, spec.Args),
			CollectionScope: "best-effort",
			CollectedAt:     collectedAt.Format(time.RFC3339),
			CollectorStatus: "error",
			Error:           &msg,
			Notes:           spec.Notes,
			Tags:            spec.Tags,
		}, notes
	}

	if err := os.WriteFile(artifactPath, output, 0o644); err != nil {
		msg := err.Error()
		notes := append([]string{}, spec.Notes...)
		notes = append(notes, fmt.Sprintf("%s: %s", spec.ArtifactID, msg))
		return model.ArtifactRecord{
			ArtifactID:      spec.ArtifactID,
			Category:        "logs",
			RelativePath:    relativePath,
			Format:          spec.Format,
			SourceCommand:   sourceCommand(spec.Command, spec.Args),
			CollectionScope: "best-effort",
			CollectedAt:     collectedAt.Format(time.RFC3339),
			CollectorStatus: "error",
			Error:           &msg,
			Notes:           spec.Notes,
			Tags:            spec.Tags,
		}, notes
	}

	hash, size, err := checksum.SHA256File(artifactPath)
	if err != nil {
		msg := err.Error()
		notes := append([]string{}, spec.Notes...)
		notes = append(notes, fmt.Sprintf("%s: %s", spec.ArtifactID, msg))
		return model.ArtifactRecord{
			ArtifactID:      spec.ArtifactID,
			Category:        "logs",
			RelativePath:    relativePath,
			Format:          spec.Format,
			SourceCommand:   sourceCommand(spec.Command, spec.Args),
			CollectionScope: "best-effort",
			CollectedAt:     collectedAt.Format(time.RFC3339),
			CollectorStatus: "error",
			Error:           &msg,
			Notes:           spec.Notes,
			Tags:            spec.Tags,
		}, notes
	}

	status := "ok"
	if len(spec.Notes) > 0 {
		status = "partial"
	}
	return model.ArtifactRecord{
		ArtifactID:      spec.ArtifactID,
		Category:        "logs",
		RelativePath:    relativePath,
		Format:          spec.Format,
		SHA256:          hash,
		SizeBytes:       size,
		SourceCommand:   sourceCommand(spec.Command, spec.Args),
		CollectionScope: "best-effort",
		CollectedAt:     collectedAt.Format(time.RFC3339),
		CollectorStatus: status,
		Notes:           spec.Notes,
		Tags:            spec.Tags,
	}, spec.Notes
}

func logSpecs() ([]logSpec, []string) {
	switch runtime.GOOS {
	case "windows":
		const recentEventLimit = "/c:1000"
		limitNote := "SEKER baseline collects the most recent 1000 readable events from this log, not the endpoint's full historical Event Log. Treat counts as collected-record counts."
		return []logSpec{
			{ArtifactID: "logs-application", Path: "logs/application-events.txt", Format: "txt", Command: "wevtutil", Args: []string{"qe", "Application", recentEventLimit, "/rd:true", "/f:text"}, Tags: []string{"logs", "application"}, Notes: []string{limitNote}},
			{ArtifactID: "logs-system", Path: "logs/system-events.txt", Format: "txt", Command: "wevtutil", Args: []string{"qe", "System", recentEventLimit, "/rd:true", "/f:text"}, Tags: []string{"logs", "system"}, Notes: []string{limitNote}},
			{ArtifactID: "logs-powershell", Path: "logs/powershell-operational.txt", Format: "txt", Command: "wevtutil", Args: []string{"qe", "Microsoft-Windows-PowerShell/Operational", recentEventLimit, "/rd:true", "/f:text"}, Tags: []string{"logs", "powershell"}, Notes: []string{limitNote, "PowerShell operational log availability varies by host configuration; missing or empty output should be treated as best-effort."}},
			{ArtifactID: "logs-defender", Path: "logs/defender-operational.txt", Format: "txt", Command: "wevtutil", Args: []string{"qe", "Microsoft-Windows-Windows Defender/Operational", recentEventLimit, "/rd:true", "/f:text"}, Tags: []string{"logs", "defender"}, Notes: []string{limitNote, "Defender operational log availability varies by host role and product state; missing or empty output should be treated as best-effort."}},
		}, nil
	case "darwin":
		return []logSpec{
			{ArtifactID: "logs-system", Path: "logs/system-events.txt", Format: "txt", Command: "log", Args: []string{"show", "--style", "syslog", "--last", "1h"}, Tags: []string{"logs", "system"}, Notes: []string{"macOS dev-harness fallback only; Windows Event Log collection remains the primary target."}},
		}, nil
	case "linux":
		return []logSpec{
			{ArtifactID: "logs-system", Path: "logs/system-events.txt", Format: "txt", Command: "sh", Args: []string{"-c", `journalctl -n 100 --no-pager 2>&1 || true`}, Tags: []string{"logs", "system"}, Notes: []string{"Linux dev-harness fallback only; Windows Event Log collection remains the primary target."}},
		}, nil
	default:
		return nil, nil
	}
}
