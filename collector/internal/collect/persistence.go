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

// PersistenceCollector is organized around Windows-first baseline checks; macOS/Linux are best-effort fallback harnesses.
type PersistenceCollector struct{}

type persistenceSpec struct {
	ArtifactID   string
	Path         string
	Format       string
	Command      string
	Args         []string
	Notes        []string
	Tags         []string
	BenignNoData []string
}

func (PersistenceCollector) Collect(ctx context.Context, caseDir string, collectedAt time.Time) ([]model.ArtifactRecord, []string) {
	specs, warnings := persistenceSpecs()
	if len(specs) == 0 {
		msg := "persistence collection is not implemented for this platform"
		return []model.ArtifactRecord{{
			ArtifactID:      "persistence-collection",
			Category:        "persistence",
			RelativePath:    "persistence/",
			Format:          "txt",
			SourceCommand:   "unsupported-platform",
			CollectionScope: "user",
			CollectedAt:     collectedAt.Format(time.RFC3339),
			CollectorStatus: "error",
			Error:           &msg,
			Notes:           []string{msg},
			Tags:            []string{"persistence"},
		}}, []string{msg}
	}

	artifacts := make([]model.ArtifactRecord, 0, len(specs))
	allWarnings := append([]string{}, warnings...)
	for i, spec := range specs {
		record, notes := runPersistenceSpec(ctx, caseDir, spec, collectedAt.Add(time.Duration(i)*time.Second))
		artifacts = append(artifacts, record)
		allWarnings = append(allWarnings, notes...)
	}
	return artifacts, allWarnings
}

func runPersistenceSpec(ctx context.Context, caseDir string, spec persistenceSpec, collectedAt time.Time) (model.ArtifactRecord, []string) {
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
		if isBenignPersistenceNoData(msg, spec.BenignNoData) {
			content := strings.TrimSpace(msg) + "\n"
			if writeErr := os.WriteFile(artifactPath, []byte(content), 0o644); writeErr == nil {
				hash, size, hashErr := checksum.SHA256File(artifactPath)
				if hashErr == nil {
					notes := append([]string{}, spec.Notes...)
					notes = append(notes, fmt.Sprintf("%s: %s", spec.ArtifactID, msg))
					return model.ArtifactRecord{
						ArtifactID:      spec.ArtifactID,
						Category:        "persistence",
						RelativePath:    relativePath,
						Format:          spec.Format,
						SHA256:          hash,
						SizeBytes:       size,
						SourceCommand:   sourceCommand(spec.Command, spec.Args),
						CollectionScope: persistenceScope(spec.ArtifactID),
						CollectedAt:     collectedAt.Format(time.RFC3339),
						CollectorStatus: "partial",
						Notes:           notes,
						Tags:            spec.Tags,
					}, notes
				}
			}
		}
		notes := append([]string{}, spec.Notes...)
		notes = append(notes, fmt.Sprintf("%s: %s", spec.ArtifactID, msg))
		return model.ArtifactRecord{
			ArtifactID:      spec.ArtifactID,
			Category:        "persistence",
			RelativePath:    relativePath,
			Format:          spec.Format,
			SourceCommand:   sourceCommand(spec.Command, spec.Args),
			CollectionScope: persistenceScope(spec.ArtifactID),
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
			Category:        "persistence",
			RelativePath:    relativePath,
			Format:          spec.Format,
			SourceCommand:   sourceCommand(spec.Command, spec.Args),
			CollectionScope: persistenceScope(spec.ArtifactID),
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
			Category:        "persistence",
			RelativePath:    relativePath,
			Format:          spec.Format,
			SourceCommand:   sourceCommand(spec.Command, spec.Args),
			CollectionScope: persistenceScope(spec.ArtifactID),
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
	if strings.TrimSpace(string(output)) == "" && len(spec.Notes) == 0 {
		status = "partial"
	}
	return model.ArtifactRecord{
		ArtifactID:      spec.ArtifactID,
		Category:        "persistence",
		RelativePath:    relativePath,
		Format:          spec.Format,
		SHA256:          hash,
		SizeBytes:       size,
		SourceCommand:   sourceCommand(spec.Command, spec.Args),
		CollectionScope: persistenceScope(spec.ArtifactID),
		CollectedAt:     collectedAt.Format(time.RFC3339),
		CollectorStatus: status,
		Notes:           spec.Notes,
		Tags:            spec.Tags,
	}, spec.Notes
}

func persistenceSpecs() ([]persistenceSpec, []string) {
	switch runtime.GOOS {
	case "windows":
		return []persistenceSpec{
			{ArtifactID: "persistence-user-run", Path: "persistence/hkcu-run.txt", Format: "txt", Command: "reg", Args: []string{"query", `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`}, Tags: []string{"persistence", "autorun", "registry"}},
			{ArtifactID: "persistence-user-runonce", Path: "persistence/hkcu-runonce.txt", Format: "txt", Command: "reg", Args: []string{"query", `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`}, Tags: []string{"persistence", "autorun", "registry"}, Notes: []string{"RunOnce may be empty on healthy systems; empty output is not itself suspicious."}, BenignNoData: []string{"unable to find the specified registry key or value"}},
			{ArtifactID: "persistence-startup-folder", Path: "persistence/startup-folder.txt", Format: "txt", Command: "powershell", Args: []string{"-NoProfile", "-Command", `Get-ChildItem -Force (Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\Startup') | Format-List Mode,LastWriteTime,Length,Name,FullName`}, Tags: []string{"persistence", "startup-folder"}, Notes: []string{"Startup folder listing is limited to the current user in baseline mode."}, BenignNoData: []string{"cannot find path", "path not found"}},
			{ArtifactID: "persistence-scheduled-tasks", Path: "persistence/scheduled-tasks.csv", Format: "txt", Command: "schtasks", Args: []string{"/query", "/fo", "csv", "/v"}, Tags: []string{"persistence", "scheduled-tasks"}, Notes: []string{"Verbose scheduled-task output can be large; baseline collector stores raw CSV text."}},
		}, nil
	case "darwin":
		return []persistenceSpec{
			{ArtifactID: "persistence-launchagents-user", Path: "persistence/launchagents-user.txt", Format: "txt", Command: "sh", Args: []string{"-c", `ls -la ~/Library/LaunchAgents 2>&1 || true`}, Tags: []string{"persistence", "launchagents", "user"}, Notes: []string{"macOS dev-harness fallback only; Windows HKCU Run/RunOnce and Startup folder remain the primary baseline persistence targets."}},
			{ArtifactID: "persistence-login-items", Path: "persistence/login-items.txt", Format: "txt", Command: "osascript", Args: []string{"-e", `tell application "System Events" to get the name of every login item`}, Tags: []string{"persistence", "login-items"}, Notes: []string{"macOS dev-harness fallback only; login item enumeration also depends on Automation permission."}},
			{ArtifactID: "persistence-launchd-list", Path: "persistence/launchd-list.txt", Format: "txt", Command: "launchctl", Args: []string{"list"}, Tags: []string{"persistence", "launchd"}, Notes: []string{"macOS dev-harness fallback only; launchctl list includes active jobs beyond persistence-specific entries."}},
			{ArtifactID: "persistence-crontab", Path: "persistence/crontab.txt", Format: "txt", Command: "sh", Args: []string{"-c", `crontab -l 2>&1 || true`}, Tags: []string{"persistence", "cron"}, Notes: []string{"macOS dev-harness fallback only; user crontab may be absent."}},
		}, nil
	case "linux":
		return []persistenceSpec{
			{ArtifactID: "persistence-autostart", Path: "persistence/autostart.txt", Format: "txt", Command: "sh", Args: []string{"-c", `ls -la ~/.config/autostart 2>&1 || true`}, Tags: []string{"persistence", "autostart"}, Notes: []string{"Linux dev-harness fallback only; Windows HKCU Run/RunOnce and Startup folder remain the primary baseline persistence targets."}},
			{ArtifactID: "persistence-systemd-user", Path: "persistence/systemd-user.txt", Format: "txt", Command: "systemctl", Args: []string{"--user", "list-unit-files"}, Tags: []string{"persistence", "systemd", "user"}, Notes: []string{"Linux dev-harness fallback only; systemctl --user output can include non-persistence units."}},
			{ArtifactID: "persistence-crontab", Path: "persistence/crontab.txt", Format: "txt", Command: "sh", Args: []string{"-c", `crontab -l 2>&1 || true`}, Tags: []string{"persistence", "cron"}, Notes: []string{"Linux dev-harness fallback only; user crontab may be absent."}},
		}, nil
	default:
		return nil, nil
	}
}

func persistenceScope(artifactID string) string {
	switch artifactID {
	case "persistence-user-run", "persistence-user-runonce", "persistence-startup-folder", "persistence-launchagents-user", "persistence-login-items", "persistence-autostart", "persistence-crontab":
		return "user"
	default:
		return "system-readable"
	}
}

func isBenignPersistenceNoData(message string, signatures []string) bool {
	message = strings.ToLower(strings.TrimSpace(message))
	for _, signature := range signatures {
		if strings.Contains(message, strings.ToLower(signature)) {
			return true
		}
	}
	return false
}
