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

// ProcessCollector is Windows-first; macOS/Linux exist only as best-effort local plumbing harnesses.
type ProcessCollector struct{}

// ProcessDetailCollector runs only after contamination-sensitive logs have been captured.
// It attempts a richer CIM/WMI-backed process inventory and leaves ProcessCollector's
// tasklist artifact as the restrictive-host fallback.
type ProcessDetailCollector struct{}

func (ProcessCollector) Collect(ctx context.Context, caseDir string, collectedAt time.Time) ([]model.ArtifactRecord, []string) {
	command, args, format, notes := processCommand()
	relativePath := processRelativePath(format)
	artifactPath := filepath.Join(caseDir, filepath.FromSlash(relativePath))
	warnings := append([]string{}, notes...)

	if command == "" {
		msg := "process collection is not implemented for this platform"
		return []model.ArtifactRecord{{
			ArtifactID:      "process-list",
			Category:        "processes",
			RelativePath:    relativePath,
			Format:          "csv",
			SourceCommand:   "unsupported-platform",
			CollectionScope: "system-readable",
			CollectedAt:     collectedAt.Format(time.RFC3339),
			CollectorStatus: "error",
			Error:           &msg,
			Notes:           []string{msg},
			Tags:            []string{"process", "execution"},
		}}, []string{msg}
	}

	cmd := exec.CommandContext(ctx, command, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	output, err := cmd.Output()
	if err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return []model.ArtifactRecord{{
			ArtifactID:      "process-list",
			Category:        "processes",
			RelativePath:    relativePath,
			Format:          format,
			SourceCommand:   sourceCommand(command, args),
			CollectionScope: "system-readable",
			CollectedAt:     collectedAt.Format(time.RFC3339),
			CollectorStatus: "error",
			Error:           &msg,
			Notes:           warnings,
			Tags:            []string{"process", "execution"},
		}}, append(warnings, msg)
	}

	if err := os.WriteFile(artifactPath, output, 0o644); err != nil {
		msg := err.Error()
		return []model.ArtifactRecord{{
			ArtifactID:      "process-list",
			Category:        "processes",
			RelativePath:    relativePath,
			Format:          format,
			SourceCommand:   sourceCommand(command, args),
			CollectionScope: "system-readable",
			CollectedAt:     collectedAt.Format(time.RFC3339),
			CollectorStatus: "error",
			Error:           &msg,
			Notes:           warnings,
			Tags:            []string{"process", "execution"},
		}}, append(warnings, msg)
	}

	hash, size, err := checksum.SHA256File(artifactPath)
	if err != nil {
		msg := err.Error()
		return []model.ArtifactRecord{{
			ArtifactID:      "process-list",
			Category:        "processes",
			RelativePath:    relativePath,
			Format:          format,
			SourceCommand:   sourceCommand(command, args),
			CollectionScope: "system-readable",
			CollectedAt:     collectedAt.Format(time.RFC3339),
			CollectorStatus: "error",
			Error:           &msg,
			Notes:           warnings,
			Tags:            []string{"process", "execution"},
		}}, append(warnings, msg)
	}

	status := "ok"
	if len(warnings) > 0 {
		status = "partial"
	}

	return []model.ArtifactRecord{{
		ArtifactID:      "process-list",
		Category:        "processes",
		RelativePath:    relativePath,
		Format:          format,
		SHA256:          hash,
		SizeBytes:       size,
		SourceCommand:   sourceCommand(command, args),
		CollectionScope: "system-readable",
		CollectedAt:     collectedAt.Format(time.RFC3339),
		CollectorStatus: status,
		Notes:           warnings,
		Tags:            []string{"process", "execution"},
	}}, warnings
}

func (ProcessDetailCollector) Collect(ctx context.Context, caseDir string, collectedAt time.Time) ([]model.ArtifactRecord, []string) {
	if runtime.GOOS != "windows" {
		note := "richer process detail is Windows-only; dev-harness fallback uses processes/process-list.txt"
		return nil, []string{note}
	}

	command, args := processDetailCommand()
	relativePath := "processes/process-details.csv"
	artifactPath := filepath.Join(caseDir, filepath.FromSlash(relativePath))
	notes := []string{"richer process detail uses PowerShell/CIM after log snapshots; processes/process-list.csv remains the fallback artifact"}

	cmd := exec.CommandContext(ctx, command, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	output, err := cmd.Output()
	if err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		note := "richer process detail unavailable; using tasklist fallback process-list.csv"
		return []model.ArtifactRecord{processDetailRecord(collectedAt, "partial", 0, sourceCommand(command, args), stringPtr(msg), append(notes, note))}, []string{note, msg}
	}

	if len(bytes.TrimSpace(output)) == 0 {
		msg := "richer process detail command returned no rows"
		note := "richer process detail unavailable; using tasklist fallback process-list.csv"
		return []model.ArtifactRecord{processDetailRecord(collectedAt, "partial", 0, sourceCommand(command, args), stringPtr(msg), append(notes, note))}, []string{note, msg}
	}

	if err := os.WriteFile(artifactPath, output, 0o644); err != nil {
		msg := err.Error()
		return []model.ArtifactRecord{processDetailRecord(collectedAt, "partial", 0, sourceCommand(command, args), stringPtr(msg), notes)}, []string{msg}
	}

	hash, size, err := checksum.SHA256File(artifactPath)
	if err != nil {
		msg := err.Error()
		return []model.ArtifactRecord{processDetailRecord(collectedAt, "partial", 0, sourceCommand(command, args), stringPtr(msg), notes)}, []string{msg}
	}

	record := processDetailRecord(collectedAt, "ok", size, sourceCommand(command, args), nil, notes)
	record.SHA256 = hash
	record.RelativePath = relativePath
	return []model.ArtifactRecord{record}, nil
}

func processCommand() (string, []string, string, []string) {
	switch runtime.GOOS {
	case "windows":
		return "tasklist", []string{"/fo", "csv", "/v"}, "csv", []string{"tasklist /fo csv /v fallback does not include PPID or full command line; see processes/process-details.csv when richer detail is available."}
	case "darwin":
		return "ps", []string{"-Ao", "pid,ppid,user,comm,args"}, "txt", []string{"macOS dev-harness fallback writes raw ps output only; Windows remains the primary process collector target."}
	case "linux":
		return "ps", []string{"-eo", "pid,ppid,user,comm,args"}, "txt", []string{"Linux dev-harness fallback writes raw ps output only; Windows remains the primary process collector target."}
	default:
		return "", nil, "csv", nil
	}
}

func processDetailCommand() (string, []string) {
	script := `$ErrorActionPreference = 'Stop'; Get-CimInstance Win32_Process | Select-Object @{Name='PID';Expression={$_.ProcessId}},@{Name='PPID';Expression={$_.ParentProcessId}},@{Name='Name';Expression={$_.Name}},@{Name='ExecutablePath';Expression={$_.ExecutablePath}},@{Name='CommandLine';Expression={$_.CommandLine}},@{Name='UserName';Expression={try { $owner = Invoke-CimMethod -InputObject $_ -MethodName GetOwner; if ($owner.User) { if ($owner.Domain) { "$($owner.Domain)\$($owner.User)" } else { $owner.User } } else { '' } } catch { '' }}} | ConvertTo-Csv -NoTypeInformation`
	return "powershell.exe", []string{"-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script}
}

func processDetailRecord(collectedAt time.Time, status string, size int64, source string, errPtr *string, notes []string) model.ArtifactRecord {
	relativePath := "processes/process-details.csv"
	if runtime.GOOS != "windows" {
		relativePath = "processes/process-list.txt"
	} else if size == 0 {
		relativePath = "processes/process-list.csv"
	}
	return model.ArtifactRecord{
		ArtifactID:      "process-details",
		Category:        "processes",
		RelativePath:    relativePath,
		Format:          "csv",
		SizeBytes:       size,
		SourceCommand:   source,
		CollectionScope: "system-readable",
		CollectedAt:     collectedAt.Format(time.RFC3339),
		CollectorStatus: status,
		Error:           errPtr,
		Notes:           notes,
		Tags:            []string{"process", "execution", "process-detail"},
	}
}

func processRelativePath(format string) string {
	if format == "txt" {
		return "processes/process-list.txt"
	}
	return "processes/process-list.csv"
}

func sourceCommand(command string, args []string) string {
	return strings.TrimSpace(fmt.Sprintf("%s %s", command, strings.Join(args, " ")))
}

func stringPtr(value string) *string {
	return &value
}
