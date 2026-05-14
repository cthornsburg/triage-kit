package collect

import (
	"bytes"
	"context"
	"encoding/json"
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

// SecurityCollector collects low-risk Windows security posture after log capture.
type SecurityCollector struct{}

type defenderStatus struct {
	Source                 string         `json:"source"`
	Confidence             string         `json:"confidence"`
	Status                 string         `json:"status"`
	Fields                 map[string]any `json:"fields,omitempty"`
	WinDefendServiceStatus string         `json:"win_defend_service_status,omitempty"`
	Notes                  []string       `json:"notes,omitempty"`
	Error                  string         `json:"error,omitempty"`
}

type securityToolHint struct {
	Name       string `json:"name"`
	Kind       string `json:"kind"`
	Source     string `json:"source"`
	Confidence string `json:"confidence"`
	MatchedOn  string `json:"matched_on,omitempty"`
}

type securityProducts struct {
	Source     string             `json:"source"`
	Confidence string             `json:"confidence"`
	Tools      []securityToolHint `json:"tools"`
	Notes      []string           `json:"notes,omitempty"`
}

func (SecurityCollector) Collect(ctx context.Context, caseDir string, collectedAt time.Time) ([]model.ArtifactRecord, []string) {
	if runtime.GOOS != "windows" {
		note := "security posture collection is Windows-only; skipped in local dev harness"
		return nil, []string{note}
	}

	records := make([]model.ArtifactRecord, 0, 3)
	warnings := []string{}

	firewall, firewallNotes := collectFirewall(ctx, caseDir, collectedAt)
	records = append(records, firewall)
	warnings = appendPrefixed(warnings, "security-firewall", firewallNotes)

	defender, defenderNotes := collectDefender(ctx, caseDir, collectedAt.Add(time.Second))
	records = append(records, defender)
	warnings = appendPrefixed(warnings, "security-defender", defenderNotes)

	products, productNotes := collectSecurityProducts(ctx, caseDir, collectedAt.Add(2*time.Second))
	records = append(records, products)
	warnings = appendPrefixed(warnings, "security-products", productNotes)

	return records, warnings
}

func collectFirewall(ctx context.Context, caseDir string, collectedAt time.Time) (model.ArtifactRecord, []string) {
	spec := networkCommandSpec{ArtifactID: "security-firewall", Category: "security", Path: "security/firewall-status.txt", Format: "txt", Command: "netsh", Args: []string{"advfirewall", "show", "allprofiles"}, Notes: []string{"Windows Firewall profile posture from netsh; interpret source text rather than assuming pass/fail."}}
	record, notes := runCommandArtifact(ctx, caseDir, spec, collectedAt)
	record.Tags = []string{"security", "firewall", "posture"}
	return record, notes
}

func collectDefender(ctx context.Context, caseDir string, collectedAt time.Time) (model.ArtifactRecord, []string) {
	status := defenderStatus{Source: "Get-MpComputerStatus + sc query WinDefend", Confidence: "medium", Status: "partial", Fields: map[string]any{}, Notes: []string{"Get-MpComputerStatus is best-effort and may be unavailable when Defender is disabled, replaced, or policy-restricted."}}
	script := `$fields='AMServiceEnabled','AntivirusEnabled','RealTimeProtectionEnabled','BehaviorMonitorEnabled','AntispywareEnabled','IoavProtectionEnabled','AntivirusSignatureVersion','AntispywareSignatureVersion','NISSignatureVersion','AntivirusSignatureLastUpdated','AntispywareSignatureLastUpdated','NISSignatureLastUpdated','QuickScanStartTime','QuickScanEndTime','FullScanStartTime','FullScanEndTime','LastQuickScanSource','LastFullScanSource'; try { Get-MpComputerStatus | Select-Object $fields | ConvertTo-Json -Depth 3 -Compress } catch { Write-Error $_; exit 1 }`
	out, errText, err := runCommand(ctx, "powershell.exe", []string{"-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script})
	if err == nil && len(bytes.TrimSpace(out)) > 0 {
		var fields map[string]any
		if jsonErr := json.Unmarshal(out, &fields); jsonErr == nil {
			status.Fields = fields
			status.Status = "ok"
			status.Confidence = "high"
		} else {
			status.Error = "Get-MpComputerStatus JSON parse failed: " + jsonErr.Error()
			status.Notes = append(status.Notes, status.Error)
		}
	} else {
		status.Error = strings.TrimSpace(errText)
		if status.Error == "" && err != nil {
			status.Error = err.Error()
		}
		status.Confidence = "low"
		status.Notes = append(status.Notes, "Defender posture unavailable from Get-MpComputerStatus; WinDefend service status retained as fallback context.")
	}

	serviceOut, _, _ := runCommand(ctx, "sc.exe", []string{"query", "WinDefend"})
	status.WinDefendServiceStatus = strings.TrimSpace(string(serviceOut))
	if status.WinDefendServiceStatus == "" {
		serviceOut, _, _ = runCommand(ctx, "sc", []string{"query", "WinDefend"})
		status.WinDefendServiceStatus = strings.TrimSpace(string(serviceOut))
	}
	if status.WinDefendServiceStatus == "" {
		status.Notes = append(status.Notes, "WinDefend service status unavailable")
	}

	return writeSecurityJSON(caseDir, "security/defender-status.json", "security-defender", status, "powershell.exe Get-MpComputerStatus; sc query WinDefend", collectedAt, status.Status, status.Notes)
}

func collectSecurityProducts(ctx context.Context, caseDir string, collectedAt time.Time) (model.ArtifactRecord, []string) {
	products := securityProducts{Source: "tasklist /fo csv /v + sc query type= service state= all", Confidence: "low", Tools: []securityToolHint{}, Notes: []string{"Security-tool hints are keyword matches against readable process/service names; use as leads, not installed-product proof."}}
	seen := map[string]struct{}{}
	processOut, _, _ := runCommand(ctx, "tasklist", []string{"/fo", "csv", "/v"})
	serviceOut, _, _ := runCommand(ctx, "sc.exe", []string{"query", "type=", "service", "state=", "all"})
	if len(serviceOut) == 0 {
		serviceOut, _, _ = runCommand(ctx, "sc", []string{"query", "type=", "service", "state=", "all"})
	}
	for _, hint := range matchSecurityHints("process", "tasklist", string(processOut)) {
		key := hint.Kind + ":" + strings.ToLower(hint.Name)
		if _, ok := seen[key]; !ok {
			products.Tools = append(products.Tools, hint)
			seen[key] = struct{}{}
		}
	}
	for _, hint := range matchSecurityHints("service", "sc query", string(serviceOut)) {
		key := hint.Kind + ":" + strings.ToLower(hint.Name)
		if _, ok := seen[key]; !ok {
			products.Tools = append(products.Tools, hint)
			seen[key] = struct{}{}
		}
	}
	if len(products.Tools) > 0 {
		products.Confidence = "medium"
	}
	return writeSecurityJSON(caseDir, "security/security-products.json", "security-products", products, products.Source, collectedAt, "ok", products.Notes)
}

func matchSecurityHints(kind, source, content string) []securityToolHint {
	patterns := []string{"crowdstrike", "csagent", "sentinelone", "sentinelagent", "carbonblack", "cbdefense", "cylance", "sophos", "mcafee", "trellix", "symantec", "sep", "tanium", "defender", "windefend", "msmpeng", "sense", "mdatp", "elastic", "osquery", "splunk", "qualys", "rapid7", "falcon"}
	lines := strings.Split(content, "\n")
	hints := []securityToolHint{}
	for _, line := range lines {
		lower := strings.ToLower(line)
		for _, pattern := range patterns {
			if strings.Contains(lower, pattern) {
				hints = append(hints, securityToolHint{Name: pattern, Kind: kind, Source: source, Confidence: "low", MatchedOn: strings.TrimSpace(line)})
				break
			}
		}
	}
	return hints
}

func writeSecurityJSON(caseDir, relativePath, artifactID string, value any, source string, collectedAt time.Time, status string, notes []string) (model.ArtifactRecord, []string) {
	artifactPath := filepath.Join(caseDir, filepath.FromSlash(relativePath))
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		msg := err.Error()
		return securityRecord(artifactID, relativePath, source, collectedAt, "error", 0, "", &msg, notes), append(notes, msg)
	}
	if err := os.WriteFile(artifactPath, append(data, '\n'), 0o644); err != nil {
		msg := err.Error()
		return securityRecord(artifactID, relativePath, source, collectedAt, "error", 0, "", &msg, notes), append(notes, msg)
	}
	hash, size, err := checksum.SHA256File(artifactPath)
	if err != nil {
		msg := err.Error()
		return securityRecord(artifactID, relativePath, source, collectedAt, "error", 0, "", &msg, notes), append(notes, msg)
	}
	return securityRecord(artifactID, relativePath, source, collectedAt, status, size, hash, nil, notes), notes
}

func securityRecord(artifactID, relativePath, source string, collectedAt time.Time, status string, size int64, hash string, errPtr *string, notes []string) model.ArtifactRecord {
	return model.ArtifactRecord{ArtifactID: artifactID, Category: "security", RelativePath: filepath.ToSlash(relativePath), Format: "json", SHA256: hash, SizeBytes: size, SourceCommand: source, CollectionScope: "system-readable", CollectedAt: collectedAt.Format(time.RFC3339), CollectorStatus: status, Error: errPtr, Notes: notes, Tags: []string{"security", "posture"}}
}

func runCommand(ctx context.Context, command string, args []string) ([]byte, string, error) {
	cmd := exec.CommandContext(ctx, command, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	return out, strings.TrimSpace(stderr.String()), err
}

func appendPrefixed(target []string, prefix string, notes []string) []string {
	for _, note := range notes {
		if strings.TrimSpace(note) != "" {
			target = append(target, fmt.Sprintf("%s: %s", prefix, note))
		}
	}
	return target
}
