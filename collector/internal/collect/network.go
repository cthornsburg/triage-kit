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

// NetworkCollector is implemented Windows-first, with macOS/Linux fallback commands kept for local harness verification only.
type NetworkCollector struct{}

type networkCommandSpec struct {
	ArtifactID  string
	Category    string
	Path        string
	Format      string
	Command     string
	Args        []string
	Notes       []string
	StubContent string
}

func (NetworkCollector) Collect(ctx context.Context, caseDir string, collectedAt time.Time) ([]model.ArtifactRecord, []string) {
	specs, platformNotes := networkCommandSpecs()
	if len(specs) == 0 {
		msg := "network collection is not implemented for this platform"
		return []model.ArtifactRecord{{
			ArtifactID:      "network-collection",
			Category:        "network",
			RelativePath:    "network/",
			Format:          "txt",
			SourceCommand:   "unsupported-platform",
			CollectionScope: "system-readable",
			CollectedAt:     collectedAt.Format(time.RFC3339),
			CollectorStatus: "error",
			Error:           &msg,
			Notes:           []string{msg},
			Tags:            []string{"network"},
		}}, []string{msg}
	}

	warnings := append([]string{}, platformNotes...)
	artifacts := make([]model.ArtifactRecord, 0, len(specs))
	for i, spec := range specs {
		record, notes := runCommandArtifact(ctx, caseDir, spec, collectedAt.Add(time.Duration(i)*time.Second))
		artifacts = append(artifacts, record)
		for _, note := range notes {
			warnings = append(warnings, fmt.Sprintf("%s: %s", spec.ArtifactID, note))
		}
	}

	return artifacts, warnings
}

func runCommandArtifact(ctx context.Context, caseDir string, spec networkCommandSpec, collectedAt time.Time) (model.ArtifactRecord, []string) {
	relativePath := filepath.ToSlash(spec.Path)
	artifactPath := filepath.Join(caseDir, filepath.FromSlash(relativePath))
	var output []byte
	source := sourceCommand(spec.Command, spec.Args)
	if spec.Command == "" {
		output = []byte(spec.StubContent)
		source = "non-Windows dev harness stub"
	} else {
		cmd := exec.CommandContext(ctx, spec.Command, spec.Args...)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		var err error
		output, err = cmd.Output()
		if err != nil {
			msg := strings.TrimSpace(stderr.String())
			if msg == "" {
				msg = err.Error()
			}
			return model.ArtifactRecord{
				ArtifactID:      spec.ArtifactID,
				Category:        spec.Category,
				RelativePath:    relativePath,
				Format:          spec.Format,
				SourceCommand:   source,
				CollectionScope: "system-readable",
				CollectedAt:     collectedAt.Format(time.RFC3339),
				CollectorStatus: "error",
				Error:           &msg,
				Notes:           spec.Notes,
				Tags:            networkTags(spec.ArtifactID),
			}, append(spec.Notes, msg)
		}
	}

	if err := os.WriteFile(artifactPath, output, 0o644); err != nil {
		msg := err.Error()
		return model.ArtifactRecord{
			ArtifactID:      spec.ArtifactID,
			Category:        spec.Category,
			RelativePath:    relativePath,
			Format:          spec.Format,
			SourceCommand:   source,
			CollectionScope: "system-readable",
			CollectedAt:     collectedAt.Format(time.RFC3339),
			CollectorStatus: "error",
			Error:           &msg,
			Notes:           spec.Notes,
			Tags:            networkTags(spec.ArtifactID),
		}, append(spec.Notes, msg)
	}

	hash, size, err := checksum.SHA256File(artifactPath)
	if err != nil {
		msg := err.Error()
		return model.ArtifactRecord{
			ArtifactID:      spec.ArtifactID,
			Category:        spec.Category,
			RelativePath:    relativePath,
			Format:          spec.Format,
			SourceCommand:   source,
			CollectionScope: "system-readable",
			CollectedAt:     collectedAt.Format(time.RFC3339),
			CollectorStatus: "error",
			Error:           &msg,
			Notes:           spec.Notes,
			Tags:            networkTags(spec.ArtifactID),
		}, append(spec.Notes, msg)
	}

	status := "ok"
	if len(spec.Notes) > 0 {
		status = "partial"
	}
	return model.ArtifactRecord{
		ArtifactID:      spec.ArtifactID,
		Category:        spec.Category,
		RelativePath:    relativePath,
		Format:          spec.Format,
		SHA256:          hash,
		SizeBytes:       size,
		SourceCommand:   source,
		CollectionScope: "system-readable",
		CollectedAt:     collectedAt.Format(time.RFC3339),
		CollectorStatus: status,
		Notes:           spec.Notes,
		Tags:            networkTags(spec.ArtifactID),
	}, spec.Notes
}

func networkCommandSpecs() ([]networkCommandSpec, []string) {
	switch runtime.GOOS {
	case "windows":
		return []networkCommandSpec{
			{ArtifactID: "network-ipconfig", Category: "network", Path: "network/ipconfig.txt", Format: "txt", Command: "ipconfig", Args: []string{"/all"}},
			{ArtifactID: "network-routes", Category: "network", Path: "network/routes.txt", Format: "txt", Command: "route", Args: []string{"print"}},
			{ArtifactID: "network-connections", Category: "network", Path: "network/net-connections.txt", Format: "txt", Command: "netstat", Args: []string{"-ano"}, Notes: []string{"Windows netstat output is stored as raw text in baseline mode; CSV normalization can come later."}},
			{ArtifactID: "network-dns", Category: "network", Path: "network/dns-info.txt", Format: "txt", Command: "ipconfig", Args: []string{"/displaydns"}, Notes: []string{"DNS cache output is best-effort and may be noisy on busy hosts."}},
			{ArtifactID: "network-wifi-interfaces", Category: "network", Path: "network/wifi-interfaces.txt", Format: "txt", Command: "netsh", Args: []string{"wlan", "show", "interfaces"}, Notes: []string{"Wi-Fi interface state only; no credential material requested or collected."}},
			{ArtifactID: "network-wifi-profiles", Category: "network", Path: "network/wifi-profiles.txt", Format: "txt", Command: "netsh", Args: []string{"wlan", "show", "profiles"}, Notes: []string{"Saved Wi-Fi profile names/metadata only; key reveal option is intentionally not used."}},
			{ArtifactID: "network-bluetooth-devices", Category: "network", Path: "network/bluetooth-devices.txt", Format: "txt", Command: "pnputil", Args: []string{"/enum-devices", "/class", "Bluetooth"}, Notes: []string{"Bluetooth PnP adapter/device context only; this is not a forensic pairing timeline."}},
			{ArtifactID: "network-bluetooth-connected", Category: "network", Path: "network/bluetooth-connected.txt", Format: "txt", Command: "pnputil", Args: []string{"/enum-devices", "/class", "Bluetooth", "/connected"}, Notes: []string{"Connected Bluetooth PnP indicators only; absence may mean unsupported command, disabled service, or no connected Bluetooth hardware."}},
		}, nil
	case "darwin":
		stub := "SEKER non-Windows dev harness stub. Windows-first collector; no secrets collected.\n"
		return []networkCommandSpec{
			{ArtifactID: "network-ipconfig", Category: "network", Path: "network/ipconfig.txt", Format: "txt", Command: "ifconfig", Args: []string{"-a"}, Notes: []string{"macOS dev-harness fallback only; Windows ipconfig /all is the primary target output."}},
			{ArtifactID: "network-routes", Category: "network", Path: "network/routes.txt", Format: "txt", Command: "netstat", Args: []string{"-rn"}, Notes: []string{"macOS dev-harness fallback only; Windows route print is the primary target output."}},
			{ArtifactID: "network-connections", Category: "network", Path: "network/net-connections.txt", Format: "txt", Command: "netstat", Args: []string{"-anv"}, Notes: []string{"macOS dev-harness fallback writes raw netstat text only; Windows netstat -ano remains the primary baseline collector path."}},
			{ArtifactID: "network-dns", Category: "network", Path: "network/dns-info.txt", Format: "txt", Command: "scutil", Args: []string{"--dns"}, Notes: []string{"macOS dev-harness fallback reports resolver state only; Windows ipconfig /displaydns remains the primary baseline collector path."}},
			{ArtifactID: "network-wifi-interfaces", Category: "network", Path: "network/wifi-interfaces.txt", Format: "txt", Notes: []string{"macOS dev-harness stub only; Windows netsh wlan show interfaces is the primary collector."}, StubContent: stub},
			{ArtifactID: "network-wifi-profiles", Category: "network", Path: "network/wifi-profiles.txt", Format: "txt", Notes: []string{"macOS dev-harness stub only; Windows netsh wlan show profiles is used without any key-reveal option."}, StubContent: stub},
			{ArtifactID: "network-bluetooth-devices", Category: "network", Path: "network/bluetooth-devices.txt", Format: "txt", Notes: []string{"macOS dev-harness stub only; Windows pnputil Bluetooth PnP context is the primary collector."}, StubContent: stub},
			{ArtifactID: "network-bluetooth-connected", Category: "network", Path: "network/bluetooth-connected.txt", Format: "txt", Notes: []string{"macOS dev-harness stub only; Windows pnputil connected Bluetooth context is the primary collector."}, StubContent: stub},
		}, nil
	case "linux":
		stub := "SEKER non-Windows dev harness stub. Windows-first collector; no secrets collected.\n"
		return []networkCommandSpec{
			{ArtifactID: "network-ipconfig", Category: "network", Path: "network/ipconfig.txt", Format: "txt", Command: "ip", Args: []string{"address", "show"}, Notes: []string{"Linux dev-harness fallback only; Windows ipconfig /all is the primary target output."}},
			{ArtifactID: "network-routes", Category: "network", Path: "network/routes.txt", Format: "txt", Command: "ip", Args: []string{"route", "show"}, Notes: []string{"Linux dev-harness fallback only; Windows route print is the primary target output."}},
			{ArtifactID: "network-connections", Category: "network", Path: "network/net-connections.txt", Format: "txt", Command: "ss", Args: []string{"-tunap"}, Notes: []string{"Linux dev-harness fallback may omit PID/program details; Windows netstat -ano remains the primary baseline collector path."}},
			{ArtifactID: "network-dns", Category: "network", Path: "network/dns-info.txt", Format: "txt", Command: "cat", Args: []string{"/etc/resolv.conf"}, Notes: []string{"Linux dev-harness fallback may only show stub resolver config; Windows ipconfig /displaydns remains the primary baseline collector path."}},
			{ArtifactID: "network-wifi-interfaces", Category: "network", Path: "network/wifi-interfaces.txt", Format: "txt", Notes: []string{"Linux dev-harness stub only; Windows netsh wlan show interfaces is the primary collector."}, StubContent: stub},
			{ArtifactID: "network-wifi-profiles", Category: "network", Path: "network/wifi-profiles.txt", Format: "txt", Notes: []string{"Linux dev-harness stub only; Windows netsh wlan show profiles is used without any key-reveal option."}, StubContent: stub},
			{ArtifactID: "network-bluetooth-devices", Category: "network", Path: "network/bluetooth-devices.txt", Format: "txt", Notes: []string{"Linux dev-harness stub only; Windows pnputil Bluetooth PnP context is the primary collector."}, StubContent: stub},
			{ArtifactID: "network-bluetooth-connected", Category: "network", Path: "network/bluetooth-connected.txt", Format: "txt", Notes: []string{"Linux dev-harness stub only; Windows pnputil connected Bluetooth context is the primary collector."}, StubContent: stub},
		}, nil
	default:
		return nil, nil
	}
}

func networkTags(artifactID string) []string {
	switch artifactID {
	case "network-ipconfig":
		return []string{"network", "interfaces", "ipconfig"}
	case "network-routes":
		return []string{"network", "routes"}
	case "network-connections":
		return []string{"network", "connections"}
	case "network-dns":
		return []string{"network", "dns"}
	case "network-wifi-interfaces", "network-wifi-profiles":
		return []string{"network", "wifi"}
	case "network-bluetooth-devices", "network-bluetooth-connected":
		return []string{"network", "bluetooth"}
	default:
		return []string{"network"}
	}
}
