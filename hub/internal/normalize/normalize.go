package normalize

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	storesqlite "github.com/chip/incident-response-kit/hub/internal/store/sqlite"
)

type CaseNormalizationResult struct {
	CaseUUID     string              `json:"case_uuid"`
	CaseID       string              `json:"case_id"`
	Hostname     string              `json:"hostname"`
	NormalizedAt string              `json:"normalized_at"`
	Artifacts    map[string]Artifact `json:"artifacts"`
	Warnings     []string            `json:"warnings,omitempty"`
}

type Artifact struct {
	SourcePath string `json:"source_path"`
	OutputPath string `json:"output_path"`
	Count      int    `json:"count,omitempty"`
	Status     string `json:"status"`
	Note       string `json:"note,omitempty"`
}

type HostIdentity struct {
	Hostname             string            `json:"hostname"`
	Username             string            `json:"username"`
	Domain               string            `json:"domain,omitempty"`
	Workgroup            string            `json:"workgroup,omitempty"`
	AccountScope         string            `json:"account_scope,omitempty"`
	ProfilePath          string            `json:"profile_path,omitempty"`
	LogonServer          string            `json:"logon_server,omitempty"`
	SessionName          string            `json:"session_name,omitempty"`
	ClientName           string            `json:"client_name,omitempty"`
	OSFamily             string            `json:"os_family"`
	OSVersion            string            `json:"os_version,omitempty"`
	Architecture         string            `json:"architecture,omitempty"`
	Timezone             string            `json:"timezone,omitempty"`
	BootTime             string            `json:"boot_time,omitempty"`
	UptimeSeconds        *int64            `json:"uptime_seconds,omitempty"`
	UptimeHuman          string            `json:"uptime_human,omitempty"`
	BootTimeSource       string            `json:"boot_time_source,omitempty"`
	BootTimeConfidence   string            `json:"boot_time_confidence,omitempty"`
	Environment          map[string]string `json:"environment,omitempty"`
	MissingFields        []string          `json:"missing_fields,omitempty"`
	CollectionConfidence string            `json:"collection_confidence,omitempty"`
	CollectedAt          string            `json:"collected_at,omitempty"`
}

type ProcessRecord struct {
	ImageName      string `json:"image_name"`
	PID            int    `json:"pid,omitempty"`
	PPID           int    `json:"ppid,omitempty"`
	ProcessName    string `json:"process_name,omitempty"`
	ExecutablePath string `json:"executable_path,omitempty"`
	CommandLine    string `json:"command_line,omitempty"`
	SessionName    string `json:"session_name,omitempty"`
	SessionID      int    `json:"session_id,omitempty"`
	MemUsage       string `json:"mem_usage,omitempty"`
	Status         string `json:"status,omitempty"`
	UserName       string `json:"user_name,omitempty"`
	CPUTime        string `json:"cpu_time,omitempty"`
	WindowTitle    string `json:"window_title,omitempty"`
}

type NetConnection struct {
	Protocol       string `json:"protocol"`
	LocalAddress   string `json:"local_address"`
	ForeignAddress string `json:"foreign_address"`
	State          string `json:"state,omitempty"`
	PID            int    `json:"pid,omitempty"`
}

type IPConfig struct {
	Global   map[string]any `json:"global"`
	Adapters []Adapter      `json:"adapters"`
}

type Adapter struct {
	Name   string         `json:"name"`
	Fields map[string]any `json:"fields"`
}

type RunEntry struct {
	RegistryPath string `json:"registry_path"`
	Name         string `json:"name"`
	Type         string `json:"type"`
	Value        string `json:"value"`
}

type RouteTables struct {
	InterfaceList []string            `json:"interface_list,omitempty"`
	IPv4Routes    []map[string]string `json:"ipv4_routes,omitempty"`
	IPv6Routes    []map[string]string `json:"ipv6_routes,omitempty"`
	Notes         map[string][]string `json:"notes,omitempty"`
}

type FirewallPosture struct {
	Source     string              `json:"source"`
	Confidence string              `json:"confidence"`
	Profiles   []map[string]string `json:"profiles"`
	RawSummary string              `json:"raw_summary,omitempty"`
	Notes      []string            `json:"notes,omitempty"`
}

func NormalizeCase(summary storesqlite.CaseSummary) (CaseNormalizationResult, error) {
	result := CaseNormalizationResult{
		CaseUUID:     summary.CaseUUID,
		CaseID:       summary.CaseID,
		Hostname:     summary.Hostname,
		NormalizedAt: summary.CollectedAt,
		Artifacts:    map[string]Artifact{},
	}

	if summary.NormalizedCasePath == "" {
		return result, fmt.Errorf("case %s is missing a normalized path", summary.CaseUUID)
	}
	if err := os.MkdirAll(summary.NormalizedCasePath, 0o755); err != nil {
		return result, fmt.Errorf("create normalized dir: %w", err)
	}

	if err := normalizeHost(summary, &result); err != nil {
		result.Warnings = append(result.Warnings, err.Error())
	}
	if err := normalizeProcesses(summary, &result); err != nil {
		result.Warnings = append(result.Warnings, err.Error())
	}
	if err := normalizeConnections(summary, &result); err != nil {
		result.Warnings = append(result.Warnings, err.Error())
	}
	if err := normalizeIPConfig(summary, &result); err != nil {
		result.Warnings = append(result.Warnings, err.Error())
	}
	if err := normalizeRunEntries(summary, &result, "persistence/hkcu-run.txt", "persistence_hkcu_run.json"); err != nil {
		result.Warnings = append(result.Warnings, err.Error())
	}
	if err := normalizeRunEntries(summary, &result, "persistence/hkcu-runonce.txt", "persistence_hkcu_runonce.json"); err != nil {
		result.Warnings = append(result.Warnings, err.Error())
	}
	if err := normalizeCSVArtifact(summary, &result, "persistence/scheduled-tasks.csv", "scheduled_tasks.json"); err != nil {
		result.Warnings = append(result.Warnings, err.Error())
	}
	if err := normalizeRoutes(summary, &result); err != nil {
		result.Warnings = append(result.Warnings, err.Error())
	}
	if err := normalizeDNS(summary, &result); err != nil {
		result.Warnings = append(result.Warnings, err.Error())
	}
	if err := normalizeStartupFolder(summary, &result); err != nil {
		result.Warnings = append(result.Warnings, err.Error())
	}
	if err := normalizeFirewall(summary, &result); err != nil {
		result.Warnings = append(result.Warnings, err.Error())
	}
	if err := normalizeJSONArtifact(summary, &result, "security/defender-status.json", "security_defender.json"); err != nil {
		result.Warnings = append(result.Warnings, err.Error())
	}
	if err := normalizeJSONArtifact(summary, &result, "security/security-products.json", "security_products.json"); err != nil {
		result.Warnings = append(result.Warnings, err.Error())
	}
	if err := normalizeJSONArtifact(summary, &result, "software/installed-programs.json", "software_installed_programs.json"); err != nil {
		result.Warnings = append(result.Warnings, err.Error())
	}
	for _, item := range []struct {
		source string
		output string
	}{
		{"devices/volumes.json", "devices_volumes.json"},
		{"devices/pnp-summary.json", "devices_pnp_summary.json"},
		{"devices/usb-current.json", "devices_usb_current.json"},
		{"devices/usb-previous.json", "devices_usb_previous.json"},
	} {
		if err := normalizeJSONItemsArtifact(summary, &result, item.source, item.output); err != nil {
			result.Warnings = append(result.Warnings, err.Error())
		}
	}
	for _, item := range []struct {
		source string
		output string
	}{
		{"network/wifi-interfaces.txt", "network_wifi_interfaces.json"},
		{"network/bluetooth-devices.txt", "network_bluetooth_devices.json"},
		{"network/bluetooth-connected.txt", "network_bluetooth_connected.json"},
	} {
		if err := normalizeFormatListArtifact(summary, &result, item.source, item.output); err != nil {
			result.Warnings = append(result.Warnings, err.Error())
		}
	}
	if err := normalizeWiFiProfiles(summary, &result); err != nil {
		result.Warnings = append(result.Warnings, err.Error())
	}
	for _, item := range []struct {
		key    string
		source string
		output string
	}{
		{"logs_application", "logs/application-events.txt", "logs_application_events.json"},
		{"logs_system", "logs/system-events.txt", "logs_system_events.json"},
		{"logs_powershell", "logs/powershell-operational.txt", "logs_powershell_operational.json"},
		{"logs_defender", "logs/defender-operational.txt", "logs_defender_operational.json"},
	} {
		if err := normalizeEventLog(summary, &result, item.key, item.source, item.output); err != nil {
			result.Warnings = append(result.Warnings, err.Error())
		}
	}

	indexPath := filepath.Join(summary.NormalizedCasePath, "index.json")
	if err := writeJSON(indexPath, result); err != nil {
		return result, fmt.Errorf("write normalization index: %w", err)
	}

	return result, nil
}

func normalizeHost(summary storesqlite.CaseSummary, result *CaseNormalizationResult) error {
	source := filepath.Join(summary.RawCasePath, "host", "identity.json")
	var host HostIdentity
	if err := readJSON(source, &host); err != nil {
		return fmt.Errorf("normalize host identity: %w", err)
	}
	output := filepath.Join(summary.NormalizedCasePath, "host_identity.json")
	if err := writeJSON(output, host); err != nil {
		return fmt.Errorf("write normalized host identity: %w", err)
	}
	result.Artifacts["host_identity"] = Artifact{SourcePath: source, OutputPath: output, Count: 1, Status: "ok"}
	return nil
}

func normalizeProcesses(summary storesqlite.CaseSummary, result *CaseNormalizationResult) error {
	source := filepath.Join(summary.RawCasePath, "processes", "process-details.csv")
	rich := true
	if _, err := os.Stat(source); err != nil {
		source = filepath.Join(summary.RawCasePath, "processes", "process-list.csv")
		rich = false
	}
	records, err := readCSVObjects(source)
	if err != nil {
		return fmt.Errorf("normalize process list: %w", err)
	}
	processes := make([]ProcessRecord, 0, len(records))
	for _, row := range records {
		if rich {
			name := firstNonEmpty(row["Name"], row["ProcessName"], row["Image Name"])
			processes = append(processes, ProcessRecord{
				ImageName:      name,
				PID:            atoi(firstNonEmpty(row["PID"], row["ProcessId"])),
				PPID:           atoi(firstNonEmpty(row["PPID"], row["ParentProcessId"])),
				ProcessName:    name,
				ExecutablePath: firstNonEmpty(row["ExecutablePath"], row["Path"]),
				CommandLine:    row["CommandLine"],
				UserName:       firstNonEmpty(row["UserName"], row["Owner"]),
			})
			continue
		}
		processes = append(processes, ProcessRecord{
			ImageName:   row["Image Name"],
			PID:         atoi(row["PID"]),
			SessionName: row["Session Name"],
			SessionID:   atoi(row["Session#"]),
			MemUsage:    row["Mem Usage"],
			Status:      row["Status"],
			UserName:    row["User Name"],
			CPUTime:     row["CPU Time"],
			WindowTitle: row["Window Title"],
		})
	}
	output := filepath.Join(summary.NormalizedCasePath, "processes.json")
	if err := writeJSON(output, processes); err != nil {
		return fmt.Errorf("write normalized processes: %w", err)
	}
	result.Artifacts["processes"] = Artifact{SourcePath: source, OutputPath: output, Count: len(processes), Status: "ok"}
	return nil
}

func normalizeConnections(summary storesqlite.CaseSummary, result *CaseNormalizationResult) error {
	source := filepath.Join(summary.RawCasePath, "network", "net-connections.txt")
	content, err := os.ReadFile(source)
	if err != nil {
		return fmt.Errorf("normalize network connections: %w", err)
	}
	lines := strings.Split(string(content), "\n")
	connections := []NetConnection{}
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Active Connections") || strings.HasPrefix(line, "Proto") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 4 {
			continue
		}
		conn := NetConnection{
			Protocol:       parts[0],
			LocalAddress:   parts[1],
			ForeignAddress: parts[2],
		}
		if strings.EqualFold(parts[0], "UDP") {
			conn.PID = atoi(parts[len(parts)-1])
		} else {
			conn.State = parts[3]
			if len(parts) >= 5 {
				conn.PID = atoi(parts[4])
			}
		}
		connections = append(connections, conn)
	}
	output := filepath.Join(summary.NormalizedCasePath, "network_connections.json")
	if err := writeJSON(output, connections); err != nil {
		return fmt.Errorf("write normalized network connections: %w", err)
	}
	result.Artifacts["network_connections"] = Artifact{SourcePath: source, OutputPath: output, Count: len(connections), Status: "ok"}
	return nil
}

func normalizeIPConfig(summary storesqlite.CaseSummary, result *CaseNormalizationResult) error {
	source := filepath.Join(summary.RawCasePath, "network", "ipconfig.txt")
	content, err := os.ReadFile(source)
	if err != nil {
		return fmt.Errorf("normalize ipconfig: %w", err)
	}

	ipconfig := IPConfig{Global: map[string]any{}, Adapters: []Adapter{}}
	var current *Adapter
	var lastField string
	for _, rawLine := range strings.Split(string(content), "\n") {
		line := strings.TrimRight(rawLine, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || trimmed == "Windows IP Configuration" {
			continue
		}
		if strings.HasSuffix(trimmed, ":") && strings.Contains(trimmed, "adapter ") {
			adapter := Adapter{Name: strings.TrimSuffix(trimmed, ":"), Fields: map[string]any{}}
			ipconfig.Adapters = append(ipconfig.Adapters, adapter)
			current = &ipconfig.Adapters[len(ipconfig.Adapters)-1]
			lastField = ""
			continue
		}
		if strings.Contains(line, ":") {
			parts := strings.SplitN(line, ":", 2)
			key := normalizeKey(parts[0])
			value := strings.TrimSpace(parts[1])
			lastField = key
			if current == nil {
				ipconfig.Global[key] = value
			} else {
				current.Fields[key] = value
			}
			continue
		}
		if lastField != "" && current != nil {
			existing, ok := current.Fields[lastField]
			if !ok {
				current.Fields[lastField] = []string{trimmed}
				continue
			}
			switch value := existing.(type) {
			case string:
				current.Fields[lastField] = []string{value, trimmed}
			case []string:
				current.Fields[lastField] = append(value, trimmed)
			}
		}
	}

	enrichNetworkAdapters(ipconfig.Adapters)

	output := filepath.Join(summary.NormalizedCasePath, "network_ipconfig.json")
	if err := writeJSON(output, ipconfig); err != nil {
		return fmt.Errorf("write normalized ipconfig: %w", err)
	}
	result.Artifacts["network_ipconfig"] = Artifact{SourcePath: source, OutputPath: output, Count: len(ipconfig.Adapters), Status: "ok"}
	return nil
}

func enrichNetworkAdapters(adapters []Adapter) {
	for i := range adapters {
		fields := adapters[i].Fields
		nameDesc := strings.ToLower(adapters[i].Name + " " + normalizeStringValue(fields["description"]))
		hint := virtualAdapterHint(nameDesc)
		if hint != "" {
			fields["adapter_context"] = hint
			fields["likely_virtual_or_local_only"] = "true"
		}
		gateway := strings.TrimSpace(normalizeStringValue(fields["default_gateway"]))
		ipv4 := cleanIPPreferred(normalizeStringValue(fields["ipv4_address"]))
		if gateway != "" && hint == "" && ipv4 != "" && !strings.HasPrefix(ipv4, "169.254.") {
			fields["likely_primary_routed"] = "true"
		} else {
			fields["likely_primary_routed"] = "false"
		}
	}
}

func normalizeStringValue(value any) string {
	switch v := value.(type) {
	case string:
		return strings.TrimSpace(v)
	case []string:
		return strings.TrimSpace(strings.Join(v, " "))
	case []any:
		parts := make([]string, 0, len(v))
		for _, item := range v {
			parts = append(parts, normalizeStringValue(item))
		}
		return strings.TrimSpace(strings.Join(parts, " "))
	case nil:
		return ""
	default:
		return strings.TrimSpace(fmt.Sprint(v))
	}
}

func cleanIPPreferred(value string) string {
	value = strings.TrimSpace(value)
	value = strings.TrimSuffix(value, "(Preferred)")
	return strings.TrimSpace(value)
}

func virtualAdapterHint(nameDesc string) string {
	switch {
	case strings.Contains(nameDesc, "hyper-v") || strings.Contains(nameDesc, "vethernet"):
		return "Hyper-V/virtual switch adapter hint"
	case strings.Contains(nameDesc, "wsl"):
		return "WSL virtual adapter hint"
	case strings.Contains(nameDesc, "docker"):
		return "Docker/container adapter hint"
	case strings.Contains(nameDesc, "vmware") || strings.Contains(nameDesc, "vmnet"):
		return "VMware virtual adapter hint"
	case strings.Contains(nameDesc, "virtualbox") || strings.Contains(nameDesc, "host-only"):
		return "VirtualBox/host-only adapter hint"
	case strings.Contains(nameDesc, "vpn") || strings.Contains(nameDesc, "wireguard") || strings.Contains(nameDesc, "tap-windows") || strings.Contains(nameDesc, "tailscale") || strings.Contains(nameDesc, "zerotier") || strings.Contains(nameDesc, "anyconnect") || strings.Contains(nameDesc, "globalprotect") || strings.Contains(nameDesc, "mcafee"):
		return "VPN/tunnel adapter hint"
	case strings.Contains(nameDesc, "npcap") || strings.Contains(nameDesc, "loopback"):
		return "Npcap/loopback adapter hint"
	case strings.Contains(nameDesc, "bluetooth"):
		return "Bluetooth PAN/local adapter hint"
	default:
		return ""
	}
}

var regLine = regexp.MustCompile(`^\s{2,}(.+?)\s+(REG_\w+)\s+(.*)$`)

func normalizeRunEntries(summary storesqlite.CaseSummary, result *CaseNormalizationResult, relativeSource, outputName string) error {
	source := filepath.Join(summary.RawCasePath, filepath.FromSlash(relativeSource))
	content, err := os.ReadFile(source)
	if err != nil {
		return fmt.Errorf("normalize %s: %w", relativeSource, err)
	}
	scanner := bufio.NewScanner(strings.NewReader(string(content)))
	registryPath := ""
	entries := []RunEntry{}
	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "HKEY_") {
			registryPath = trimmed
			continue
		}
		matches := regLine.FindStringSubmatch(line)
		if len(matches) != 4 {
			continue
		}
		entries = append(entries, RunEntry{
			RegistryPath: registryPath,
			Name:         strings.TrimSpace(matches[1]),
			Type:         strings.TrimSpace(matches[2]),
			Value:        strings.TrimSpace(matches[3]),
		})
	}
	output := filepath.Join(summary.NormalizedCasePath, outputName)
	if err := writeJSON(output, entries); err != nil {
		return fmt.Errorf("write normalized %s: %w", relativeSource, err)
	}
	result.Artifacts[strings.TrimSuffix(outputName, ".json")] = Artifact{SourcePath: source, OutputPath: output, Count: len(entries), Status: "ok"}
	return nil
}

func normalizeCSVArtifact(summary storesqlite.CaseSummary, result *CaseNormalizationResult, relativeSource, outputName string) error {
	source := filepath.Join(summary.RawCasePath, filepath.FromSlash(relativeSource))
	rows, err := readCSVObjects(source)
	if err != nil {
		return fmt.Errorf("normalize %s: %w", relativeSource, err)
	}
	output := filepath.Join(summary.NormalizedCasePath, outputName)
	if err := writeJSON(output, rows); err != nil {
		return fmt.Errorf("write normalized %s: %w", relativeSource, err)
	}
	result.Artifacts[strings.TrimSuffix(outputName, ".json")] = Artifact{SourcePath: source, OutputPath: output, Count: len(rows), Status: "ok"}
	return nil
}

func normalizeJSONArtifact(summary storesqlite.CaseSummary, result *CaseNormalizationResult, relativeSource, outputName string) error {
	source := filepath.Join(summary.RawCasePath, filepath.FromSlash(relativeSource))
	var payload any
	if err := readJSON(source, &payload); err != nil {
		return fmt.Errorf("normalize %s: %w", relativeSource, err)
	}
	output := filepath.Join(summary.NormalizedCasePath, outputName)
	if err := writeJSON(output, payload); err != nil {
		return fmt.Errorf("write normalized %s: %w", relativeSource, err)
	}
	count := 1
	if typed, ok := payload.([]any); ok {
		count = len(typed)
	}
	result.Artifacts[strings.TrimSuffix(outputName, ".json")] = Artifact{SourcePath: source, OutputPath: output, Count: count, Status: "ok"}
	return nil
}

func normalizeJSONItemsArtifact(summary storesqlite.CaseSummary, result *CaseNormalizationResult, relativeSource, outputName string) error {
	source := filepath.Join(summary.RawCasePath, filepath.FromSlash(relativeSource))
	var payload any
	if err := readJSON(source, &payload); err != nil {
		return fmt.Errorf("normalize %s: %w", relativeSource, err)
	}
	normalized := payload
	count := 1
	if envelope, ok := payload.(map[string]any); ok {
		if items, ok := envelope["items"].([]any); ok {
			sourceName := normalizeStringValue(envelope["source"])
			confidence := normalizeStringValue(envelope["confidence"])
			notes := envelope["notes"]
			for _, item := range items {
				if obj, ok := item.(map[string]any); ok {
					if _, exists := obj["source"]; !exists && sourceName != "" {
						obj["source"] = sourceName
					}
					if _, exists := obj["confidence"]; !exists && confidence != "" {
						obj["confidence"] = confidence
					}
					if _, exists := obj["collection_notes"]; !exists && notes != nil {
						obj["collection_notes"] = notes
					}
				}
			}
			normalized = items
			count = len(items)
		}
	} else if typed, ok := payload.([]any); ok {
		count = len(typed)
	}
	output := filepath.Join(summary.NormalizedCasePath, outputName)
	if err := writeJSON(output, normalized); err != nil {
		return fmt.Errorf("write normalized %s: %w", relativeSource, err)
	}
	result.Artifacts[strings.TrimSuffix(outputName, ".json")] = Artifact{SourcePath: source, OutputPath: output, Count: count, Status: "ok"}
	return nil
}

func normalizeFormatListArtifact(summary storesqlite.CaseSummary, result *CaseNormalizationResult, relativeSource, outputName string) error {
	source := filepath.Join(summary.RawCasePath, filepath.FromSlash(relativeSource))
	entries, err := parseFormatListFile(source)
	if err != nil {
		return fmt.Errorf("normalize %s: %w", relativeSource, err)
	}
	output := filepath.Join(summary.NormalizedCasePath, outputName)
	if err := writeJSON(output, entries); err != nil {
		return fmt.Errorf("write normalized %s: %w", relativeSource, err)
	}
	result.Artifacts[strings.TrimSuffix(outputName, ".json")] = Artifact{SourcePath: source, OutputPath: output, Count: len(entries), Status: "ok"}
	return nil
}

func normalizeWiFiProfiles(summary storesqlite.CaseSummary, result *CaseNormalizationResult) error {
	relativeSource := "network/wifi-profiles.txt"
	source := filepath.Join(summary.RawCasePath, filepath.FromSlash(relativeSource))
	content, err := os.ReadFile(source)
	if err != nil {
		return fmt.Errorf("normalize %s: %w", relativeSource, err)
	}
	profiles := []map[string]string{}
	for _, rawLine := range strings.Split(string(content), "\n") {
		line := strings.TrimSpace(strings.TrimRight(rawLine, "\r"))
		if line == "" || !strings.Contains(line, ":") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		key := normalizeKey(parts[0])
		value := strings.TrimSpace(parts[1])
		if value == "" {
			continue
		}
		switch key {
		case "all_user_profile", "user_profile", "group_policy_profiles_read_only", "current_user_profile":
			profiles = append(profiles, map[string]string{"profile_name": value, "profile_scope": key, "credential_material_collected": "false"})
		}
	}
	output := filepath.Join(summary.NormalizedCasePath, "network_wifi_profiles.json")
	if err := writeJSON(output, profiles); err != nil {
		return fmt.Errorf("write normalized %s: %w", relativeSource, err)
	}
	result.Artifacts["network_wifi_profiles"] = Artifact{SourcePath: source, OutputPath: output, Count: len(profiles), Status: "ok", Note: "Wi-Fi profile names only; keys/passwords are intentionally not collected."}
	return nil
}

func normalizeFirewall(summary storesqlite.CaseSummary, result *CaseNormalizationResult) error {
	source := filepath.Join(summary.RawCasePath, "security", "firewall-status.txt")
	content, err := os.ReadFile(source)
	if err != nil {
		return fmt.Errorf("normalize firewall posture: %w", err)
	}
	posture := parseFirewallStatus(string(content))
	output := filepath.Join(summary.NormalizedCasePath, "security_firewall.json")
	if err := writeJSON(output, posture); err != nil {
		return fmt.Errorf("write normalized firewall posture: %w", err)
	}
	result.Artifacts["security_firewall"] = Artifact{SourcePath: source, OutputPath: output, Count: len(posture.Profiles), Status: "ok"}
	return nil
}

func parseFirewallStatus(content string) FirewallPosture {
	posture := FirewallPosture{Source: "netsh advfirewall show allprofiles", Confidence: "medium", Profiles: []map[string]string{}, Notes: []string{"Parsed from localized netsh text using heading/key-value heuristics; raw summary retained for analyst verification."}}
	var current map[string]string
	for _, rawLine := range strings.Split(content, "\n") {
		line := strings.TrimSpace(strings.TrimRight(rawLine, "\r"))
		if line == "" || strings.HasPrefix(line, "---") {
			continue
		}
		lower := strings.ToLower(line)
		if strings.Contains(lower, "profile settings") {
			if current != nil {
				posture.Profiles = append(posture.Profiles, current)
			}
			current = map[string]string{"profile": strings.TrimSpace(strings.TrimSuffix(line, "Settings"))}
			continue
		}
		if current == nil {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			key := normalizeKey(strings.Join(parts[:len(parts)-1], " "))
			current[key] = parts[len(parts)-1]
		}
	}
	if current != nil {
		posture.Profiles = append(posture.Profiles, current)
	}
	if len(posture.Profiles) > 0 {
		posture.Confidence = "high"
	}
	posture.RawSummary = firstLines(content, 40)
	return posture
}

func firstLines(content string, limit int) string {
	lines := strings.Split(content, "\n")
	if len(lines) > limit {
		lines = lines[:limit]
	}
	return strings.TrimSpace(strings.Join(lines, "\n"))
}

func normalizeRoutes(summary storesqlite.CaseSummary, result *CaseNormalizationResult) error {
	source := filepath.Join(summary.RawCasePath, "network", "routes.txt")
	content, err := os.ReadFile(source)
	if err != nil {
		return fmt.Errorf("normalize routes: %w", err)
	}

	routes := RouteTables{Notes: map[string][]string{}}
	section := ""
	for _, rawLine := range strings.Split(string(content), "\n") {
		line := strings.TrimRight(rawLine, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "===") {
			continue
		}
		switch trimmed {
		case "Interface List":
			section = "interfaces"
			continue
		case "IPv4 Route Table":
			section = "ipv4"
			continue
		case "IPv6 Route Table":
			section = "ipv6"
			continue
		case "Active Routes:", "Persistent Routes:":
			continue
		}

		switch section {
		case "interfaces":
			routes.InterfaceList = append(routes.InterfaceList, trimmed)
		case "ipv4":
			parts := strings.Fields(trimmed)
			if len(parts) == 5 && parts[0] != "Network" {
				routes.IPv4Routes = append(routes.IPv4Routes, map[string]string{
					"destination": parts[0],
					"netmask":     parts[1],
					"gateway":     parts[2],
					"interface":   parts[3],
					"metric":      parts[4],
				})
			} else {
				routes.Notes["ipv4"] = append(routes.Notes["ipv4"], trimmed)
			}
		case "ipv6":
			parts := strings.Fields(trimmed)
			if len(parts) >= 4 && parts[0] != "If" {
				gateway := strings.Join(parts[3:], " ")
				routes.IPv6Routes = append(routes.IPv6Routes, map[string]string{
					"interface":   parts[0],
					"metric":      parts[1],
					"destination": parts[2],
					"gateway":     gateway,
				})
			} else {
				routes.Notes["ipv6"] = append(routes.Notes["ipv6"], trimmed)
			}
		}
	}

	output := filepath.Join(summary.NormalizedCasePath, "network_routes.json")
	if err := writeJSON(output, routes); err != nil {
		return fmt.Errorf("write normalized routes: %w", err)
	}
	result.Artifacts["network_routes"] = Artifact{SourcePath: source, OutputPath: output, Count: len(routes.IPv4Routes) + len(routes.IPv6Routes), Status: "ok"}
	return nil
}

func normalizeDNS(summary storesqlite.CaseSummary, result *CaseNormalizationResult) error {
	source := filepath.Join(summary.RawCasePath, "network", "dns-info.txt")
	content, err := os.ReadFile(source)
	if err != nil {
		return fmt.Errorf("normalize dns cache: %w", err)
	}

	var records []map[string]string
	current := map[string]string{}
	commit := func() {
		if len(current) == 0 {
			return
		}
		copyMap := map[string]string{}
		for k, v := range current {
			copyMap[k] = v
		}
		records = append(records, copyMap)
		current = map[string]string{}
	}

	for _, rawLine := range strings.Split(string(content), "\n") {
		line := strings.TrimRight(rawLine, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || trimmed == "Windows IP Configuration" {
			continue
		}
		if strings.HasPrefix(trimmed, "----------------------------------------") {
			continue
		}
		if strings.Contains(trimmed, ":") {
			parts := strings.SplitN(trimmed, ":", 2)
			current[normalizeKey(parts[0])] = strings.TrimSpace(parts[1])
			continue
		}
		commit()
		current["display_name"] = trimmed
	}
	commit()

	output := filepath.Join(summary.NormalizedCasePath, "network_dns_cache.json")
	if err := writeJSON(output, records); err != nil {
		return fmt.Errorf("write normalized dns cache: %w", err)
	}
	result.Artifacts["network_dns_cache"] = Artifact{SourcePath: source, OutputPath: output, Count: len(records), Status: "ok"}
	return nil
}

func normalizeStartupFolder(summary storesqlite.CaseSummary, result *CaseNormalizationResult) error {
	source := filepath.Join(summary.RawCasePath, "persistence", "startup-folder.txt")
	entries, err := parseFormatListFile(source)
	if err != nil {
		return fmt.Errorf("normalize startup folder: %w", err)
	}
	output := filepath.Join(summary.NormalizedCasePath, "persistence_startup_folder.json")
	if err := writeJSON(output, entries); err != nil {
		return fmt.Errorf("write normalized startup folder: %w", err)
	}
	result.Artifacts["persistence_startup_folder"] = Artifact{SourcePath: source, OutputPath: output, Count: len(entries), Status: "ok"}
	return nil
}

func normalizeEventLog(summary storesqlite.CaseSummary, result *CaseNormalizationResult, artifactKey, relativeSource, outputName string) error {
	source := filepath.Join(summary.RawCasePath, filepath.FromSlash(relativeSource))
	events, err := parseWindowsEventLog(source)
	if err != nil {
		return fmt.Errorf("normalize %s: %w", relativeSource, err)
	}
	output := filepath.Join(summary.NormalizedCasePath, outputName)
	if err := writeJSON(output, events); err != nil {
		return fmt.Errorf("write normalized %s: %w", relativeSource, err)
	}
	result.Artifacts[artifactKey] = Artifact{SourcePath: source, OutputPath: output, Count: len(events), Status: "ok"}
	return nil
}

func parseFormatListFile(path string) ([]map[string]string, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	entries := []map[string]string{}
	current := map[string]string{}
	lastKey := ""
	commit := func() {
		if len(current) == 0 {
			return
		}
		copyMap := map[string]string{}
		for k, v := range current {
			copyMap[k] = strings.TrimSpace(v)
		}
		entries = append(entries, copyMap)
		current = map[string]string{}
		lastKey = ""
	}

	for _, rawLine := range strings.Split(string(content), "\n") {
		line := strings.TrimRight(rawLine, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			commit()
			continue
		}
		if strings.Contains(line, ":") {
			parts := strings.SplitN(line, ":", 2)
			key := normalizeKey(parts[0])
			value := strings.TrimSpace(parts[1])
			current[key] = value
			lastKey = key
			continue
		}
		if lastKey != "" {
			current[lastKey] = strings.TrimSpace(current[lastKey] + " " + trimmed)
		}
	}
	commit()
	return entries, nil
}

func parseWindowsEventLog(path string) ([]map[string]string, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var events []map[string]string
	current := map[string]string{}
	lastKey := ""
	inDescription := false
	commit := func() {
		if len(current) == 0 {
			return
		}
		copyMap := map[string]string{}
		for k, v := range current {
			copyMap[k] = strings.TrimSpace(v)
		}
		events = append(events, copyMap)
		current = map[string]string{}
		lastKey = ""
		inDescription = false
	}

	for _, rawLine := range strings.Split(string(content), "\n") {
		line := strings.TrimRight(rawLine, "\r")
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "Event[") {
			commit()
			current["event_ref"] = strings.TrimSuffix(trimmed, ":")
			continue
		}
		if trimmed == "" {
			if inDescription {
				current[lastKey] = strings.TrimRight(current[lastKey]+"\n", "\r")
				continue
			}
			commit()
			continue
		}
		if inDescription && lastKey == "description" {
			current[lastKey] = strings.TrimSpace(current[lastKey] + "\n" + trimmed)
			continue
		}
		if strings.Contains(line, ":") {
			parts := strings.SplitN(line, ":", 2)
			key := normalizeKey(parts[0])
			value := strings.TrimSpace(parts[1])
			current[key] = value
			lastKey = key
			inDescription = key == "description"
			continue
		}
		if inDescription && lastKey == "description" {
			current[lastKey] = strings.TrimSpace(current[lastKey] + "\n" + trimmed)
		}
	}
	commit()
	return events, nil
}

func readCSVObjects(path string) ([]map[string]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	reader := csv.NewReader(file)
	reader.FieldsPerRecord = -1
	reader.LazyQuotes = true
	records, err := reader.ReadAll()
	if err != nil {
		return nil, err
	}
	if len(records) == 0 {
		return nil, nil
	}
	headers := records[0]
	capacity := 0
	if len(records) > 1 {
		capacity = len(records) - 1
	}
	rows := make([]map[string]string, 0, capacity)
	for _, record := range records[1:] {
		row := map[string]string{}
		for idx, header := range headers {
			if idx < len(record) {
				row[header] = record[idx]
			} else {
				row[header] = ""
			}
		}
		rows = append(rows, row)
	}
	return rows, nil
}

func readJSON(path string, target any) error {
	content, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(content, target)
}

func writeJSON(path string, value any) error {
	content, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(content, '\n'), 0o644)
}

func normalizeKey(raw string) string {
	raw = strings.ReplaceAll(raw, ".", "")
	raw = strings.TrimSpace(raw)
	raw = strings.ToLower(raw)
	raw = strings.ReplaceAll(raw, " ", "_")
	raw = strings.ReplaceAll(raw, "-", "_")
	return raw
}

func atoi(value string) int {
	value = strings.TrimSpace(strings.ReplaceAll(value, ",", ""))
	if value == "" || strings.EqualFold(value, "N/A") {
		return 0
	}
	number, err := strconv.Atoi(value)
	if err != nil {
		return 0
	}
	return number
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" && !strings.EqualFold(value, "N/A") {
			return value
		}
	}
	return ""
}
