package collect

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/chip/incident-response-kit/collector/internal/checksum"
	"github.com/chip/incident-response-kit/collector/internal/model"
)

// HostCollector uses a Windows-first baseline path and falls back to lightweight runtime inspection on dev-harness platforms.
type HostCollector struct{}

type hostIdentity struct {
	Hostname             string            `json:"hostname"`
	Username             string            `json:"username"`
	Domain               string            `json:"domain,omitempty"`
	Workgroup            string            `json:"workgroup,omitempty"`
	AccountScope         string            `json:"account_scope,omitempty"`
	ProfilePath          string            `json:"profile_path,omitempty"`
	HomeDrive            string            `json:"home_drive,omitempty"`
	HomePath             string            `json:"home_path,omitempty"`
	LogonServer          string            `json:"logon_server,omitempty"`
	SessionName          string            `json:"session_name,omitempty"`
	ClientName           string            `json:"client_name,omitempty"`
	OSFamily             string            `json:"os_family"`
	OSVersion            string            `json:"os_version,omitempty"`
	Architecture         string            `json:"architecture,omitempty"`
	ProcessorArch        string            `json:"processor_architecture,omitempty"`
	NumberOfProcessors   string            `json:"number_of_processors,omitempty"`
	Timezone             string            `json:"timezone,omitempty"`
	BootTime             string            `json:"boot_time,omitempty"`
	UptimeSeconds        *int64            `json:"uptime_seconds,omitempty"`
	UptimeHuman          string            `json:"uptime_human,omitempty"`
	BootTimeSource       string            `json:"boot_time_source,omitempty"`
	BootTimeConfidence   string            `json:"boot_time_confidence,omitempty"`
	Environment          map[string]string `json:"environment,omitempty"`
	MissingFields        []string          `json:"missing_fields,omitempty"`
	CollectionConfidence string            `json:"collection_confidence"`
	CollectedAt          string            `json:"collected_at"`
}

// HostIdentitySnapshot returns the same low-risk host/session context written by HostCollector.
// It is exported so manifest metadata can use the collector's cleaned username/domain/boot-time fields.
func HostIdentitySnapshot(ctx context.Context, collectedAt time.Time) (hostIdentity, []string) {
	sysInfo := CollectSystemInfo(ctx)
	osVersion := runtime.Version()
	architecture := runtime.GOARCH
	if sysInfo.OSVersion != "" {
		osVersion = sysInfo.OSVersion
	}
	if sysInfo.Architecture != "" {
		architecture = sysInfo.Architecture
	}

	currentUser, profilePath := currentUserAndProfile()
	env := safeHostEnvironment()
	domainValue, domainSource := domainFromEnvironment()
	workgroup := strings.TrimSpace(os.Getenv("USERDOMAIN"))
	if runtime.GOOS == "windows" && strings.EqualFold(workgroup, strings.TrimSpace(env["COMPUTERNAME"])) {
		// USERDOMAIN is often the local computer name for non-domain accounts. Keep it as domain
		// compatibility, but surface account_scope so Thoth doesn't overstate AD membership.
		workgroup = ""
	}

	identity := hostIdentity{
		Hostname:             hostname(),
		Username:             currentUser,
		Domain:               domainValue,
		Workgroup:            workgroup,
		AccountScope:         accountScope(domainValue, env["COMPUTERNAME"], env["USERDNSDOMAIN"]),
		ProfilePath:          profilePath,
		HomeDrive:            env["HOMEDRIVE"],
		HomePath:             env["HOMEPATH"],
		LogonServer:          strings.TrimPrefix(env["LOGONSERVER"], `\\`),
		SessionName:          env["SESSIONNAME"],
		ClientName:           env["CLIENTNAME"],
		OSFamily:             normalizeOS(runtime.GOOS),
		OSVersion:            osVersion,
		Architecture:         architecture,
		ProcessorArch:        firstNonEmpty(env["PROCESSOR_ARCHITECTURE"], env["PROCESSOR_IDENTIFIER"]),
		NumberOfProcessors:   env["NUMBER_OF_PROCESSORS"],
		Timezone:             collectedAt.Location().String(),
		Environment:          env,
		CollectionConfidence: "partial",
		CollectedAt:          collectedAt.Format(time.RFC3339),
	}

	warnings := make([]string, 0)
	missing := make([]string, 0)
	if identity.Hostname == "" {
		missing = append(missing, "hostname")
		warnings = append(warnings, "host-identity.hostname: unavailable from OS hostname lookup")
	}
	if identity.Username == "" {
		missing = append(missing, "username")
		warnings = append(warnings, "host-identity.username: unavailable from OS user lookup and USER/USERNAME environment")
	}
	if identity.ProfilePath == "" {
		missing = append(missing, "profile_path")
		warnings = append(warnings, "host-identity.profile_path: unavailable from OS user lookup and USERPROFILE/HOME environment")
	}
	if identity.Domain == "" && identity.Workgroup == "" {
		missing = append(missing, "domain_or_workgroup")
		warnings = append(warnings, "host-identity.domain_or_workgroup: unavailable from USERDOMAIN/USERDNSDOMAIN/DOMAIN/HOSTDOMAIN environment")
	} else if domainSource != "" {
		identity.Environment["DOMAIN_SOURCE"] = domainSource
	}

	if uptime, ok, note := collectUptime(ctx, collectedAt); ok {
		seconds := int64(uptime.Uptime.Round(time.Second).Seconds())
		identity.UptimeSeconds = &seconds
		identity.UptimeHuman = humanDuration(uptime.Uptime)
		identity.BootTime = uptime.BootTime.UTC().Format(time.RFC3339)
		identity.BootTimeSource = uptime.Source
		identity.BootTimeConfidence = uptime.Confidence
	} else {
		missing = append(missing, "boot_time", "uptime_seconds")
		warnings = append(warnings, fmt.Sprintf("host-identity.uptime: %s", note))
		identity.BootTimeSource = uptime.Source
		identity.BootTimeConfidence = "unavailable"
	}

	identity.MissingFields = missing
	if len(warnings) == 0 && identity.BootTimeConfidence == "high" {
		identity.CollectionConfidence = "high"
	} else if len(warnings) <= 1 && identity.BootTime != "" {
		identity.CollectionConfidence = "medium"
	}
	return identity, warnings
}

func (HostCollector) Collect(ctx context.Context, caseDir string, collectedAt time.Time) ([]model.ArtifactRecord, []string) {
	artifactPath := filepath.Join(caseDir, "host", "identity.json")
	identity, warnings := HostIdentitySnapshot(ctx, collectedAt)

	status := "ok"
	if len(warnings) > 0 || identity.CollectionConfidence != "high" {
		status = "partial"
	}

	data, err := json.MarshalIndent(identity, "", "  ")
	if err != nil {
		msg := err.Error()
		return []model.ArtifactRecord{{
			ArtifactID:      "host-identity",
			Category:        "host",
			RelativePath:    "host/identity.json",
			Format:          "json",
			SourceCommand:   hostSourceCommand(),
			CollectionScope: "system-readable",
			CollectedAt:     collectedAt.Format(time.RFC3339),
			CollectorStatus: "error",
			Error:           &msg,
			Notes:           []string{"failed to serialize host identity"},
			Tags:            []string{"identity", "host", "session", "uptime"},
		}}, []string{msg}
	}
	data = append(data, '\n')

	if err := os.WriteFile(artifactPath, data, 0o644); err != nil {
		msg := err.Error()
		return []model.ArtifactRecord{{
			ArtifactID:      "host-identity",
			Category:        "host",
			RelativePath:    "host/identity.json",
			Format:          "json",
			SourceCommand:   hostSourceCommand(),
			CollectionScope: "system-readable",
			CollectedAt:     collectedAt.Format(time.RFC3339),
			CollectorStatus: "error",
			Error:           &msg,
			Notes:           []string{"failed to write host identity artifact"},
			Tags:            []string{"identity", "host", "session", "uptime"},
		}}, []string{msg}
	}

	hash, size, err := checksum.SHA256File(artifactPath)
	if err != nil {
		msg := err.Error()
		return []model.ArtifactRecord{{
			ArtifactID:      "host-identity",
			Category:        "host",
			RelativePath:    "host/identity.json",
			Format:          "json",
			SourceCommand:   hostSourceCommand(),
			CollectionScope: "system-readable",
			CollectedAt:     collectedAt.Format(time.RFC3339),
			CollectorStatus: "error",
			Error:           &msg,
			Notes:           []string{"failed to hash host identity artifact"},
			Tags:            []string{"identity", "host", "session", "uptime"},
		}}, []string{msg}
	}

	return []model.ArtifactRecord{{
		ArtifactID:      "host-identity",
		Category:        "host",
		RelativePath:    "host/identity.json",
		Format:          "json",
		SHA256:          hash,
		SizeBytes:       size,
		SourceCommand:   hostSourceCommand(),
		CollectionScope: "system-readable",
		CollectedAt:     collectedAt.Format(time.RFC3339),
		CollectorStatus: status,
		Notes:           warnings,
		Tags:            []string{"identity", "host", "session", "uptime"},
	}}, warnings
}

func hostname() string {
	if value, err := os.Hostname(); err == nil && strings.TrimSpace(value) != "" {
		return value
	}
	return ""
}

func currentUserAndProfile() (string, string) {
	var usernameValue string
	var profilePath string
	if current, err := user.Current(); err == nil {
		usernameValue = strings.TrimSpace(current.Username)
		profilePath = strings.TrimSpace(current.HomeDir)
	}
	if usernameValue == "" {
		usernameValue = firstNonEmpty(os.Getenv("USERNAME"), os.Getenv("USER"))
	}
	if profilePath == "" {
		profilePath = firstNonEmpty(os.Getenv("USERPROFILE"), os.Getenv("HOME"))
	}
	return usernameValue, profilePath
}

func domainFromEnvironment() (string, string) {
	for _, key := range []string{"USERDNSDOMAIN", "USERDOMAIN", "DOMAIN", "HOSTDOMAIN"} {
		if value := strings.TrimSpace(os.Getenv(key)); value != "" {
			return value, key
		}
	}
	return "", ""
}

func accountScope(domainValue, computerName, dnsDomain string) string {
	if strings.TrimSpace(dnsDomain) != "" {
		return "domain"
	}
	if domainValue != "" && computerName != "" && strings.EqualFold(domainValue, computerName) {
		return "local"
	}
	if domainValue != "" {
		return "domain_or_workgroup"
	}
	return "unknown"
}

func safeHostEnvironment() map[string]string {
	keys := []string{
		"COMPUTERNAME", "USERDOMAIN", "USERDNSDOMAIN", "USERDOMAIN_ROAMINGPROFILE",
		"USERNAME", "USER", "USERPROFILE", "HOME", "HOMEDRIVE", "HOMEPATH",
		"LOGONSERVER", "SESSIONNAME", "CLIENTNAME", "OS", "PROCESSOR_ARCHITECTURE",
		"PROCESSOR_IDENTIFIER", "NUMBER_OF_PROCESSORS", "SystemRoot", "windir",
	}
	result := map[string]string{}
	for _, key := range keys {
		if value := strings.TrimSpace(os.Getenv(key)); value != "" {
			result[key] = value
		}
	}
	return result
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func humanDuration(duration time.Duration) string {
	if duration < 0 {
		duration = 0
	}
	totalSeconds := int64(duration.Round(time.Second).Seconds())
	days := totalSeconds / 86400
	hours := (totalSeconds % 86400) / 3600
	minutes := (totalSeconds % 3600) / 60
	seconds := totalSeconds % 60
	if days > 0 {
		return fmt.Sprintf("%dd %02dh %02dm %02ds", days, hours, minutes, seconds)
	}
	return fmt.Sprintf("%02dh %02dm %02ds", hours, minutes, seconds)
}

func hostSourceCommand() string {
	switch runtime.GOOS {
	case "windows":
		return "Windows API GetTickCount64 + environment/user context"
	case "darwin", "linux":
		return "fallback runtime inspection (dev harness)"
	default:
		return "runtime inspection"
	}
}

func normalizeOS(goos string) string {
	switch goos {
	case "darwin":
		return "macos"
	default:
		return goos
	}
}
