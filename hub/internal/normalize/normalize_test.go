package normalize

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	storesqlite "github.com/chip/incident-response-kit/hub/internal/store/sqlite"
)

func TestNormalizeJSONItemsArtifactFlattensEnvelope(t *testing.T) {
	tmp := t.TempDir()
	raw := filepath.Join(tmp, "source")
	normalized := filepath.Join(tmp, "normalized")
	if err := os.MkdirAll(filepath.Join(raw, "devices"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(normalized, 0o755); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(raw, "devices", "usb-previous.json")
	payload := `{
  "source": "HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR",
  "confidence": "previously seen",
  "notes": ["source-backed context only"],
  "items": [{"friendly_name":"USB Disk","serial_candidate":"ABC123"}]
}`
	if err := os.WriteFile(source, []byte(payload), 0o644); err != nil {
		t.Fatal(err)
	}

	result := &CaseNormalizationResult{Artifacts: map[string]Artifact{}}
	summary := storesqlite.CaseSummary{RawCasePath: raw, NormalizedCasePath: normalized}
	if err := normalizeJSONItemsArtifact(summary, result, "devices/usb-previous.json", "devices_usb_previous.json"); err != nil {
		t.Fatalf("normalizeJSONItemsArtifact returned error: %v", err)
	}
	artifact, ok := result.Artifacts["devices_usb_previous"]
	if !ok {
		t.Fatalf("artifact result missing")
	}
	if artifact.Count != 1 {
		t.Fatalf("artifact count = %d, want 1", artifact.Count)
	}
	var rows []map[string]any
	content, err := os.ReadFile(filepath.Join(normalized, "devices_usb_previous.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(content, &rows); err != nil {
		t.Fatalf("normalized output is not an item array: %v", err)
	}
	if got := rows[0]["source"]; got != "HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR" {
		t.Fatalf("source = %v", got)
	}
	if got := rows[0]["confidence"]; got != "previously seen" {
		t.Fatalf("confidence = %v", got)
	}
}

func TestNormalizeWiFiProfilesNamesOnly(t *testing.T) {
	tmp := t.TempDir()
	raw := filepath.Join(tmp, "source")
	normalized := filepath.Join(tmp, "normalized")
	if err := os.MkdirAll(filepath.Join(raw, "network"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(normalized, 0o755); err != nil {
		t.Fatal(err)
	}
	content := "Profiles on interface Wi-Fi:\n\nGroup policy profiles (read only)\n---------------------------------\n    <None>\n\nUser profiles\n-------------\n    All User Profile     : OfficeNet\n    All User Profile     : GuestNet\n"
	if err := os.WriteFile(filepath.Join(raw, "network", "wifi-profiles.txt"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	result := &CaseNormalizationResult{Artifacts: map[string]Artifact{}}
	summary := storesqlite.CaseSummary{RawCasePath: raw, NormalizedCasePath: normalized}
	if err := normalizeWiFiProfiles(summary, result); err != nil {
		t.Fatalf("normalizeWiFiProfiles returned error: %v", err)
	}
	if result.Artifacts["network_wifi_profiles"].Count != 2 {
		t.Fatalf("profile count = %d, want 2", result.Artifacts["network_wifi_profiles"].Count)
	}
	var rows []map[string]string
	data, err := os.ReadFile(filepath.Join(normalized, "network_wifi_profiles.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &rows); err != nil {
		t.Fatal(err)
	}
	if rows[0]["profile_name"] != "OfficeNet" || rows[0]["credential_material_collected"] != "false" {
		t.Fatalf("unexpected first profile: %#v", rows[0])
	}
}
