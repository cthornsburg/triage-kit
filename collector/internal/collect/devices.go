package collect

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/chip/incident-response-kit/collector/internal/checksum"
	"github.com/chip/incident-response-kit/collector/internal/model"
)

// DeviceCollector collects current removable-media state and source-backed previous USB context.
type DeviceCollector struct{}

type deviceVolume struct {
	DriveLetter      string `json:"drive_letter,omitempty"`
	MountPoint       string `json:"mount_point,omitempty"`
	VolumeLabel      string `json:"volume_label,omitempty"`
	FileSystem       string `json:"filesystem,omitempty"`
	SizeBytes        uint64 `json:"size_bytes,omitempty"`
	FreeBytes        uint64 `json:"free_bytes,omitempty"`
	DriveType        string `json:"drive_type,omitempty"`
	BusType          string `json:"bus_type,omitempty"`
	InterfaceType    string `json:"interface_type,omitempty"`
	PNPDeviceID      string `json:"pnp_device_id,omitempty"`
	Classification   string `json:"classification"`
	Confidence       string `json:"confidence"`
	Source           string `json:"source"`
	CollectionStatus string `json:"collection_status,omitempty"`
}

type pnpDeviceSummary struct {
	FriendlyName string `json:"friendly_name,omitempty"`
	DeviceID     string `json:"device_id,omitempty"`
	Manufacturer string `json:"manufacturer,omitempty"`
	Class        string `json:"class,omitempty"`
	Status       string `json:"status,omitempty"`
	BusClues     string `json:"bus_interface_clues,omitempty"`
	Confidence   string `json:"confidence"`
	Source       string `json:"source"`
}

type currentUSBDevice struct {
	FriendlyName    string   `json:"friendly_name,omitempty"`
	DeviceID        string   `json:"device_id,omitempty"`
	Manufacturer    string   `json:"manufacturer,omitempty"`
	Model           string   `json:"model,omitempty"`
	InterfaceType   string   `json:"interface_type,omitempty"`
	BusType         string   `json:"bus_type,omitempty"`
	SerialCandidate string   `json:"serial_candidate,omitempty"`
	DriveLetters    []string `json:"drive_letters,omitempty"`
	Confidence      string   `json:"confidence"`
	Source          string   `json:"source"`
}

type previousUSBDevice struct {
	EvidenceType     string `json:"evidence_type"`
	Confidence       string `json:"confidence"`
	SourcePath       string `json:"source_path"`
	Vendor           string `json:"vendor,omitempty"`
	Product          string `json:"product,omitempty"`
	Revision         string `json:"revision,omitempty"`
	SerialCandidate  string `json:"serial_candidate,omitempty"`
	FriendlyName     string `json:"friendly_name,omitempty"`
	DeviceID         string `json:"device_id,omitempty"`
	Class            string `json:"class,omitempty"`
	Manufacturer     string `json:"manufacturer,omitempty"`
	Status           string `json:"status,omitempty"`
	MountedDevice    string `json:"mounted_device,omitempty"`
	VolumeIdentifier string `json:"volume_identifier,omitempty"`
	RawID            string `json:"raw_id,omitempty"`
}

type deviceArtifactEnvelope[T any] struct {
	Source     string   `json:"source"`
	Confidence string   `json:"confidence"`
	Notes      []string `json:"notes,omitempty"`
	Items      []T      `json:"items"`
}

type usbStorParts struct {
	Vendor   string
	Product  string
	Revision string
}

func parseUSBStorDiskID(id string) usbStorParts {
	parts := usbStorParts{}
	for _, token := range strings.Split(id, "&") {
		upper := strings.ToUpper(token)
		switch {
		case strings.HasPrefix(upper, "VEN_"):
			parts.Vendor = cleanUSBIDValue(token[4:])
		case strings.HasPrefix(upper, "PROD_"):
			parts.Product = cleanUSBIDValue(token[5:])
		case strings.HasPrefix(upper, "REV_"):
			parts.Revision = cleanUSBIDValue(token[4:])
		}
	}
	return parts
}

func cleanUSBIDValue(value string) string {
	value = strings.ReplaceAll(value, "_", " ")
	return strings.TrimSpace(value)
}

func serialCandidateFromDeviceID(id string) string {
	id = strings.TrimSpace(id)
	if id == "" {
		return ""
	}
	id = strings.ReplaceAll(id, `/`, `\`)
	parts := strings.Split(id, `\`)
	for i := len(parts) - 1; i >= 0; i-- {
		candidate := strings.Trim(parts[i], " {}")
		if candidate != "" {
			return candidate
		}
	}
	return ""
}

func busCluesFromID(id string) string {
	upper := strings.ToUpper(id)
	clues := []string{}
	for _, clue := range []string{"USBSTOR", "USB", "SCSI", "STORAGE", "WPDBUSENUM", "SWD", "BTH", "HID"} {
		if strings.Contains(upper, clue) {
			clues = append(clues, clue)
		}
	}
	return strings.Join(clues, ",")
}

func decodeMountedDeviceValue(data []byte) string {
	if len(data) >= 2 && len(data)%2 == 0 {
		units := make([]uint16, 0, len(data)/2)
		for i := 0; i+1 < len(data); i += 2 {
			units = append(units, uint16(data[i])|uint16(data[i+1])<<8)
		}
		decoded := strings.TrimRight(string(utf16.Decode(units)), "\x00")
		printable := regexp.MustCompile(`^[[:print:]\s]+$`).MatchString(decoded)
		if printable && strings.TrimSpace(decoded) != "" {
			return decoded
		}
	}
	return strings.ToUpper(hex.EncodeToString(data))
}

func sortPreviousUSB(items []previousUSBDevice) {
	sort.SliceStable(items, func(i, j int) bool {
		left := strings.ToLower(items[i].EvidenceType + "\x00" + items[i].SourcePath + "\x00" + items[i].DeviceID + "\x00" + items[i].MountedDevice)
		right := strings.ToLower(items[j].EvidenceType + "\x00" + items[j].SourcePath + "\x00" + items[j].DeviceID + "\x00" + items[j].MountedDevice)
		return left < right
	})
}

func writeDeviceJSON[T any](caseDir, relativePath, artifactID string, value deviceArtifactEnvelope[T], source string, collectedAt time.Time, status string, notes []string) (model.ArtifactRecord, []string) {
	artifactPath := filepath.Join(caseDir, filepath.FromSlash(relativePath))
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		msg := err.Error()
		return deviceRecord(artifactID, relativePath, source, collectedAt, "error", 0, "", &msg, notes), append(notes, msg)
	}
	if err := os.WriteFile(artifactPath, append(data, '\n'), 0o644); err != nil {
		msg := err.Error()
		return deviceRecord(artifactID, relativePath, source, collectedAt, "error", 0, "", &msg, notes), append(notes, msg)
	}
	hash, size, err := checksum.SHA256File(artifactPath)
	if err != nil {
		msg := err.Error()
		return deviceRecord(artifactID, relativePath, source, collectedAt, "error", 0, "", &msg, notes), append(notes, msg)
	}
	return deviceRecord(artifactID, relativePath, source, collectedAt, status, size, hash, nil, notes), notes
}

func deviceRecord(artifactID, relativePath, source string, collectedAt time.Time, status string, size int64, hash string, errPtr *string, notes []string) model.ArtifactRecord {
	return model.ArtifactRecord{
		ArtifactID:      artifactID,
		Category:        "devices",
		RelativePath:    filepath.ToSlash(relativePath),
		Format:          "json",
		SHA256:          hash,
		SizeBytes:       size,
		SourceCommand:   source,
		CollectionScope: "system-readable",
		CollectedAt:     collectedAt.Format(time.RFC3339),
		CollectorStatus: status,
		Error:           errPtr,
		Notes:           notes,
		Tags:            []string{"devices", "usb", "removable-media"},
	}
}
