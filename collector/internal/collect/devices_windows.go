//go:build windows

package collect

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/chip/incident-response-kit/collector/internal/model"
	"golang.org/x/sys/windows/registry"
)

type usbRegistrySource struct {
	HiveName string
	Path     string
}

func (DeviceCollector) Collect(ctx context.Context, caseDir string, collectedAt time.Time) ([]model.ArtifactRecord, []string) {
	records := make([]model.ArtifactRecord, 0, 4)
	warnings := []string{}

	volumes, volumeNotes := collectVolumes(ctx)
	volumeStatus := statusFromNotesAndCount(volumeNotes, len(volumes))
	volumeEnvelope := deviceArtifactEnvelope[deviceVolume]{Source: "PowerShell Get-CimInstance Win32_LogicalDisk + Win32_DiskDrive", Confidence: "medium", Notes: volumeNotes, Items: volumes}
	record, notes := writeDeviceJSON(caseDir, "devices/volumes.json", "devices-volumes", volumeEnvelope, volumeEnvelope.Source, collectedAt, volumeStatus, volumeNotes)
	records = append(records, record)
	warnings = appendPrefixed(warnings, "devices-volumes", notes)

	pnp, pnpNotes := collectPnPSummary(ctx)
	pnpStatus := statusFromNotesAndCount(pnpNotes, len(pnp))
	pnpEnvelope := deviceArtifactEnvelope[pnpDeviceSummary]{Source: "PowerShell Get-PnpDevice / CIM_PnPEntity fallback", Confidence: "medium", Notes: pnpNotes, Items: pnp}
	record, notes = writeDeviceJSON(caseDir, "devices/pnp-summary.json", "devices-pnp-summary", pnpEnvelope, pnpEnvelope.Source, collectedAt.Add(time.Second), pnpStatus, pnpNotes)
	records = append(records, record)
	warnings = appendPrefixed(warnings, "devices-pnp-summary", notes)

	current, currentNotes := collectCurrentUSB(ctx)
	currentStatus := statusFromNotesAndCount(currentNotes, len(current))
	currentEnvelope := deviceArtifactEnvelope[currentUSBDevice]{Source: "PowerShell Win32_DiskDrive USB/STORAGE PnP association", Confidence: "medium", Notes: currentNotes, Items: current}
	record, notes = writeDeviceJSON(caseDir, "devices/usb-current.json", "devices-usb-current", currentEnvelope, currentEnvelope.Source, collectedAt.Add(2*time.Second), currentStatus, currentNotes)
	records = append(records, record)
	warnings = appendPrefixed(warnings, "devices-usb-current", notes)

	previous, previousNotes := collectPreviousUSB()
	previousStatus := statusFromNotesAndCount(previousNotes, len(previous))
	previousNotes = append(previousNotes, "Baseline SEKER v1.0 separates source-backed previous USB evidence from complete USB forensic history; no first/last-seen timeline is claimed.")
	previousEnvelope := deviceArtifactEnvelope[previousUSBDevice]{Source: `HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR; HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USB; HKLM\\SYSTEM\\MountedDevices`, Confidence: "medium", Notes: previousNotes, Items: previous}
	record, notes = writeDeviceJSON(caseDir, "devices/usb-previous.json", "devices-usb-previous", previousEnvelope, previousEnvelope.Source, collectedAt.Add(3*time.Second), previousStatus, previousNotes)
	records = append(records, record)
	warnings = appendPrefixed(warnings, "devices-usb-previous", notes)

	return records, warnings
}

func collectVolumes(ctx context.Context) ([]deviceVolume, []string) {
	script := `$ErrorActionPreference='SilentlyContinue'; $items=@(); Get-CimInstance Win32_LogicalDisk | ForEach-Object { $items += [pscustomobject]@{DriveLetter=$_.DeviceID; MountPoint=$_.DeviceID; VolumeLabel=$_.VolumeName; FileSystem=$_.FileSystem; SizeBytes=[UInt64]($_.Size); FreeBytes=[UInt64]($_.FreeSpace); DriveType=$_.DriveType; PNPDeviceID=''; InterfaceType=''; BusType=''} }; Get-CimInstance Win32_DiskDrive | ForEach-Object { $disk=$_; $classification=if(($disk.InterfaceType -eq 'USB') -or ($disk.PNPDeviceID -match 'USB|USBSTOR')){'removable/current'}else{'fixed-or-other/current'}; $items += [pscustomobject]@{DriveLetter=''; MountPoint=$disk.DeviceID; VolumeLabel=$disk.Model; FileSystem=''; SizeBytes=[UInt64]($disk.Size); FreeBytes=0; DriveType='disk'; PNPDeviceID=$disk.PNPDeviceID; InterfaceType=$disk.InterfaceType; BusType=$disk.MediaType; Classification=$classification} }; $items | ConvertTo-Json -Depth 4 -Compress`
	var raw []map[string]any
	if notes := runPowerShellJSON(ctx, script, &raw); len(notes) > 0 {
		return nil, notes
	}
	items := make([]deviceVolume, 0, len(raw))
	for _, row := range raw {
		classification := stringField(row, "Classification")
		if classification == "" {
			classification = classifyVolume(stringField(row, "DriveType"), stringField(row, "InterfaceType"), stringField(row, "PNPDeviceID"))
		}
		items = append(items, deviceVolume{DriveLetter: stringField(row, "DriveLetter"), MountPoint: stringField(row, "MountPoint"), VolumeLabel: stringField(row, "VolumeLabel"), FileSystem: stringField(row, "FileSystem"), SizeBytes: uint64Field(row, "SizeBytes"), FreeBytes: uint64Field(row, "FreeBytes"), DriveType: stringField(row, "DriveType"), BusType: stringField(row, "BusType"), InterfaceType: stringField(row, "InterfaceType"), PNPDeviceID: stringField(row, "PNPDeviceID"), Classification: classification, Confidence: "medium", Source: "Win32_LogicalDisk/Win32_DiskDrive"})
	}
	return items, nil
}

func collectPnPSummary(ctx context.Context) ([]pnpDeviceSummary, []string) {
	script := `$ErrorActionPreference='SilentlyContinue'; $items=@(); if (Get-Command Get-PnpDevice -ErrorAction SilentlyContinue) { Get-PnpDevice | Where-Object { $_.InstanceId -match 'USB|USBSTOR|STORAGE|WPDBUSENUM' -or $_.Class -match 'USB|DiskDrive|WPD|Volume' } | ForEach-Object { $items += [pscustomobject]@{FriendlyName=$_.FriendlyName; DeviceID=$_.InstanceId; Manufacturer=$_.Manufacturer; Class=$_.Class; Status=$_.Status} } } else { Get-CimInstance Win32_PnPEntity | Where-Object { $_.DeviceID -match 'USB|USBSTOR|STORAGE|WPDBUSENUM' -or $_.PNPClass -match 'USB|DiskDrive|WPD|Volume' } | ForEach-Object { $items += [pscustomobject]@{FriendlyName=$_.Name; DeviceID=$_.DeviceID; Manufacturer=$_.Manufacturer; Class=$_.PNPClass; Status=$_.Status} } }; $items | ConvertTo-Json -Depth 4 -Compress`
	var raw []map[string]any
	if notes := runPowerShellJSON(ctx, script, &raw); len(notes) > 0 {
		return nil, notes
	}
	items := make([]pnpDeviceSummary, 0, len(raw))
	for _, row := range raw {
		deviceID := stringField(row, "DeviceID")
		items = append(items, pnpDeviceSummary{FriendlyName: stringField(row, "FriendlyName"), DeviceID: deviceID, Manufacturer: stringField(row, "Manufacturer"), Class: stringField(row, "Class"), Status: stringField(row, "Status"), BusClues: busCluesFromID(deviceID), Confidence: "medium", Source: "Get-PnpDevice/CIM_PnPEntity"})
	}
	sort.SliceStable(items, func(i, j int) bool { return strings.ToLower(items[i].DeviceID) < strings.ToLower(items[j].DeviceID) })
	return items, nil
}

func collectCurrentUSB(ctx context.Context) ([]currentUSBDevice, []string) {
	script := `$ErrorActionPreference='SilentlyContinue'; $items=@(); Get-CimInstance Win32_DiskDrive | Where-Object { $_.InterfaceType -eq 'USB' -or $_.PNPDeviceID -match 'USB|USBSTOR' } | ForEach-Object { $disk=$_; $letters=@(); Get-CimAssociatedInstance -InputObject $disk -Association Win32_DiskDriveToDiskPartition | ForEach-Object { Get-CimAssociatedInstance -InputObject $_ -Association Win32_LogicalDiskToPartition | ForEach-Object { if ($_.DeviceID) { $letters += $_.DeviceID } } }; $items += [pscustomobject]@{FriendlyName=$disk.Caption; DeviceID=$disk.PNPDeviceID; Manufacturer=$disk.Manufacturer; Model=$disk.Model; InterfaceType=$disk.InterfaceType; BusType=$disk.MediaType; DriveLetters=($letters -join ',')} }; $items | ConvertTo-Json -Depth 4 -Compress`
	var raw []map[string]any
	if notes := runPowerShellJSON(ctx, script, &raw); len(notes) > 0 {
		return nil, notes
	}
	items := make([]currentUSBDevice, 0, len(raw))
	for _, row := range raw {
		deviceID := stringField(row, "DeviceID")
		items = append(items, currentUSBDevice{FriendlyName: stringField(row, "FriendlyName"), DeviceID: deviceID, Manufacturer: stringField(row, "Manufacturer"), Model: stringField(row, "Model"), InterfaceType: stringField(row, "InterfaceType"), BusType: stringField(row, "BusType"), SerialCandidate: serialCandidateFromDeviceID(deviceID), DriveLetters: splitCSV(stringField(row, "DriveLetters")), Confidence: "current", Source: "Win32_DiskDrive USB PnP association"})
	}
	return items, nil
}

func collectPreviousUSB() ([]previousUSBDevice, []string) {
	items := []previousUSBDevice{}
	notes := []string{}
	usbStorItems, usbStorNotes := enumUSBStor(usbRegistrySource{HiveName: "HKLM", Path: `SYSTEM\CurrentControlSet\Enum\USBSTOR`})
	items = append(items, usbStorItems...)
	notes = append(notes, usbStorNotes...)
	usbItems, usbNotes := enumUSB(usbRegistrySource{HiveName: "HKLM", Path: `SYSTEM\CurrentControlSet\Enum\USB`})
	items = append(items, usbItems...)
	notes = append(notes, usbNotes...)
	mountedItems, mountedNotes := enumMountedDevices(usbRegistrySource{HiveName: "HKLM", Path: `SYSTEM\MountedDevices`})
	items = append(items, mountedItems...)
	notes = append(notes, mountedNotes...)
	sortPreviousUSB(items)
	return items, notes
}

func enumUSBStor(source usbRegistrySource) ([]previousUSBDevice, []string) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, source.Path, registry.READ)
	if err != nil {
		return nil, []string{fmt.Sprintf(`%s\\%s unreadable or absent: %v`, source.HiveName, source.Path, err)}
	}
	defer key.Close()
	diskIDs, err := key.ReadSubKeyNames(-1)
	if err != nil {
		return nil, []string{fmt.Sprintf(`%s\\%s subkey enumeration failed: %v`, source.HiveName, source.Path, err)}
	}
	items := []previousUSBDevice{}
	notes := []string{}
	for _, diskID := range diskIDs {
		diskKey, err := registry.OpenKey(key, diskID, registry.READ)
		if err != nil {
			notes = append(notes, fmt.Sprintf(`%s\\%s\\%s unreadable: %v`, source.HiveName, source.Path, diskID, err))
			continue
		}
		serials, err := diskKey.ReadSubKeyNames(-1)
		diskKey.Close()
		if err != nil {
			notes = append(notes, fmt.Sprintf(`%s\\%s\\%s serial enumeration failed: %v`, source.HiveName, source.Path, diskID, err))
			continue
		}
		parts := parseUSBStorDiskID(diskID)
		for _, serial := range serials {
			fullPath := fmt.Sprintf(`%s\\%s\\%s\\%s`, source.HiveName, source.Path, diskID, serial)
			items = append(items, previousUSBDevice{EvidenceType: "previously seen", Confidence: "previously seen", SourcePath: fullPath, Vendor: parts.Vendor, Product: parts.Product, Revision: parts.Revision, SerialCandidate: strings.Trim(serial, "&"), DeviceID: `USBSTOR\\` + diskID + `\\` + serial, RawID: diskID})
		}
	}
	return items, notes
}

func enumUSB(source usbRegistrySource) ([]previousUSBDevice, []string) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, source.Path, registry.READ)
	if err != nil {
		return nil, []string{fmt.Sprintf(`%s\\%s unreadable or absent: %v`, source.HiveName, source.Path, err)}
	}
	defer key.Close()
	classes, err := key.ReadSubKeyNames(-1)
	if err != nil {
		return nil, []string{fmt.Sprintf(`%s\\%s subkey enumeration failed: %v`, source.HiveName, source.Path, err)}
	}
	items := []previousUSBDevice{}
	notes := []string{}
	for _, classID := range classes {
		classKey, err := registry.OpenKey(key, classID, registry.READ)
		if err != nil {
			notes = append(notes, fmt.Sprintf(`%s\\%s\\%s unreadable: %v`, source.HiveName, source.Path, classID, err))
			continue
		}
		instances, err := classKey.ReadSubKeyNames(-1)
		classKey.Close()
		if err != nil {
			notes = append(notes, fmt.Sprintf(`%s\\%s\\%s instance enumeration failed: %v`, source.HiveName, source.Path, classID, err))
			continue
		}
		for _, instance := range instances {
			fullPath := fmt.Sprintf(`%s\\%s\\%s\\%s`, source.HiveName, source.Path, classID, instance)
			items = append(items, previousUSBDevice{EvidenceType: "previously seen", Confidence: "previously seen", SourcePath: fullPath, DeviceID: `USB\\` + classID + `\\` + instance, SerialCandidate: strings.Trim(instance, "&"), RawID: classID})
		}
	}
	return items, notes
}

func enumMountedDevices(source usbRegistrySource) ([]previousUSBDevice, []string) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, source.Path, registry.READ)
	if err != nil {
		return nil, []string{fmt.Sprintf(`%s\\%s unreadable or absent: %v`, source.HiveName, source.Path, err)}
	}
	defer key.Close()
	names, err := key.ReadValueNames(-1)
	if err != nil {
		return nil, []string{fmt.Sprintf(`%s\\%s value enumeration failed: %v`, source.HiveName, source.Path, err)}
	}
	items := []previousUSBDevice{}
	for _, name := range names {
		data, _, err := key.GetBinaryValue(name)
		if err != nil {
			continue
		}
		decoded := decodeMountedDeviceValue(data)
		items = append(items, previousUSBDevice{EvidenceType: "volume mapping observed", Confidence: "volume mapping observed", SourcePath: source.HiveName + `\\` + source.Path, MountedDevice: name, VolumeIdentifier: decoded, SerialCandidate: serialCandidateFromDeviceID(decoded)})
	}
	return items, nil
}

func runPowerShellJSON(ctx context.Context, script string, target any) []string {
	out, errText, err := runCommand(ctx, "powershell.exe", []string{"-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script})
	if err != nil {
		msg := strings.TrimSpace(errText)
		if msg == "" {
			msg = err.Error()
		}
		return []string{msg}
	}
	trimmed := bytes.TrimSpace(out)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil
	}
	if err := json.Unmarshal(trimmed, target); err != nil {
		var single map[string]any
		if singleErr := json.Unmarshal(trimmed, &single); singleErr == nil {
			slicePtr, ok := target.(*[]map[string]any)
			if ok {
				*slicePtr = []map[string]any{single}
				return nil
			}
		}
		return []string{"PowerShell JSON parse failed: " + err.Error()}
	}
	return nil
}

func statusFromNotesAndCount(notes []string, count int) string {
	if len(notes) > 0 || count == 0 {
		return "partial"
	}
	return "ok"
}

func classifyVolume(driveType, interfaceType, pnpID string) string {
	if driveType == "2" || strings.EqualFold(interfaceType, "USB") || strings.Contains(strings.ToUpper(pnpID), "USB") {
		return "current"
	}
	return "fixed-or-other/current"
}

func stringField(row map[string]any, key string) string {
	if value, ok := row[key]; ok && value != nil {
		return strings.TrimSpace(fmt.Sprint(value))
	}
	return ""
}

func uint64Field(row map[string]any, key string) uint64 {
	value, ok := row[key]
	if !ok || value == nil {
		return 0
	}
	switch v := value.(type) {
	case float64:
		if v > 0 {
			return uint64(v)
		}
	case json.Number:
		n, _ := v.Int64()
		if n > 0 {
			return uint64(n)
		}
	case string:
		var n uint64
		fmt.Sscanf(v, "%d", &n)
		return n
	}
	return 0
}

func splitCSV(value string) []string {
	parts := strings.Split(value, ",")
	out := []string{}
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}
