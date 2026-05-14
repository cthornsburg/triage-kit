//go:build !windows

package collect

import (
	"context"
	"fmt"
	"runtime"
	"time"

	"github.com/chip/incident-response-kit/collector/internal/model"
)

func (DeviceCollector) Collect(ctx context.Context, caseDir string, collectedAt time.Time) ([]model.ArtifactRecord, []string) {
	_ = ctx
	note := fmt.Sprintf("device/removable-media collection is Windows-first; local dev harness stub emitted on %s", runtime.GOOS)
	records := make([]model.ArtifactRecord, 0, 4)

	volumes := deviceArtifactEnvelope[deviceVolume]{Source: "non-Windows dev harness stub", Confidence: "low", Notes: []string{note}, Items: []deviceVolume{}}
	record, notes := writeDeviceJSON(caseDir, "devices/volumes.json", "devices-volumes", volumes, volumes.Source, collectedAt, "partial", []string{note})
	records = append(records, record)
	warnings := appendPrefixed(nil, "devices-volumes", notes)

	pnp := deviceArtifactEnvelope[pnpDeviceSummary]{Source: "non-Windows dev harness stub", Confidence: "low", Notes: []string{note}, Items: []pnpDeviceSummary{}}
	record, notes = writeDeviceJSON(caseDir, "devices/pnp-summary.json", "devices-pnp-summary", pnp, pnp.Source, collectedAt.Add(time.Second), "partial", []string{note})
	records = append(records, record)
	warnings = appendPrefixed(warnings, "devices-pnp-summary", notes)

	current := deviceArtifactEnvelope[currentUSBDevice]{Source: "non-Windows dev harness stub", Confidence: "low", Notes: []string{note}, Items: []currentUSBDevice{}}
	record, notes = writeDeviceJSON(caseDir, "devices/usb-current.json", "devices-usb-current", current, current.Source, collectedAt.Add(2*time.Second), "partial", []string{note})
	records = append(records, record)
	warnings = appendPrefixed(warnings, "devices-usb-current", notes)

	previous := deviceArtifactEnvelope[previousUSBDevice]{Source: "non-Windows dev harness stub", Confidence: "low", Notes: []string{note, "Baseline SEKER v1.0 does not claim complete USB forensic history."}, Items: []previousUSBDevice{}}
	record, notes = writeDeviceJSON(caseDir, "devices/usb-previous.json", "devices-usb-previous", previous, previous.Source, collectedAt.Add(3*time.Second), "partial", []string{note})
	records = append(records, record)
	warnings = appendPrefixed(warnings, "devices-usb-previous", notes)

	return records, warnings
}
