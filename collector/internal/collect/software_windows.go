//go:build windows

package collect

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/chip/incident-response-kit/collector/internal/model"
	"golang.org/x/sys/windows/registry"
)

type uninstallRegistrySource struct {
	Hive     registry.Key
	HiveName string
	Path     string
	Scope    string
}

func (SoftwareCollector) Collect(ctx context.Context, caseDir string, collectedAt time.Time) ([]model.ArtifactRecord, []string) {
	_ = ctx
	sources := []uninstallRegistrySource{
		{Hive: registry.LOCAL_MACHINE, HiveName: "HKLM", Path: `Software\Microsoft\Windows\CurrentVersion\Uninstall`, Scope: "machine"},
		{Hive: registry.LOCAL_MACHINE, HiveName: "HKLM", Path: `Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`, Scope: "machine_wow6432"},
		{Hive: registry.CURRENT_USER, HiveName: "HKCU", Path: `Software\Microsoft\Windows\CurrentVersion\Uninstall`, Scope: "per_user"},
	}

	programs := []installedProgram{}
	notes := []string{"InstallDate is copied from uninstall registry values and labeled per-entry because it is often missing or not a reliable install timestamp."}
	for _, source := range sources {
		items, sourceNotes := readUninstallSource(source)
		programs = append(programs, items...)
		for _, note := range sourceNotes {
			if strings.TrimSpace(note) != "" {
				notes = append(notes, note)
			}
		}
	}
	sort.SliceStable(programs, func(i, j int) bool {
		left := strings.ToLower(programs[i].DisplayName + "\x00" + programs[i].SourcePath)
		right := strings.ToLower(programs[j].DisplayName + "\x00" + programs[j].SourcePath)
		return left < right
	})

	status := "ok"
	if len(notes) > 1 {
		status = "partial"
	}
	if len(programs) == 0 {
		status = "partial"
		notes = append(notes, "No display-name uninstall entries were readable from the scoped uninstall registry paths.")
	}
	record, warnings := writeSoftwareJSON(caseDir, programs, collectedAt, status, notes, nil)
	return []model.ArtifactRecord{record}, warnings
}

func readUninstallSource(source uninstallRegistrySource) ([]installedProgram, []string) {
	key, err := registry.OpenKey(source.Hive, source.Path, registry.READ)
	if err != nil {
		return nil, []string{fmt.Sprintf("%s\\%s unreadable or absent: %v", source.HiveName, source.Path, err)}
	}
	defer key.Close()

	names, err := key.ReadSubKeyNames(-1)
	if err != nil {
		return nil, []string{fmt.Sprintf("%s\\%s subkey enumeration failed: %v", source.HiveName, source.Path, err)}
	}

	programs := make([]installedProgram, 0, len(names))
	notes := []string{}
	for _, name := range names {
		select {
		default:
		}
		child, err := registry.OpenKey(key, name, registry.READ)
		if err != nil {
			notes = append(notes, fmt.Sprintf("%s\\%s\\%s unreadable: %v", source.HiveName, source.Path, name, err))
			continue
		}
		program, include := readInstalledProgram(child, source, name)
		child.Close()
		if include {
			programs = append(programs, program)
		}
	}
	return programs, notes
}

func readInstalledProgram(key registry.Key, source uninstallRegistrySource, subkeyName string) (installedProgram, bool) {
	displayName := registryString(key, "DisplayName")
	if strings.TrimSpace(displayName) == "" {
		return installedProgram{}, false
	}
	installDate := registryString(key, "InstallDate")
	return installedProgram{
		DisplayName:       displayName,
		Publisher:         registryString(key, "Publisher"),
		DisplayVersion:    registryString(key, "DisplayVersion"),
		InstallDate:       installDate,
		InstallDateStatus: installDateStatus(installDate),
		InstallLocation:   registryString(key, "InstallLocation"),
		InstallSource:     registryString(key, "InstallSource"),
		UninstallString:   registryString(key, "UninstallString"),
		QuietUninstall:    registryString(key, "QuietUninstallString"),
		Scope:             source.Scope,
		SourceHive:        source.HiveName,
		SourcePath:        source.HiveName + `\` + source.Path + `\` + subkeyName,
		SourceKeyName:     subkeyName,
	}, true
}

func registryString(key registry.Key, name string) string {
	value, _, err := key.GetStringValue(name)
	if err == nil {
		return strings.TrimSpace(value)
	}
	stringsValue, _, err := key.GetStringsValue(name)
	if err == nil {
		return strings.TrimSpace(strings.Join(stringsValue, "; "))
	}
	return ""
}
