package casebundle

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var caseSubdirs = []string{
	"host",
	"processes",
	"network",
	"persistence",
	"files",
	"security",
	"software",
	"logs",
	"devices",
}

type Layout struct {
	RootDir      string
	BatchDir     string
	CaseDir      string
	CaseName     string
	RelativeCase string
}

func Create(rootDir, batchID, hostname string, collectedAt time.Time) (Layout, error) {
	timestamp := collectedAt.UTC().Format("2006-01-02T150405Z")
	caseName := fmt.Sprintf("case-%s-%s", sanitize(hostname), timestamp)
	batchDir := filepath.Join(rootDir, "collections", batchID)
	caseDir := filepath.Join(batchDir, caseName)

	for _, dir := range append([]string{batchDir, caseDir}, childDirs(caseDir)...) {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return Layout{}, err
		}
	}

	return Layout{
		RootDir:      rootDir,
		BatchDir:     batchDir,
		CaseDir:      caseDir,
		CaseName:     caseName,
		RelativeCase: filepath.ToSlash(caseName),
	}, nil
}

func childDirs(caseDir string) []string {
	dirs := make([]string, 0, len(caseSubdirs))
	for _, dir := range caseSubdirs {
		dirs = append(dirs, filepath.Join(caseDir, dir))
	}
	return dirs
}

func sanitize(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	value = strings.ReplaceAll(value, " ", "-")
	value = strings.ReplaceAll(value, "_", "-")
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
			return r
		case r >= '0' && r <= '9':
			return r
		case r == '-':
			return r
		default:
			return -1
		}
	}, value)
}
