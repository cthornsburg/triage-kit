//go:build !windows

package collect

import (
	"context"
	"runtime"
	"time"

	"github.com/chip/incident-response-kit/collector/internal/model"
)

func (SoftwareCollector) Collect(ctx context.Context, caseDir string, collectedAt time.Time) ([]model.ArtifactRecord, []string) {
	_ = ctx
	_ = caseDir
	_ = collectedAt
	note := "installed-program inventory is Windows-only; skipped in local dev harness on " + runtime.GOOS
	return nil, []string{note}
}
