package collect

import (
	"context"
	"time"

	"github.com/chip/incident-response-kit/collector/internal/model"
)

type Collector interface {
	Collect(ctx context.Context, caseDir string, collectedAt time.Time) ([]model.ArtifactRecord, []string)
}
