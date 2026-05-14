package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/chip/incident-response-kit/collector/internal/app"
)

func main() {
	cfg := app.Config{}
	flag.StringVar(&cfg.OutputDir, "output-dir", ".", "Root directory for collector output")
	flag.StringVar(&cfg.BatchID, "batch-id", "", "Optional batch identifier; generated if omitted")
	flag.StringVar(&cfg.Hostname, "hostname", "sample-host", "Target hostname label")
	flag.StringVar(&cfg.OperatorID, "operator-id", "dev-operator", "Operator identifier")
	flag.StringVar(&cfg.MediaLabel, "media-label", "USB-DRY-RUN", "Media label or serial")
	flag.StringVar(&cfg.Notes, "notes", "", "Optional operator notes")
	flag.Parse()

	cfg.Now = time.Now().UTC()
	if err := app.Run(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "seker: %v\n", err)
		os.Exit(1)
	}
}
