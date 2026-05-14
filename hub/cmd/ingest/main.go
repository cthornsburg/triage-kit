package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"strings"

	"github.com/chip/incident-response-kit/hub/internal/ingest"
	thruntime "github.com/chip/incident-response-kit/hub/internal/runtime"
	"github.com/chip/incident-response-kit/hub/internal/store/sqlite"
)

func main() {
	layout, err := thruntime.Detect()
	if err != nil {
		log.Fatalf("detect layout: %v", err)
	}
	if err := layout.Ensure(); err != nil {
		log.Fatalf("ensure layout: %v", err)
	}

	var dbPath string
	var dataRoot string
	flag.StringVar(&dbPath, "db", layout.DBPath, "path to the Thoth sqlite database")
	flag.StringVar(&dataRoot, "data-root", layout.DataRoot, "root directory for Thoth staged imports and case workspaces")
	flag.Parse()

	ctx := context.Background()
	store, err := sqlite.Open(dbPath)
	if err != nil {
		log.Fatalf("open store: %v", err)
	}
	defer store.Close()

	if err := store.ApplyMigrations(ctx); err != nil {
		log.Fatalf("apply migrations: %v", err)
	}

	if flag.NArg() == 0 {
		stats, err := store.Stats(ctx)
		if err != nil {
			log.Fatalf("collect store stats: %v", err)
		}
		fmt.Printf("Thoth DB ready: %s\n", dbPath)
		fmt.Printf("migrations=%d imports=%d cases=%d open_findings=%d notes=%d\n", stats.CompletedMigs, stats.Imports, stats.Cases, stats.OpenFindings, stats.AnalystNotes)
		return
	}

	importer := ingest.Importer{Store: store, DataRoot: dataRoot}
	result, err := importer.ImportPath(ctx, flag.Arg(0))
	if err != nil {
		log.Fatalf("ingest source: %v", err)
	}

	stats, err := store.Stats(ctx)
	if err != nil {
		log.Fatalf("collect store stats: %v", err)
	}

	fmt.Printf("Ingested source: %s\n", result.SourcePath)
	fmt.Printf("batches=%d cases=%d batch_ids=%s\n", result.ImportedBatches, result.ImportedCases, strings.Join(result.BatchIDs, ","))
	fmt.Printf("Store totals: migrations=%d imports=%d cases=%d open_findings=%d notes=%d\n", stats.CompletedMigs, stats.Imports, stats.Cases, stats.OpenFindings, stats.AnalystNotes)
}
