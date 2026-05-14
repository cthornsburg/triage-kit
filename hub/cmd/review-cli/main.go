package main

import (
	"context"
	"flag"
	"fmt"
	"log"

	"github.com/chip/incident-response-kit/hub/internal/findings"
	"github.com/chip/incident-response-kit/hub/internal/normalize"
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
	flag.StringVar(&dbPath, "db", layout.DBPath, "path to the Thoth sqlite database")
	flag.Parse()

	store, err := sqlite.Open(dbPath)
	if err != nil {
		log.Fatalf("open store: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	if err := store.ApplyMigrations(ctx); err != nil {
		log.Fatalf("apply migrations: %v", err)
	}

	if flag.NArg() > 0 && flag.Arg(0) == "doctor" {
		summaries, err := store.ListCaseSummaries(ctx)
		if err != nil {
			log.Fatalf("list cases: %v", err)
		}
		fmt.Printf("mode=%s\nroot=%s\ndata_root=%s\ndb=%s\ndocs=%s\n", layout.Mode, layout.RootDir, layout.DataRoot, dbPath, layout.DocsDir)
		fmt.Printf("cases=%d\n", len(summaries))
		return
	}

	summaries, err := store.ListCaseSummaries(ctx)
	if err != nil {
		log.Fatalf("list cases: %v", err)
	}

	if len(summaries) == 0 {
		fmt.Println("No ingested cases found.")
		return
	}

	if flag.NArg() > 0 && flag.Arg(0) == "findings" {
		for _, summary := range summaries {
			items, err := findings.GenerateCaseFindings(ctx, store, summary)
			if err != nil {
				log.Fatalf("generate findings for case %s: %v", summary.CaseUUID, err)
			}
			fmt.Printf("findings %s (%s): %d\n", summary.CaseUUID, summary.Hostname, len(items))
		}
		return
	}

	if flag.NArg() > 0 && flag.Arg(0) == "normalize" {
		for _, summary := range summaries {
			result, err := normalize.NormalizeCase(summary)
			if err != nil {
				log.Fatalf("normalize case %s: %v", summary.CaseUUID, err)
			}
			if err := normalize.LoadNormalizedArtifacts(ctx, store, summary, result); err != nil {
				log.Fatalf("load normalized artifacts for case %s: %v", summary.CaseUUID, err)
			}
			fmt.Printf("normalized %s (%s): %d artifact sets -> %s\n", result.CaseUUID, result.Hostname, len(result.Artifacts), summary.NormalizedCasePath)
			for _, warning := range result.Warnings {
				fmt.Printf("  warning: %s\n", warning)
			}
		}
		return
	}

	for _, summary := range summaries {
		fmt.Printf("%s | %s | %s | status=%s integrity=%s warnings=%d errors=%d\n",
			summary.CaseUUID,
			summary.Hostname,
			summary.CollectedAt,
			summary.Status,
			summary.IntegrityStatus,
			summary.WarningsCount,
			summary.ErrorsCount,
		)
		fmt.Printf("  case_id=%s batch_id=%s collector=%s\n", summary.CaseID, summary.BatchID, summary.CollectorVersion)
		fmt.Printf("  raw=%s\n", summary.RawCasePath)
		if summary.NormalizedCasePath != "" {
			fmt.Printf("  normalized=%s\n", summary.NormalizedCasePath)
		}
	}
}
