package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	thruntime "github.com/chip/incident-response-kit/hub/internal/runtime"
	"github.com/chip/incident-response-kit/hub/internal/store/sqlite"
)

func TestHandleFieldUpdatePersistsDecisionAndNote(t *testing.T) {
	ctx := context.Background()
	store, err := sqlite.Open(filepath.Join(t.TempDir(), "thoth.sqlite"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	if err := store.ApplyMigrations(ctx); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	importID, err := store.InsertImport(ctx, sqlite.ImportRecord{
		ImportUUID: "import-field-update",
		SourcePath: "/tmp/seker",
		SourceKind: "batch",
	})
	if err != nil {
		t.Fatalf("insert import: %v", err)
	}
	if _, err := store.InsertCase(ctx, sqlite.CaseRecord{
		CaseUUID:        "case-field-update",
		ImportID:        importID,
		CaseID:          "FIELD-UPDATE",
		Status:          "new",
		IntegrityStatus: "pending",
		RawCasePath:     "/tmp/seker/case-field-update",
	}); err != nil {
		t.Fatalf("insert case: %v", err)
	}

	form := url.Values{}
	form.Set("disposition", "needs_follow_up")
	form.Set("priority", "high")
	form.Set("note_type", "decision")
	form.Set("author", "Analyst")
	form.Set("body", "Unsaved note text should survive the decision update.")
	form.Set("intent", "add_note")

	request := httptest.NewRequest(http.MethodPost, "/cases/case-field-update/field", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()

	handleFieldUpdate(store, response, request, "case-field-update")

	if response.Code != http.StatusSeeOther {
		t.Fatalf("expected redirect, got %d with body %q", response.Code, response.Body.String())
	}

	summaries, err := store.ListCaseSummaries(ctx)
	if err != nil {
		t.Fatalf("list summaries: %v", err)
	}
	if len(summaries) != 1 {
		t.Fatalf("expected 1 case, got %d", len(summaries))
	}
	if summaries[0].Disposition != "needs_follow_up" || summaries[0].Priority != "high" {
		t.Fatalf("decision was not saved: disposition=%q priority=%q", summaries[0].Disposition, summaries[0].Priority)
	}

	notes, err := store.ListAnalystNotes(ctx, "case-field-update")
	if err != nil {
		t.Fatalf("list notes: %v", err)
	}
	if len(notes) != 1 {
		t.Fatalf("expected 1 note, got %d", len(notes))
	}
	if notes[0].Body != "Unsaved note text should survive the decision update." {
		t.Fatalf("unexpected note body: %q", notes[0].Body)
	}
}

func TestExportDataBundleUsesSelectedDestination(t *testing.T) {
	root := t.TempDir()
	layout := thruntime.Layout{
		RootDir:  root,
		DataRoot: filepath.Join(root, "data"),
		DBPath:   filepath.Join(root, "data", "db", "thoth.sqlite"),
		DocsDir:  filepath.Join(root, "docs"),
		Mode:     "test",
	}
	if err := layout.Ensure(); err != nil {
		t.Fatalf("ensure layout: %v", err)
	}
	if err := os.WriteFile(filepath.Join(layout.DataRoot, "cases", "synthetic.txt"), []byte("case data"), 0o644); err != nil {
		t.Fatalf("write synthetic case data: %v", err)
	}

	destination := filepath.Join(t.TempDir(), "selected-destination")
	archivePath, err := exportDataBundle(layout, destination)
	if err != nil {
		t.Fatalf("export data bundle: %v", err)
	}
	if filepath.Dir(archivePath) != destination {
		t.Fatalf("archive was not written to selected destination: %s", archivePath)
	}
	if !strings.Contains(filepath.Base(archivePath), "thoth-investigation-") {
		t.Fatalf("archive name does not use investigation terminology: %s", archivePath)
	}
	if _, err := os.Stat(archivePath); err != nil {
		t.Fatalf("archive missing at selected destination: %v", err)
	}
}
