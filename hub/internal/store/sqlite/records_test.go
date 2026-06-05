package sqlite

import (
	"context"
	"path/filepath"
	"testing"
)

func TestCaseDecisionAndAnalystNotes(t *testing.T) {
	ctx := context.Background()
	store, err := Open(filepath.Join(t.TempDir(), "thoth.sqlite"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	if err := store.ApplyMigrations(ctx); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}

	importID, err := store.InsertImport(ctx, ImportRecord{
		ImportUUID: "import-test",
		SourcePath: "/tmp/seker",
		SourceKind: "batch",
	})
	if err != nil {
		t.Fatalf("insert import: %v", err)
	}

	if _, err := store.InsertCase(ctx, CaseRecord{
		CaseUUID:         "case-test",
		ImportID:         importID,
		CaseID:           "FIELD-001",
		CollectionCaseID: "bundle-test",
		Hostname:         "HOST-01",
		Status:           "new",
		IntegrityStatus:  "pending",
		RawCasePath:      "/tmp/seker/case-test",
	}); err != nil {
		t.Fatalf("insert case: %v", err)
	}

	if err := store.UpdateCaseDecision(ctx, "case-test", "forensic_escalation", "high", true); err != nil {
		t.Fatalf("update decision: %v", err)
	}
	if err := store.AddAnalystNote(ctx, "case-test", "decision", "Escalate for deeper forensic review.", "Analyst"); err != nil {
		t.Fatalf("add decision note: %v", err)
	}
	if err := store.AddAnalystNote(ctx, "case-test", "observation", "PowerShell and persistence require follow-up.", "Intern 1"); err != nil {
		t.Fatalf("add observation note: %v", err)
	}

	summaries, err := store.ListCaseSummaries(ctx)
	if err != nil {
		t.Fatalf("list case summaries: %v", err)
	}
	if len(summaries) != 1 {
		t.Fatalf("expected 1 case summary, got %d", len(summaries))
	}
	summary := summaries[0]
	if summary.Disposition != "forensic_escalation" || summary.Priority != "high" || !summary.Escalated {
		t.Fatalf("unexpected decision state: disposition=%q priority=%q escalated=%v", summary.Disposition, summary.Priority, summary.Escalated)
	}

	notes, err := store.ListAnalystNotes(ctx, "case-test")
	if err != nil {
		t.Fatalf("list analyst notes: %v", err)
	}
	if len(notes) != 2 {
		t.Fatalf("expected 2 notes, got %d", len(notes))
	}
	if notes[0].NoteType != "observation" || notes[0].Author != "Intern 1" {
		t.Fatalf("expected newest note first, got type=%q author=%q", notes[0].NoteType, notes[0].Author)
	}
	if notes[1].NoteType != "decision" || notes[1].Author != "Analyst" {
		t.Fatalf("expected decision note second, got type=%q author=%q", notes[1].NoteType, notes[1].Author)
	}

	if err := store.ClearAnalysisState(ctx); err != nil {
		t.Fatalf("clear analysis state: %v", err)
	}
	summaries, err = store.ListCaseSummaries(ctx)
	if err != nil {
		t.Fatalf("list case summaries after clear: %v", err)
	}
	if len(summaries) != 0 {
		t.Fatalf("expected no case summaries after clear, got %d", len(summaries))
	}
	notes, err = store.ListAnalystNotes(ctx, "case-test")
	if err != nil {
		t.Fatalf("list analyst notes after clear: %v", err)
	}
	if len(notes) != 0 {
		t.Fatalf("expected no notes after clear, got %d", len(notes))
	}
}
