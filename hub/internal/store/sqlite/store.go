package sqlite

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	_ "modernc.org/sqlite"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

type Store struct {
	DB *sql.DB
}

func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("create db directory: %w", err)
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite db: %w", err)
	}

	pragmas := []string{
		"PRAGMA foreign_keys = ON;",
		"PRAGMA journal_mode = WAL;",
		"PRAGMA synchronous = NORMAL;",
	}
	for _, pragma := range pragmas {
		if _, err := db.Exec(pragma); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("apply sqlite pragma %q: %w", pragma, err)
		}
	}

	return &Store{DB: db}, nil
}

func (s *Store) Close() error {
	if s == nil || s.DB == nil {
		return nil
	}
	return s.DB.Close()
}

func (s *Store) ApplyMigrations(ctx context.Context) error {
	entries, err := fs.ReadDir(migrationFS, "migrations")
	if err != nil {
		return fmt.Errorf("read embedded migrations: %w", err)
	}

	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		names = append(names, entry.Name())
	}
	sort.Strings(names)

	for _, name := range names {
		applied, err := s.migrationApplied(ctx, name)
		if err != nil {
			return err
		}
		if applied {
			continue
		}

		content, err := migrationFS.ReadFile(filepath.ToSlash(filepath.Join("migrations", name)))
		if err != nil {
			return fmt.Errorf("read migration %s: %w", name, err)
		}

		if err := s.applyMigration(ctx, name, string(content)); err != nil {
			return err
		}
	}

	return nil
}

func (s *Store) migrationApplied(ctx context.Context, name string) (bool, error) {
	if _, err := s.DB.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			name TEXT PRIMARY KEY,
			applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
		)
	`); err != nil {
		return false, fmt.Errorf("ensure schema_migrations: %w", err)
	}

	var count int
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(1) FROM schema_migrations WHERE name = ?`, name).Scan(&count); err != nil {
		return false, fmt.Errorf("check migration %s: %w", name, err)
	}

	return count > 0, nil
}

func (s *Store) applyMigration(ctx context.Context, name, content string) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin migration %s: %w", name, err)
	}

	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	if _, err = tx.ExecContext(ctx, content); err != nil {
		return fmt.Errorf("execute migration %s: %w", name, err)
	}

	if _, err = tx.ExecContext(ctx, `INSERT INTO schema_migrations(name) VALUES (?)`, name); err != nil {
		return fmt.Errorf("record migration %s: %w", name, err)
	}

	if err = tx.Commit(); err != nil {
		return fmt.Errorf("commit migration %s: %w", name, err)
	}

	return nil
}

type Stats struct {
	Cases         int
	Imports       int
	OpenFindings  int
	AnalystNotes  int
	CompletedMigs int
}

func (s *Store) Stats(ctx context.Context) (Stats, error) {
	stats := Stats{}
	queries := []struct {
		query string
		dest  *int
	}{
		{`SELECT COUNT(1) FROM cases`, &stats.Cases},
		{`SELECT COUNT(1) FROM case_imports`, &stats.Imports},
		{`SELECT COUNT(1) FROM findings WHERE status = 'open'`, &stats.OpenFindings},
		{`SELECT COUNT(1) FROM analyst_notes`, &stats.AnalystNotes},
		{`SELECT COUNT(1) FROM schema_migrations`, &stats.CompletedMigs},
	}

	for _, item := range queries {
		if err := s.DB.QueryRowContext(ctx, item.query).Scan(item.dest); err != nil {
			return Stats{}, fmt.Errorf("collect stats with %q: %w", item.query, err)
		}
	}

	return stats, nil
}
