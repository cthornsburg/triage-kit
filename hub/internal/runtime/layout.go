package runtime

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type Layout struct {
	RootDir  string
	DataRoot string
	DBPath   string
	DocsDir  string
	Mode     string
}

func Detect() (Layout, error) {
	if root := strings.TrimSpace(os.Getenv("THOTH_ROOT")); root != "" {
		return buildLayout(root)
	}

	cwd, err := os.Getwd()
	if err != nil {
		return Layout{}, fmt.Errorf("get working directory: %w", err)
	}

	if looksLikePortableRoot(cwd) || looksLikeDevHubRoot(cwd) {
		return buildLayout(cwd)
	}

	if filepath.Base(cwd) == "bin" && looksLikePortableRoot(filepath.Dir(cwd)) {
		return buildLayout(filepath.Dir(cwd))
	}

	return buildLayout(cwd)
}

func buildLayout(root string) (Layout, error) {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return Layout{}, fmt.Errorf("resolve layout root: %w", err)
	}

	docsDir := filepath.Join(absRoot, "lib", "docs")
	if !dirExists(docsDir) {
		candidate := filepath.Join(filepath.Dir(absRoot), "docs")
		if dirExists(candidate) {
			docsDir = candidate
		}
	}

	return Layout{
		RootDir:  absRoot,
		DataRoot: filepath.Join(absRoot, "data"),
		DBPath:   filepath.Join(absRoot, "data", "db", "thoth.sqlite"),
		DocsDir:  docsDir,
		Mode:     detectMode(absRoot),
	}, nil
}

func (l Layout) Ensure() error {
	paths := []string{
		filepath.Join(l.RootDir, "bin"),
		filepath.Join(l.RootDir, "lib"),
		filepath.Join(l.RootDir, "config"),
		filepath.Join(l.RootDir, "scripts"),
		filepath.Join(l.RootDir, "logs"),
		filepath.Join(l.DataRoot, "db"),
		filepath.Join(l.DataRoot, "imports"),
		filepath.Join(l.DataRoot, "cases"),
		filepath.Join(l.DataRoot, "quarantine"),
		filepath.Join(l.DataRoot, "exports"),
		filepath.Join(l.DataRoot, "tmp"),
	}
	for _, path := range paths {
		if err := os.MkdirAll(path, 0o755); err != nil {
			return fmt.Errorf("ensure path %s: %w", path, err)
		}
	}
	return nil
}

func looksLikePortableRoot(path string) bool {
	return dirExists(filepath.Join(path, "bin")) || dirExists(filepath.Join(path, "lib")) || dirExists(filepath.Join(path, "config")) || dirExists(filepath.Join(path, "data"))
}

func looksLikeDevHubRoot(path string) bool {
	return dirExists(filepath.Join(path, "cmd")) && dirExists(filepath.Join(path, "internal"))
}

func detectMode(path string) string {
	if looksLikeDevHubRoot(path) {
		return "dev"
	}
	if looksLikePortableRoot(path) {
		return "portable"
	}
	return "unknown"
}

func dirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}
