// build-feed generates a publishable feed package from a database directory.
// It computes SHA-256 checksums for every YAML file and writes a manifest.json.
//
// Usage:
//
//	build-feed --db <database-dir> --out <output-dir> --version <version>
//
// Example:
//
//	build-feed --db database/ --out dist/feed/ --version 2026-05-17
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// manifestSchemaVersion matches db.SchemaVersion — the schema version the
// database files in this release use.
const manifestSchemaVersion = 1

// FileEntry mirrors feed.FileEntry without importing the internal package.
type FileEntry struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
}

// Manifest mirrors feed.Manifest.
type Manifest struct {
	SchemaVersion int         `json:"schema_version"`
	DBVersion     string      `json:"db_version"`
	Files         []FileEntry `json:"files"`
}

func main() {
	dbDir := flag.String("db", "database", "database root directory (curated YAML files)")
	outDir := flag.String("out", "dist/feed", "output directory for manifest and DB files")
	version := flag.String("version", "", "database release version (e.g. 2026-05-17 or 1.0.0) [required]")
	flag.Parse()

	if *version == "" {
		fmt.Fprintln(os.Stderr, "error: --version is required")
		flag.Usage()
		os.Exit(1)
	}

	if err := run(*dbDir, *outDir, *version); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run(dbDir, outDir, version string) error {
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return fmt.Errorf("create output dir %s: %w", outDir, err)
	}

	var entries []FileEntry

	// Walk the database directory (excluding _raw/ and non-YAML files).
	rawDir := filepath.Join(dbDir, "_raw")
	schemaDir := filepath.Join(dbDir, "_schema")

	err := filepath.WalkDir(dbDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if filepath.Clean(path) == filepath.Clean(rawDir) ||
				filepath.Clean(path) == filepath.Clean(schemaDir) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(d.Name(), ".yaml") {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}

		// Compute SHA-256.
		h := sha256.Sum256(data)
		checksum := hex.EncodeToString(h[:])

		// Copy to output dir, preserving relative path from dbDir.
		rel, _ := filepath.Rel(dbDir, path)
		destPath := filepath.Join(outDir, rel)
		if err := os.MkdirAll(filepath.Dir(destPath), 0o755); err != nil {
			return fmt.Errorf("mkdir %s: %w", filepath.Dir(destPath), err)
		}
		if err := copyFile(path, destPath); err != nil {
			return fmt.Errorf("copy %s → %s: %w", path, destPath, err)
		}

		entries = append(entries, FileEntry{Name: rel, SHA256: checksum})
		fmt.Printf("  added: %s  sha256=%s\n", rel, checksum[:8]+"…")
		return nil
	})
	if err != nil {
		return fmt.Errorf("walk %s: %w", dbDir, err)
	}

	manifest := Manifest{
		SchemaVersion: manifestSchemaVersion,
		DBVersion:     version,
		Files:         entries,
	}

	manifestData, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal manifest: %w", err)
	}
	manifestPath := filepath.Join(outDir, "manifest.json")
	if err := os.WriteFile(manifestPath, manifestData, 0o644); err != nil {
		return fmt.Errorf("write manifest: %w", err)
	}

	fmt.Printf("✓ manifest written: %s (%d files, version=%s, schema=%d)\n",
		manifestPath, len(entries), version, manifestSchemaVersion)
	return nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}
