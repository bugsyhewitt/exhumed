package db

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// LoadDir discovers every *.yaml file under root, parses them, and returns the
// merged in-memory Database. Root may be an absolute or relative path.
//
// An empty or non-existent root is not an error — an empty Database is returned.
// This allows the curated database/ root to be empty during Packet 02b development
// without breaking scan or the test suite.
//
// Duplicate group IDs across files or duplicate entry IDs within a file are
// hard errors: the returned Database is nil and the error is non-nil.
func LoadDir(root string) (*Database, error) {
	if _, err := os.Stat(root); os.IsNotExist(err) {
		return newDatabase(), nil
	}

	var yamlFiles []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(d.Name(), ".yaml") {
			yamlFiles = append(yamlFiles, path)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk %s: %w", root, err)
	}

	db := newDatabase()
	for _, f := range yamlFiles {
		if err := loadFile(db, f); err != nil {
			return nil, err
		}
	}
	return db, nil
}

// LoadCurated loads only the curated entries from root, excluding any _raw/
// subdirectory. Use this for real scans.
func LoadCurated(root string) (*Database, error) {
	rawDir := filepath.Join(root, "_raw")
	if _, err := os.Stat(root); os.IsNotExist(err) {
		return newDatabase(), nil
	}

	var yamlFiles []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		// Skip the _raw subdirectory entirely.
		if d.IsDir() && filepath.Clean(path) == filepath.Clean(rawDir) {
			return filepath.SkipDir
		}
		if !d.IsDir() && strings.HasSuffix(d.Name(), ".yaml") {
			yamlFiles = append(yamlFiles, path)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk curated %s: %w", root, err)
	}

	db := newDatabase()
	for _, f := range yamlFiles {
		if err := loadFile(db, f); err != nil {
			return nil, err
		}
	}
	return db, nil
}

// loadFile parses one YAML file and inserts its entries into db.
func loadFile(db *Database, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}

	var gf GroupFile
	if err := yaml.Unmarshal(data, &gf); err != nil {
		return fmt.Errorf("parse %s: %w", path, err)
	}

	if gf.SchemaVersion != SchemaVersion {
		return fmt.Errorf("file %s: unsupported schema_version %d (want %d)",
			path, gf.SchemaVersion, SchemaVersion)
	}

	// Reject duplicate group IDs.
	if _, exists := db.groups[gf.Group.ID]; exists {
		return fmt.Errorf("file %s: duplicate group id %q (first seen in another file)", path, gf.Group.ID)
	}
	db.groups[gf.Group.ID] = gf.Group

	// Track entry IDs within this file for duplicate detection.
	seenIDs := make(map[string]struct{}, len(gf.Entries))

	for i := range gf.Entries {
		e := &gf.Entries[i]

		if _, dup := seenIDs[e.ID]; dup {
			return fmt.Errorf("file %s: duplicate entry id %q", path, e.ID)
		}
		seenIDs[e.ID] = struct{}{}

		ce := CompiledEntry{
			Entry:      *e,
			SourceFile: path,
			GroupID:    gf.Group.ID,
		}

		// Compile confirm regexes at load time so detection (Packet 03) pays
		// zero compilation cost per request. A broken regex is a release-blocker.
		if e.Confirm.Type == ConfirmTypeRegex {
			ce.CompiledPatterns = make([]*regexp.Regexp, len(e.Confirm.Patterns))
			for j, pat := range e.Confirm.Patterns {
				compiled, err := regexp.Compile(pat)
				if err != nil {
					return fmt.Errorf("file %s entry %q: invalid confirm pattern %q: %w",
						path, e.ID, pat, err)
				}
				ce.CompiledPatterns[j] = compiled
			}
			ce.CompiledNegate = make([]*regexp.Regexp, len(e.Confirm.Negate))
			for j, pat := range e.Confirm.Negate {
				compiled, err := regexp.Compile(pat)
				if err != nil {
					return fmt.Errorf("file %s entry %q: invalid negate pattern %q: %w",
						path, e.ID, pat, err)
				}
				ce.CompiledNegate[j] = compiled
			}
		}

		idx := len(db.entries)
		db.entries = append(db.entries, ce)

		db.byGroup[gf.Group.ID] = append(db.byGroup[gf.Group.ID], idx)
		for _, os := range e.OS {
			db.byOS[os] = append(db.byOS[os], idx)
		}
		db.byCategory[string(gf.Group.Category)] = append(db.byCategory[string(gf.Group.Category)], idx)
		db.byInfoGoal[string(e.InfoGoal)] = append(db.byInfoGoal[string(e.InfoGoal)], idx)
	}

	return nil
}
