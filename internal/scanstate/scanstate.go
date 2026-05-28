// Package scanstate implements resumable-scan persistence.
//
// A scan over a large database × many traversal techniques × traversal depth
// is thousands of HTTP requests. If the operator Ctrl-Cs, hits a rate limit,
// or the target flaps, all progress is lost and a re-run re-hammers the target
// — bad for scan time and for stealth. scanstate persists per-entry completion
// to a JSON file so a restart can skip already-attempted entries.
//
// The state file is bound to a (target, marker, db_fingerprint) triple. Resuming
// against a file whose binding differs is refused (fail closed) — silently
// skipping entries that were never attempted against the current target would be
// a correctness hazard.
package scanstate

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// FormatVersion identifies the on-disk state-file schema. Reading a file with a
// higher version than this binary understands is refused.
const FormatVersion = 1

// Hit records a confirmed readable file from a prior (or the current) run so
// resumed scans can replay earlier findings without re-requesting them.
type Hit struct {
	EntryID   string `json:"entry_id"`
	Path      string `json:"path"`
	Technique string `json:"technique"`
	Status    int    `json:"status"`
}

// State is the persisted, resumable scan state. It is bound to the target,
// marker, and database fingerprint it was created against; see Validate.
type State struct {
	// FormatVersion is the on-disk schema version (see FormatVersion).
	FormatVersion int `json:"format_version"`
	// Target is the scanned URL the state belongs to.
	Target string `json:"target"`
	// Marker is the injection marker used (default "FUZZ").
	Marker string `json:"marker"`
	// DBFingerprint identifies the database content the scan walked. A scan
	// resumed against a different database is refused, because the skip-set would
	// otherwise hide entries that were never attempted.
	DBFingerprint string `json:"db_fingerprint"`
	// AttemptedEntryIDs lists every entry that has been fully scanned.
	AttemptedEntryIDs []string `json:"attempted_entry_ids"`
	// ConfirmedHits replays confirmed reads from prior runs.
	ConfirmedHits []Hit `json:"confirmed_hits"`

	// path is the file this state is flushed to. Not serialised.
	path string
	// attempted is the in-memory skip-set, kept in sync with AttemptedEntryIDs.
	attempted map[string]struct{}
}

// Fingerprint derives a stable identifier for a database from its entry IDs.
// It is order-independent (IDs are sorted before hashing) so that loader
// iteration order never invalidates an otherwise-identical database.
func Fingerprint(entryIDs []string) string {
	ids := make([]string, len(entryIDs))
	copy(ids, entryIDs)
	sort.Strings(ids)
	h := sha256.New()
	for _, id := range ids {
		h.Write([]byte(id))
		h.Write([]byte{0}) // delimiter prevents "ab"+"c" colliding with "a"+"bc"
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// New returns a fresh, empty state bound to target/marker/fingerprint and
// destined for path. It does not touch the filesystem.
func New(path, target, marker, fingerprint string) *State {
	return &State{
		FormatVersion: FormatVersion,
		Target:        target,
		Marker:        marker,
		DBFingerprint: fingerprint,
		path:          path,
		attempted:     map[string]struct{}{},
	}
}

// Load reads an existing state file. If the file does not exist it returns a
// fresh state bound to the supplied binding (the first run of a resumable scan).
// If the file exists but its binding (target, marker, or db fingerprint) does
// not match, Load fails closed with a descriptive error rather than silently
// skipping unattempted entries.
func Load(path, target, marker, fingerprint string) (*State, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return New(path, target, marker, fingerprint), nil
	}
	if err != nil {
		return nil, fmt.Errorf("read resume file %q: %w", path, err)
	}

	var s State
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("parse resume file %q: %w", path, err)
	}
	if s.FormatVersion > FormatVersion {
		return nil, fmt.Errorf("resume file %q has format_version %d, unsupported by this binary (supports <= %d): upgrade exhumed",
			path, s.FormatVersion, FormatVersion)
	}
	if err := validateBinding(&s, target, marker, fingerprint); err != nil {
		return nil, err
	}

	s.path = path
	s.attempted = make(map[string]struct{}, len(s.AttemptedEntryIDs))
	for _, id := range s.AttemptedEntryIDs {
		s.attempted[id] = struct{}{}
	}
	return &s, nil
}

// validateBinding refuses to resume a state whose target, marker, or database
// fingerprint differs from the current scan.
func validateBinding(s *State, target, marker, fingerprint string) error {
	if s.Target != target {
		return fmt.Errorf("resume file targets %q but this scan targets %q: refusing to resume (delete the file to start fresh)", s.Target, target)
	}
	if s.Marker != marker {
		return fmt.Errorf("resume file uses marker %q but this scan uses %q: refusing to resume", s.Marker, marker)
	}
	if s.DBFingerprint != fingerprint {
		return fmt.Errorf("resume file was built against a different database (fingerprint %q vs %q): refusing to resume (the skip-set would hide unattempted entries)", s.DBFingerprint, fingerprint)
	}
	return nil
}

// Attempted reports whether entryID has already been scanned in a prior run.
func (s *State) Attempted(entryID string) bool {
	_, ok := s.attempted[entryID]
	return ok
}

// AttemptedCount returns how many entries have been recorded as attempted.
func (s *State) AttemptedCount() int {
	return len(s.attempted)
}

// Hits returns the confirmed hits recorded so far (prior runs + this run).
func (s *State) Hits() []Hit {
	return s.ConfirmedHits
}

// Record marks entryID attempted and, if hit is non-nil, appends a confirmed
// hit. It then atomically flushes the state to disk. Recording an already-
// attempted entry is idempotent for the skip-set but still flushes.
func (s *State) Record(entryID string, hit *Hit) error {
	if _, ok := s.attempted[entryID]; !ok {
		s.attempted[entryID] = struct{}{}
		s.AttemptedEntryIDs = append(s.AttemptedEntryIDs, entryID)
	}
	if hit != nil {
		s.ConfirmedHits = append(s.ConfirmedHits, *hit)
	}
	return s.flush()
}

// flush writes the state to a temp file in the same directory and atomically
// renames it over the destination, mirroring the feed package's atomic-swap
// pattern. A crash mid-write leaves the previous good file intact.
func (s *State) flush() error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal resume state: %w", err)
	}

	dir := filepath.Dir(s.path)
	tmp, err := os.CreateTemp(dir, ".tmp-resume-*")
	if err != nil {
		return fmt.Errorf("create temp resume file: %w", err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("write temp resume file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("close temp resume file: %w", err)
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("atomic rename resume file: %w", err)
	}
	return nil
}
