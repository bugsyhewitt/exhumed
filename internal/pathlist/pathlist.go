// Package pathlist parses external file-path wordlists (SecLists-style) into
// synthetic database entries that scan can fire alongside the curated database.
//
// A wordlist is a plain-text file with one candidate file path per line. This
// is the de-facto format of the LFI/path-traversal lists shipped in SecLists
// (e.g. Fuzzing/LFI/LFI-Jhaddix.txt, Discovery/Web-Content/...). exhumed treats
// each line as a target path and walks it with the normal traversal engine,
// using a weak confirm (any non-empty 2xx body) so any readable file surfaces.
//
// Parsing rules, chosen to match how SecLists and similar lists are written:
//   - lines are trimmed of surrounding whitespace
//   - blank lines are skipped
//   - lines beginning with '#' are treated as comments and skipped
//   - duplicate paths (after trimming) are de-duplicated, first occurrence wins
//   - any leading "{marker}"-style placeholders are NOT interpreted here; the
//     traversal generator owns prefix synthesis, so the raw path is used as-is
package pathlist

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/bugsyhewitt/exhumed/internal/db"
)

// weakConfirmPattern matches any single character, i.e. any non-empty body.
// Detection still enforces the 2xx-status and minimum-body-length gates, so this
// is "any readable, non-trivial response" rather than literally anything.
const weakConfirmPattern = `.`

// Parse reads a wordlist from r and returns one synthetic CompiledEntry per
// unique, non-comment path. Entries are returned in first-seen order. The
// confirm regex is pre-compiled exactly as the YAML loader would compile it, so
// the returned entries are immediately usable by detect.Check.
//
// source is used only for diagnostics in entry IDs and SourceFile.
func Parse(r io.Reader, source string) ([]db.CompiledEntry, error) {
	weakRE, err := regexp.Compile(weakConfirmPattern)
	if err != nil {
		// weakConfirmPattern is a compile-time constant; this never fails.
		return nil, fmt.Errorf("pathlist: compile weak confirm: %w", err)
	}

	var entries []db.CompiledEntry
	seen := make(map[string]struct{})

	sc := bufio.NewScanner(r)
	// Allow long lines: some wordlists carry very long encoded paths.
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if _, dup := seen[line]; dup {
			continue
		}
		seen[line] = struct{}{}

		entries = append(entries, synthFromPath(line, source, weakRE))
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("pathlist: read %s: %w", source, err)
	}
	return entries, nil
}

// ParseFile opens path and delegates to Parse. A missing or unreadable file is
// an error so the operator learns immediately rather than silently scanning the
// curated database only.
func ParseFile(path string) ([]db.CompiledEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("pathlist: open %s: %w", path, err)
	}
	defer f.Close()
	return Parse(f, path)
}

// synthFromPath builds a weak-confirm CompiledEntry for a single wordlist path.
// The parser hint is inferred from the path so that, on a hit, the right
// format-aware extractor runs (mirroring scan's chain-target synthesis).
func synthFromPath(path, source string, weakRE *regexp.Regexp) db.CompiledEntry {
	return db.CompiledEntry{
		Entry: db.Entry{
			ID:        "wordlist:" + path,
			Name:      path,
			Path:      path,
			OS:        []string{"linux", "windows"},
			InfoGoal:  db.InfoGoalConfig,
			Privilege: db.PrivilegeUnknown,
			Parser:    inferParser(path),
			Tags:      []string{"wordlist"},
			Confirm: db.Confirm{
				Type:     db.ConfirmTypeRegex,
				Patterns: []string{weakConfirmPattern},
			},
		},
		CompiledPatterns: []*regexp.Regexp{weakRE},
		SourceFile:       source,
		GroupID:          "wordlist",
	}
}

// inferParser picks a format-aware parser hint from a file path. It mirrors the
// heuristics scan uses for chain follow-on targets so wordlist hits extract the
// same way curated hits do. Unknown shapes fall back to generic secret scraping.
func inferParser(path string) string {
	p := strings.ToLower(path)
	switch {
	case strings.Contains(p, "id_rsa") || strings.Contains(p, "id_ed25519") || strings.Contains(p, "id_dsa"):
		return "ssh-key"
	case strings.Contains(p, "passwd"):
		return "unix-passwd"
	case strings.Contains(p, "environ"):
		return "proc-environ"
	case strings.HasSuffix(p, ".env") ||
		strings.HasSuffix(p, ".ini") ||
		strings.HasSuffix(p, ".cfg") ||
		strings.HasSuffix(p, ".conf") ||
		strings.HasSuffix(p, ".cnf") ||
		strings.HasSuffix(p, ".properties"):
		return "ini-config"
	default:
		return "generic-secrets"
	}
}
