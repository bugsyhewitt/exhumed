package db

import (
	"fmt"
	"regexp"
	"strings"
)

// ValidationError records a single problem found during database validation.
type ValidationError struct {
	File    string
	EntryID string
	Field   string
	Message string
}

func (e ValidationError) Error() string {
	if e.EntryID != "" {
		return fmt.Sprintf("%s [entry %s] %s: %s", e.File, e.EntryID, e.Field, e.Message)
	}
	return fmt.Sprintf("%s %s: %s", e.File, e.Field, e.Message)
}

// validIDRE accepts lowercase alphanumeric and hyphen only.
var validIDRE = regexp.MustCompile(`^[a-z0-9-]+$`)

// Validate checks every entry in db for structural and semantic correctness.
// It returns ALL problems found — it never stops at the first error.
// An empty slice means the database is valid.
func Validate(db *Database) []ValidationError {
	var errs []ValidationError

	for _, ce := range db.entries {
		e := ce.Entry
		file := ce.SourceFile
		id := e.ID

		add := func(field, msg string) {
			errs = append(errs, ValidationError{
				File:    file,
				EntryID: id,
				Field:   field,
				Message: msg,
			})
		}

		// ── Required string fields ────────────────────────────────────────────

		if e.ID == "" {
			add("id", "required field missing")
		} else if !validIDRE.MatchString(e.ID) {
			add("id", fmt.Sprintf("must match [a-z0-9-]+, got %q", e.ID))
		}

		if e.Name == "" {
			add("name", "required field missing")
		}
		if e.Description == "" {
			add("description", "required field missing")
		}
		if e.Path == "" {
			add("path", "required field missing")
		} else {
			// Path must be absolute for the declared OS families.
			hasWindows := containsStr(e.OS, "windows")
			hasUnix := containsStr(e.OS, "linux") || containsStr(e.OS, "bsd") || containsStr(e.OS, "macos")

			if hasWindows && !hasUnix {
				// Windows-only: must look like a Windows absolute path.
				if !isWindowsAbsolute(e.Path) {
					add("path", fmt.Sprintf("Windows entry path must be absolute (e.g. C:\\...), got %q", e.Path))
				}
			} else {
				// Unix or mixed: must start with /.
				if !strings.HasPrefix(e.Path, "/") {
					add("path", fmt.Sprintf("unix path must start with /, got %q", e.Path))
				}
			}
		}

		// ── OS enum ──────────────────────────────────────────────────────────

		if len(e.OS) == 0 {
			add("os", "required field: at least one OS must be listed")
		}
		for _, os := range e.OS {
			if _, ok := ValidOSValues[os]; !ok {
				add("os", fmt.Sprintf("unknown OS value %q (valid: linux, windows, bsd, macos)", os))
			}
		}

		// ── info_goal enum ────────────────────────────────────────────────────

		if e.InfoGoal == "" {
			add("info_goal", "required field missing")
		} else if _, ok := ValidInfoGoals[e.InfoGoal]; !ok {
			add("info_goal", fmt.Sprintf("unknown value %q", e.InfoGoal))
		}

		// ── privilege enum ────────────────────────────────────────────────────

		if e.Privilege == "" {
			add("privilege", "required field missing")
		} else if _, ok := ValidPrivileges[e.Privilege]; !ok {
			add("privilege", fmt.Sprintf("unknown value %q", e.Privilege))
		}

		// ── confirm block ─────────────────────────────────────────────────────

		if _, ok := ValidConfirmTypes[e.Confirm.Type]; !ok {
			add("confirm.type", fmt.Sprintf("unknown type %q (valid: regex, keyword, keyword-all)", e.Confirm.Type))
		}
		if len(e.Confirm.Patterns) == 0 {
			add("confirm.patterns", "must contain at least one pattern")
		}
		if e.Confirm.Type == ConfirmTypeRegex {
			for i, pat := range e.Confirm.Patterns {
				if _, err := regexp.Compile(pat); err != nil {
					add("confirm.patterns", fmt.Sprintf("[%d] invalid regex %q: %v", i, pat, err))
				}
			}
			for i, pat := range e.Confirm.Negate {
				if _, err := regexp.Compile(pat); err != nil {
					add("confirm.negate", fmt.Sprintf("[%d] invalid regex %q: %v", i, pat, err))
				}
			}
		} else {
			// keyword types: patterns must be non-empty strings.
			for i, pat := range e.Confirm.Patterns {
				if strings.TrimSpace(pat) == "" {
					add("confirm.patterns", fmt.Sprintf("[%d] keyword pattern must not be empty", i))
				}
			}
		}

		// ── min_traversal ─────────────────────────────────────────────────────

		if e.MinTraversal != nil && *e.MinTraversal < 0 {
			add("min_traversal", fmt.Sprintf("must be >= 0, got %d", *e.MinTraversal))
		}
	}

	return errs
}

// isWindowsAbsolute reports whether path looks like a Windows absolute path.
// Accepts drive-letter form (C:\...) or UNC (\\server\...).
func isWindowsAbsolute(path string) bool {
	if len(path) >= 3 && path[1] == ':' && (path[2] == '\\' || path[2] == '/') {
		return true
	}
	// UNC paths
	if strings.HasPrefix(path, `\\`) || strings.HasPrefix(path, `//`) {
		return true
	}
	return false
}

func containsStr(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}
