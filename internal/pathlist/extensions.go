package pathlist

import (
	"fmt"
	"strings"
)

// NormalizeExtensions cleans a caller-supplied list of file extensions into the
// canonical "leading-dot" form used when appending to wordlist paths.
//
// It implements the ffuf "-e" ergonomics so the operator can write the
// extensions whichever way is convenient:
//
//	"php"        -> ".php"
//	".php"       -> ".php"   (already canonical)
//	"  .bak  "   -> ".bak"   (surrounding whitespace trimmed)
//	"PHP"        -> ".PHP"   (case preserved — paths are case-sensitive)
//
// Each extension is trimmed of surrounding whitespace; empty entries (e.g. from
// a trailing comma) are skipped rather than producing a bare "." suffix.
// Duplicates are removed, first occurrence wins, so the emission order the
// operator requested is preserved.
//
// An extension that still contains whitespace after trimming, or that contains
// a path separator, is rejected: those are almost certainly a malformed spec
// (a forgotten comma, a pasted path) and silently scanning them would waste
// requests on nonsense targets. A nil/empty input returns a nil slice and no
// error.
func NormalizeExtensions(exts []string) ([]string, error) {
	if len(exts) == 0 {
		return nil, nil
	}

	var out []string
	seen := make(map[string]struct{})

	for _, raw := range exts {
		e := strings.TrimSpace(raw)
		if e == "" {
			// Tolerate a trailing/doubled comma rather than failing the scan.
			continue
		}
		if strings.ContainsAny(e, " \t/\\") {
			return nil, fmt.Errorf("pathlist: invalid extension %q: extensions must not contain whitespace or path separators (use a comma-separated list like '.php,.bak')", raw)
		}
		if !strings.HasPrefix(e, ".") {
			e = "." + e
		}
		// Reject a bare "." (i.e. the operator passed ".") — it appends nothing
		// meaningful and would duplicate the bare path.
		if e == "." {
			return nil, fmt.Errorf("pathlist: invalid extension %q: a bare '.' appends no extension", raw)
		}
		if _, dup := seen[e]; dup {
			continue
		}
		seen[e] = struct{}{}
		out = append(out, e)
	}

	return out, nil
}
