// Package matchbodyjson parses one or more JSON body-path "require" specs and
// decides whether a given response should be KEPT (reported) because a value at
// a named JSON path matches.
//
// matchbodyjson extends the positive keep-gate family
// (matchfilter/--match-regex, matchcode/--match-code, matchsize/--match-size,
// matchtime/--match-time, matchwords/--match-words, matchheaders/--match-headers)
// to a surface none of them inspect structurally: the *parsed* JSON body. Where
// --match-regex does an unanchored "contains" match against the raw body bytes,
// --match-body-json walks the decoded JSON to a specific path and matches the
// regex against the scalar value found there.
//
// This matters because modern LFI targets are frequently JSON APIs, not HTML
// pages. A vulnerable endpoint that wraps file content in a JSON envelope
// (`{"ok":true,"content":"...file bytes..."}`) returns a soft-404 as the SAME
// envelope shape with a different field value (`{"ok":false,"error":"not
// found"}`). The two responses can be byte-for-byte indistinguishable to
// --match-size and word-count brittle to --match-words, while a raw
// --match-regex on the whole body is noisy: a regex meant for the `content`
// field also matches if the same token happens to appear in an `error` message
// or an echoed request field. --match-body-json pins the match to one field, so
// the operator can say "keep only responses where the JSON field `ok` is `true`"
// or "where `data.path` looks like a unix path" and drop the structured noise
// that the other matchers cannot separate.
//
// There is no single ffuf flag for this; ffuf's matchers are body/status/size/
// word/line/header oriented and treat the body as opaque text. --match-body-json
// is the structured-JSON complement that rounds out the family for the JSON-API
// LFI use case.
//
// Spec model: the flag is repeatable. Each occurrence is one "json.path: regex"
// pair:
//
//	--match-body-json 'ok: true'
//	--match-body-json 'data.path: ^/(etc|home)/'
//	--match-body-json 'results.0.name: passwd'
//
// The path before the first colon is a dot-separated JSON path. Each segment is
// either an object key or a non-negative array index. The path is matched
// against the decoded JSON document; the value found there is stringified to its
// natural scalar form (see scalarString) and the rule's Go (RE2) regex is run as
// an unanchored "contains" match against that string. The pair is satisfied if
// the path resolves to a scalar (string, number, bool, or null) AND the regex
// matches its string form. A path that does not exist, that resolves to a
// non-scalar (object or array), or a body that is not valid JSON never satisfies
// a rule.
//
// Because object keys may themselves contain dots, a literal dot inside a key is
// escaped with a backslash: `a\.b.c` is the two-segment path ["a.b", "c"]. A
// backslash is escaped as `\\`.
//
// When more than one pair is supplied they compose as a CONJUNCTION: every pair
// must be satisfied for the response to be kept. This mirrors the conjunction
// semantics of matchheaders and the rest of the match family (every match gate
// must pass).
//
// An empty spec set yields a Filter that keeps everything (Active() == false),
// so the scan output is unchanged. A malformed pair — missing colon, empty path,
// a path segment that is empty, an empty regex, or a regex that fails to compile
// — is rejected at parse time so the operator learns immediately rather than
// silently keeping nothing.
//
// This NEVER touches confirmed hits. Confirmation in exhumed is content-based
// (see internal/detect): a body that satisfies an entry's confirm block is a hit
// regardless of its JSON shape. matchbodyjson only governs the unconfirmed
// "[responded]" stream, turning it from "everything that responded" into "only
// the responses whose JSON carries an interesting value at a named path."
package matchbodyjson

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// pathRule is one "json.path: regex" requirement. segments is the decoded,
// unescaped path (object keys and/or array-index strings); re is the compiled
// require-regex run against the stringified value at that path.
type pathRule struct {
	segments []string
	re       *regexp.Regexp
	// raw is the original spec text, retained for clear error messages.
	raw string
}

// Filter decides whether a response should be kept (reported) because the values
// at its named JSON paths satisfy every require rule. The zero value is inactive
// (keeps everything) and is safe to use.
type Filter struct {
	rules []pathRule
}

// Parse builds a Filter from a slice of "json.path: regex" specs (typically one
// per repeated --match-body-json flag). An empty slice — or a slice whose entries
// are all blank — returns an inactive Filter and no error; callers treat an
// inactive filter as "keep everything." A malformed pair returns an error so the
// operator learns immediately rather than silently keeping nothing.
func Parse(specs []string) (*Filter, error) {
	f := &Filter{}
	for _, raw := range specs {
		spec := strings.TrimSpace(raw)
		if spec == "" {
			// A blank repeat is tolerated rather than fatal.
			continue
		}

		pathSpec, pattern, ok := strings.Cut(spec, ":")
		if !ok {
			return nil, fmt.Errorf("matchbodyjson: invalid spec %q: expected 'json.path: regex'", spec)
		}
		pathSpec = strings.TrimSpace(pathSpec)
		if pathSpec == "" {
			return nil, fmt.Errorf("matchbodyjson: invalid spec %q: empty JSON path", spec)
		}
		// A regex rarely intends to depend on the leading shell-quoting space
		// after the colon; trim it like matchheaders does for --match-headers.
		pattern = strings.TrimSpace(pattern)
		if pattern == "" {
			return nil, fmt.Errorf("matchbodyjson: invalid spec %q: empty regex for path %q", spec, pathSpec)
		}

		segments, err := splitPath(pathSpec)
		if err != nil {
			return nil, fmt.Errorf("matchbodyjson: invalid path %q: %w", pathSpec, err)
		}

		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("matchbodyjson: invalid regex %q for path %q: %w", pattern, pathSpec, err)
		}

		f.rules = append(f.rules, pathRule{segments: segments, re: re, raw: spec})
	}
	return f, nil
}

// splitPath decodes a dot-separated JSON path into its segments, honouring
// backslash escaping so a literal dot inside an object key (`a\.b`) is one
// segment and a literal backslash is written `\\`. An empty segment (a leading,
// trailing, or doubled dot) is an error, as is a dangling escape.
func splitPath(spec string) ([]string, error) {
	var segments []string
	var cur strings.Builder
	escaped := false
	for _, r := range spec {
		if escaped {
			cur.WriteRune(r)
			escaped = false
			continue
		}
		switch r {
		case '\\':
			escaped = true
		case '.':
			seg := cur.String()
			if seg == "" {
				return nil, fmt.Errorf("empty path segment (check for leading, trailing, or doubled '.')")
			}
			segments = append(segments, seg)
			cur.Reset()
		default:
			cur.WriteRune(r)
		}
	}
	if escaped {
		return nil, fmt.Errorf("dangling escape: path ends with a backslash")
	}
	seg := cur.String()
	if seg == "" {
		return nil, fmt.Errorf("empty path segment (check for leading, trailing, or doubled '.')")
	}
	segments = append(segments, seg)
	return segments, nil
}

// Active reports whether the filter has any rules. When false, Keep always
// returns true (keep everything) and callers can skip the check entirely.
func (f *Filter) Active() bool {
	return f != nil && len(f.rules) > 0
}

// Keep reports whether a response carrying the given body should be kept
// (reported). Every rule must be satisfied: the rule's JSON path must resolve to
// a scalar value in the decoded body AND that value's string form must match the
// rule's regex. An inactive filter keeps everything, returning true. A body that
// is not valid JSON satisfies no rule, so an active filter drops it.
func (f *Filter) Keep(body []byte) bool {
	if !f.Active() {
		return true
	}
	var doc any
	if err := json.Unmarshal(body, &doc); err != nil {
		// Not valid JSON: an active matcher requires a JSON match, so drop it.
		return false
	}
	for _, rule := range f.rules {
		if !ruleMatches(rule, doc) {
			return false
		}
	}
	return true
}

// ruleMatches walks the decoded JSON document to the rule's path and reports
// whether the value found there is a scalar whose string form matches the rule's
// regex. A path that does not resolve, or that lands on an object or array,
// never matches.
func ruleMatches(rule pathRule, doc any) bool {
	val, ok := resolve(doc, rule.segments)
	if !ok {
		return false
	}
	s, ok := scalarString(val)
	if !ok {
		return false
	}
	return rule.re.MatchString(s)
}

// resolve walks doc following segments. Object keys index map[string]any; a
// segment that is a non-negative integer indexes a []any. Returns the value at
// the path and true, or (nil, false) if any segment cannot be followed.
func resolve(doc any, segments []string) (any, bool) {
	cur := doc
	for _, seg := range segments {
		switch node := cur.(type) {
		case map[string]any:
			next, ok := node[seg]
			if !ok {
				return nil, false
			}
			cur = next
		case []any:
			idx, err := strconv.Atoi(seg)
			if err != nil || idx < 0 || idx >= len(node) {
				return nil, false
			}
			cur = node[idx]
		default:
			// Can't descend into a scalar with a remaining segment.
			return nil, false
		}
	}
	return cur, true
}

// scalarString renders a decoded JSON scalar to the string the regex matches
// against. Strings are returned verbatim. Booleans become "true"/"false". null
// becomes "null". Numbers (always float64 from encoding/json) are formatted with
// strconv.FormatFloat 'g' so integers render without a trailing ".0" (e.g. 200
// -> "200", 1.5 -> "1.5"). Objects and arrays are not scalars and return
// ("", false) so a rule targeting a container never matches.
func scalarString(v any) (string, bool) {
	switch t := v.(type) {
	case string:
		return t, true
	case bool:
		if t {
			return "true", true
		}
		return "false", true
	case float64:
		return strconv.FormatFloat(t, 'g', -1, 64), true
	case nil:
		return "null", true
	default:
		// map[string]any or []any — not a scalar.
		return "", false
	}
}
