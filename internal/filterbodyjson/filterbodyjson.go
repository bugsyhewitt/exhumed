// Package filterbodyjson parses one or more JSON body-path "noise" specs and
// decides whether a given response should be SUPPRESSED (filtered) from output
// because a scalar value at a named JSON path matches a known-noise regex.
//
// filterbodyjson is the negative twin of matchbodyjson: where matchbodyjson's
// --match-body-json KEEPS only the unconfirmed "[responded]" responses whose
// decoded JSON body satisfies every require rule at a named path,
// filterbodyjson's --filter-body-json inverts the polarity — it SUPPRESSES the
// unconfirmed responses whose JSON carries a known-noise scalar at a named path
// and keeps everything else. It is the structured-JSON companion to bodyfilter's
// --filter-regex (raw body), respfilter's --filter-size (length), codefilter's
// --filter-code (status), timefilter's --filter-time (latency), wordfilter's
// --filter-words (word count), linefilter's --filter-lines (line count),
// headerfilter's --filter-headers (header block), and filtertitle's
// --filter-title (HTML <title>). Together they let an operator quiet the
// uniform soft-404/WAF noise from whichever surface most cleanly distinguishes
// it.
//
// The structured-JSON surface matters because modern LFI targets are
// frequently JSON APIs, not HTML pages. A vulnerable endpoint wraps file
// content in a JSON envelope (`{"ok":true,"content":"...file bytes..."}`) and
// returns a soft-404 as the SAME envelope shape with a different field value
// (`{"ok":false,"error":"file not found"}`). The two responses can be byte-
// identical to --filter-size and word-count-brittle to --filter-words, while a
// raw --filter-regex on the whole body is noisy — a regex meant for the `error`
// field also fires if the same token happens to appear in an echoed request
// field or a real read's content. --filter-body-json pins the suppressor to one
// field, so the operator can say "drop responses whose JSON field `ok` is
// `false`" or "drop responses whose `error` field looks like a 'not found'
// message" and quiet the structured noise that the other filters cannot
// separate cleanly.
//
// There is no single ffuf flag for this; ffuf's matchers/filters are body /
// status / size / word / line / header oriented and treat the body as opaque
// text. --filter-body-json is the structured-JSON complement that rounds out
// the suppression family for the JSON-API LFI use case.
//
// Spec model: the flag is repeatable. Each occurrence is one "json.path: regex"
// pair, identical to --match-body-json's grammar (and using its parser, so the
// path semantics are guaranteed to stay in sync):
//
//	--filter-body-json 'ok: false'
//	--filter-body-json 'error: (?i)not found|forbidden'
//	--filter-body-json 'results.0.status: 404'
//
// The path before the first colon is a dot-separated JSON path. Each segment is
// either an object key or a non-negative array index. A literal dot inside a
// key is escaped with a backslash (`a\.b.c` is the two-segment path ["a.b",
// "c"]). The value side is a Go (RE2) "contains" match against the scalar
// value's string form — strings verbatim, booleans as "true"/"false", numbers
// formatted with strconv.FormatFloat 'g' (so integers render `200` not
// `200.0`), and JSON `null` as the literal "null". A pair fires when the path
// resolves to a SCALAR at the supplied path AND the regex matches its string
// form.
//
// When more than one pair is supplied they compose as a DISJUNCTION: a response
// is suppressed if ANY pair matches. This mirrors the suppression semantics of
// the rest of the --filter-* family (a response is dropped if any --filter-*
// gate fires) and is the deliberate opposite of matchbodyjson's conjunction —
// there, every keep-rule must pass; here, any drop-rule is enough.
//
// A body that is NOT valid JSON, a body whose JSON does not contain the named
// path, or a path that lands on an OBJECT or ARRAY (not a scalar) never
// satisfies any rule and is therefore NOT suppressed — the operator opted in
// to a JSON suppressor, so a body that cannot be classified by it must be left
// alone. (If you want to drop non-JSON bodies too, pair this with
// --match-body-json or another --filter-* gate.) This mirrors filtertitle's
// behaviour: a title suppressor does not fire on a body that has no title.
//
// An empty spec set yields a Filter that matches nothing (Active() == false),
// so the scan output is unchanged. A malformed pair — missing colon, empty
// path, empty path segment, an empty regex, or a regex that fails to compile —
// is rejected at parse time so the operator learns immediately rather than
// silently filtering nothing.
//
// This NEVER touches confirmed hits. Confirmation in exhumed is content-based
// (see internal/detect): a body that satisfies an entry's confirm block is a
// hit regardless of its JSON shape. filterbodyjson only quiets the unconfirmed
// "[responded]" noise that --only-hits would otherwise suppress wholesale. It
// is a finer-grained scalpel than --only-hits.
package filterbodyjson

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/bugsyhewitt/exhumed/internal/matchbodyjson"
)

// pathRule is one "json.path: regex" suppression requirement. segments is the
// decoded, unescaped path (object keys and/or array-index strings); re is the
// compiled noise-regex run against the stringified value at that path.
type pathRule struct {
	segments []string
	re       *regexp.Regexp
	// raw is the original spec text, retained for clear error messages.
	raw string
}

// Filter decides whether a response should be suppressed (filtered) because the
// scalar value at one of its named JSON paths matches a known-noise regex. The
// zero value matches nothing (keeps everything) and is safe to use.
type Filter struct {
	rules []pathRule
}

// Parse builds a Filter from a slice of "json.path: regex" specs (typically one
// per repeated --filter-body-json flag). An empty slice — or a slice whose
// entries are all blank — returns an inactive Filter and no error; callers
// treat an inactive filter as "suppress nothing." A malformed pair returns an
// error so the operator learns immediately rather than silently filtering
// nothing. The path grammar is shared with matchbodyjson (via
// matchbodyjson.SplitPath) so the positive and negative twins stay in lockstep.
func Parse(specs []string) (*Filter, error) {
	f := &Filter{}
	for _, raw := range specs {
		spec := strings.TrimSpace(raw)
		if spec == "" {
			// A blank repeat is tolerated rather than fatal, mirroring
			// matchbodyjson.Parse and the other --filter-* parsers.
			continue
		}

		pathSpec, pattern, ok := strings.Cut(spec, ":")
		if !ok {
			return nil, fmt.Errorf("filterbodyjson: invalid spec %q: expected 'json.path: regex'", spec)
		}
		pathSpec = strings.TrimSpace(pathSpec)
		if pathSpec == "" {
			return nil, fmt.Errorf("filterbodyjson: invalid spec %q: empty JSON path", spec)
		}
		// Trim the leading shell-quoting whitespace after the colon, mirroring
		// matchbodyjson and matchheaders.
		pattern = strings.TrimSpace(pattern)
		if pattern == "" {
			return nil, fmt.Errorf("filterbodyjson: invalid spec %q: empty regex for path %q", spec, pathSpec)
		}

		segments, err := matchbodyjson.SplitPath(pathSpec)
		if err != nil {
			return nil, fmt.Errorf("filterbodyjson: invalid path %q: %w", pathSpec, err)
		}

		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("filterbodyjson: invalid regex %q for path %q: %w", pattern, pathSpec, err)
		}

		f.rules = append(f.rules, pathRule{segments: segments, re: re, raw: spec})
	}
	return f, nil
}

// Active reports whether the filter has any rules. When false, MatchBody always
// returns false (suppress nothing) and callers can skip the check entirely.
func (f *Filter) Active() bool {
	return f != nil && len(f.rules) > 0
}

// MatchBody reports whether a response carrying the given body should be
// suppressed (filtered). A response is suppressed if ANY rule fires: the rule's
// JSON path must resolve to a scalar in the decoded body AND the value's string
// form must match the rule's regex. An inactive filter suppresses nothing,
// returning false. A body that is not valid JSON satisfies no rule, so an
// active filter does NOT suppress it — see the package doc for the rationale.
func (f *Filter) MatchBody(body []byte) bool {
	if !f.Active() {
		return false
	}
	var doc any
	if err := json.Unmarshal(body, &doc); err != nil {
		// Not valid JSON: an active suppressor cannot classify this body as
		// JSON-shaped noise, so leave it alone.
		return false
	}
	for _, rule := range f.rules {
		if ruleMatches(rule, doc) {
			return true
		}
	}
	return false
}

// ruleMatches walks the decoded JSON document to the rule's path and reports
// whether the value found there is a scalar whose string form matches the
// rule's regex. A path that does not resolve, or that lands on an object or
// array, never matches. Path descent and scalar stringification reuse
// matchbodyjson's exported helpers so the positive and negative twins share one
// definition.
func ruleMatches(rule pathRule, doc any) bool {
	val, ok := matchbodyjson.Resolve(doc, rule.segments)
	if !ok {
		return false
	}
	s, ok := matchbodyjson.ScalarString(val)
	if !ok {
		return false
	}
	return rule.re.MatchString(s)
}
