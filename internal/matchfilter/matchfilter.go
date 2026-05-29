// Package matchfilter parses a response-body "require" regex spec and decides
// whether a given response body should be KEPT (reported) because it matches.
//
// matchfilter is the positive complement to bodyfilter: where bodyfilter's
// --filter-regex suppresses unconfirmed "[responded]" responses whose body
// matches a known-noise regex, matchfilter's --match-regex inverts the polarity
// — it KEEPS only the unconfirmed responses whose body matches an interesting
// regex and drops everything else. This is the classic ffuf "-mr" (match regex)
// workflow, the positive twin of ffuf's "-fr".
//
// The two compose naturally. During reconnaissance an operator first narrows the
// haystack with --match-regex (e.g. only show responses that mention "password",
// "BEGIN RSA PRIVATE KEY", or "DB_HOST"), then prunes residual noise from the
// kept set with --filter-regex/--filter-size/--filter-code/--filter-time. The
// gating order in the scan loop is: a confirmed hit is ALWAYS reported; an
// unconfirmed response is reported only if (match filter is inactive OR its body
// matches the match regex) AND none of the suppression filters fire.
//
// This NEVER touches confirmed hits. Confirmation in exhumed is content-based
// (see internal/detect): a body that satisfies an entry's confirm block is a hit
// regardless of whether it matches --match-regex. matchfilter only governs the
// unconfirmed "[responded]" stream, turning it from "everything that responded"
// into "only the responses worth a second look."
//
// Spec grammar (the value of --match-regex): a single Go (RE2) regular
// expression, matched against the response body interpreted as a UTF-8 string.
// The match is a "contains" match (the pattern need not anchor to the whole
// body); use ^ and $ explicitly if whole-body anchoring is wanted. Examples:
//
//	password              bodies containing the literal phrase "password"
//	(?i)secret|api[_-]?key  case-insensitive secret-ish markers
//	BEGIN [A-Z ]+PRIVATE KEY  a PEM private-key header
//
// An empty spec yields a Filter that keeps everything (Active() == false), so
// the scan output is unchanged. A malformed regex is rejected at parse time so
// the operator learns immediately rather than silently keeping nothing.
package matchfilter

import (
	"fmt"
	"regexp"
	"strings"
)

// Filter decides whether a response body should be kept (reported) because it
// matches a require-regex. The zero value is inactive (keeps everything) and is
// safe to use.
type Filter struct {
	re *regexp.Regexp
}

// Parse builds a Filter from a single response-body regex spec. An empty (or
// all-whitespace) spec returns an inactive Filter and no error — callers treat
// an inactive filter as "keep everything." A regex that fails to compile returns
// an error so the operator learns immediately rather than silently keeping
// nothing.
//
// Leading and trailing whitespace around the spec is trimmed, since a regex
// rarely intends to depend on it and a stray shell-quoting space is a common
// mistake. Whitespace inside the pattern is preserved.
func Parse(spec string) (*Filter, error) {
	f := &Filter{}
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return f, nil
	}

	re, err := regexp.Compile(spec)
	if err != nil {
		return nil, fmt.Errorf("matchfilter: invalid regex %q: %w", spec, err)
	}
	f.re = re
	return f, nil
}

// Active reports whether the filter has a compiled pattern. When false, Keep
// always returns true (keep everything) and callers can skip the check entirely.
func (f *Filter) Active() bool {
	return f != nil && f.re != nil
}

// Keep reports whether a response with the given body should be kept (reported).
// The body is matched as a UTF-8 string with a "contains" (unanchored) match.
// An inactive filter keeps everything, returning true.
func (f *Filter) Keep(body []byte) bool {
	if !f.Active() {
		return true
	}
	return f.re.Match(body)
}
