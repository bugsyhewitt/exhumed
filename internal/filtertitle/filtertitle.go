// Package filtertitle parses one or more HTML <title> "noise" regex specs and
// decides whether a given response should be SUPPRESSED (filtered) from output
// because the title extracted from its body matches a known-noise signature.
//
// filtertitle is the negative twin of matchtitle: where matchtitle's
// --match-title KEEPS only the unconfirmed "[responded]" responses whose
// extracted HTML <title> satisfies every require regex, filtertitle's
// --filter-title inverts the polarity — it SUPPRESSES the unconfirmed responses
// whose title matches a known-noise regex and keeps everything else. It is the
// title-surface companion to bodyfilter's --filter-regex (body),
// respfilter's --filter-size (length), codefilter's --filter-code (status),
// timefilter's --filter-time (latency), wordfilter's --filter-words (word
// count), linefilter's --filter-lines (line count), and headerfilter's
// --filter-headers (header block). Together they let an operator quiet the
// uniform soft-404/WAF noise from whichever surface most cleanly distinguishes
// it.
//
// The title surface matters because the chrome of an HTML-rendered web app
// frequently stamps its "file not found" / "access denied" template with a
// constant <title> ("404 Not Found", "403 Forbidden", "Access denied"), while
// a genuine file read shifts the title to something else ("Index of /etc",
// "passwd"). When the noise body's length, word count, status, and headers are
// too variable to pin with the other --filter-* gates (because the template
// echoes a query string, stamps a per-request token, or rotates CDN headers),
// its title is typically a single constant string. --filter-title names that
// string and drops it.
//
// Spec model: the flag is repeatable. Each occurrence is one Go (RE2) regex,
// applied as an unanchored "contains" match against the EXTRACTED <title>
// text (entity-decoded, whitespace-collapsed — see matchtitle.ExtractTitle).
// The first <title>...</title> pair in the body is the source of truth.
//
//	--filter-title '404 Not Found'
//	--filter-title '(?i)access denied|forbidden'
//	--filter-title '^Error '
//
// When more than one regex is supplied they compose as a DISJUNCTION: a
// response is suppressed if ANY regex matches the extracted title. This
// mirrors the suppression semantics of the rest of the filter family (a
// response is dropped if any --filter-* gate fires) and is the deliberate
// opposite of matchtitle's conjunction — there, every keep-rule must pass;
// here, any drop-rule is enough.
//
// A response whose body contains no extractable <title> element never matches
// any rule and is therefore NOT suppressed — the operator opted in to a title
// suppressor, so a body that has no title to inspect cannot be classified as
// title-shaped noise. This mirrors headerfilter's behaviour: a header-block
// suppressor does not fire on a response that lacks the named header. (If the
// operator wants to drop titleless bodies as well, a positive --match-title
// gate is the right tool.)
//
// An empty spec set yields a Filter that matches nothing (Active() == false),
// so the scan output is unchanged. A malformed regex is rejected at parse
// time so the operator learns immediately rather than silently filtering
// nothing.
//
// This NEVER touches confirmed hits. Confirmation in exhumed is content-based
// (see internal/detect): a body that satisfies an entry's confirm block is a
// hit regardless of its title. filtertitle only quiets the unconfirmed
// "[responded]" noise that --only-hits would otherwise suppress wholesale. It
// is a finer-grained scalpel than --only-hits.
package filtertitle

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/bugsyhewitt/exhumed/internal/matchtitle"
)

// Filter decides whether a response should be suppressed (filtered) because
// the title extracted from its body matches any of the supplied noise
// regexes. The zero value matches nothing (keeps everything) and is safe to
// use.
type Filter struct {
	res []*regexp.Regexp
}

// Parse builds a Filter from a slice of regex specs (typically one per
// repeated --filter-title flag). An empty slice — or a slice whose entries
// are all blank — returns an inactive Filter and no error; callers treat an
// inactive filter as "suppress nothing." A malformed regex returns an error
// so the operator learns immediately rather than silently filtering nothing.
func Parse(specs []string) (*Filter, error) {
	f := &Filter{}
	for _, raw := range specs {
		spec := strings.TrimSpace(raw)
		if spec == "" {
			// A blank repeat is tolerated rather than fatal, mirroring
			// headerfilter.Parse and matchtitle.Parse — repeated flags with one
			// empty entry should not crash the scan.
			continue
		}
		re, err := regexp.Compile(spec)
		if err != nil {
			return nil, fmt.Errorf("filtertitle: invalid regex %q: %w", spec, err)
		}
		f.res = append(f.res, re)
	}
	return f, nil
}

// Active reports whether the filter has any rules. When false, MatchBody
// always returns false (suppress nothing) and callers can skip the check
// entirely.
func (f *Filter) Active() bool {
	return f != nil && len(f.res) > 0
}

// MatchBody reports whether a response carrying the given body should be
// suppressed (filtered). A response is suppressed if its extracted title
// matches ANY rule. An inactive filter suppresses nothing, returning false. A
// body with no extractable title matches no rule, so an active filter does
// NOT suppress it — see the package doc for the rationale.
func (f *Filter) MatchBody(body []byte) bool {
	if !f.Active() {
		return false
	}
	title, ok := matchtitle.ExtractTitle(body)
	if !ok {
		return false
	}
	for _, re := range f.res {
		if re.MatchString(title) {
			return true
		}
	}
	return false
}
