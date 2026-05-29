// Package matchtitle parses one or more HTML <title> "require" regex specs and
// decides whether a given response should be KEPT (reported) because the title
// extracted from its body matches.
//
// matchtitle extends the positive keep-gate family
// (matchfilter/--match-regex, matchcode/--match-code, matchsize/--match-size,
// matchtime/--match-time, matchwords/--match-words, matchlines/--match-lines,
// matchheaders/--match-headers, matchbodyjson/--match-body-json) to a surface
// none of them touch: the contents of the HTML <title> element. Where
// --match-regex inspects the raw body bytes (and so fires on the wrong
// fragment when a soft-404 page embeds the searched term anywhere in its
// chrome — navigation, footer, error template) and --match-body-json walks a
// structured envelope, --match-title pins the match to a single, semantically
// meaningful field of an HTML response: the document title. When a real LFI
// payload causes the target to read and serve a file that the framework
// renders inside a generic HTML chrome, the chrome's <title> commonly shifts
// ("Index of /etc", "passwd"), whereas the uniform soft-404/WAF block page
// keeps a constant title ("Not Found", "403 Forbidden", "Access denied").
// Pinning the keep-gate to the title removes the cross-fragment false
// positives a whole-body --match-regex produces.
//
// There is no ffuf equivalent (ffuf's matchers are body/status/size/word/line
// oriented and have no HTML-structural matcher); this rounds out the family
// for the LFI use case where many targets are HTML-rendered web apps.
//
// Spec model: the flag is repeatable. Each occurrence is one Go (RE2) regex,
// applied as an unanchored "contains" match against the EXTRACTED <title>
// text (see ExtractTitle). The first <title>...</title> pair in the body is
// the source of truth — HTML allows only one title and pathological multi-
// title documents are not the realistic LFI signal we are trying to
// preserve.
//
//	--match-title 'Index of'
//	--match-title '(?i)passwd|shadow|hosts'
//	--match-title '^/etc/'
//
// When more than one spec is supplied they compose as a CONJUNCTION: every
// regex must match the same extracted title for the response to be kept.
// This mirrors the conjunction semantics of the rest of the match family.
//
// A response whose body contains no <title> element never satisfies an active
// matcher (every rule fails) and is dropped. A body that is not HTML, or is
// truncated before the title closes, likewise yields no title and is dropped
// — the operator opted in to a positive title gate.
//
// An empty spec set yields a Filter that keeps everything (Active() == false),
// so the scan output is unchanged. A malformed regex is rejected at parse time
// so the operator learns immediately rather than silently keeping nothing.
//
// This NEVER touches confirmed hits. Confirmation in exhumed is content-based
// (see internal/detect): a body that satisfies an entry's confirm block is a
// hit regardless of its title. matchtitle only governs the unconfirmed
// "[responded]" stream, turning it from "everything that responded" into
// "only the responses whose HTML title looks interesting."
package matchtitle

import (
	"fmt"
	"regexp"
	"strings"
)

// titleExtractRE matches the first <title>...</title> pair in an HTML body.
// Case-insensitive on the tag name (HTML is case-insensitive for element
// names), permissive on intra-tag whitespace and attributes (a few real-world
// templates emit <title id="page">…</title>), non-greedy on the inner text so
// a second stray <title> in malformed markup does not slurp the document.
// The single capture group is the inner text.
var titleExtractRE = regexp.MustCompile(`(?is)<title\b[^>]*>(.*?)</title\s*>`)

// htmlEntityRE matches the four ubiquitous named entities and any decimal or
// hex numeric character reference. Anything else is left verbatim — we are
// only interested in normalising the common cases enough that an operator's
// regex against the extracted title does not need to know that the server
// emitted "&amp;" for "&".
var htmlEntityRE = regexp.MustCompile(`&(?:amp|lt|gt|quot|#x[0-9A-Fa-f]+|#[0-9]+);`)

// Filter decides whether a response should be kept (reported) because the
// title extracted from its body satisfies every require regex. The zero value
// is inactive (keeps everything) and is safe to use.
type Filter struct {
	res []*regexp.Regexp
}

// Parse builds a Filter from a slice of regex specs (typically one per
// repeated --match-title flag). An empty slice — or a slice whose entries are
// all blank — returns an inactive Filter and no error; callers treat an
// inactive filter as "keep everything." A malformed regex returns an error so
// the operator learns immediately rather than silently keeping nothing.
func Parse(specs []string) (*Filter, error) {
	f := &Filter{}
	for _, raw := range specs {
		spec := strings.TrimSpace(raw)
		if spec == "" {
			// A blank repeat is tolerated rather than fatal, mirroring
			// matchheaders.Parse — repeated flags with one empty entry should
			// not crash the scan.
			continue
		}
		re, err := regexp.Compile(spec)
		if err != nil {
			return nil, fmt.Errorf("matchtitle: invalid regex %q: %w", spec, err)
		}
		f.res = append(f.res, re)
	}
	return f, nil
}

// Active reports whether the filter has any rules. When false, KeepBody
// always returns true (keep everything) and callers can skip the check
// entirely.
func (f *Filter) Active() bool {
	return f != nil && len(f.res) > 0
}

// KeepBody reports whether a response carrying the given body should be kept
// (reported). Every rule must match the extracted <title>. An inactive filter
// keeps everything, returning true. A body with no extractable title
// satisfies no rule, so an active filter drops it.
func (f *Filter) KeepBody(body []byte) bool {
	if !f.Active() {
		return true
	}
	title, ok := ExtractTitle(body)
	if !ok {
		return false
	}
	for _, re := range f.res {
		if !re.MatchString(title) {
			return false
		}
	}
	return true
}

// ExtractTitle returns the inner text of the first <title>...</title> pair in
// body, with surrounding whitespace trimmed, internal whitespace runs
// collapsed to a single space (mirroring how a browser renders the title
// bar), and the four ubiquitous named entities plus decimal/hex numeric
// character references decoded. ok is false when no closed title element is
// found — a body that is not HTML, is truncated before the closing tag, or
// simply omits the element. An empty inner text ("<title></title>") returns
// ("", true): the title exists but is empty, which is a legitimate signal
// the operator may want to match.
func ExtractTitle(body []byte) (string, bool) {
	m := titleExtractRE.FindSubmatch(body)
	if m == nil {
		return "", false
	}
	inner := string(m[1])
	inner = decodeEntities(inner)
	inner = collapseWhitespace(inner)
	return inner, true
}

// decodeEntities replaces the four common named entities and any numeric
// character references with their literal characters. Unknown entities are
// left verbatim — an operator regex can still match them as-is if they
// matter.
func decodeEntities(s string) string {
	return htmlEntityRE.ReplaceAllStringFunc(s, func(ent string) string {
		switch ent {
		case "&amp;":
			return "&"
		case "&lt;":
			return "<"
		case "&gt;":
			return ">"
		case "&quot;":
			return `"`
		}
		// Numeric reference: &#NNN; or &#xHH;
		body := ent[2 : len(ent)-1] // strip "&#" prefix and ";" suffix
		var n int
		if len(body) > 0 && (body[0] == 'x' || body[0] == 'X') {
			if _, err := fmt.Sscanf(body[1:], "%x", &n); err != nil {
				return ent
			}
		} else {
			if _, err := fmt.Sscanf(body, "%d", &n); err != nil {
				return ent
			}
		}
		if n < 0 || n > 0x10FFFF {
			return ent
		}
		return string(rune(n))
	})
}

// collapseWhitespace trims leading/trailing whitespace and collapses internal
// runs of whitespace (any Unicode whitespace, including newlines and tabs
// commonly emitted by templating engines) to a single ASCII space. This
// mirrors the visible-title normalisation a browser performs and lets the
// operator's regex be written against the human-readable form.
func collapseWhitespace(s string) string {
	return strings.Join(strings.Fields(s), " ")
}
