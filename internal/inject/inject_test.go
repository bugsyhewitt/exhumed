package inject

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/bugsyhewitt/exhumed/internal/engine"
)

const marker = "FUZZ"

// ── Substitute: query surface ─────────────────────────────────────────────────

func TestSubstitute_QuerySurface(t *testing.T) {
	req := engine.Request{
		Method:  "GET",
		URL:     "http://example.com/page?file=FUZZ",
		Headers: make(http.Header),
		Cookies: make(map[string]string),
	}

	out := Substitute(req, marker, "../etc/passwd")

	// Slash must be percent-encoded inside the query string.
	want := "http://example.com/page?file=..%2Fetc%2Fpasswd"
	if out.URL != want {
		t.Errorf("query substitution: got %q, want %q", out.URL, want)
	}
}

func TestSubstitute_QuerySurface_AllOccurrences(t *testing.T) {
	req := engine.Request{
		Method:  "GET",
		URL:     "http://example.com/?a=FUZZ&b=FUZZ",
		Headers: make(http.Header),
	}

	out := Substitute(req, marker, "x")

	if strings.Contains(out.URL, marker) {
		t.Errorf("marker still present in URL after substitution: %s", out.URL)
	}
}

// ── Substitute: body surface ──────────────────────────────────────────────────

func TestSubstitute_BodySurface(t *testing.T) {
	req := engine.Request{
		Method:  "POST",
		URL:     "http://example.com/load",
		Headers: make(http.Header),
		Body:    []byte("path=FUZZ&extra=1"),
	}

	out := Substitute(req, marker, "etc/passwd")

	if string(out.Body) != "path=etc/passwd&extra=1" {
		t.Errorf("body substitution: got %q, want %q", out.Body, "path=etc/passwd&extra=1")
	}
}

// ── Substitute: header surface ────────────────────────────────────────────────

func TestSubstitute_HeaderSurface(t *testing.T) {
	h := make(http.Header)
	h.Set("X-Include-File", "FUZZ")

	req := engine.Request{
		Method:  "GET",
		URL:     "http://example.com/header",
		Headers: h,
		Cookies: make(map[string]string),
	}

	out := Substitute(req, marker, "etc/passwd")

	if got := out.Headers.Get("X-Include-File"); got != "etc/passwd" {
		t.Errorf("header substitution: got %q, want %q", got, "etc/passwd")
	}
}

// ── Substitute: cookie surface ────────────────────────────────────────────────

func TestSubstitute_CookieSurface(t *testing.T) {
	req := engine.Request{
		Method:  "GET",
		URL:     "http://example.com/cookie",
		Headers: make(http.Header),
		Cookies: map[string]string{"lfi_path": "FUZZ"},
	}

	out := Substitute(req, marker, "etc/passwd")

	if got := out.Cookies["lfi_path"]; got != "etc/passwd" {
		t.Errorf("cookie substitution: got %q, want %q", got, "etc/passwd")
	}
}

// ── Substitute: JSON surface ──────────────────────────────────────────────────

func TestSubstitute_JSONSurface(t *testing.T) {
	req := engine.Request{
		Method:  "POST",
		URL:     "http://example.com/json",
		Headers: make(http.Header),
		Body:    []byte(`{"path":"FUZZ","extra":42}`),
	}

	out := Substitute(req, marker, "etc/passwd")

	var v map[string]interface{}
	if err := json.Unmarshal(out.Body, &v); err != nil {
		t.Fatalf("result is not valid JSON: %v — body was: %s", err, out.Body)
	}
	if v["path"] != "etc/passwd" {
		t.Errorf("json substitution path: got %v, want etc/passwd", v["path"])
	}
}

func TestSubstitute_JSONSurface_EscapesQuotes(t *testing.T) {
	req := engine.Request{
		Method:  "POST",
		URL:     "http://example.com/json",
		Headers: make(http.Header),
		Body:    []byte(`{"path":"FUZZ"}`),
	}

	// Payload contains a double-quote; must be JSON-escaped so output is valid.
	out := Substitute(req, marker, `say "hello"`)

	var v map[string]interface{}
	if err := json.Unmarshal(out.Body, &v); err != nil {
		t.Fatalf("result is not valid JSON after quote escaping: %v — body was: %s", err, out.Body)
	}
	if v["path"] != `say "hello"` {
		t.Errorf("json quote escaping: got %v, want: say \"hello\"", v["path"])
	}
}

// ── FindSurfaces ──────────────────────────────────────────────────────────────

func TestFindSurfaces_Query(t *testing.T) {
	req := engine.Request{
		Method:  "GET",
		URL:     "http://example.com/?file=FUZZ",
		Headers: make(http.Header),
	}
	assertSurface(t, FindSurfaces(req, marker), SurfaceQuery)
}

func TestFindSurfaces_Body(t *testing.T) {
	req := engine.Request{
		Method:  "POST",
		URL:     "http://example.com/",
		Headers: make(http.Header),
		Body:    []byte("path=FUZZ"),
	}
	assertSurface(t, FindSurfaces(req, marker), SurfaceBody)
}

func TestFindSurfaces_Header(t *testing.T) {
	h := make(http.Header)
	h.Set("X-Include-File", "FUZZ")
	req := engine.Request{
		Method:  "GET",
		URL:     "http://example.com/",
		Headers: h,
	}
	assertSurface(t, FindSurfaces(req, marker), SurfaceHeader)
}

func TestFindSurfaces_Cookie(t *testing.T) {
	req := engine.Request{
		Method:  "GET",
		URL:     "http://example.com/",
		Headers: make(http.Header),
		Cookies: map[string]string{"lfi_path": "FUZZ"},
	}
	assertSurface(t, FindSurfaces(req, marker), SurfaceCookie)
}

func TestFindSurfaces_JSON(t *testing.T) {
	req := engine.Request{
		Method:  "POST",
		URL:     "http://example.com/",
		Headers: make(http.Header),
		Body:    []byte(`{"path":"FUZZ"}`),
	}
	assertSurface(t, FindSurfaces(req, marker), SurfaceJSON)
}

// ── URL encoding correctness ──────────────────────────────────────────────────

func TestSubstitute_QueryEncoding_Slash(t *testing.T) {
	req := engine.Request{
		Method:  "GET",
		URL:     "http://example.com/?file=FUZZ",
		Headers: make(http.Header),
	}
	out := Substitute(req, marker, "../etc/passwd")

	if strings.Contains(out.URL, "../etc/passwd") {
		t.Error("unencoded traversal payload found in query URL — must be URL-encoded")
	}
	lower := strings.ToLower(out.URL)
	if !strings.Contains(lower, "%2f") {
		t.Errorf("expected percent-encoded slash in query URL, got: %s", out.URL)
	}
}

func TestSubstitute_QueryEncoding_Space(t *testing.T) {
	req := engine.Request{
		Method:  "GET",
		URL:     "http://example.com/?q=FUZZ",
		Headers: make(http.Header),
	}
	out := Substitute(req, marker, "a b")

	if strings.Contains(out.URL, " ") {
		t.Errorf("literal space in query URL after encoding: %s", out.URL)
	}
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func assertSurface(t *testing.T, surfaces []Surface, want Surface) {
	t.Helper()
	for _, s := range surfaces {
		if s == want {
			return
		}
	}
	t.Errorf("surface %q not found in %v", want, surfaces)
}
