// Package inject substitutes a marker string with a payload across all
// injection surfaces of an engine.Request: URL query parameters, request body,
// HTTP headers, cookies, and JSON body string values.
//
// The marker is substituted in EVERY occurrence across ALL surfaces. If the
// marker appears in multiple surfaces (e.g. both a header value and the URL),
// all occurrences are replaced. This behaviour is intentional and documented
// so callers can construct multi-surface injection templates.
package inject

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"github.com/bugsyhewitt/exhumed/internal/engine"
)

// Surface names the injection surface where a marker was found.
type Surface string

const (
	SurfaceQuery  Surface = "query"
	SurfaceBody   Surface = "body"
	SurfaceHeader Surface = "header"
	SurfaceCookie Surface = "cookie"
	SurfaceJSON   Surface = "json"
)

// FindSurfaces returns the list of surfaces in req that contain marker.
// Callers use this to report injection points before scanning.
func FindSurfaces(req engine.Request, marker string) []Surface {
	var found []Surface

	if strings.Contains(req.URL, marker) {
		// Check whether marker is in a query param value (not the key).
		if queryContainsMarker(req.URL, marker) {
			found = append(found, SurfaceQuery)
		}
	}

	if len(req.Body) > 0 {
		body := string(req.Body)
		if isJSON(req.Body) {
			if jsonContainsMarker(req.Body, marker) {
				found = append(found, SurfaceJSON)
			}
		} else if strings.Contains(body, marker) {
			found = append(found, SurfaceBody)
		}
	}

	for _, vals := range req.Headers {
		for _, v := range vals {
			if strings.Contains(v, marker) {
				found = append(found, SurfaceHeader)
				goto doneHeaders
			}
		}
	}
doneHeaders:

	for _, v := range req.Cookies {
		if strings.Contains(v, marker) {
			found = append(found, SurfaceCookie)
			break
		}
	}

	return found
}

// Substitute replaces all occurrences of marker with payload across every
// surface of req and returns a new engine.Request ready to send. Encoding is
// applied per surface: query values are URL-encoded, JSON string values are
// JSON-escaped, other surfaces receive the raw payload.
func Substitute(req engine.Request, marker, payload string) engine.Request {
	out := engine.Request{
		Method:  req.Method,
		Headers: req.Headers.Clone(),
		Cookies: cloneCookies(req.Cookies),
	}

	// ── URL / query surface ───────────────────────────────────────────────────
	if strings.Contains(req.URL, marker) {
		out.URL = substituteQuery(req.URL, marker, payload)
	} else {
		out.URL = req.URL
	}

	// ── Body surface ─────────────────────────────────────────────────────────
	if len(req.Body) > 0 {
		if isJSON(req.Body) {
			out.Body = substituteJSON(req.Body, marker, payload)
		} else {
			out.Body = []byte(strings.ReplaceAll(string(req.Body), marker, payload))
		}
	}

	// ── Header surface ────────────────────────────────────────────────────────
	for key, vals := range out.Headers {
		for i, v := range vals {
			if strings.Contains(v, marker) {
				out.Headers[key][i] = strings.ReplaceAll(v, marker, payload)
			}
		}
	}

	// ── Cookie surface ────────────────────────────────────────────────────────
	for k, v := range out.Cookies {
		if strings.Contains(v, marker) {
			out.Cookies[k] = strings.ReplaceAll(v, marker, payload)
		}
	}

	return out
}

// substituteQuery replaces marker in all query parameter values of rawURL,
// URL-encoding the payload so it is safe to embed in the query string.
func substituteQuery(rawURL, marker, payload string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		// Fallback: raw string replacement without encoding.
		return strings.ReplaceAll(rawURL, marker, url.QueryEscape(payload))
	}

	q := u.Query()
	changed := false
	for key, vals := range q {
		for i, v := range vals {
			if strings.Contains(v, marker) {
				q[key][i] = strings.ReplaceAll(v, marker, payload)
				changed = true
			}
		}
	}
	if changed {
		u.RawQuery = q.Encode()
	}
	return u.String()
}

// queryContainsMarker reports whether marker appears in any query value of rawURL.
func queryContainsMarker(rawURL, marker string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return strings.Contains(rawURL, marker)
	}
	for _, vals := range u.Query() {
		for _, v := range vals {
			if strings.Contains(v, marker) {
				return true
			}
		}
	}
	// Also check if it appears in the path.
	return strings.Contains(u.Path, marker)
}

// isJSON reports whether b looks like a JSON object or array.
func isJSON(b []byte) bool {
	b = bytes.TrimSpace(b)
	return len(b) > 0 && (b[0] == '{' || b[0] == '[')
}

// substituteJSON walks a JSON document and replaces marker in all string
// values, returning the re-serialised document. JSON encoding ensures special
// characters in the payload (quotes, backslashes, control chars) are properly
// escaped so the result remains valid JSON.
func substituteJSON(body []byte, marker, payload string) []byte {
	var v interface{}
	if err := json.Unmarshal(body, &v); err != nil {
		// Not valid JSON; fall back to raw replacement.
		return []byte(strings.ReplaceAll(string(body), marker, payload))
	}

	v = replaceInValue(v, marker, payload)

	out, err := json.Marshal(v)
	if err != nil {
		return body
	}
	return out
}

// replaceInValue recursively substitutes marker in all string leaf values.
func replaceInValue(v interface{}, marker, payload string) interface{} {
	switch val := v.(type) {
	case string:
		return strings.ReplaceAll(val, marker, payload)
	case map[string]interface{}:
		for k, child := range val {
			val[k] = replaceInValue(child, marker, payload)
		}
		return val
	case []interface{}:
		for i, child := range val {
			val[i] = replaceInValue(child, marker, payload)
		}
		return val
	default:
		return v
	}
}

// jsonContainsMarker reports whether marker appears in any JSON string value.
func jsonContainsMarker(body []byte, marker string) bool {
	var v interface{}
	if err := json.Unmarshal(body, &v); err != nil {
		return strings.Contains(string(body), marker)
	}
	return valueContainsMarker(v, marker)
}

// valueContainsMarker recursively checks JSON values for marker.
func valueContainsMarker(v interface{}, marker string) bool {
	switch val := v.(type) {
	case string:
		return strings.Contains(val, marker)
	case map[string]interface{}:
		for _, child := range val {
			if valueContainsMarker(child, marker) {
				return true
			}
		}
	case []interface{}:
		for _, child := range val {
			if valueContainsMarker(child, marker) {
				return true
			}
		}
	}
	return false
}

// cloneCookies returns a shallow copy of the cookie map.
func cloneCookies(c map[string]string) map[string]string {
	if c == nil {
		return nil
	}
	out := make(map[string]string, len(c))
	for k, v := range c {
		out[k] = v
	}
	return out
}

// NewRequest is a convenience constructor for engine.Request with initialised
// maps, to avoid nil-map panics in callers.
func NewRequest(method, rawURL string) engine.Request {
	return engine.Request{
		Method:  method,
		URL:     rawURL,
		Headers: make(http.Header),
		Cookies: make(map[string]string),
	}
}
