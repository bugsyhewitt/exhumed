package replay

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bugsyhewitt/exhumed/internal/engine"
)

func TestParse_EmptyYieldsInactive(t *testing.T) {
	for _, spec := range []string{"", "   ", "\t", "\n  "} {
		c, err := Parse(spec, time.Second, false)
		if err != nil {
			t.Fatalf("Parse(%q): unexpected error: %v", spec, err)
		}
		if c == nil {
			t.Fatalf("Parse(%q): nil client", spec)
		}
		if c.Active() {
			t.Fatalf("Parse(%q): expected inactive client", spec)
		}
		if c.ProxyURL() != "" {
			t.Fatalf("Parse(%q): inactive client should have empty ProxyURL, got %q", spec, c.ProxyURL())
		}
		// Replay on an inactive client must be a silent no-op.
		if err := c.Replay(context.Background(), engine.Request{URL: "http://example.invalid/"}); err != nil {
			t.Fatalf("Parse(%q): inactive Replay returned %v, want nil", spec, err)
		}
	}
}

func TestParse_RejectsMalformed(t *testing.T) {
	cases := []struct {
		spec string
		want string // substring expected in error
	}{
		{"://no-scheme", "scheme"},
		{"http://", "host"},
		{"ftp://burp:8080", "scheme"},
		{"gopher://example.com", "scheme"},
		{"%zz", "parse"}, // url.Parse failure
	}
	for _, tc := range cases {
		_, err := Parse(tc.spec, time.Second, false)
		if err == nil {
			t.Errorf("Parse(%q): expected error containing %q, got nil", tc.spec, tc.want)
			continue
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("Parse(%q): error %q does not contain %q", tc.spec, err.Error(), tc.want)
		}
	}
}

func TestParse_AcceptsValidSchemes(t *testing.T) {
	cases := []string{
		"http://127.0.0.1:8080",
		"https://burp.local:8443",
		"socks5://127.0.0.1:1080",
		"socks5h://tor.local:9050",
		"HTTP://upper.example:8080", // case-insensitive scheme
		"http://user:pass@127.0.0.1:8080",
	}
	for _, spec := range cases {
		c, err := Parse(spec, time.Second, false)
		if err != nil {
			t.Errorf("Parse(%q): unexpected error: %v", spec, err)
			continue
		}
		if !c.Active() {
			t.Errorf("Parse(%q): expected active client", spec)
		}
		if c.ProxyURL() == "" {
			t.Errorf("Parse(%q): expected non-empty ProxyURL", spec)
		}
	}
}

// TestReplay_RoutesThroughProxy stands up a fake HTTP proxy and an upstream
// target, points the replay client at the proxy, and verifies the proxy saw
// the request. This is the core integration assertion: a confirmed-hit request
// must reach the replay proxy verbatim so the operator's Burp/ZAP history
// shows it.
func TestReplay_RoutesThroughProxy(t *testing.T) {
	// Upstream target: records what the proxy forwarded.
	var (
		mu          sync.Mutex
		gotPath     string
		gotHeader   string
		gotCookie   string
		gotBody     []byte
		gotMethod   string
		reqReceived int32
	)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&reqReceived, 1)
		mu.Lock()
		gotPath = r.URL.Path + "?" + r.URL.RawQuery
		gotHeader = r.Header.Get("X-Custom")
		if c, err := r.Cookie("sess"); err == nil {
			gotCookie = c.Value
		}
		buf := make([]byte, 1024)
		n, _ := r.Body.Read(buf)
		gotBody = buf[:n]
		gotMethod = r.Method
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	// Fake HTTP proxy: forwards plain HTTP to the upstream and counts hits.
	var proxyHits int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&proxyHits, 1)
		// Forward to the actual destination encoded in the request URL.
		// httptest's HTTP proxy gets an absolute URL in r.URL.
		outReq, err := http.NewRequest(r.Method, r.URL.String(), r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		for k, vs := range r.Header {
			if strings.EqualFold(k, "Proxy-Connection") {
				continue
			}
			for _, v := range vs {
				outReq.Header.Add(k, v)
			}
		}
		resp, err := http.DefaultTransport.RoundTrip(outReq)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		for k, vs := range resp.Header {
			for _, v := range vs {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		buf := make([]byte, 4096)
		for {
			n, err := resp.Body.Read(buf)
			if n > 0 {
				_, _ = w.Write(buf[:n])
			}
			if err != nil {
				break
			}
		}
	}))
	defer proxy.Close()

	c, err := Parse(proxy.URL, 5*time.Second, false)
	if err != nil {
		t.Fatalf("Parse(%q): %v", proxy.URL, err)
	}
	if !c.Active() {
		t.Fatal("expected active client")
	}

	req := engine.Request{
		Method: "POST",
		URL:    upstream.URL + "/etc/passwd?x=1",
		Headers: http.Header{
			"X-Custom": []string{"replayed"},
		},
		Cookies: map[string]string{"sess": "abc123"},
		Body:    []byte("payload=../../../../etc/passwd"),
	}
	if err := c.Replay(context.Background(), req); err != nil {
		t.Fatalf("Replay: %v", err)
	}

	if atomic.LoadInt32(&proxyHits) != 1 {
		t.Errorf("proxy hits = %d, want 1", proxyHits)
	}
	if atomic.LoadInt32(&reqReceived) != 1 {
		t.Errorf("upstream requests = %d, want 1", reqReceived)
	}

	mu.Lock()
	defer mu.Unlock()
	if !strings.HasPrefix(gotPath, "/etc/passwd?x=1") {
		t.Errorf("upstream path %q, want prefix /etc/passwd?x=1", gotPath)
	}
	if gotMethod != "POST" {
		t.Errorf("upstream method %q, want POST", gotMethod)
	}
	if gotHeader != "replayed" {
		t.Errorf("upstream X-Custom %q, want %q", gotHeader, "replayed")
	}
	if gotCookie != "abc123" {
		t.Errorf("upstream cookie %q, want %q", gotCookie, "abc123")
	}
	if string(gotBody) != "payload=../../../../etc/passwd" {
		t.Errorf("upstream body %q, want %q", string(gotBody), "payload=../../../../etc/passwd")
	}
}

func TestReplay_NilReceiverIsNoop(t *testing.T) {
	var c *Client
	if c.Active() {
		t.Error("nil client should not report Active")
	}
	if c.ProxyURL() != "" {
		t.Error("nil client should have empty ProxyURL")
	}
	if err := c.Replay(context.Background(), engine.Request{URL: "http://example.invalid/"}); err != nil {
		t.Errorf("nil Replay returned %v, want nil", err)
	}
}

func TestReplay_DefaultsToGET(t *testing.T) {
	var gotMethod string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	// Use an HTTP proxy that's just a passthrough.
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		outReq, _ := http.NewRequest(r.Method, r.URL.String(), r.Body)
		for k, vs := range r.Header {
			for _, v := range vs {
				outReq.Header.Add(k, v)
			}
		}
		resp, err := http.DefaultTransport.RoundTrip(outReq)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		w.WriteHeader(resp.StatusCode)
	}))
	defer proxy.Close()

	c, err := Parse(proxy.URL, 5*time.Second, false)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	// Method omitted in engine.Request — replay should default to GET.
	req := engine.Request{URL: upstream.URL + "/"}
	if err := c.Replay(context.Background(), req); err != nil {
		t.Fatalf("Replay: %v", err)
	}
	if gotMethod != "GET" {
		t.Errorf("upstream saw method %q, want GET", gotMethod)
	}
}

func TestReplay_ProxyUnreachableReturnsError(t *testing.T) {
	// Pick a port that's almost certainly unbound.
	c, err := Parse("http://127.0.0.1:1", 200*time.Millisecond, false)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	err = c.Replay(context.Background(), engine.Request{URL: "http://example.invalid/"})
	if err == nil {
		t.Fatal("expected error when proxy is unreachable, got nil")
	}
	if !strings.Contains(err.Error(), "replay") {
		t.Errorf("error %q should mention 'replay'", err.Error())
	}
}

func TestReplay_CancelledContextAborts(t *testing.T) {
	// Proxy that sleeps forever, blocking the replay.
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer proxy.Close()

	c, err := Parse(proxy.URL, 10*time.Second, false)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	err = c.Replay(ctx, engine.Request{URL: "http://example.invalid/"})
	if err == nil {
		t.Fatal("expected error from cancelled context")
	}
}

func TestReplay_InsecureSkipsTLSVerify(t *testing.T) {
	// Self-signed HTTPS upstream — a strict client would reject it.
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	// HTTPS-aware passthrough proxy: handles CONNECT for HTTPS upstreams.
	// Easier to test: use an HTTP proxy and an HTTP upstream BUT verify the
	// insecure flag actually propagates by constructing the client directly
	// and inspecting the transport.
	c, err := Parse("https://proxy.local:8443", time.Second, true)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	tr, ok := c.client.Transport.(*http.Transport)
	if !ok {
		t.Fatal("transport is not *http.Transport")
	}
	if tr.TLSClientConfig == nil || !tr.TLSClientConfig.InsecureSkipVerify {
		t.Error("insecure=true did not set TLSClientConfig.InsecureSkipVerify")
	}

	// And the inverse:
	c2, err := Parse("https://proxy.local:8443", time.Second, false)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	tr2 := c2.client.Transport.(*http.Transport)
	if tr2.TLSClientConfig.InsecureSkipVerify {
		t.Error("insecure=false should leave InsecureSkipVerify=false")
	}

	_ = upstream // silence unused-var lint
	_ = (&tls.Config{}).InsecureSkipVerify
}

func TestReplay_RedirectIsNotFollowed(t *testing.T) {
	// Upstream returns a 302; the replay must observe the 302 verbatim, not
	// the redirect target's response. We assert this via the proxy: the proxy
	// should see EXACTLY ONE forwarded request, not two.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "http://elsewhere.invalid/")
		w.WriteHeader(http.StatusFound)
	}))
	defer upstream.Close()

	var proxyHits int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&proxyHits, 1)
		outReq, _ := http.NewRequest(r.Method, r.URL.String(), r.Body)
		for k, vs := range r.Header {
			for _, v := range vs {
				outReq.Header.Add(k, v)
			}
		}
		resp, err := http.DefaultTransport.RoundTrip(outReq)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		for k, vs := range resp.Header {
			for _, v := range vs {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
	}))
	defer proxy.Close()

	c, err := Parse(proxy.URL, 5*time.Second, false)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if err := c.Replay(context.Background(), engine.Request{URL: upstream.URL + "/start"}); err != nil {
		t.Fatalf("Replay: %v", err)
	}
	if got := atomic.LoadInt32(&proxyHits); got != 1 {
		t.Errorf("proxy hits = %d, want 1 (redirect must not be followed)", got)
	}
}

func TestParse_PreservesProxyURLFormat(t *testing.T) {
	spec := "http://127.0.0.1:8080"
	c, err := Parse(spec, time.Second, false)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	u, err := url.Parse(c.ProxyURL())
	if err != nil {
		t.Fatalf("ProxyURL re-parse: %v", err)
	}
	if u.Host != "127.0.0.1:8080" || u.Scheme != "http" {
		t.Errorf("ProxyURL = %q, want canonical form of %q", c.ProxyURL(), spec)
	}
}
