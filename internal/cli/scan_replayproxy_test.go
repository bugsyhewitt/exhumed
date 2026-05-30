package cli

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// replayProxyFlags builds a scanFlags pointed at serverURL with replay-proxy
// set to proxyURL. onlyHits=true keeps the output deterministic — we care
// about the replay path, not the "[responded]" stream.
func replayProxyFlags(t *testing.T, serverURL, proxyURL string) scanFlags {
	return scanFlags{
		url:            serverURL + "/?file=FUZZ",
		marker:         "FUZZ",
		method:         "GET",
		concurrency:    1,
		timeout:        5 * time.Second,
		traversalDepth: 1,
		dbPath:         curatedDBPath(t),
		onlyHits:       true,
		maxDepth:       0,
		maxTargets:     0,
		outputFormat:   "text",
		replayProxy:    proxyURL,
	}
}

// passthroughProxy builds a counting HTTP proxy that forwards each received
// request to its absolute-URL destination and returns the upstream response.
// It records request URLs and methods so a test can assert the replay payload
// arrived verbatim.
func passthroughProxy(t *testing.T) (server *httptest.Server, hits *int32, recordedURLs *[]string, mu *sync.Mutex) {
	t.Helper()
	var counter int32
	var (
		urls   []string
		urlsMu sync.Mutex
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&counter, 1)
		urlsMu.Lock()
		urls = append(urls, r.URL.String())
		urlsMu.Unlock()

		outReq, err := http.NewRequestWithContext(r.Context(), r.Method, r.URL.String(), r.Body)
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
	return srv, &counter, &urls, &urlsMu
}

// TestScan_ReplayProxyMirrorsConfirmedHits verifies that --replay-proxy sends
// every confirmed hit's winning request to the replay proxy, and that
// unconfirmed responses are NOT replayed.
func TestScan_ReplayProxyMirrorsConfirmedHits(t *testing.T) {
	var (
		upstreamHits int32
	)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&upstreamHits, 1)
		// Confirm only on /etc/passwd requests so we have a single, predictable
		// hit. Every other path returns a 404 (unconfirmed noise).
		if strings.Contains(r.URL.RawQuery, "passwd") {
			_, _ = w.Write([]byte("root:x:0:0:root:/root:/bin/bash\n"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer upstream.Close()

	proxy, proxyHits, recordedURLs, urlsMu := passthroughProxy(t)
	defer proxy.Close()

	f := replayProxyFlags(t, upstream.URL, proxy.URL)
	if err := runScan(f); err != nil {
		t.Fatalf("runScan: %v", err)
	}

	// The upstream was hit by both the scan AND the replay. We assert the
	// replay proxy saw AT LEAST one request and it targeted the passwd path —
	// i.e. only the confirmed hit's request was mirrored, not the unconfirmed
	// 404s.
	got := atomic.LoadInt32(proxyHits)
	if got < 1 {
		t.Fatalf("replay proxy saw %d requests; expected at least 1 confirmed-hit replay", got)
	}

	urlsMu.Lock()
	defer urlsMu.Unlock()
	sawPasswd := false
	for _, u := range *recordedURLs {
		if strings.Contains(u, "passwd") {
			sawPasswd = true
		}
		// No unconfirmed-noise URL should reach the replay proxy. The fixture
		// DB hits passwd only on /etc/passwd-like queries.
		if !strings.Contains(u, "passwd") {
			t.Errorf("replay proxy received non-hit URL %q (only confirmed hits should be replayed)", u)
		}
	}
	if !sawPasswd {
		t.Errorf("replay proxy never saw the passwd hit; recorded URLs: %v", *recordedURLs)
	}
}

// TestScan_ReplayProxyRejectsMalformedURL verifies the replay-proxy spec is
// validated at parse time, before any requests fire.
func TestScan_ReplayProxyRejectsMalformedURL(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("upstream should not be hit when replay-proxy spec is malformed")
	}))
	defer upstream.Close()

	cases := []string{
		"ftp://burp:8080",
		"http://",
		"not a url at all",
	}
	for _, spec := range cases {
		f := replayProxyFlags(t, upstream.URL, spec)
		err := runScan(f)
		if err == nil {
			t.Errorf("runScan(--replay-proxy %q) returned nil; expected validation error", spec)
		}
	}
}

// TestScan_ReplayProxyUnreachableDoesNotFailScan verifies the core out-of-band
// contract: a replay proxy that's down MUST NOT fail the scan. The hit was
// already confirmed by detect.Check; the replay is a courtesy I/O.
func TestScan_ReplayProxyUnreachableDoesNotFailScan(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.RawQuery, "passwd") {
			_, _ = w.Write([]byte("root:x:0:0:root:/root:/bin/bash\n"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer upstream.Close()

	// Port 1 is almost certainly unbound.
	f := replayProxyFlags(t, upstream.URL, "http://127.0.0.1:1")
	f.timeout = 200 * time.Millisecond // keep the test fast
	if err := runScan(f); err != nil {
		t.Fatalf("runScan must not fail when replay proxy is unreachable, got: %v", err)
	}
}

// TestScan_NoReplayProxyIsBackwardCompatible verifies that omitting
// --replay-proxy preserves prior behaviour: no replay client active, no
// extra requests, scan completes normally.
func TestScan_NoReplayProxyIsBackwardCompatible(t *testing.T) {
	var upstreamHits int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&upstreamHits, 1)
		if strings.Contains(r.URL.RawQuery, "passwd") {
			_, _ = w.Write([]byte("root:x:0:0:root:/root:/bin/bash\n"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer upstream.Close()

	f := replayProxyFlags(t, upstream.URL, "") // empty replay-proxy
	if err := runScan(f); err != nil {
		t.Fatalf("runScan: %v", err)
	}
	scanHits := atomic.LoadInt32(&upstreamHits)
	if scanHits == 0 {
		t.Fatal("expected scan to hit upstream at least once")
	}

	// Re-run with the same setup and a real replay proxy; confirm the upstream
	// sees additional hits beyond the scan-only count.
	atomic.StoreInt32(&upstreamHits, 0)
	proxy, _, _, _ := passthroughProxy(t)
	defer proxy.Close()
	f2 := replayProxyFlags(t, upstream.URL, proxy.URL)
	if err := runScan(f2); err != nil {
		t.Fatalf("runScan with replay: %v", err)
	}
	withReplay := atomic.LoadInt32(&upstreamHits)
	if withReplay <= scanHits {
		t.Errorf("expected upstream hits with replay (%d) > scan-only (%d)", withReplay, scanHits)
	}
}
