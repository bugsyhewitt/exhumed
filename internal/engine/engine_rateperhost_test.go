package engine

import (
	"context"
	"fmt"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

// TestEngine_RatePerHost_SingleHost asserts that --rate-per-host throttles
// requests to a single host: 6 requests at 5 req/s should span >= ~800ms
// (5 tokens are immediate via the burst, the 6th waits ~200ms). The first
// token in a token bucket is available immediately, so the inter-token wait
// is the slack we observe — we check that wall time exceeds a conservative
// floor that an unthrottled run could never hit.
func TestEngine_RatePerHost_SingleHost(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	base, stop := startTestServer(t, mux)
	defer stop()

	eng := New(Config{
		Concurrency:       4,
		RatePerHostPerSec: 5,
		Timeout:           5 * time.Second,
	})

	reqs := make([]Request, 6)
	for i := range reqs {
		reqs[i] = Request{Method: "GET", URL: base + "/"}
	}

	start := time.Now()
	results := eng.Run(context.Background(), reqs)
	elapsed := time.Since(start)

	if len(results) != 6 {
		t.Fatalf("expected 6 results, got %d", len(results))
	}
	for i, r := range results {
		if r.Err != nil {
			t.Fatalf("result %d: unexpected error: %v", i, r.Err)
		}
	}
	// At 5 req/s with burst 1, 6 requests need >= ~1000ms in the worst case
	// (first immediate, then 5 inter-token waits of 200ms). We use 700ms as a
	// conservative floor that an unrate-limited run (which would finish in
	// tens of ms) cannot reach.
	if elapsed < 700*time.Millisecond {
		t.Errorf("rate-per-host did not throttle: elapsed=%s, expected >=700ms", elapsed)
	}
}

// TestEngine_RatePerHost_IndependentPerHost asserts that per-host limiters
// are independent: 4 requests split across 2 distinct hosts at 2 req/s per
// host finish faster than 4 requests to a single host at the same rate.
// This proves the limiter is keyed by host, not shared globally.
func TestEngine_RatePerHost_IndependentPerHost(t *testing.T) {
	makeServer := func() (string, func()) {
		mux := http.NewServeMux()
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
		return startTestServer(t, mux)
	}

	baseA, stopA := makeServer()
	defer stopA()
	baseB, stopB := makeServer()
	defer stopB()

	eng := New(Config{
		Concurrency:       4,
		RatePerHostPerSec: 2,
		Timeout:           5 * time.Second,
	})

	reqs := []Request{
		{Method: "GET", URL: baseA + "/"},
		{Method: "GET", URL: baseB + "/"},
		{Method: "GET", URL: baseA + "/"},
		{Method: "GET", URL: baseB + "/"},
	}

	start := time.Now()
	results := eng.Run(context.Background(), reqs)
	elapsed := time.Since(start)

	if len(results) != 4 {
		t.Fatalf("expected 4 results, got %d", len(results))
	}
	// Each host gets 2 requests at 2 req/s. With burst 1, that's 1 immediate
	// + 1 after 500ms = ~500ms per host. Hosts run in parallel, so total
	// elapsed should be ~500ms, well under 900ms (which a single-host run at
	// 2 req/s would take: 1 immediate + 3 at 500ms intervals = ~1500ms).
	if elapsed > 900*time.Millisecond {
		t.Errorf("per-host limiters appear shared: elapsed=%s for 2 hosts at 2 req/s each, expected <900ms", elapsed)
	}
}

// TestEngine_RatePerHost_ComposesWithGlobalRate asserts that when both --rate
// and --rate-per-host are active, both gates fire — the tighter one wins.
// With global 100 req/s and per-host 4 req/s on a single host, 5 requests
// should be throttled by the per-host limit (4 req/s), not the global one.
func TestEngine_RatePerHost_ComposesWithGlobalRate(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	base, stop := startTestServer(t, mux)
	defer stop()

	eng := New(Config{
		Concurrency:       8,
		RatePerSec:        100,
		RatePerHostPerSec: 4,
		Timeout:           5 * time.Second,
	})

	reqs := make([]Request, 5)
	for i := range reqs {
		reqs[i] = Request{Method: "GET", URL: base + "/"}
	}

	start := time.Now()
	results := eng.Run(context.Background(), reqs)
	elapsed := time.Since(start)

	if len(results) != 5 {
		t.Fatalf("expected 5 results, got %d", len(results))
	}
	// 5 requests at 4 req/s: 1 immediate + 4 at 250ms intervals = ~1000ms.
	// Floor at 700ms to absorb token-bucket jitter.
	if elapsed < 700*time.Millisecond {
		t.Errorf("per-host did not throttle when composed with --rate: elapsed=%s, expected >=700ms", elapsed)
	}
}

// TestEngine_RatePerHost_Zero_NoThrottle asserts that RatePerHostPerSec=0 is
// the documented "unlimited" sentinel and adds no per-host throttling. With
// no global rate either, a 5-request scan must complete near-instantly.
func TestEngine_RatePerHost_Zero_NoThrottle(t *testing.T) {
	var count int32
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&count, 1)
		w.WriteHeader(http.StatusOK)
	})
	base, stop := startTestServer(t, mux)
	defer stop()

	eng := New(Config{
		Concurrency:       4,
		RatePerHostPerSec: 0,
		Timeout:           5 * time.Second,
	})

	reqs := make([]Request, 5)
	for i := range reqs {
		reqs[i] = Request{Method: "GET", URL: base + fmt.Sprintf("/?n=%d", i)}
	}

	start := time.Now()
	_ = eng.Run(context.Background(), reqs)
	elapsed := time.Since(start)

	if got := atomic.LoadInt32(&count); got != 5 {
		t.Fatalf("expected 5 requests, got %d", got)
	}
	if elapsed > 500*time.Millisecond {
		t.Errorf("zero per-host rate should not throttle: elapsed=%s, expected <500ms", elapsed)
	}
}
