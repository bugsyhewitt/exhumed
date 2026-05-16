package engine

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"
)

// startTestServer binds a minimal HTTP server on a random free port and
// returns the base URL. The caller is responsible for closing the listener.
func startTestServer(t *testing.T, handler http.Handler) (baseURL string, close func()) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	srv := &http.Server{Handler: handler}
	go srv.Serve(ln) //nolint:errcheck

	return fmt.Sprintf("http://%s", ln.Addr().String()), func() {
		srv.Close()
	}
}

func TestEngine_BasicGET(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "hello from testserver")
	})

	base, stop := startTestServer(t, mux)
	defer stop()

	eng := New(Config{
		Concurrency: 1,
		Timeout:     5 * time.Second,
	})

	reqs := []Request{{Method: "GET", URL: base + "/"}}
	results := eng.Run(context.Background(), reqs)

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	r := results[0]
	if r.Err != nil {
		t.Fatalf("unexpected error: %v", r.Err)
	}
	if r.StatusCode != http.StatusOK {
		t.Errorf("status: got %d, want %d", r.StatusCode, http.StatusOK)
	}
	if string(r.Body) != "hello from testserver" {
		t.Errorf("body: got %q, want %q", r.Body, "hello from testserver")
	}
	if r.Elapsed <= 0 {
		t.Error("elapsed should be > 0")
	}
}

func TestEngine_No4xxRetry(t *testing.T) {
	attempts := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.WriteHeader(http.StatusNotFound)
	})

	base, stop := startTestServer(t, mux)
	defer stop()

	eng := New(Config{
		Concurrency: 1,
		Timeout:     5 * time.Second,
	})

	reqs := []Request{{Method: "GET", URL: base + "/"}}
	results := eng.Run(context.Background(), reqs)

	if results[0].StatusCode != http.StatusNotFound {
		t.Errorf("expected 404, got %d", results[0].StatusCode)
	}
	if attempts != 1 {
		t.Errorf("4xx should not be retried: got %d attempts, want 1", attempts)
	}
}

func TestEngine_5xxRetried(t *testing.T) {
	attempts := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	base, stop := startTestServer(t, mux)
	defer stop()

	eng := New(Config{
		Concurrency: 1,
		Timeout:     5 * time.Second,
	})

	reqs := []Request{{Method: "GET", URL: base + "/"}}
	results := eng.Run(context.Background(), reqs)

	if results[0].StatusCode != http.StatusOK {
		t.Errorf("expected 200 after retries, got %d", results[0].StatusCode)
	}
	if attempts != 3 {
		t.Errorf("expected 3 attempts (2 retries), got %d", attempts)
	}
}

func TestEngine_CancelledContext(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Simulate slow response.
		select {
		case <-r.Context().Done():
		case <-time.After(10 * time.Second):
		}
		w.WriteHeader(http.StatusOK)
	})

	base, stop := startTestServer(t, mux)
	defer stop()

	eng := New(Config{
		Concurrency: 1,
		Timeout:     30 * time.Second,
	})

	ctx, cancel := context.WithCancel(context.Background())
	// Cancel immediately.
	cancel()

	reqs := []Request{{Method: "GET", URL: base + "/"}}
	results := eng.Run(ctx, reqs)

	if results[0].Err == nil {
		t.Error("expected an error after context cancel")
	}
}

func TestEngine_ConcurrentRequests(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	base, stop := startTestServer(t, mux)
	defer stop()

	eng := New(Config{
		Concurrency: 5,
		Timeout:     5 * time.Second,
	})

	reqs := make([]Request, 20)
	for i := range reqs {
		reqs[i] = Request{Method: "GET", URL: base + "/"}
	}

	results := eng.Run(context.Background(), reqs)
	if len(results) != 20 {
		t.Errorf("expected 20 results, got %d", len(results))
	}
	for i, r := range results {
		if r.Err != nil {
			t.Errorf("result[%d] error: %v", i, r.Err)
		}
	}
}

func TestEngine_BodyCap(t *testing.T) {
	const bodySize = 1024

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		// Write more than cap.
		for i := 0; i < 2048; i++ {
			w.Write([]byte("x")) //nolint:errcheck
		}
	})

	base, stop := startTestServer(t, mux)
	defer stop()

	eng := New(Config{
		Concurrency: 1,
		Timeout:     5 * time.Second,
		MaxBodySize: bodySize,
	})

	reqs := []Request{{Method: "GET", URL: base + "/"}}
	results := eng.Run(context.Background(), reqs)

	if int64(len(results[0].Body)) > bodySize {
		t.Errorf("body not capped: got %d bytes, cap is %d", len(results[0].Body), bodySize)
	}
}
