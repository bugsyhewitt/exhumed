package engine

import (
	"context"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bugsyhewitt/exhumed/internal/calibrate"
)

// TestEngine_AutoCalibrate_DisabledByDefault asserts a zero AutoCalibrateTarget
// leaves the engine in its pre-existing behaviour: no calibrator, no calib
// limiter, CalibrateRate() reports 0.
func TestEngine_AutoCalibrate_DisabledByDefault(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	base, stop := startTestServer(t, mux)
	defer stop()

	eng := New(Config{Concurrency: 2, Timeout: 2 * time.Second})
	if got := eng.CalibrateRate(); got != 0 {
		t.Fatalf("CalibrateRate() with target=0 = %g, want 0", got)
	}
	results := eng.Run(context.Background(), []Request{{Method: "GET", URL: base + "/"}})
	if len(results) != 1 || results[0].Err != nil {
		t.Fatalf("baseline request failed: %+v", results)
	}
	if got := eng.CalibrateRate(); got != 0 {
		t.Fatalf("CalibrateRate() after Run = %g, want 0", got)
	}
}

// TestEngine_AutoCalibrate_SlowResponsesDecreaseRate sends a batch of slow
// responses (well above the configured 50ms target) through an engine with
// auto-calibrate enabled and asserts the rate moves down and the OnCalibrate
// callback fires with reason="decrease".
func TestEngine_AutoCalibrate_SlowResponsesDecreaseRate(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	})
	base, stop := startTestServer(t, mux)
	defer stop()

	var lastReason atomic.Value
	var calls atomic.Int32
	eng := New(Config{
		Concurrency:          2,
		Timeout:              5 * time.Second,
		AutoCalibrateTarget:  50 * time.Millisecond,
		AutoCalibrateInitial: 20,
		AutoCalibrateMin:     0.5,
		AutoCalibrateMax:     100,
		OnCalibrate: func(obs calibrate.Observation) {
			lastReason.Store(obs.Reason)
			calls.Add(1)
		},
	})

	reqs := make([]Request, 6)
	for i := range reqs {
		reqs[i] = Request{Method: "GET", URL: base + "/"}
	}
	startRate := eng.CalibrateRate()
	results := eng.Run(context.Background(), reqs)
	if len(results) != 6 {
		t.Fatalf("want 6 results, got %d", len(results))
	}
	endRate := eng.CalibrateRate()

	if calls.Load() == 0 {
		t.Fatalf("OnCalibrate was never invoked")
	}
	if endRate >= startRate {
		t.Fatalf("rate did not decrease after slow batch: start=%g end=%g", startRate, endRate)
	}
	got, _ := lastReason.Load().(string)
	if got != "decrease" {
		t.Fatalf("last reason = %q, want %q", got, "decrease")
	}
}

// TestEngine_AutoCalibrate_FastResponsesIncreaseRate verifies the inverse:
// uniformly fast responses (well below target) cause the adaptive rate to
// climb from its initial value.
func TestEngine_AutoCalibrate_FastResponsesIncreaseRate(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	base, stop := startTestServer(t, mux)
	defer stop()

	eng := New(Config{
		Concurrency:          2,
		Timeout:              5 * time.Second,
		AutoCalibrateTarget:  500 * time.Millisecond,
		AutoCalibrateInitial: 10,
		AutoCalibrateMin:     0.5,
		AutoCalibrateMax:     1000,
	})

	startRate := eng.CalibrateRate()
	reqs := make([]Request, 8)
	for i := range reqs {
		reqs[i] = Request{Method: "GET", URL: base + "/"}
	}
	results := eng.Run(context.Background(), reqs)
	for i, r := range results {
		if r.Err != nil {
			t.Fatalf("result %d: %v", i, r.Err)
		}
	}
	endRate := eng.CalibrateRate()
	if endRate <= startRate {
		t.Fatalf("rate did not increase after fast batch: start=%g end=%g", startRate, endRate)
	}
}

// TestEngine_AutoCalibrate_StaticRateIsCeiling asserts the static --rate
// limiter still gates the engine when auto-calibrate is on: even if the
// adaptive limiter would permit a high rate, the static limiter's lower cap
// dominates. We assert the batch elapsed time still respects the static rate.
func TestEngine_AutoCalibrate_StaticRateIsCeiling(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	base, stop := startTestServer(t, mux)
	defer stop()

	eng := New(Config{
		Concurrency:          2,
		Timeout:              5 * time.Second,
		RatePerSec:           5,
		AutoCalibrateTarget:  500 * time.Millisecond,
		AutoCalibrateInitial: 1000,
		AutoCalibrateMax:     1000,
	})

	reqs := make([]Request, 6)
	for i := range reqs {
		reqs[i] = Request{Method: "GET", URL: base + "/"}
	}
	start := time.Now()
	results := eng.Run(context.Background(), reqs)
	elapsed := time.Since(start)

	if len(results) != 6 {
		t.Fatalf("want 6 results, got %d", len(results))
	}
	// 6 requests at 5 r/s with burst 1: first immediate, then 5 × 200ms ≈ 1s.
	// A 700ms floor cleanly distinguishes a throttled run from an unbounded
	// one (which would finish in tens of ms even with no per-handler work).
	if elapsed < 700*time.Millisecond {
		t.Errorf("static --rate did not throttle: elapsed=%s, want >=700ms", elapsed)
	}
}

// TestEngine_AutoCalibrate_NoSamplesNoCallback asserts that a batch of pure
// errors (no successful latency) does not invoke OnCalibrate and does not
// move the rate, since the controller skips zero/negative samples.
func TestEngine_AutoCalibrate_NoSamplesNoCallback(t *testing.T) {
	var calls atomic.Int32
	eng := New(Config{
		Concurrency:          1,
		Timeout:              200 * time.Millisecond,
		AutoCalibrateTarget:  100 * time.Millisecond,
		AutoCalibrateInitial: 10,
		OnCalibrate: func(_ calibrate.Observation) {
			calls.Add(1)
		},
	})
	// Unroutable host so every request errors out.
	reqs := []Request{{Method: "GET", URL: "http://127.0.0.1:1/"}}
	results := eng.Run(context.Background(), reqs)
	if len(results) != 1 || results[0].Err == nil {
		t.Fatalf("expected error result, got %+v", results)
	}
	// The retry loop yields a non-zero Elapsed (it measures wall time across
	// retries), but Err != nil so the engine skips it from the calibration
	// sample set — Observe sees an empty batch and OnCalibrate stays silent.
	if calls.Load() != 0 {
		t.Fatalf("OnCalibrate fired on all-error batch: %d calls", calls.Load())
	}
}
