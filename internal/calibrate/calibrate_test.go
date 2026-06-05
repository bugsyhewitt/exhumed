package calibrate

import (
	"testing"
	"time"
)

func mustController(t *testing.T, cfg Config) *Controller {
	t.Helper()
	c, err := NewController(cfg)
	if err != nil {
		t.Fatalf("NewController(%+v): %v", cfg, err)
	}
	return c
}

func TestNewController_RejectsNonPositiveTarget(t *testing.T) {
	if _, err := NewController(Config{Target: 0, InitialRate: 10}); err == nil {
		t.Fatalf("expected error for zero target")
	}
	if _, err := NewController(Config{Target: -1 * time.Millisecond, InitialRate: 10}); err == nil {
		t.Fatalf("expected error for negative target")
	}
}

func TestNewController_DefaultsAndInitialFallback(t *testing.T) {
	c := mustController(t, Config{Target: 200 * time.Millisecond})
	if got := c.Rate(); got != DefaultMaxRate {
		t.Fatalf("initial rate fallback: want %g (DefaultMaxRate), got %g", DefaultMaxRate, got)
	}
	if c.Target() != 200*time.Millisecond {
		t.Fatalf("target mismatch")
	}
}

func TestNewController_RejectsInvertedClamp(t *testing.T) {
	if _, err := NewController(Config{Target: 100 * time.Millisecond, MinRate: 200, MaxRate: 100, InitialRate: 50}); err == nil {
		t.Fatalf("expected error when MinRate > MaxRate")
	}
}

func TestObserve_NoSamplesIsNoOp(t *testing.T) {
	c := mustController(t, Config{Target: 100 * time.Millisecond, InitialRate: 10})
	obs := c.Observe(nil)
	if obs.Changed || obs.Reason != "no-samples" {
		t.Fatalf("nil batch: want unchanged no-samples, got %+v", obs)
	}
	if obs.NewRate != 10 {
		t.Fatalf("rate moved on no-samples: %g", obs.NewRate)
	}

	obs = c.Observe([]time.Duration{0, -1 * time.Millisecond})
	if obs.Changed || obs.Reason != "no-samples" {
		t.Fatalf("all-skipped batch: want no-samples, got %+v", obs)
	}
}

func TestObserve_LatencyAboveTarget_DecreasesRate(t *testing.T) {
	c := mustController(t, Config{
		Target:      100 * time.Millisecond,
		InitialRate: 100,
	})
	obs := c.Observe([]time.Duration{
		300 * time.Millisecond,
		400 * time.Millisecond,
		350 * time.Millisecond,
	})
	if obs.Reason != "decrease" {
		t.Fatalf("want decrease, got %s (obs=%+v)", obs.Reason, obs)
	}
	if !obs.Changed {
		t.Fatalf("expected rate change")
	}
	if obs.NewRate >= obs.OldRate {
		t.Fatalf("rate did not decrease: old=%g new=%g", obs.OldRate, obs.NewRate)
	}
	wantNew := 100.0 / DefaultDecreaseFactor
	if obs.NewRate != wantNew {
		t.Fatalf("decrease factor not applied: want %g, got %g", wantNew, obs.NewRate)
	}
}

func TestObserve_LatencyBelowTarget_IncreasesRate(t *testing.T) {
	c := mustController(t, Config{
		Target:      100 * time.Millisecond,
		InitialRate: 10,
	})
	obs := c.Observe([]time.Duration{
		20 * time.Millisecond,
		30 * time.Millisecond,
		25 * time.Millisecond,
	})
	if obs.Reason != "increase" {
		t.Fatalf("want increase, got %s (obs=%+v)", obs.Reason, obs)
	}
	wantNew := 10.0 * DefaultIncreaseFactor
	if obs.NewRate != wantNew {
		t.Fatalf("increase factor not applied: want %g, got %g", wantNew, obs.NewRate)
	}
}

func TestObserve_LatencyInBand_NoChange(t *testing.T) {
	c := mustController(t, Config{
		Target:      100 * time.Millisecond,
		InitialRate: 50,
	})
	obs := c.Observe([]time.Duration{
		90 * time.Millisecond,
		100 * time.Millisecond,
		110 * time.Millisecond,
	})
	if obs.Reason != "in-band" || obs.Changed {
		t.Fatalf("want unchanged in-band, got %+v", obs)
	}
	if obs.NewRate != 50 {
		t.Fatalf("rate moved in-band: %g", obs.NewRate)
	}
}

func TestObserve_ClampsAtMin(t *testing.T) {
	c := mustController(t, Config{
		Target:      100 * time.Millisecond,
		InitialRate: 1,
		MinRate:     0.5,
		MaxRate:     10,
	})
	// 3 successive decreases should clamp at MinRate well before 1/decFactor^3
	for i := 0; i < 5; i++ {
		c.Observe([]time.Duration{500 * time.Millisecond})
	}
	if got := c.Rate(); got != 0.5 {
		t.Fatalf("want clamped at min 0.5, got %g", got)
	}
	obs := c.Observe([]time.Duration{500 * time.Millisecond})
	if !obs.ClampedMin {
		t.Fatalf("expected ClampedMin flag")
	}
}

func TestObserve_ClampsAtMax(t *testing.T) {
	c := mustController(t, Config{
		Target:      100 * time.Millisecond,
		InitialRate: 50,
		MinRate:     1,
		MaxRate:     100,
	})
	for i := 0; i < 10; i++ {
		c.Observe([]time.Duration{1 * time.Millisecond})
	}
	if got := c.Rate(); got != 100 {
		t.Fatalf("want clamped at max 100, got %g", got)
	}
	obs := c.Observe([]time.Duration{1 * time.Millisecond})
	if !obs.ClampedMax {
		t.Fatalf("expected ClampedMax flag")
	}
}

func TestObserve_OutlierDoesNotCollapseRate(t *testing.T) {
	c := mustController(t, Config{
		Target:      100 * time.Millisecond,
		InitialRate: 50,
	})
	// One catastrophic 10s outlier among nine in-band samples.
	batch := []time.Duration{
		90 * time.Millisecond, 95 * time.Millisecond, 100 * time.Millisecond,
		100 * time.Millisecond, 100 * time.Millisecond, 100 * time.Millisecond,
		105 * time.Millisecond, 110 * time.Millisecond, 110 * time.Millisecond,
		10 * time.Second,
	}
	obs := c.Observe(batch)
	if obs.Reason != "in-band" {
		t.Fatalf("median should ignore outlier: got %+v", obs)
	}
}

func TestObserve_SkipsErrorLatencies(t *testing.T) {
	c := mustController(t, Config{
		Target:      100 * time.Millisecond,
		InitialRate: 10,
	})
	obs := c.Observe([]time.Duration{
		0, 0, 0,
		20 * time.Millisecond, 25 * time.Millisecond, 30 * time.Millisecond,
	})
	if obs.Samples != 3 {
		t.Fatalf("want 3 samples (zeros skipped), got %d", obs.Samples)
	}
	if obs.Reason != "increase" {
		t.Fatalf("want increase from fast samples, got %s", obs.Reason)
	}
}

func TestObserve_DownThenUp_RecoversRate(t *testing.T) {
	c := mustController(t, Config{
		Target:      100 * time.Millisecond,
		InitialRate: 50,
		MinRate:     0.1,
		MaxRate:     1000,
	})
	// Burst of slow → rate drops.
	for i := 0; i < 3; i++ {
		c.Observe([]time.Duration{500 * time.Millisecond})
	}
	dropped := c.Rate()
	if dropped >= 50 {
		t.Fatalf("rate did not drop after slow batches: %g", dropped)
	}
	// Recovery: fast batches → rate climbs back up.
	for i := 0; i < 10; i++ {
		c.Observe([]time.Duration{20 * time.Millisecond})
	}
	recovered := c.Rate()
	if recovered <= dropped {
		t.Fatalf("rate did not recover: dropped=%g recovered=%g", dropped, recovered)
	}
}

func TestObserve_MedianEven(t *testing.T) {
	c := mustController(t, Config{Target: 100 * time.Millisecond, InitialRate: 50})
	// Four samples, sorted: 50,80,120,150 → median = (80+120)/2 = 100ms (in-band)
	obs := c.Observe([]time.Duration{
		150 * time.Millisecond, 50 * time.Millisecond,
		120 * time.Millisecond, 80 * time.Millisecond,
	})
	if obs.Median != 100*time.Millisecond {
		t.Fatalf("median mis-computed: want 100ms, got %s", obs.Median)
	}
	if obs.Reason != "in-band" {
		t.Fatalf("want in-band, got %s", obs.Reason)
	}
}
