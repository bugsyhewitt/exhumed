// Package calibrate provides an adaptive request-rate controller that holds
// the engine's request rate near a target response latency.
//
// During a long scan the target's response latency is the cheapest live signal
// of how hard exhumed is pushing it: a healthy server returns in tens of
// milliseconds; the same server under load, behind a struggling WAF, or
// approaching a per-IP threshold returns in hundreds of milliseconds to
// seconds. A static --rate cannot react to that — set it high and the scan
// hammers a flapping target into degraded responses (and trips rate-limit
// detection); set it low and a healthy target is under-utilised and the scan
// takes longer than it needs to.
//
// --auto-calibrate <target-latency> closes that loop. The operator names the
// p50 latency they want the target to sit at (e.g. 200ms); the Controller
// observes the actual latencies of each batch of requests the engine sends and
// adjusts the engine's effective rate up when latencies are comfortably below
// the target and down when they exceed it. The adjustment is multiplicative
// (TCP-friendly AIMD-style: a moderate increase when things look fine, a
// sharper decrease when they don't) and clamped to a sane min/max so the loop
// can never run away.
//
// The Controller is intentionally framework-free: it has no network I/O, no
// time source dependency beyond the latencies it is handed, and no knowledge
// of the rate.Limiter it ultimately drives. It computes "what should the rate
// be now?"; the engine wires that into a *rate.Limiter via SetLimit.
//
// The decision rule, given the latency band [target*tolDown, target*tolUp]:
//
//	median(batch) > target*tolUp    → newRate = oldRate / decreaseFactor (slow down hard)
//	median(batch) < target*tolDown  → newRate = oldRate * increaseFactor (probe upwards)
//	otherwise                       → newRate unchanged (inside the comfort band)
//
// Median (not mean) is the comparator: one outlier slow request (a single
// proxy reconnect, a single chunky response) must not collapse the rate.
package calibrate

import (
	"fmt"
	"sort"
	"sync"
	"time"
)

// Defaults chosen for the typical exhumed scan: each entry fires ~20 payloads
// through engine.Run, so the controller sees a ~20-sample batch per entry.
// The asymmetric increase/decrease factors are AIMD-flavoured: probe upwards
// conservatively (1.25x), back off aggressively when latency exceeds the
// target (1.5x divide) so a degrading target is unloaded faster than it was
// loaded. The 0.5 req/s minimum keeps a wedged scan from stalling entirely;
// the 1000 req/s maximum keeps a runaway controller from saturating either
// the engine's worker pool or the target.
const (
	DefaultIncreaseFactor = 1.25
	DefaultDecreaseFactor = 1.5
	DefaultTolUp          = 1.2
	DefaultTolDown        = 0.8
	DefaultMinRate        = 0.5
	DefaultMaxRate        = 1000.0
)

// Controller holds the adaptive rate state. It is safe for concurrent use:
// Observe and Rate may be called from different goroutines (the engine driver
// reads Rate after each batch to push into rate.Limiter.SetLimit).
type Controller struct {
	mu sync.Mutex

	target time.Duration
	rate   float64

	minRate, maxRate float64
	tolUp, tolDown   float64
	incFactor        float64
	decFactor        float64
}

// Config bundles Controller knobs. The zero value of any tunable field is
// replaced with the package default at NewController time, so a caller that
// only cares about target+initial can pass the rest as zero.
type Config struct {
	Target         time.Duration
	InitialRate    float64
	MinRate        float64
	MaxRate        float64
	TolUp          float64 // multiplier above target that triggers a rate decrease
	TolDown        float64 // multiplier below target that triggers a rate increase
	IncreaseFactor float64 // multiplicative factor applied on an increase decision
	DecreaseFactor float64 // divisor applied on a decrease decision (must be >1)
}

// NewController builds a Controller from cfg. A non-positive Target is an
// error — the controller has no signal to track without one. A non-positive
// InitialRate falls back to MaxRate (start fast, let the loop slow it).
// Unset tunables fall back to package defaults; out-of-range tunables (e.g.
// IncreaseFactor <= 1 or DecreaseFactor <= 1) are corrected to the defaults
// silently rather than rejected, since the operator is expected to be tuning
// the target only.
func NewController(cfg Config) (*Controller, error) {
	if cfg.Target <= 0 {
		return nil, fmt.Errorf("calibrate: target latency must be > 0, got %s", cfg.Target)
	}

	c := &Controller{
		target:    cfg.Target,
		minRate:   pickPos(cfg.MinRate, DefaultMinRate),
		maxRate:   pickPos(cfg.MaxRate, DefaultMaxRate),
		tolUp:     pickGreater(cfg.TolUp, 1.0, DefaultTolUp),
		tolDown:   pickLessOne(cfg.TolDown, DefaultTolDown),
		incFactor: pickGreater(cfg.IncreaseFactor, 1.0, DefaultIncreaseFactor),
		decFactor: pickGreater(cfg.DecreaseFactor, 1.0, DefaultDecreaseFactor),
	}
	if c.minRate > c.maxRate {
		return nil, fmt.Errorf("calibrate: min rate %g > max rate %g", c.minRate, c.maxRate)
	}

	initial := cfg.InitialRate
	if initial <= 0 {
		initial = c.maxRate
	}
	c.rate = clamp(initial, c.minRate, c.maxRate)

	return c, nil
}

// Rate returns the current adaptive rate in requests/sec.
func (c *Controller) Rate() float64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.rate
}

// Target returns the configured target latency.
func (c *Controller) Target() time.Duration {
	return c.target
}

// Observation summarises a single Observe call's outcome.
type Observation struct {
	Samples    int           // number of latencies considered (negatives skipped)
	Median     time.Duration // median of the samples, or 0 when Samples == 0
	OldRate    float64
	NewRate    float64
	Changed    bool   // true if the rate moved
	Reason     string // "decrease", "increase", "in-band", "no-samples"
	ClampedMin bool   // newRate hit the lower clamp
	ClampedMax bool   // newRate hit the upper clamp
}

// Observe folds a batch of observed request latencies into the controller and
// returns the resulting Observation. Negative or zero latencies are skipped
// (they correspond to request errors and to incompletely measured retries).
// An empty / all-skipped batch leaves the rate unchanged.
//
// Observe is the only mutator of the controller's rate.
func (c *Controller) Observe(latencies []time.Duration) Observation {
	c.mu.Lock()
	defer c.mu.Unlock()

	old := c.rate

	samples := make([]time.Duration, 0, len(latencies))
	for _, d := range latencies {
		if d > 0 {
			samples = append(samples, d)
		}
	}

	if len(samples) == 0 {
		return Observation{
			OldRate: old,
			NewRate: old,
			Reason:  "no-samples",
		}
	}

	med := median(samples)
	upBound := time.Duration(float64(c.target) * c.tolUp)
	downBound := time.Duration(float64(c.target) * c.tolDown)

	var newRate float64
	var reason string
	switch {
	case med > upBound:
		newRate = old / c.decFactor
		reason = "decrease"
	case med < downBound:
		newRate = old * c.incFactor
		reason = "increase"
	default:
		newRate = old
		reason = "in-band"
	}

	clampedMin := false
	clampedMax := false
	if newRate < c.minRate {
		newRate = c.minRate
		clampedMin = true
	}
	if newRate > c.maxRate {
		newRate = c.maxRate
		clampedMax = true
	}

	c.rate = newRate

	return Observation{
		Samples:    len(samples),
		Median:     med,
		OldRate:    old,
		NewRate:    newRate,
		Changed:    newRate != old,
		Reason:     reason,
		ClampedMin: clampedMin,
		ClampedMax: clampedMax,
	}
}

func median(xs []time.Duration) time.Duration {
	sorted := make([]time.Duration, len(xs))
	copy(sorted, xs)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	n := len(sorted)
	if n%2 == 1 {
		return sorted[n/2]
	}
	return (sorted[n/2-1] + sorted[n/2]) / 2
}

func clamp(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func pickPos(v, def float64) float64 {
	if v > 0 {
		return v
	}
	return def
}

// pickGreater returns v when it strictly exceeds floor, else def.
func pickGreater(v, floor, def float64) float64 {
	if v > floor {
		return v
	}
	return def
}

// pickLessOne returns v when in (0, 1), else def.
func pickLessOne(v, def float64) float64 {
	if v > 0 && v < 1 {
		return v
	}
	return def
}
