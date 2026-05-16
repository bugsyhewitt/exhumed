// Package engine provides a concurrent, rate-limited HTTP request engine.
package engine

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/time/rate"
)

const (
	// DefaultMaxBodySize caps response body reads at 2 MB.
	DefaultMaxBodySize int64 = 2 * 1024 * 1024
)

// Request is the template for a single HTTP request.
// Headers uses the canonical net/http form (map[string][]string).
// Cookies is a flat name→value map for simplicity; multi-value cookies
// can be combined by the caller before submission.
type Request struct {
	Method  string
	URL     string
	Headers http.Header
	Cookies map[string]string
	Body    []byte
}

// Result is the outcome of a single HTTP request.
type Result struct {
	URL        string
	StatusCode int
	Headers    http.Header
	Body       []byte
	Elapsed    time.Duration
	Err        error
}

// Config controls engine behaviour.
type Config struct {
	Concurrency int
	RatePerSec  float64 // 0 = unlimited
	Timeout     time.Duration
	MaxBodySize int64
	ProxyURL    string
	Insecure    bool
}

// Engine dispatches requests concurrently.
type Engine struct {
	client  *http.Client
	limiter *rate.Limiter
	cfg     Config
}

// New creates an Engine from cfg and starts the worker pool.
func New(cfg Config) *Engine {
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 1
	}
	if cfg.MaxBodySize <= 0 {
		cfg.MaxBodySize = DefaultMaxBodySize
	}

	transport := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: cfg.Insecure}, //nolint:gosec
		DisableKeepAlives:   false,
		MaxIdleConns:        cfg.Concurrency * 2,
		MaxIdleConnsPerHost: cfg.Concurrency,
	}

	if cfg.ProxyURL != "" {
		proxyURL, err := url.Parse(cfg.ProxyURL)
		if err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	}

	var lim *rate.Limiter
	if cfg.RatePerSec > 0 {
		lim = rate.NewLimiter(rate.Limit(cfg.RatePerSec), 1)
	}

	e := &Engine{
		client: &http.Client{
			Transport: transport,
			Timeout:   cfg.Timeout,
		},
		limiter: lim,
		cfg:     cfg,
	}

	return e
}

// indexedResult pairs a Result with the original request index so the output
// slice preserves input order regardless of worker completion order.
type indexedResult struct {
	idx    int
	result Result
}

// Run processes all requests in reqs and returns results in the same order as
// the input slice. Workers complete in non-deterministic order; results are
// placed into indexed slots before returning.
// Cancelling ctx causes all in-flight requests to abort.
func (e *Engine) Run(ctx context.Context, reqs []Request) []Result {
	if len(reqs) == 0 {
		return nil
	}

	type indexedJob struct {
		idx int
		req Request
	}

	jobs := make(chan indexedJob, len(reqs))
	resultCh := make(chan indexedResult, len(reqs))

	for i := 0; i < e.cfg.Concurrency; i++ {
		go func() {
			for j := range jobs {
				select {
				case <-ctx.Done():
					resultCh <- indexedResult{j.idx, Result{URL: j.req.URL, Err: ctx.Err()}}
					continue
				default:
				}

				if e.limiter != nil {
					if err := e.limiter.Wait(ctx); err != nil {
						resultCh <- indexedResult{j.idx, Result{URL: j.req.URL, Err: err}}
						continue
					}
				}

				resultCh <- indexedResult{j.idx, e.do(ctx, j.req)}
			}
		}()
	}

	for i, r := range reqs {
		jobs <- indexedJob{i, r}
	}
	close(jobs)

	out := make([]Result, len(reqs))
	for range reqs {
		ir := <-resultCh
		out[ir.idx] = ir.result
	}
	return out
}

// do executes a single request with retry logic.
func (e *Engine) do(ctx context.Context, req Request) Result {
	const maxRetries = 2

	start := time.Now()
	var lastResult Result

	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			// Exponential backoff: 100ms, 200ms
			backoff := time.Duration(math.Pow(2, float64(attempt-1)) * 100 * float64(time.Millisecond))
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return Result{URL: req.URL, Elapsed: time.Since(start), Err: ctx.Err()}
			}
		}

		result := e.doOnce(ctx, req, start)
		lastResult = result

		if result.Err != nil {
			// Network error — retry
			continue
		}
		// Never retry 4xx
		if result.StatusCode >= 400 && result.StatusCode < 500 {
			return result
		}
		// Retry 5xx
		if result.StatusCode >= 500 {
			continue
		}
		// Success
		return result
	}

	return lastResult
}

// doOnce sends a single HTTP request without retry.
func (e *Engine) doOnce(ctx context.Context, req Request, start time.Time) Result {
	httpReq, err := http.NewRequestWithContext(ctx, req.Method, req.URL, bytes.NewReader(req.Body))
	if err != nil {
		return Result{URL: req.URL, Elapsed: time.Since(start), Err: fmt.Errorf("build request: %w", err)}
	}

	for key, vals := range req.Headers {
		for _, v := range vals {
			httpReq.Header.Add(key, v)
		}
	}

	for name, val := range req.Cookies {
		httpReq.AddCookie(&http.Cookie{Name: name, Value: val})
	}

	resp, err := e.client.Do(httpReq)
	if err != nil {
		return Result{URL: req.URL, Elapsed: time.Since(start), Err: fmt.Errorf("send request: %w", err)}
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, e.cfg.MaxBodySize))
	if err != nil {
		return Result{
			URL:        req.URL,
			StatusCode: resp.StatusCode,
			Headers:    resp.Header,
			Elapsed:    time.Since(start),
			Err:        fmt.Errorf("read body: %w", err),
		}
	}

	return Result{
		URL:        req.URL,
		StatusCode: resp.StatusCode,
		Headers:    resp.Header,
		Body:       body,
		Elapsed:    time.Since(start),
	}
}
