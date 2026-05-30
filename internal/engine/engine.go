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
	"sync"
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
	// RatePerHostPerSec caps the request rate to a single target host (keyed by
	// URL host:port) independently of the global RatePerSec budget. The two
	// limits compose: a request must acquire a token from BOTH the global
	// limiter (if active) and the per-host limiter for its destination (if
	// active) before being dispatched. 0 = unlimited per-host. The typical use
	// is to fan out across many targets (high --concurrency, high global --rate)
	// while staying polite to each individual host (low --rate-per-host).
	RatePerHostPerSec float64
	Timeout           time.Duration
	MaxBodySize       int64
	ProxyURL          string
	Insecure          bool
	// FollowRedirects controls whether 3xx responses are transparently
	// followed. When false (the default), the engine returns the redirect
	// response verbatim — the original 3xx status and Location header are
	// preserved instead of being masked by the redirect target's response.
	// Not following redirects is the correct default for a fuzzer: a 302 to a
	// login page must not be reported as the login page's 200.
	FollowRedirects bool
}

// Engine dispatches requests concurrently.
type Engine struct {
	client       *http.Client
	limiter      *rate.Limiter
	hostLimiters sync.Map // host string -> *rate.Limiter; populated lazily
	cfg          Config
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

	client := &http.Client{
		Transport: transport,
		Timeout:   cfg.Timeout,
	}
	// By default, do not follow redirects: a fuzzer must observe the original
	// 3xx status and Location header, not the redirect target's response.
	// Returning http.ErrUseLastResponse makes Client.Do hand back the 3xx
	// response verbatim without error.
	if !cfg.FollowRedirects {
		client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	e := &Engine{
		client:  client,
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
				if e.cfg.RatePerHostPerSec > 0 {
					if hl := e.hostLimiterFor(j.req.URL); hl != nil {
						if err := hl.Wait(ctx); err != nil {
							resultCh <- indexedResult{j.idx, Result{URL: j.req.URL, Err: err}}
							continue
						}
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

// hostLimiterFor returns the per-host rate limiter for the request URL's host,
// lazily creating one on first sight. An unparseable URL falls back to a
// shared "" bucket so a malformed input still gets throttled rather than
// bypassing the per-host budget entirely.
func (e *Engine) hostLimiterFor(rawURL string) *rate.Limiter {
	host := ""
	if u, err := url.Parse(rawURL); err == nil {
		host = u.Host
	}
	if v, ok := e.hostLimiters.Load(host); ok {
		return v.(*rate.Limiter)
	}
	lim := rate.NewLimiter(rate.Limit(e.cfg.RatePerHostPerSec), 1)
	actual, _ := e.hostLimiters.LoadOrStore(host, lim)
	return actual.(*rate.Limiter)
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
