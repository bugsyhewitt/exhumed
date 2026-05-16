package cli

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/bugsyhewitt/exhumed/internal/engine"
	"github.com/bugsyhewitt/exhumed/internal/inject"
	"github.com/bugsyhewitt/exhumed/internal/traversal"
	"github.com/spf13/cobra"
)

// scanFlags holds the parsed flag values for the scan command.
type scanFlags struct {
	url            string
	marker         string
	method         string
	data           string
	headers        []string
	cookies        []string
	concurrency    int
	rate           float64
	timeout        time.Duration
	proxy          string
	insecure       bool
	traversalDepth int
	verbose        bool
}

func newScanCmd() *cobra.Command {
	var f scanFlags

	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan a URL for LFI vulnerabilities",
		Long: `scan fires traversal payloads at a target URL parameter and prints raw responses.

The URL must contain the marker string (default FUZZ) to indicate the injection
point. Example:

  exhumed scan --url "http://target.local/?file=FUZZ"

Packet 01: raw responses only. Detection and extraction arrive in Packets 03–04.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runScan(f)
		},
	}

	cmd.Flags().StringVarP(&f.url, "url", "u", "", "Target URL containing the injection marker (required)")
	cmd.Flags().StringVarP(&f.marker, "marker", "m", "FUZZ", "Placeholder string to substitute with payloads")
	cmd.Flags().StringVarP(&f.method, "method", "X", "GET", "HTTP method")
	cmd.Flags().StringVarP(&f.data, "data", "d", "", "Request body for POST/PUT")
	cmd.Flags().StringArrayVarP(&f.headers, "header", "H", nil, "Extra header (repeatable): 'Name: value'")
	cmd.Flags().StringArrayVarP(&f.cookies, "cookie", "b", nil, "Cookie (repeatable): 'name=value'")
	cmd.Flags().IntVarP(&f.concurrency, "concurrency", "c", 10, "Number of concurrent workers")
	cmd.Flags().Float64Var(&f.rate, "rate", 0, "Max requests/sec (0 = unlimited)")
	cmd.Flags().DurationVar(&f.timeout, "timeout", 10*time.Second, "Per-request timeout")
	cmd.Flags().StringVar(&f.proxy, "proxy", "", "HTTP proxy URL (e.g. http://127.0.0.1:8080)")
	cmd.Flags().BoolVar(&f.insecure, "insecure", false, "Skip TLS certificate verification")
	cmd.Flags().IntVar(&f.traversalDepth, "traversal-depth", 8, "Max directory traversal depth")
	cmd.Flags().BoolVarP(&f.verbose, "verbose", "v", false, "Verbose output")

	_ = cmd.MarkFlagRequired("url")

	return cmd
}

func runScan(f scanFlags) error {
	// Fast-fail if the marker is not present in the URL or request body.
	if !strings.Contains(f.url, f.marker) && !strings.Contains(f.data, f.marker) {
		return fmt.Errorf("marker %q not found in --url or --data; add it at the injection point", f.marker)
	}

	// Build the request template from flags.
	tmpl := inject.NewRequest(f.method, f.url)

	for _, h := range f.headers {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) != 2 {
			return fmt.Errorf("invalid header format %q: expected 'Name: value'", h)
		}
		tmpl.Headers.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
	}

	for _, c := range f.cookies {
		parts := strings.SplitN(c, "=", 2)
		if len(parts) != 2 {
			return fmt.Errorf("invalid cookie format %q: expected 'name=value'", c)
		}
		tmpl.Cookies[parts[0]] = parts[1]
	}

	if f.data != "" {
		tmpl.Body = []byte(f.data)
	}

	// Report which surfaces the marker was found in.
	surfaces := inject.FindSurfaces(tmpl, f.marker)
	if len(surfaces) == 0 {
		return fmt.Errorf("marker %q not found in any injection surface of the request", f.marker)
	}
	if f.verbose {
		fmt.Fprintf(os.Stderr, "[*] Injection surfaces: %v\n", surfaces)
	}

	// Demo: generate traversal payloads for a single hardcoded path so the
	// full pipeline is exercisable end-to-end in Packet 01.
	// Packet 02/03 will replace this with the database-driven file list.
	demoPath := "etc/passwd"
	payloads := traversal.Generate(demoPath, f.traversalDepth)

	if f.verbose {
		fmt.Fprintf(os.Stderr, "[*] Generated %d payloads for demo path %q\n", len(payloads), demoPath)
	}

	// Build concrete requests by injecting each payload.
	reqs := make([]engine.Request, 0, len(payloads))
	for _, p := range payloads {
		reqs = append(reqs, inject.Substitute(tmpl, f.marker, p.Value))
	}

	// Fire requests.
	eng := engine.New(engine.Config{
		Concurrency: f.concurrency,
		RatePerSec:  f.rate,
		Timeout:     f.timeout,
		ProxyURL:    f.proxy,
		Insecure:    f.insecure,
	})

	ctx := context.Background()
	results := eng.Run(ctx, reqs)

	// Print raw results.
	for i, r := range results {
		if r.Err != nil {
			fmt.Fprintf(os.Stderr, "[!] %s — %v\n", r.URL, r.Err)
			continue
		}
		tech := payloads[i].Technique
		fmt.Printf("[%d] %s  technique=%s  status=%d  bytes=%d  elapsed=%s\n",
			i+1, r.URL, tech, r.StatusCode, len(r.Body), r.Elapsed.Round(time.Millisecond))
		if f.verbose && len(r.Body) > 0 {
			preview := string(r.Body)
			if len(preview) > 256 {
				preview = preview[:256] + "…"
			}
			fmt.Printf("    %s\n", strings.ReplaceAll(preview, "\n", "\n    "))
		}
	}

	return nil
}
