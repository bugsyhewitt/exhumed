package cli

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/bugsyhewitt/exhumed/internal/db"
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
	dbPath         string
}

func newScanCmd() *cobra.Command {
	var f scanFlags

	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan a URL for LFI vulnerabilities",
		Long: `scan loads the file database and fires traversal payloads at a target URL
parameter, walking every database entry to find readable files.

The URL must contain the marker string (default FUZZ) at the injection point:

  exhumed scan --url "http://target.local/?file=FUZZ"

The database is loaded from --db (default: database/).
Use --db database/_raw to scan against the unfiltered raw corpus.

Hit-confirmation using the confirm block is Packet 03 — this packet prints
raw HTTP responses and notes "(confirmation: Packet 03)".`,
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
	// --db is resolved relative to the process working directory.
	cmd.Flags().StringVar(&f.dbPath, "db", "database", "path to database root (default: database/ in working directory)")

	_ = cmd.MarkFlagRequired("url")

	return cmd
}

func runScan(f scanFlags) error {
	// Fast-fail if the marker is not present in the URL or request body.
	if !strings.Contains(f.url, f.marker) && !strings.Contains(f.data, f.marker) {
		return fmt.Errorf("marker %q not found in --url or --data; add it at the injection point", f.marker)
	}

	// Load the database. LoadCurated excludes _raw/ for default scans;
	// passing --db database/_raw loads raw corpus directly.
	var database *db.Database
	var err error

	if strings.HasSuffix(strings.TrimRight(f.dbPath, "/\\"), "_raw") {
		database, err = db.LoadDir(f.dbPath)
	} else {
		database, err = db.LoadCurated(f.dbPath)
	}
	if err != nil {
		return fmt.Errorf("load database %q: %w", f.dbPath, err)
	}

	entries := database.AllEntries()
	if len(entries) == 0 {
		fmt.Fprintf(os.Stderr, "info: database at %q is empty — add curated entries (Packet 02b) or use --db database/_raw for the raw corpus\n", f.dbPath)
		return nil
	}

	if f.verbose {
		fmt.Fprintf(os.Stderr, "[*] Loaded %d entries from %q\n", len(entries), f.dbPath)
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

	// Report injection surfaces.
	surfaces := inject.FindSurfaces(tmpl, f.marker)
	if len(surfaces) == 0 {
		return fmt.Errorf("marker %q not found in any injection surface of the request", f.marker)
	}
	if f.verbose {
		fmt.Fprintf(os.Stderr, "[*] Injection surfaces: %v\n", surfaces)
	}

	eng := engine.New(engine.Config{
		Concurrency: f.concurrency,
		RatePerSec:  f.rate,
		Timeout:     f.timeout,
		ProxyURL:    f.proxy,
		Insecure:    f.insecure,
	})

	ctx := context.Background()
	total := 0

	// Walk every database entry; for each, generate traversal payloads and fire.
	for _, entry := range entries {
		payloads := traversal.Generate(entry.Entry.Path, f.traversalDepth)

		reqs := make([]engine.Request, len(payloads))
		for i, p := range payloads {
			reqs[i] = inject.Substitute(tmpl, f.marker, p.Value)
		}

		results := eng.Run(ctx, reqs)

		for i, r := range results {
			total++
			if r.Err != nil {
				if f.verbose {
					fmt.Fprintf(os.Stderr, "[!] %s — %v\n", r.URL, r.Err)
				}
				continue
			}
			tech := payloads[i].Technique
			fmt.Printf("[%d] entry=%s technique=%s status=%d bytes=%d elapsed=%s (confirmation: Packet 03)\n",
				total, entry.Entry.ID, tech, r.StatusCode, len(r.Body), r.Elapsed.Round(time.Millisecond))
			if f.verbose && len(r.Body) > 0 {
				preview := string(r.Body)
				if len(preview) > 256 {
					preview = preview[:256] + "…"
				}
				fmt.Printf("    url: %s\n    %s\n", r.URL,
					strings.ReplaceAll(preview, "\n", "\n    "))
			}
		}
	}

	return nil
}
