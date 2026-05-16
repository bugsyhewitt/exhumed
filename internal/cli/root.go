// Package cli wires the cobra command tree for exhumed.
package cli

import (
	"github.com/spf13/cobra"
)

// rootCmd is the base command that all subcommands attach to.
var rootCmd = &cobra.Command{
	Use:   "exhumed",
	Short: "Modern LFI exploitation CLI",
	Long: `exhumed — Modern LFI exploitation CLI and revival of the abandoned panoptic.

Point it at a vulnerable parameter and it walks a curated database of
high-value file paths to find what's readable and extract content for
follow-on targeting.

LEGAL NOTICE: exhumed is for authorized security testing and bug bounty work
only. Using it against systems you do not have explicit permission to test is
illegal. You are responsible for complying with applicable laws.`,
}

// Execute runs the root command. Called from main.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.AddCommand(newScanCmd())
	rootCmd.AddCommand(newVersionCmd())
	rootCmd.AddCommand(newUpdateCmd())
	rootCmd.AddCommand(newDBCmd())
}
