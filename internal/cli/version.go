package cli

import (
	"fmt"

	"github.com/bugsyhewitt/exhumed/internal/feed"
	"github.com/bugsyhewitt/exhumed/internal/version"
	"github.com/spf13/cobra"
)

func newVersionCmd() *cobra.Command {
	var dbInfo bool
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Fprintf(cmd.OutOrStdout(), "exhumed %s (commit: %s, built: %s)\n",
				version.Version, version.Commit, version.Date)
			if dbInfo {
				printDBVersion(cmd)
			}
		},
	}
	cmd.Flags().BoolVar(&dbInfo, "db", false, "Also print the active database version and source")
	return cmd
}

// printDBVersion resolves the database the scan/db commands would load (bundled
// vs. feed cache) and prints its version and source, so the operator can answer
// "am I current?" without running a scan. It performs no network access.
func printDBVersion(cmd *cobra.Command) {
	path, source := ResolveDBPath(defaultDBPath, defaultCacheDir())
	ver := feed.LocalVersion(path)
	if ver == "" {
		ver = "unknown"
	}
	fmt.Fprintf(cmd.OutOrStdout(), "database %s (%s, %s)\n", ver, source, path)
}
