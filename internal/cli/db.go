package cli

import (
	"fmt"
	"os"
	"sort"
	"text/tabwriter"

	"github.com/bugsyhewitt/exhumed/internal/db"
	"github.com/spf13/cobra"
)

func newDBCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "db",
		Short: "Database inspection and validation commands",
	}
	cmd.AddCommand(newDBValidateCmd())
	cmd.AddCommand(newDBStatsCmd())
	return cmd
}

func newDBValidateCmd() *cobra.Command {
	var dbPath string
	var verbose bool

	cmd := &cobra.Command{
		Use:   "validate",
		Short: "Validate the file database for structural and semantic correctness",
		Long: `validate loads the database, runs every validation rule, and reports all
problems found. Exits non-zero if any problem exists.

Validation checks:
  - All required fields present and non-empty
  - id matches [a-z0-9-]+ and is unique within its file
  - os, category, info_goal, privilege values within enum
  - path is absolute for the declared OS
  - confirm.type valid; patterns non-empty; every regex compiles
  - min_traversal >= 0 if present
  - schema_version supported`,
		RunE: func(cmd *cobra.Command, args []string) error {
			resolved := resolvedDBPath(dbPath, verbose, os.Stderr)
			database, err := db.LoadDir(resolved)
			if err != nil {
				return fmt.Errorf("load database %s: %w", resolved, err)
			}

			if len(database.AllEntries()) == 0 {
				fmt.Fprintf(os.Stderr, "info: database at %q is empty — nothing to validate\n", resolved)
				return nil
			}

			errs := db.Validate(database)
			if len(errs) == 0 {
				fmt.Printf("✓ database valid: %d entries, 0 problems\n", len(database.AllEntries()))
				return nil
			}

			fmt.Fprintf(os.Stderr, "✗ %d validation problem(s) found:\n\n", len(errs))
			for _, e := range errs {
				fmt.Fprintf(os.Stderr, "  [%s] entry=%q field=%s: %s\n",
					e.File, e.EntryID, e.Field, e.Message)
			}
			fmt.Fprintln(os.Stderr)
			return fmt.Errorf("%d validation error(s)", len(errs))
		},
	}

	cmd.Flags().StringVar(&dbPath, "db", defaultDBPath, "path to database root directory (defaults to the freshest of the bundled DB and the feed cache)")
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "print the resolved database source")
	return cmd
}

func newDBStatsCmd() *cobra.Command {
	var dbPath string
	var verbose bool

	cmd := &cobra.Command{
		Use:   "stats",
		Short: "Print database statistics (entry counts by group, category, OS, info_goal)",
		RunE: func(cmd *cobra.Command, args []string) error {
			resolved := resolvedDBPath(dbPath, verbose, os.Stderr)
			database, err := db.LoadDir(resolved)
			if err != nil {
				return fmt.Errorf("load database %s: %w", resolved, err)
			}

			stats := database.Stats()
			fmt.Printf("Database: %s\n", resolved)
			fmt.Printf("Total entries: %d\n\n", stats.Total)

			printSortedTable("By group", stats.PerGroup)
			printSortedTable("By category", stats.PerCategory)
			printSortedTable("By OS", stats.PerOS)
			printSortedTable("By info_goal", stats.PerInfoGoal)
			return nil
		},
	}

	cmd.Flags().StringVar(&dbPath, "db", defaultDBPath, "path to database root directory (defaults to the freshest of the bundled DB and the feed cache)")
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "print the resolved database source")
	return cmd
}

func printSortedTable(title string, m map[string]int) {
	if len(m) == 0 {
		fmt.Printf("%s: (none)\n\n", title)
		return
	}

	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	fmt.Printf("%s:\n", title)
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	for _, k := range keys {
		fmt.Fprintf(tw, "  %s\t%d\n", k, m[k])
	}
	tw.Flush()
	fmt.Println()
}
