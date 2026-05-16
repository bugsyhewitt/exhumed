package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newUpdateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "update",
		Short: "Update the file database from the remote feed (stub)",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("feed not implemented yet (Packet 05)")
		},
	}
}
