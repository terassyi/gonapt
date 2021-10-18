package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use: "version",
		Short: "gonapt version",
		Long: "gonapt version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("0.1.0")
		},
	}
}
