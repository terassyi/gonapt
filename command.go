package main

import (
	"github.com/spf13/cobra"
)

type Command struct {
	*cobra.Command
}

func NewCommand() *Command {
	return &Command {
		Command: &cobra.Command{
		Use: "gonapt",
		Short: "Go NAPT Router",
		Long: "Go NAPT Router",
		},
	}
}


func (c *Command) Prepare() error {
	c.AddCommand(
		newVersionCmd(),
		newStartCmd().Command,
		newStopCmd().Command,
		newTableCmd().Command,
	)
	return nil
}

func (c *Command) Run() error {
	return c.Execute()
}
