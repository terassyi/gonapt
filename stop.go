package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

type stopCmd struct {
	*cobra.Command
}

func newStopCmd() *stopCmd {
	sc := &stopCmd{}
	c := &cobra.Command{
		Use: "stop",
		Short: "stop napt server",
		Run: func(cmd *cobra.Command, args []string) {
			if !isRunning() {
				fmt.Println("gonapt don't run.")
			}
			rep, err := request(newStopRequest())
			if err != nil {
				fmt.Println(err)
				return
			}
			if rep.Result != "success" {
				fmt.Println("failed to stop: ", rep.Result)
			}
			fmt.Println("success to stop.")
		},
	}
	sc.Command = c
	return sc
}

func newStopRequest() *Request {
	return &Request {
		Command: "stop",
	}
}
