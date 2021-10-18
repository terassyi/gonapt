package main

import (

	"github.com/spf13/cobra"
)

type startCmd struct {
	*cobra.Command
	inLink string
	outLink string
	global string
	local string
	timeout int
	tcpTimeout int
}

func newStartCmd() *startCmd {
	sc := &startCmd{}
	c := &cobra.Command {
		Use: "start",
		Short: "start napt router",
		Long: "start napt router",
		RunE: sc.start,
	}
	c.Flags().StringVarP(&sc.inLink, "in", "i", "", "ingress interface")
	c.Flags().StringVarP(&sc.outLink, "out", "o", "", "egress interface")
	c.Flags().StringVarP(&sc.global, "global", "g", "", "global address")
	c.Flags().StringVarP(&sc.local, "local", "l", "", "local address and subnet mask")
	sc.Command = c
	return sc
}

func (s *startCmd) start(cmd *cobra.Command, args []string) error {
	napt, err := newNapt(s.inLink, s.outLink, s.global, s.local)
	if err != nil {
		return err
	}
	if err := napt.Prepare(); err != nil {
		return err
	}
	return napt.RunBackGround()
}
