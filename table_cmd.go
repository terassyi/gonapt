package main

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/spf13/cobra"
)

type tableCmd struct {
	*cobra.Command
	subCmd string
}

func newTableCmd() *tableCmd {
	tc := &tableCmd{}
	c := &cobra.Command{
		Use: "table",
		Short: "table command",
	}
	c.AddCommand(
		newTableShowCmd().Command,
	)
	tc.Command = c
	return tc

}

type tableShowCmd struct {
	*cobra.Command
}

func newTableShowCmd() *tableShowCmd {
	tsc := &tableShowCmd{}
	c := &cobra.Command{
		Use: "show",
		Short: "show nat table",
		RunE: tsc.run,
	}
	tsc.Command = c
	return tsc
}

func (tsc *tableShowCmd) run(cmd *cobra.Command, args []string) error {
	req := &Request{
		Command: "table",
		Body: tableRequest{ SubCommand: "show"},
	}
	rep, err := request(req)
	if err != nil {
		return err
	}
	if rep.Result != "success" {
		log.Println("failed to table show: ", rep.Result)
		fmt.Println("failed to table show: ", rep.Result)
		return nil
	}
	body, err := marshalBody(rep.Body.(map[string]interface{}))
	if err != nil {
		return err
	}
	body.show()
	return nil
}

func marshalBody(body map[string]interface{}) (*tableResponse, error) {
	bodyByte, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	rep := &tableResponse{}
	if err := json.Unmarshal(bodyByte, rep); err != nil {
		return nil, err
	}
	return rep, nil
}
