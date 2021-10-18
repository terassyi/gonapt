package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
)

const (
	protocol string = "unix"
	addr string = "/var/run/gonapt.sock"
)

type Request struct {
	Command string `json:"command"`
	Body interface{} `json:"body,omitempty"`
}

type Response struct {
	Result string `json:"result"`
	Body interface{} `json:"body"`
}

func cleanup() error {
	if _, err := os.Stat(addr); err == nil {
		if err := os.RemoveAll(addr); err != nil {
			return err
		}
	}
	return nil
}

func isRunning() bool {
	if _, err := os.Stat(addr); err == nil {
		return true
	}
	return false
}

func (n *Napt) handleConn(conn net.Conn) (bool, error) {
	defer conn.Close()
	data := make([]byte, 1024)
	l, err := conn.Read(data)
	if err != nil {
		return false, err
	}
	var req = &Request{}
	if err := json.Unmarshal(data[:l], req); err != nil {
		return false, err
	}
	switch req.Command {
	case "table":
		entries, err := n.lookupEntry()
		if err != nil {
			return false, response(conn, Response{ Result: fmt.Sprintln(err) })
		}
		return false, response(conn, Response{ Result: "success", Body: tableResponse{ Entries: entries }})
	case "start":
	case "stop":
		n.quitCh<- true
		if err := response(conn, Response{ Result: "success" }); err != nil {
			return false, err
		}
		return true, nil
	default:
		log.Println("unsupported command ", req.Command)
		return false, nil
	}
	return false, nil
}

func response(conn net.Conn, rep Response) error {
	data, err := json.Marshal(rep)
	if err != nil {
		return err
	}
	if _, err := conn.Write(data); err != nil {
		return err
	}
	return nil
}
