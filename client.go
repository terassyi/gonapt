package main

import (
	"encoding/json"
	"net"
)

func request(req *Request) (*Response, error) {
	conn, err := net.Dial(protocol, addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	reqByte, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	if _, err := conn.Write(reqByte); err != nil {
		return nil, err
	}
	repByte := make([]byte, 1024 * 10)
	l, err := conn.Read(repByte)
	if err != nil {
		return nil, err
	}
	rep := &Response{}
	if err := json.Unmarshal(repByte[:l], rep); err != nil {
		return nil, err
	}
	return rep, nil
}
