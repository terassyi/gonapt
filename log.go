package main

import (
	"log"
	"os"
)


const (
	LOG_FILE string = "/var/log/gonapt"
)

func initLog() error {
	file, err := os.OpenFile(LOG_FILE, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		return err
	}
	log.SetFlags(log.Ldate|log.Ltime)
	log.SetOutput(file)
	return nil
}
