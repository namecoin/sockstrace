package main

import (
	"os/exec"
	"github.com/u-root/u-root/pkg/strace"
	"os"
	"log"
)

func main() {
	c := exec.Command("Testing_application/hello")
	if err := strace.Strace(c, os.Stdout); err != nil {
		log.Printf("strace exited: %v", err)
	}
}
