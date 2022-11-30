package main

import (
	"os/exec"
	"github.com/u-root/u-root/pkg/strace"
	"fmt"
)

func main() {
	if err := strace.Trace(exec.Command("Testing_application/hello"), func(t strace.Task, record *strace.TraceRecord) error {
		switch record.Event {
		case strace.SyscallEnter:
			fmt.Printf("System Call Detected: [PID : %d] System Call Enter Event\n", record.PID)
		case strace.SyscallExit:
			fmt.Printf("System Call Detected: [PID : %d] System Call Exit Event\n", record.PID)
		case strace.SignalExit:
			fmt.Printf("System Call Detected: PID %d exited from signal\n", record.PID)
		case strace.Exit:
			fmt.Printf("System Call Detected: PID %d exited from exit status %d (code = %d)\n", record.PID, record.Exit.WaitStatus, record.Exit.WaitStatus.ExitStatus())
		case strace.SignalStop:
			fmt.Printf("System Call Detected: PID %d got signal\n", record.PID)
		case strace.NewChild:
			fmt.Printf("System Call Detected: PID %d spawned new child %d\n", record.PID, record.NewChild.PID)
		}
		return nil
	}); err != nil {
		panic(err)
	}
}
