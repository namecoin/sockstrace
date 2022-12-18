// Copyright 2022 Namecoin Developers.

// This file is part of heteronculous-horklump.
//
// heteronculous-horklump is free software: you can redistribute it and/or
// modify it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// heteronculous-horklump is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with heteronculous-horklump.  If not, see
// <https://www.gnu.org/licenses/>.

package main

import (
	"encoding/hex"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"syscall"

	"github.com/u-root/u-root/pkg/strace"
	"golang.org/x/sys/unix"
	"gopkg.in/hlandau/easyconfig.v1"
)

type Config struct {
	Program  string `default:"curl"`
	SocksTcp string `default:"127.0.0.1:9050"`
	Args     string `default:"--proxy,socks5h://localhost:9050,https://google.com"`
}

func main() {
	cfg := Config{}

	config := easyconfig.Configurator{
		ProgramName: "horklump",
	}

	config.ParseFatal(&cfg)
	args := strings.Split(cfg.Args, ",")
	program := exec.Command(cfg.Program, args...)

	// Start the program with tracing.
	if err := strace.Trace(program, func(t strace.Task, record *strace.TraceRecord) error {
		if record.Event == strace.SyscallEnter && record.Syscall.Sysno == unix.SYS_CONNECT {
			data := strace.SysCallEnter(t, record.Syscall)
			// Detect the IP and Port.
			ip, port := GetIPAndPortdata(data, t, record.Syscall.Args)
			IpPort := fmt.Sprintf("%s:%s", ip, port)
			if IpPort ==cfg.SocksTcp || ip == "/var/run/nscd/socket"{
				fmt.Printf("Connecting to %v\n", IpPort)
			}else {
				_ = syscall.PtraceSyscall(record.PID, 0)
				var status unix.WaitStatus
				if _, err := unix.Wait4(record.PID, &status, 0, nil);err != nil {
					panic(err.Error())
				}

				regs := &unix.PtraceRegs{}
				if err := unix.PtraceSyscall(record.PID, regs);err != nil {
					panic(err)
				}
				regs.Orig_rax = 0
				if err := unix.PtraceSetRegs(record.PID, regs); err != nil {
					panic(err)
				}
				_ = syscall.PtraceSyscall(record.PID, 0)

				if _, err := unix.Wait4(record.PID, &status, 0, nil); err != nil {
					panic(err.Error())
				}
				switch (regs.Orig_rax) {
				case 0:
					syscall.Exit(1)
				}

				fmt.Printf("Blocking -> %v\n", IpPort)
			}
		}
		return nil
	}); err != nil {
		panic(err)
	}
}

// SocketSysCalls checks if a syscall is a socket syscall.
func SocketSysCalls(r *strace.TraceRecord) error {
	// Socket call functions from Ubuntu Manuals (https://manpages.ubuntu.com/manpages/bionic/man2/socketcall.2.html)
	socketfunctions := map[string]struct{}{
		"socket": {}, "bind": {}, "connect": {}, "listen": {}, "accept": {}, "getsockname": {},
		"getpeername": {}, "socketpair": {}, "send": {}, "recv": {}, "sendto": {}, "recvfrom": {}, "shutdown": {}, "setsockopt": {},
		"getsockopt": {}, "sendmsg": {}, "recvmsg": {}, "accept4": {}, "recvmmsg": {}, "sendmmsg": {},
	}

	// Get the name of the Socket System Call
	SyscallName, _ := strace.ByNumber(uintptr(r.Syscall.Sysno))
	// Check if it's a Socket System Call
	if _, err := socketfunctions[SyscallName]; !err {
		return nil
	}
	fmt.Printf("Detected a Socket System Call: %v\n", SyscallName) //nolint

	return nil
}

func GetIPAndPortdata(data string, t strace.Task, args strace.SyscallArguments) (ip string, port string) { //nolint
	if len(data) == 0 {
		return
	}
	//  For the time being, the string slicing method is being used to extract the Address.
	s1 := strings.Index(data, "Addr:")
	if s1 != -1 {
		s2 := strings.Index(data[s1:], "}")
		s3 := strings.Index(data[s1:], ",")

		if s2 < s3 {
			ip = data[s1+5 : s1+s2]
		} else {
			ip = data[s1+5 : s1+s3]
		}

		ip = strings.ReplaceAll(ip, `"`, "")
		ip = strings.ReplaceAll(ip, ` `, "")

		if ip[:2] == "0x" {
			ip = ip[2:]
			// Decode the Address
			a, _ := hex.DecodeString(ip)
			ip = fmt.Sprintf("%v.%v.%v.%v", a[0], a[1], a[2], a[3])
		}
	}
	// To extract the Port, we use the functions - CaptureAddress and GetAddress.
	addr := args[1].Pointer()
	addrlen := args[2].Uint()

	socketaddr, err := strace.CaptureAddress(t, addr, addrlen)
	if err != nil {
		return "", ""
	}

	fulladdr, err := strace.GetAddress(t, socketaddr)
	if err != nil {
		return "", ""
	}

	P := fulladdr.Port
	port = strconv.Itoa(int(P))

	return ip, port
}
