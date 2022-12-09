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
	"strings"

	"github.com/u-root/u-root/pkg/strace"
	"golang.org/x/sys/unix"
)

func main() {
	// Start the program with tracing.
	if err := strace.Trace(exec.Command("ping", "google.com"), func(t strace.Task, record *strace.TraceRecord) error {
		if record.Event == strace.SyscallEnter && record.Syscall.Sysno == unix.SYS_CONNECT {
			data := strace.SysCallEnter(t, record.Syscall)
			// Detect the IP and Port.
			ip, port := GetIPAndPortdata(data, t, record.Syscall.Args)
			switch {
			case ip == "":
				fmt.Printf("No Ip Address") //nolint		
			case port == 0:
				fmt.Printf("IP : %v\n", ip) //nolint
			default:
				fmt.Printf("IP : %v Port : %v\n", ip, port) //nolint
			}
			return nil
		}
		return SocketSysCalls(record)
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

func GetIPAndPortdata(data string, t strace.Task, args strace.SyscallArguments) (ip string, port uint16) { //nolint
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
		return "", 0
	}

	fulladdr, err := strace.GetAddress(t, socketaddr)
	if err != nil {
		return "", 0
	}

	port = fulladdr.Port

	return ip, port
}
