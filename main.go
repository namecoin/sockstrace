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

/*
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
*/
import "C"

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"github.com/hlandau/dexlogconfig"
	"github.com/hlandau/xlog"
	"github.com/oraoto/go-pidfd"
	"github.com/u-root/u-root/pkg/strace"
	"golang.org/x/sys/unix"
	"gopkg.in/hlandau/easyconfig.v1"
)

var (
	log, _            = xlog.New("horklump")
	UDPProtolNum byte = 0x11
)

type Address struct {
	ip   net.IP
	port int
}

// Config is a struct to store the program's configuration values.
type Config struct {
	Program  string   `usage:"Program Name"`
	SocksTCP string   `default:"127.0.0.1:9050"`
	Args     []string `usage:"Program Arguments"`
	KillProg bool     `default:"false" usage:"Kill the Program in case of a Proxy Leak (bool)"`
	LogLeaks bool     `default:"false" usage:"Allow Proxy Leaks but Log any that Occur (bool)"`
	EnvVar   bool     `default:"true" usage:"Use the Environment Vars TOR_SOCKS_HOST and TOR_SOCKS_PORT (bool)"`
	Redirect bool     `default:"false" usage:"Incase of leak redirect to the desired proxy (bool)"`
	Proxyusr string   `default:"" usage:"Proxy username in case of proxy redirection"`
	Proxypas string   `default:"" usage:"Proxy password in case of proxy redirection"`
}

func main() {
	// Create a Config and initialize it with default values.
	cfg := Config{}
	config := easyconfig.Configurator{
		ProgramName: "horklump",
	}

	config.ParseFatal(&cfg)
	dexlogconfig.Init()
	// Create a new command struct for the specific program and arguments
	program := exec.Command(cfg.Program, cfg.Args...)
	program.Stdin, program.Stdout, program.Stderr = os.Stdin, os.Stdout, os.Stderr

	if cfg.EnvVar {
		cfg.SocksTCP = SetEnv(cfg)
	}

	// Start the program with tracing and handle the CONNECT system call events.
	if err := strace.Trace(program, func(t strace.Task, record *strace.TraceRecord) error {
		if record.Event == strace.SyscallEnter && record.Syscall.Sysno == unix.SYS_CONNECT {
			if err := HandleConnect(t, record, program, cfg); err != nil {
				return err
			}
		} else if record.Event == strace.SyscallExit && record.Syscall.Sysno == unix.SYS_CONNECT {
			if cfg.Redirect {
				if err := Socksify(record.Syscall.Args, record, t); err != nil {
					return err
				}
			}
		}
		return nil
	}); err != nil {
		panic(err)
	}
}

func HandleConnect(task strace.Task, record *strace.TraceRecord, program *exec.Cmd, cfg Config) error {
	var IPPort string

	data := strace.SysCallEnter(task, record.Syscall)

	addrstruct, path, err := GetIPAndPortdata(data, task, record.Syscall.Args)
	if err != nil {
		return err
	}

	if addrstruct.ip == nil {
		IPPort = path
	} else {
		IPPort = addrstruct.String()
	}

	switch {
	case IPPort == cfg.SocksTCP:
		fmt.Printf("Connecting to %v\n", IPPort) //nolint
	case cfg.LogLeaks:
		log.Warnf("Proxy Leak detected, but allowed : %v", IPPort)
		return nil
	case cfg.KillProg:
		KillApp(program, IPPort)
		return nil
	case cfg.Redirect:
		err := RedirectConns(record.Syscall.Args, cfg, record)
		return err
	default:
		err := BlockSyscall(record.PID, IPPort)
		if err != nil {
			return err
		}
	}

	return nil
}

// eventName returns an event name. There should never be an event name
// we do not known and, if we encounter one, we panic.
func eventName(r *strace.TraceRecord) (string, error) { //nolint
	// form up a reasonable name for a system call.
	// If there is no name, then it will be Exxxx or Xxxxx, where x
	// is the system call number as %04x.
	// Note that users can specify this: E0x0000, for example
	var sysName string

	switch r.Event {
	case strace.SyscallEnter, strace.SyscallExit:
		var err error
		if sysName, err = strace.ByNumber(uintptr(r.Syscall.Sysno)); err != nil {
			sysName = fmt.Sprintf("%04x", r.Syscall.Sysno)
		}
	}

	switch r.Event {
	case strace.SyscallEnter:
		return sysName, nil
	case strace.SyscallExit:
		return sysName, nil
	case strace.SignalExit:
		return fmt.Sprintf("SignalExit"), nil
	case strace.Exit:
		return fmt.Sprintf("Exit"), nil
	case strace.SignalStop:
		return fmt.Sprintf("SignalStop"), nil
	case strace.NewChild:
		return fmt.Sprintf("NewChild"), nil
	}

	return "", fmt.Errorf("unknown event %#x from record %v", r.Event, r)
}

func GetIPAndPortdata(data string, t strace.Task, args strace.SyscallArguments) (Address, string, error) {
	if len(data) == 0 {
		return Address{}, "", nil
	}
	//  For the time being, the string slicing method is being used to extract the Address.
	var ip string

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
		return Address{}, "", err
	}

	fulladdr, err := strace.GetAddress(t, socketaddr)
	if err != nil {
		return Address{}, "", err
	}

	P := fulladdr.Port

	switch {
	case net.ParseIP(ip) == nil:
		return Address{}, ip, nil
	default:
		return Address{ip: net.ParseIP(ip), port: int(P)}, "", nil
	}
}

// Kill the application in case of a proxy leak.
func KillApp(program *exec.Cmd, iPPort string) {
	err := program.Process.Signal(syscall.SIGKILL)
	if err != nil {
		fmt.Println("Failed to kill the application: %v\n", err) //nolint
		panic(err)
	}
	fmt.Printf("Proxy Leak Detected : %v. Killing the Application.\n", iPPort) //nolint
}

// Setting environment variables.
func SetEnv(cfg Config) string {
	host, port := os.Getenv("TOR_SOCKS_HOST"), os.Getenv("TOR_SOCKS_PORT")
	TCPhost, TCPport, _ := net.SplitHostPort(cfg.SocksTCP)

	// Handling some edge cases, incase only one Environment variable is provided.
	switch {
	case (host == "" && port != ""):
		return TCPhost + ":" + port
	case (host != "" && port == ""):
		return host + ":" + TCPport
	case (host != "" && port != ""):
		return host + ":" + port
	default:
		return cfg.SocksTCP
	}
}

// Blocking a syscall by changing the syscall number, converting it to a syscall that doesn't exist.
func BlockSyscall(pid int, ipport string) error {
	// Trace the syscall
	if err := syscall.PtraceSyscall(pid, 0); err != nil {
		return err
	}

	if err := unix.Waitid(unix.P_PID, pid, nil, unix.WEXITED, nil); err != nil {
		return err
	}

	// Struct to store the current register values from unix.PtraceGetRegs.
	regs := &unix.PtraceRegs{}
	if err := unix.PtraceGetRegs(pid, regs); err != nil {
		return err
	}

	// Set to invalid syscall and set the new register values
	regs.Rax = math.MaxUint64
	if err := unix.PtraceSetRegs(pid, regs); err != nil {
		return err
	}

	if err := syscall.PtraceSyscall(pid, 0); err != nil {
		return err
	}

	if err := unix.Waitid(unix.P_PID, pid, nil, unix.WEXITED, nil); err != nil {
		return err
	}

	fmt.Printf("Blocking -> %v\n", ipport) //nolint

	return nil
}

func RedirectConns(args strace.SyscallArguments, cfg Config, record *strace.TraceRecord) error {
	// Extrating the address that holds the IP/Port information
	addr := args[1].Pointer()
	addrlen := args[2].Uint()
	host, port, _ := net.SplitHostPort(cfg.SocksTCP)
	parsedhost := net.ParseIP(host)

	pokeData := make([]byte, addrlen)
	// Support for UDP will be implemented
	// Switch is used to differentiate if the proxy is IPv4/IPv5/UDP/Invalid Proxy
	switch {
	// If ip is not IPv4 address, To4 returns nil
	case parsedhost.To4() != nil:
		var addrStruct C.struct_sockaddr_in
		addrStruct.sin_family = C.AF_INET
		intPort, _ := strconv.Atoi(port)
		addrStruct.sin_port = C.htons(C.in_port_t(intPort))
		ip := C.CString(host)

		defer C.free(unsafe.Pointer(ip))

		addrStruct.sin_addr.s_addr = C.inet_addr(ip)
		pokeData = C.GoBytes(unsafe.Pointer(&addrStruct), C.sizeof_struct_sockaddr_in) //nolint
	// If ip is not IPv6 address, To16 returns nil
	case parsedhost.To16() != nil:
		hostData := parsedhost.To16()

		var addrStruct C.struct_sockaddr_in6
		addrStruct.sin6_family = C.AF_INET6
		intPort, _ := strconv.Atoi(port)
		addrStruct.sin6_port = C.htons(C.in_port_t(intPort))
		C.memcpy(unsafe.Pointer(&addrStruct.sin6_addr), unsafe.Pointer(&hostData[0]), C.size_t(len(hostData))) //nolint

		pokeData = C.GoBytes(unsafe.Pointer(&addrStruct), C.int(unsafe.Sizeof(addrStruct))) //nolint
	case parsedhost.To4()[0] == UDPProtolNum:
		fmt.Println("Support for UDP will be implemented") //nolint
	default:
		return errors.New("invalid ip address")
	}

	// Poking our proxy IP/Port to the address containing the original address
	if _, err := unix.PtracePokeData(record.PID, uintptr(addr), pokeData); err != nil {
		return err
	}

	fmt.Printf("Connecting to %v\n", cfg.SocksTCP) //nolint

	return nil
}

func Socksify(args strace.SyscallArguments, record *strace.TraceRecord, t strace.Task) error {
	fd := record.Syscall.Args[0].Uint()

	p, err := pidfd.Open(record.PID, 0)
	if err != nil {
		return err
	}

	listenfd, err := p.GetFd(int(fd), 0)
	if err != nil {
		return err
	}

	file := os.NewFile(uintptr(listenfd), "")

	conn, err := net.FileConn(file)
	if err != nil {
		return err
	}

	// For Debugging purposes
	fmt.Println(conn) //nolint

	return nil
}

func (i Address) String() string {
	return fmt.Sprintf("%s:%d", i.ip.String(), i.port)
}
