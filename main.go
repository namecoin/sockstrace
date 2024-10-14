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
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	go_log "log"
	"math"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/hlandau/dexlogconfig"
	"github.com/hlandau/xlog"
	"github.com/oraoto/go-pidfd"
	"github.com/robertmin1/heteronculous-horklump/httpproxy"
	"github.com/robertmin1/socks5/v4"
	"github.com/u-root/u-root/pkg/strace"
	"golang.org/x/sys/unix"
	"gopkg.in/hlandau/easyconfig.v1"
	seccomp "github.com/elastic/go-seccomp-bpf"
)

var (
	log, _            = xlog.New("horklump")
	UDPProtolNum byte = 0x11
	nullByte          = "\x00"
)

var authData []struct {
	username string
	password string
}

var exitAddr sync.Map

// Config is a struct to store the program's configuration values.
type Config struct { //nolint
	Program           string   `usage:"Program Name"`
	SocksTCP          string   `default:"127.0.0.1:9050"`
	Args              []string `usage:"Program Arguments"`
	KillProg          bool     `default:"false" usage:"Kill the Program in case of a Proxy Leak (bool)"`
	LogLeaks          bool     `default:"false" usage:"Allow Proxy Leaks but Log any that Occur (bool)"`
	EnvVar            bool     `default:"true" usage:"Use the Environment Vars TOR_SOCKS_HOST and TOR_SOCKS_PORT (bool)"`
	Redirect          string   `default:"socks5" usage:"Incase of leak redirect to the desired proxy(socks5,http,trans)"`
	Proxyuser         string   `default:"" usage:"Proxy username in case of proxy redirection"`
	Proxypass         string   `default:"" usage:"Proxy password in case of proxy redirection"`
	OneCircuit        bool     `default:"false" usage:"Disable random SOCKS behavior"`
	WhitelistLoopback bool     `default:"false" usage:"Whitelist outgoing IP connections to loopback addresses (e.g. 127.0.0.1)"` //nolint:lll
}

// FullAddress is the network address and port
type FullAddress struct {
	// Addr is the network address.
	Addr string

	// IP is the network address as an IP.
	//
	// This may not be used by all endpoint types.
	IP net.IP

	// Family is the address family.
	Family uint16

	// Port is the transport port.
	//
	// This may not be used by all endpoint types.
	Port uint16
}

func main() {
	// Create a Config and initialize it with default values.
	cfg := Config{}
	config := easyconfig.Configurator{
		ProgramName: "horklump",
	}

	config.ParseFatal(&cfg)
	dexlogconfig.Init()
	// initialize authData
	initializeAuthData()
	// Create a new command struct for the specific program and arguments
	program := exec.Command(cfg.Program, cfg.Args...)
	program.Stdin, program.Stdout, program.Stderr = os.Stdin, os.Stdout, os.Stderr

	if cfg.EnvVar {
		cfg.SocksTCP = SetEnv(cfg)
	}

	if cfg.Proxyuser == "" || cfg.Proxypass == "" {
		username, err := GenerateRandomCredentials()
		if err != nil {
			panic(err)
		}

		password, err := GenerateRandomCredentials()
		if err != nil {
			panic(err)
		}

		cfg.Proxyuser = username
		cfg.Proxypass = password
	}

	err := applySeccompFilter()
	if err != nil {
		fmt.Printf("Error applying seccomp filter: %v\n", err)
		return
	}

	// Start the program with tracing and handle the CONNECT system call events.
	if err := strace.Trace(program, func(t strace.Task, record *strace.TraceRecord) error {
		if record.Event == strace.SyscallEnter && record.Syscall.Sysno == unix.SYS_CONNECT {
			if err := HandleConnect(t, record, program, cfg); err != nil {
				return err
			}
		} else if record.Event == strace.SyscallExit && record.Syscall.Sysno == unix.SYS_CONNECT {
			_, ok := exitAddr.Load(record.PID)
			if ok {
				if err := Socksify(record.Syscall.Args, record, t, cfg); err != nil {
					return err
				}
			}
		}

		return nil
	}); err != nil {
		panic(err)
	}
}

func IsIPAddressAllowed(address FullAddress, cfg Config) bool {
	if cfg.SocksTCP == address.String() {
		return true
	}

	if cfg.WhitelistLoopback && address.IP.IsLoopback() {
		return true
	}

	return false
}

func IsAddressAllowed(address FullAddress, cfg Config) bool {
	switch address.Family {
	case unix.AF_UNIX:
		return true
	case unix.AF_INET:
		return IsIPAddressAllowed(address, cfg)
	case unix.AF_INET6:
		return IsIPAddressAllowed(address, cfg)
	default:
		return false
	}
}

func HandleConnect(task strace.Task, record *strace.TraceRecord, program *exec.Cmd, cfg Config) error {
	// Parse the IP and Port.
	address, err := ParseAddress(task, record.Syscall.Args)
	if err != nil {
		return fmt.Errorf("failed to parse address: %w", err)
	}

	IPPort := address.String()
	if IsAddressAllowed(address, cfg) { //nolint
		log.Infof("Connecting to %v", IPPort)
	} else {
		// Dump Stack Trace and Process Information
		if err := DumpStackTrace(record.PID); err != nil {
			return err
		}

		if cfg.LogLeaks {
			log.Warnf("Proxy Leak detected, but allowed : %v", IPPort)

			return nil
		}
		if cfg.KillProg {
			KillApp(program, IPPort)

			return nil
		}
		if cfg.Redirect != "" {
			exitAddr.Store(record.PID, IPPort)
			log.Infof("Redirecting connections from %v to %v", IPPort, cfg.SocksTCP)
			err := RedirectConns(record.Syscall.Args, cfg, record)
			if err != nil {
				return fmt.Errorf("failed to redirect connections: %w", err)
			}

			return nil
			// TODO: handle invalid flag
			// Incase trans proxy will require a different implementation a switch will be used.
		}

		err := BlockSyscall(record.PID, IPPort)
		if err != nil {
			return fmt.Errorf("failed to block syscall for PID %d and IPPort %s: %w", record.PID, IPPort, err)
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

// ParseAddress reads an sockaddr struct from the given address and converts it
// to the FullAddress format. It supports AF_UNIX, AF_INET and AF_INET6
// addresses
func ParseAddress(t strace.Task, args strace.SyscallArguments) (FullAddress, error) { //nolint
	addr := args[1].Pointer()
	addrlen := args[2].Uint()

	socketaddr, err := strace.CaptureAddress(t, addr, addrlen)
	if err != nil {
		return FullAddress{}, fmt.Errorf("failed to parse socket address: %w", err)
	}

	famBuf := bytes.NewBuffer(socketaddr[:2])

	var fam uint16
	if err := binary.Read(famBuf, binary.NativeEndian, &fam); err != nil {
		return FullAddress{}, fmt.Errorf("error while reading binary data: %w", err)
	}

	// Get the rest of the fields based on the address family.
	switch fam {
	case unix.AF_UNIX:
		path := socketaddr[2:]
		if len(path) > unix.PathMax {
			return FullAddress{}, unix.EINVAL
		}
		// Drop the terminating NUL (if one exists) and everything after
		// it for filesystem (non-abstract) addresses.
		if len(path) > 0 && path[0] != 0 {
			if n := bytes.IndexByte(path[1:], 0); n >= 0 {
				path = path[:n+1]
			}
		}

		return FullAddress{
			Family: fam,
			Addr:   string(path),
		}, nil

	case unix.AF_INET:
		var inet4Addr unix.RawSockaddrInet4

		famBuf = bytes.NewBuffer(socketaddr)
		if err := binary.Read(famBuf, binary.BigEndian, &inet4Addr); err != nil {
			return FullAddress{}, unix.EFAULT
		}

		ip := net.IP(inet4Addr.Addr[:])
		out := FullAddress{
			Family: fam,
			Addr:   ip.String(),
			IP:     ip,
			Port:   inet4Addr.Port,
		}

		if out.Addr == "\x00\x00\x00\x00" {
			out.Addr = ""
		}

		return out, nil

	case unix.AF_INET6:
		var inet6Addr unix.RawSockaddrInet6

		famBuf = bytes.NewBuffer(socketaddr)
		if err := binary.Read(famBuf, binary.BigEndian, &inet6Addr); err != nil {
			return FullAddress{}, unix.EFAULT
		}

		ip := net.IP(inet6Addr.Addr[:])
		out := FullAddress{
			Family: fam,
			Addr:   ip.String(),
			IP:     ip,
			Port:   inet6Addr.Port,
		}

		// if isLinkLocal(out.Addr) {
		//			out.NIC = NICID(a.Scope_id)
		//}

		if out.Addr == strings.Repeat(nullByte, 16) {
			out.Addr = ""
		}

		return out, nil

	default:
		return FullAddress{
			Family: fam,
		}, nil
	}
}

// Kill the application in case of a proxy leak.
func KillApp(program *exec.Cmd, iPPort string) {
	err := program.Process.Signal(syscall.SIGKILL)
	if err != nil {
		log.Errorf("Failed to kill the application: %v", err)
		panic(err)
	}

	log.Warnf("Proxy Leak Detected : %v. Killing the Application.", iPPort)
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
		return fmt.Errorf("error while tracing syscall for process with PID %d: %w", pid, err)
	}

	if err := unix.Waitid(unix.P_PID, pid, nil, unix.WEXITED, nil); err != nil {
		return fmt.Errorf("error while waiting for process with PID %d: %w", pid, err)
	}

	// Struct to store the current register values from unix.PtraceGetRegs
	regs := &unix.PtraceRegs{}
	if err := unix.PtraceGetRegs(pid, regs); err != nil {
		return fmt.Errorf("error while getting register values from process with PID %d: %w", pid, err)
	}

	// Set to invalid syscall and set the new register values
	regs.Rax = math.MaxUint64
	if err := unix.PtraceSetRegs(pid, regs); err != nil {
		return fmt.Errorf("error while setting register values for process with PID %d: %w", pid, err)
	}

	if err := syscall.PtraceSyscall(pid, 0); err != nil {
		return fmt.Errorf("error while tracing syscall for process with PID %d: %w", pid, err)
	}

	if err := unix.Waitid(unix.P_PID, pid, nil, unix.WEXITED, nil); err != nil {
		return fmt.Errorf("error while waiting for process with PID %d: %w", pid, err)
	}

	log.Warnf("Blocking -> %v", ipport)

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

		defer C.free(unsafe.Pointer(ip)) //nolint

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
		log.Error("Support for UDP will be implemented")
	default:
		return errors.New("invalid ip address")
	}

	// Poking our proxy IP/Port to the address containing the original address
	if _, err := unix.PtracePokeData(record.PID, uintptr(addr), pokeData); err != nil {
		return fmt.Errorf("error poking data into process with PID %d: %w", record.PID, err)
	}

	log.Infof("Connecting to %v", cfg.SocksTCP)

	return nil
}

func Socksify(args strace.SyscallArguments, record *strace.TraceRecord, t strace.Task, cfg Config) error {
	username, password := cfg.Proxyuser, cfg.Proxypass

	if !cfg.OneCircuit {
		idxBytes := make([]byte, 1) // generate random index
		if _, err := rand.Read(idxBytes); err != nil {
			panic(err)
		}

		idx := int(idxBytes[0]) % len(authData) // get random auth data
		username = authData[idx].username
		password = authData[idx].password
	}

	addr, _ := exitAddr.LoadAndDelete(record.PID)
	IPPort := fmt.Sprintf("%v", addr)
	fd := record.Syscall.Args[0].Uint()

	p, err := pidfd.Open(record.PID, 0)
	if err != nil {
		return fmt.Errorf("error opening PID file descriptor: %w", err)
	}

	listenfd, err := p.GetFd(int(fd), 0)
	if err != nil {
		return fmt.Errorf("error getting listen file descriptor: %w", err)
	}

	file := os.NewFile(uintptr(listenfd), "")

	conn, err := net.FileConn(file)
	if err != nil {
		return fmt.Errorf("error creating connection from file: %w", err)
	}

	switch cfg.Redirect {
	case "socks5":
		cl, err := socks5.NewClient(IPPort, username, password, 10, 10)
		if err != nil {
			return err
		}

		_, err = cl.Dial("tcp", IPPort, conn)
		if err != nil {
			return fmt.Errorf("an error occurred while running dial : %w", err)
		}

	case "http":
		cl, err := httpproxy.NewClient(cfg.SocksTCP, username, password)
		if err != nil {
			return err
		}

		_, err = cl.Dial("tcp", IPPort, conn)
		if err != nil {
			return err
		}
	}

	return nil // Support more proxies
}

func DumpStackTrace(pid int) error {
	// Create or open the log file in append mode
	logFile, err := os.OpenFile("stack_trace.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644) //nolint
	if err != nil {
		return err
	}

	defer logFile.Close()
	// Set the log output to the log file
	go_log.SetOutput(logFile)

	commPath := fmt.Sprintf("/proc/%d/cmdline", pid)

	commBytes, err := os.ReadFile(commPath)
	if err != nil {
		return err
	}
	// Split the contents by null byte to separate command and arguments
	cmdline := strings.Split(string(commBytes), "\x00")

	// Add a separator with date and time for the new instance of the program
	separator := fmt.Sprintf("----------- New Instance: %s ------------", time.Now().Format("2006-01-02 15:04:05"))
	go_log.Println(separator)

	// Add the PID and Process Name and Args.
	go_log.Printf("PID :%v", pid)
	go_log.Printf("Program and Arguments:%v\n", cmdline)

	// Get the stack trace
	stack := make([]byte, 8192)
	length := runtime.Stack(stack, true)

	// Write the stack trace to the log file
	go_log.Println(string(stack[:length]))

	return nil
}

func (i FullAddress) String() string {
	switch {
	case i.IP == nil:
		return i.Addr
	case i.IP.To4() != nil:
		return fmt.Sprintf("%s:%d", i.Addr, i.Port)
	case i.IP.To16() != nil:
		return fmt.Sprintf("[%s]:%d", i.Addr, i.Port)
	default:
		return i.Addr
	}
}

func GenerateRandomCredentials() (string, error) {
	bytes := make([]byte, 48)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}

	return hex.EncodeToString(bytes), nil
}

func initializeAuthData() {
	for i := 0; i < 10; i++ {
		username, _ := GenerateRandomCredentials()
		password, _ := GenerateRandomCredentials()
		authData = append(authData, struct {
			username string
			password string
		}{username, password})
	}
}

func applySeccompFilter() error{
	// Create a filter.
	filter := seccomp.Filter{
		NoNewPrivs: true,
		Flag:       seccomp.FilterFlagTSync,
		Policy: seccomp.Policy{
			DefaultAction: seccomp.ActionAllow,
			Syscalls: []seccomp.SyscallGroup{
				{
					Action: seccomp.ActionErrno,
					// Torsocks syscall whitelist https://gitlab.torproject.org/tpo/core/torsocks/-/blob/main/src/lib/syscall.c?ref_type=heads#L486
					Names: []string{
						"socket",            // Create an endpoint for communication (network socket)
						"connect",           // Initiate a connection on a socket
						"close",             // Close a file descriptor, socket, or resource
						"mmap",              // Map files or devices into memory
						"munmap",            // Unmap previously mapped memory
						"accept",            // Accept a connection on a socket
						"getpeername",       // Retrieve the address of the peer connected to a socket
						"listen",            // Listen for connections on a socket
						"recvmsg",           // Receive messages from a socket
						"gettid",            // Get the thread ID of the calling thread
						"getrandom",         // Generate random numbers from the kernel's entropy pool
						"futex",             // Fast user-space locking (for thread synchronization)
						"accept4",           // Accept a connection on a socket with flags (non-blocking, etc.)
						"epoll_create1",     // Create an epoll instance (used for scalable I/O event notification)
						"epoll_wait",        // Wait for I/O events on an epoll instance
						"epoll_pwait",       // Similar to epoll_wait but allows signal mask modification
						"epoll_ctl",         // Control interface for epoll, used to add/remove/watch file descriptors
						"eventfd2",          // Create a file descriptor for event notifications
						"inotify_init1",     // Initialize inotify (used to monitor filesystem changes)
						"inotify_add_watch", // Add a watch for filesystem events (e.g., file changes)
						"inotify_rm_watch",  // Remove a watch from inotify
						"sched_getaffinity", // Get the CPU affinity mask for a thread (which CPUs the thread can run on)
						"seccomp",           // Load or manipulate a seccomp filter (for syscall restriction)
						"gettimeofday",      // Get the current time
						"clock_gettime",     // Retrieve the time of the specified clock (e.g., system uptime)
						"fork",              // Create a new process by duplicating the calling process
						"memfd_create",      // Create an anonymous file in memory (used for file-backed memory regions)
						"getdents",          // Read directory entries from a file descriptor
						"getdents64",        // Read directory entries (64-bit version, used on 64-bit systems)
					},
				},
			},
		},
	}

	// Load it. This will set no_new_privs before loading.
	if err := seccomp.LoadFilter(filter); err != nil {
		fmt.Println("failed to load filter: ", err)
		return err
	}
	fmt.Println("Seccomp filter applied successfully")
	
	return nil
}