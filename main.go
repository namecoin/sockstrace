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
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	go_log "log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/hlandau/dexlogconfig"              //nolint:depguard // Required for logging configuration
	"github.com/hlandau/xlog"                      //nolint:depguard // Required for logging
	"github.com/oraoto/go-pidfd"                   //nolint:depguard // Required for pidfd operations
	"github.com/robertmin1/socks5/v4"              //nolint:depguard // Required for SOCKS5 proxy operations
	seccomp "github.com/seccomp/libseccomp-golang" //nolint:depguard // Required for seccomp filtering
	"github.com/u-root/u-root/pkg/strace"          //nolint:depguard // Required for system call tracing
	"golang.org/x/sys/unix"
	easyconfig "gopkg.in/hlandau/easyconfig.v1"
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

var ErrUnsupportedProxyType = errors.New("unsupported proxy type")

type HTTPDialer struct {
	Host     string
	Username string
	Password string
}

// Config is a struct to store the program's configuration values.
type Config struct {
	Program           string   `usage:"Program Name"`
	SocksTCP          string   `default:"127.0.0.1:9050"                usage:"SOCKS TCP address"`
	Args              []string `usage:"Program Arguments"`
	KillProg          bool     `default:"false"                         usage:"Kill the Program in case of a Proxy Leak (bool)"`
	LogLeaks          bool     `default:"true"                          usage:"Allow Proxy Leaks but Log any that Occur (bool)"`
	EnvVar            bool     `default:"true"                          usage:"Use the Environment Vars TOR_SOCKS_HOST and TOR_SOCKS_PORT (bool)"`
	Redirect          string   `default:""                              usage:"In case of leak redirect to the desired proxy(socks5,http,trans)"`
	Proxyuser         string   `default:""                              usage:"Proxy username in case of proxy redirection"`
	Proxypass         string   `default:""                              usage:"Proxy password in case of proxy redirection"`
	OneCircuit        bool     `default:"false"                         usage:"Disable random SOCKS behavior"`
	WhitelistLoopback bool     `default:"false"                         usage:"Whitelist outgoing IP connections to loopback addresses (e.g. 127.0.0.1)"`
	// TODO: When using seccomp, redirect has to be empty since we currently only intercept entry syscalls
	Seccomp bool `default:"false"                         usage:"Enable seccomp filtering (bool). Provides a speed bump."`
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

	if cfg.Seccomp {
		if cfg.Redirect != "" {
			// TODO: Find a way to intercept the exit of the connect syscall.
			log.Errorf("\033[31mSeccomp filtering cannot be enabled with Socksification (Redirect flag). Please disable one of them.\033[0m")

			return
		}
		// Setup seccomp filtering.
		if err := setupSeccomp(); err != nil {
			panic(err)
		}

		log.Warnf("\033[33mSeccomp filtering enabled\033[0m")
	}

	// Start the program with tracing and handle the CONNECT system call events.
	if err := strace.New(program, cfg.Seccomp, func(task strace.Task, record *strace.TraceRecord) error {
		// TODO: Seccomp filtering intrecepts entries (Find a good way to track entry and exit)
		if cfg.Seccomp && record.Event == strace.SyscallExit {
			record.Event = strace.SyscallEnter
		}

		if record.Event == strace.SyscallEnter && record.Syscall.Sysno == unix.SYS_CONNECT {
			if err := HandleConnect(task, record, program, cfg); err != nil {
				return err
			}
		} else if record.Event == strace.SyscallExit && record.Syscall.Sysno == unix.SYS_CONNECT {
			_, ok := exitAddr.Load(record.PID)
			if ok {
				if err := Socksify(record, cfg); err != nil {
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
		log.Warnf("Connecting to %v", IPPort)
	} else {
		// Dump Stack Trace and Process Information
		if err := DumpStackTrace(record.PID); err != nil {
			return err
		}

		if cfg.LogLeaks {
			log.Warnf("\033[33mProxy Leak detected, but allowed : %v\033[0m", IPPort)

			return nil
		}

		if cfg.KillProg {
			KillApp(program, IPPort)

			return nil
		}

		if cfg.Redirect != "" {
			exitAddr.Store(record.PID, IPPort)
			log.Warnf("\033[33mRedirecting connections from %v to %v\033[0m", IPPort, cfg.SocksTCP)

			err := RedirectConns(record.Syscall.Args, cfg, record)
			if err != nil {
				return fmt.Errorf("failed to redirect connections: %w", err)
			}

			// TODO: handle invalid flag
			// Incase trans proxy will require a different implementation a switch will be used.
			return nil
		}

		err := BlockSyscall(record.PID, IPPort)
		if err != nil {
			return fmt.Errorf("failed to block syscall for PID %d and IPPort %s: %w", record.PID, IPPort, err)
		}
	}

	return nil
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

		if out.Addr == strings.Repeat(nullByte, net.IPv6len) {
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
func BlockSyscall(pid int, ipAddress string) error {
	// Get the current register values.
	var regs unix.PtraceRegs
	if err := unix.PtraceGetRegs(pid, &regs); err != nil {
		return fmt.Errorf("failed to get registers: %w", err)
	}

	// Set an invalid syscall number.
	regs.Orig_rax = ^uint64(0) // -1, invalid syscall.
	if err := unix.PtraceSetRegs(pid, &regs); err != nil {
		return fmt.Errorf("failed to set registers: %w", err)
	}

	// Continue the process.
	if err := unix.PtraceSyscall(pid, 0); err != nil {
		return fmt.Errorf("failed to resume syscall: %w", err)
	}

	if ipAddress == "" {
		log.Warnf("Blocked syscall for PID %d", pid)
	} else {
		log.Warnf("Blocked syscall for PID %d and IP %s", pid, ipAddress)
	}

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

	log.Warnf("Connecting to %v", cfg.SocksTCP)

	return nil
}

func Socksify(record *strace.TraceRecord, cfg Config) error {
	username, password, err := resolveCredentials(cfg)
	if err != nil {
		return fmt.Errorf("error resolving credentials: %w", err)
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
		return handleSocks5Proxy(IPPort, username, password, conn)
	case "http":
		return handleHTTPProxy(cfg.SocksTCP, IPPort, username, password, conn)
	}

	return fmt.Errorf("%w: %s", ErrUnsupportedProxyType, cfg.Redirect)
}

func resolveCredentials(cfg Config) (string, string, error) {
	username, password := cfg.Proxyuser, cfg.Proxypass
	if username == "" || password == "" {
		var err error

		username, err = GenerateRandomCredentials()
		if err != nil {
			return "", "", fmt.Errorf("failed to generate random username: %w", err)
		}

		password, err = GenerateRandomCredentials()
		if err != nil {
			return "", "", fmt.Errorf("failed to generate random password: %w", err)
		}
	}

	if !cfg.OneCircuit {
		idxBytes := make([]byte, 1)
		if _, err := rand.Read(idxBytes); err != nil {
			return "", "", fmt.Errorf("failed to generate random index: %w", err)
		}

		idx := int(idxBytes[0]) % len(authData)
		username = authData[idx].username
		password = authData[idx].password
	}

	return username, password, nil
}

func handleSocks5Proxy(ipPort, username, password string, conn net.Conn) error {
	const timeout = 10

	cl, err := socks5.NewClient(ipPort, username, password, timeout, timeout)
	if err != nil {
		return fmt.Errorf("failed to create SOCKS5 client: %w", err)
	}

	if _, err = cl.Dial("tcp", ipPort, conn); err != nil {
		return fmt.Errorf("error during SOCKS5 dial: %w", err)
	}

	return nil
}

func handleHTTPProxy(proxyAddr, ipPort, username, password string, conn net.Conn) error {
	cl, err := NewHTTPClient(proxyAddr, username, password)
	if err != nil {
		return fmt.Errorf("failed to create HTTP client: %w", err)
	}

	if _, err = cl.Dial("tcp", ipPort, conn); err != nil {
		return fmt.Errorf("error during HTTP dial: %w", err)
	}

	return nil
}

func DumpStackTrace(pid int) error {
	// Create or open the log file in append mode
	logFile, err := os.OpenFile("stack_trace.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644) //nolint
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
	const stackSize = 8192
	stack := make([]byte, stackSize) // 8192 bytes
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
	const credentialLength = 48
	bytes := make([]byte, credentialLength)

	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}

	return hex.EncodeToString(bytes), nil
}

func initializeAuthData() {
	for range [10]int{} {
		username, _ := GenerateRandomCredentials()
		password, _ := GenerateRandomCredentials()
		authData = append(authData, struct {
			username string
			password string
		}{username, password})
	}
}

func NewHTTPClient(addr, username, password string) (*HTTPDialer, error) {
	httpDialer := &HTTPDialer{
		Host:     addr,
		Username: username,
		Password: password,
	}

	return httpDialer, nil
}

// Dial establishes a connection to the provided address through an HTTP proxy.
// It sends an HTTP CONNECT request to the proxy server and returns the established
// connection if successful. If an error occurs, the connection is closed and the error is returned.
func (h *HTTPDialer) Dial(_, addr string, httpconn net.Conn) (net.Conn, error) {
	conn := httpconn

	reqURL, err := url.Parse("http://" + addr)
	if err != nil {
		conn.Close()

		return nil, fmt.Errorf("failed to parse URL: %w", err)
	}

	req := &http.Request{
		Method: http.MethodConnect,
		URL:    reqURL,
		Host:   addr,
		Header: make(http.Header),
	}

	// Set authentication details.
	req.SetBasicAuth(h.Username, h.Password)

	err = req.Write(conn)
	if err != nil {
		conn.Close()

		return nil, fmt.Errorf("failed to write request: %w", err)
	}

	r := bufio.NewReader(conn)

	resp, err := http.ReadResponse(r, req)
	if err != nil {
		conn.Close()

		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		conn.Close()

		return nil, fmt.Errorf("connect proxy error: %v", strings.SplitN(resp.Status, " ", 2)[1]) //nolint
	}

	return conn, nil
}

func setupSeccomp() error {
	// Create a new filter with a default action to allow all syscalls.
	filter, err := seccomp.NewFilter(seccomp.ActAllow)
	if err != nil {
		return fmt.Errorf("failed to create seccomp filter: %w", err)
	}

	if err := filter.AddRule(unix.SYS_CONNECT, seccomp.ActTrace); err != nil {
		return fmt.Errorf("failed to add connect syscall to seccomp filter: %w", err)
	}

	// Load the filter into the kernel.
	if err := filter.Load(); err != nil {
		return fmt.Errorf("failed to load seccomp filter: %w", err)
	}

	return nil
}
