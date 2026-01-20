package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/providers/posflag"
	"github.com/knadh/koanf/v2"
	"github.com/miekg/dns"
	"github.com/oraoto/go-pidfd"
	"github.com/robertmin1/socks5/v4"
	"github.com/rs/zerolog"
	libseccomp "github.com/seccomp/libseccomp-golang"
	"github.com/spf13/pflag"
	"golang.org/x/sys/unix"
)

// Global variable to store tracee details
var tracee struct {
	Name string
	Args []string
	PID  int
}

// SyscallHandler defines the handler function for a syscall notification.
type SyscallHandler func(fd libseccomp.ScmpFd, req *libseccomp.ScmpNotifReq) (val uint64, errno int32, flags uint32)

var (
	socksTCPv4           string
	socksTCPv6           string
	args                 []string
	killProg             bool
	logLeaks             bool
	redirect             string
	proxyUser            string
	proxyPass            string
	oneCircuit           bool
	whitelistLoopback    bool
	allowNonTCP          bool
	blockIncomingTCP     bool
	allowedAddresses     []string
	allowedTCPOrigin     []string
	enforceSocks5Auth    bool
	enforceSocks5TorAuth bool
	socks5IsolationRegex string
	killAllTracees       bool
	coreDump             bool
	stackTrace           bool
	enforceUnixSocks     bool
	proxydns             bool
)

var (
	proxySockaddr4 unix.Sockaddr // IPv4 proxy sockaddr
	proxySockaddr6 unix.Sockaddr // IPv6 proxy sockaddr
)

var (
	UDPProtolNum byte = 0x11
	nullByte          = "\x00"
)

var authData []struct {
	username string
	password string
}

// SOCKS5State tracks handshake and authentication per FD
type SOCKS5State struct {
	buffer             bytes.Buffer
	authCompleted      bool
	handshakeCompleted bool
	username           string
	password           string
}

// Tracks SOCKS5 state per FD
var socks5States = make(map[int]*SOCKS5State)

// Compiled regex for SOCKS5 isolation (prevents regex compilation on every call)
var compiledSocks5IsolationRegex *regexp.Regexp

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

type HTTPDialer struct {
	Host     string
	Username string
	Password string
}

var logger zerolog.Logger
var allowedAddressesMap = make(map[string]struct{})
var allowedTCPOriginMap = make(map[string]struct{})

const DNSPort = 53

// Global koanf instance and CLI flag set
var (
	K     = koanf.New(".")
	Flags = pflag.NewFlagSet("sockstrace", pflag.ExitOnError)
)

// The whitelist is obtained from:
// https://en.wikibooks.org/wiki/The_Linux_Kernel/Syscalls
// https://filippo.io/linux-syscall-table/
//
// The "connect" syscalls are excluded since we are handling them differently.
// The "gethostname" syscall is in the first link but doesn't seem to be supported.
var whitelist = []string{
	// System
	"syslog", "sysinfo", "sysfs", "_sysctl", "query_module", "get_kernel_syms", "create_module",
	"init_module", "delete_module", "iopl", "ioperm", "acct", "reboot", "swapon", "swapoff",
	"mount", "umount2", "sync", "syncfs", "vhangup", "modify_ldt", "pivot_root", "nfsservctl",
	"quotactl", "membarrier", "rseq", "bpf", "getrandom", "ptrace", "getcpu", "finit_module",
	"personality", "uname", "uselib", "chroot", "mount_setattr", "fanotify_init", "fanotify_mark",
	"perf_event_open", "kexec_load", "kexec_file_load", "setdomainname", "sethostname",

	// Time
	"time", "gettimeofday", "settimeofday", "clock_settime", "clock_gettime", "clock_getres",
	"clock_nanosleep", "timer_create", "timer_settime", "timer_gettime", "timer_getoverrun",
	"timer_delete", "timerfd_create", "timerfd_settime", "timerfd_gettime", "clock_adjtime",
	"adjtimex", "utime", "utimes", "utimensat", "futimesat", "nanosleep", "alarm", "getitimer",
	"setitimer", "times",

	// Processes
	"getpid", "getppid", "gettid", "getpgid", "setpgid", "getpgrp", "setsid", "getsid", "fork",
	"vfork", "clone", "clone3", "execve", "getegid", "execveat", "exit", "exit_group", "wait4",
	"waitid", "getpriority", "setpriority", "getrlimit", "setrlimit", "prlimit64", "getrusage",
	"sched_setparam", "sched_getparam", "sched_setscheduler", "sched_getscheduler", "sched_get_priority_max",
	"sched_get_priority_min", "sched_rr_get_interval", "sched_setaffinity", "sched_getaffinity",
	"sched_yield", "sched_setattr", "sched_getattr", "set_tid_address", "restart_syscall", "kill",
	"pidfd_send_signal", "pidfd_open", "pidfd_getfd", "process_madvise", "process_mrelease", "kcmp",
	"get_thread_area", "getresgid", "setresuid", "unshare", "setregid", "getresuid", "setns", "geteuid",
	"setreuid", "getgroups", "setresgid", "setuid", "set_thread_area", "getuid", "setgid", "getgid",
	"setgroups", "ioprio_set", "ioprio_get",

	// Synchronization
	"futex", "rt_sigaction", "rt_sigprocmask", "rt_sigreturn", "rt_sigpending", "rt_sigtimedwait",
	"rt_sigqueueinfo", "rt_sigsuspend", "rt_tgsigqueueinfo", "sigaltstack", "pause", "tkill", "tgkill",
	"signalfd", "signalfd4", "semget", "semop", "mq_getsetattr", "semctl", "semtimedop", "msgget",
	"msgsnd", "msgrcv", "msgctl", "shmget", "shmat", "shmctl", "shmdt", "mq_timedreceive", "set_robust_list",
	"get_robust_list", "futex_wake", "futex_waitv", "futex_wait", "futex_requeue", "mq_timedsend", "mq_open",
	"mq_notify", "mq_unlink", "eventfd", "eventfd2",

	// Memory
	"mmap", "mprotect", "munmap", "mremap", "msync", "mincore", "madvise", "brk", "mlock",
	"munlock", "mlockall", "munlockall", "mlock2", "remap_file_pages", "memfd_create", "memfd_secret",
	"set_mempolicy_home_node", "pkey_mprotect", "pkey_alloc", "pkey_free", "cachestat", "map_shadow_stack",
	"migrate_pages", "get_mempolicy", "set_mempolicy", "mbind", "move_pages", "userfaultfd",

	// Metadata
	"stat", "fstat", "lstat", "newfstatat", "statx", "getdents", "getdents64", "getcwd", "chdir",
	"fchdir", "rename", "renameat", "renameat2", "mkdir", "mkdirat", "rmdir", "unlink", "unlinkat",
	"symlink", "symlinkat", "readlink", "readlinkat", "chmod", "fchmod", "fchmodat", "chown", "fchown",
	"lchown", "fchownat", "umask", "truncate", "ftruncate", "fallocate", "sync_file_range", "vmsplice",
	"inotify_init1", "faccessat", "openat", "move_mount", "fsopen", "fsconfig", "fsmount",
	"fspick", "inotify_init", "lookup_dcookie", "name_to_handle_at", "open_by_handle_at", "statfs",
	"fstatfs", "ustat", "getxattr", "lgetxattr", "fgetxattr", "listxattr", "llistxattr", "flistxattr",
	"setxattr", "lsetxattr", "fsetxattr", "removexattr", "lremovexattr", "fremovexattr", "inotify_rm_watch",
	"open_tree", "quotactl_fd", "inotify_add_watch",

	// Data
	"read", "write", "pread64", "pwrite64", "readv", "writev", "preadv", "pwritev", "preadv2", "pwritev2",
	"creat", "fsync", "splice", "tee", "process_vm_readv", "process_vm_writev", "fchmodat2", "openat2",
	"faccessat2", "close_range", "copy_file_range", "fcntl", "pipe2", "flock",
	"open", "linkat", "pipe", "access", "mknod", "mknodat", "fadvise64", "readahead", "dup3", "dup", "dup2",
	"fdatasync", "lseek", "link", "close", "ioctl", "sendfile",

	// Network (Excluding connect syscall)
	// Legend:
	// A — Safe to whitelist.
	// B — Temporarily whitelisted because denying it outright would break apps and we haven’t implemented tracer logic.
	// C — Temporarily whitelisted because we haven’t audited whether it can cause proxy leaks.
	// D — Not whitelisted here because we handle it elsewhere (or it’s obsolete / handled by kernel compatibility).
	"socket", // A -> socket() only creates an endpoint and returns a file descriptor — it does not itself send network
	// traffic. Whitelisting it is reasonable if you still intercept the actual connect/send syscalls. See socket(2)
	// and the socket overview (https://man7.org/linux/man-pages/man2/socket.2.html)

	"socketpair", // A -> like socket(), socketpair() creates a pair of connected sockets, but does not send data
	// over the network. (https://man7.org/linux/man-pages/man2/socketpair.2.html)

	"bind", // B -> bind() assigns a local address/port to a socket. Denying bind would break legitimate server and
	// client behavior (such as ephemeral-port selection) (https://man7.org/linux/man-pages/man2/bind.2.html)

	"listen", // B -> listen() marks a socket as a passive socket that will be used to accept incoming connection requests.
	// Denying listen would break legitimate server behavior. (https://man7.org/linux/man-pages/man2/listen.2.html)

	"accept", "accept4", // B -> accept() creates a new connected socket for incoming connections. Denying will break server flows
	// https://man7.org/linux/man-pages/man2/accept.2.html

	"getsockname", // A -> getsockname() retrieves the local address/port of a socket. Safe to whitelist.
	// https://man7.org/linux/man-pages/man2/getsockname.2.html

	"getpeername", // A -> getpeername() retrieves the remote address/port of a connected socket. Safe to whitelist.
	// https://man7.org/linux/man-pages/man2/getpeername.2.html

	"sendto", "recvfrom", "sendmsg", "recvmsg", "sendmmsg", "recvmmsg", // C -> These perform actual data transfer and can cause leaks
	// depending on socket type (e.g. raw sockets). Until all usese are audited
	// (connected vs unconnected sockets, UDP vs TCP, raw/AF_PACKET), mark them as temporarily whitelisted pending audit.

	"shutdown", // A -> shutdown() disables sends and/or receives on a socket. Safe to whitelist.
	// https://man7.org/linux/man-pages/man2/shutdown.2.html

	"setsockopt", "getsockopt", // B -> These change or query socket behavior (timeouts, buffer sizes, socket flags).
	// Denying them can break apps; but they can affect how traffic gets sent
	// (e.g., SO_BINDTODEVICE, SO_MARK, IP_HDRINCL). Temporarily whitelist with a TODO to audit which specific options are risky

	"socketcall", // B -> On 32-bit ABIs (e.g. i386), all socket ops are multiplexed through this syscall. (socket, connect, bind, sendmsg, etc.)
	// Denying it would break networking entirely for 32-bit apps, so it is whitelisted for now.

	// Security
	"capget", "capset", "prctl", "arch_prctl", "seccomp", "landlock_create_ruleset", "landlock_add_rule",
	"keyctl", "landlock_restrict_self", "setfsgid", "request_key", "add_key", "setfsuid",

	// Nonblocking IO
	"poll", "ppoll", "select", "pselect6", "epoll_create", "epoll_create1", "epoll_ctl", "epoll_ctl_old",
	"epoll_wait", "epoll_wait_old", "epoll_pwait", "epoll_pwait2", "io_setup", "io_destroy", "io_getevents",
	"io_submit", "io_cancel", "io_uring_setup", "io_uring_enter", "io_uring_register", "io_pgetevents",

	// unimplemented system calls
	// "afs_syscall", "break", "fattach", "fdetach", "ftime", "getmsg", "getpmsg", "gtty", "isastream", "lock", "madvise1",
	// "mpx", "prof", "profil", "putmsg", "putpmsg", "security", "stty", "tuxcall", "ulimit", "vserver",
}

// Sets up the CLI command structure
func setupCLI() {
	const usage = `
sockstrace is a tool to trace and monitor network connections made by a program,

Usage:
	sockstrace <program> [flags]
	
Examples:
	sockstrace wget
	sockstrace wget --args example.com
	sockstrace wget --args "--directory-prefix=/home" --args="google.com" (Each argument must be passed separately)
	sockstrace wget --args example.com --logleaks (Allow Proxy Leaks and log them)

Sources:
	- CLI flags
	- Environment variables (SOCKSTRACE_*) example: SOCKSTRACE_LOGLEAKS=true, SOCKSTRACE_KILL_PROG=true
	- Config file (YAML) via --config

Note:
	- The first argument must always be the program you want to execute.
	- Use --args to pass extra arguments to the program.

Flags:
`

	Flags.Usage = func() {
		fmt.Fprint(os.Stderr, usage)
		Flags.PrintDefaults()
	}

	Flags.String("socks-tcp", "127.0.0.1:9050", "SOCKS TCP4 address")
	Flags.String("socks-tcp6", "[::1]:9050", "SOCKS TCP6 address (IPv6)")
	Flags.StringSlice("args", []string{}, "Arguments to pass to the program")
	Flags.Bool("kill-prog", false, "Kill program on proxy leak (default: false)")
	Flags.Bool("logleaks", false, "Allow and log proxy leaks (default: false)")
	Flags.String("redirect", "socks5", "Redirect leaked connections (options: socks5, http)")
	Flags.String("proxy-user", "", "Proxy username")
	Flags.String("proxy-pass", "", "Proxy password")
	Flags.Bool("one-circuit", false, "Disable random SOCKS behavior (default: false) If a user provides a username or password, those credentials will be used for all connections.")
	Flags.Bool("whitelist-loopback", false, "Allow loopback connections (default: false)")
	Flags.Bool("allow-non-tcp", true, "Allow non-TCP connections (Tor Proxy only supports TCP) (default: true)")
	Flags.Bool("block-incoming-tcp", false, "Block incoming TCP connections (default: false)")
	Flags.StringSlice("allowed-addresses", []string{}, "List of allowed addresses (--allowed-addrs 127.0.0.1:9150,192.168.1.100:1080)")
	Flags.StringSlice("allowed-tcp-origin", []string{}, "List of allowed TCP origin addresses (--allowed-tcp-origin  127.0.0.1:9150,127.0.0.1:1080)")
	Flags.Bool("enforce-socks5-auth", false, "Enforce SOCKS5 authentication (default: false)")
	Flags.Bool("enforce-socks5-tor-auth", false, "Enforce SOCKS5 authentication (default: false)")
	Flags.String("socks5-isolation-regex", "", "Regex pattern to check against isolation string")
	Flags.Bool("kill-all-tracees", false, "Kill all traced processes (default: false)")
	Flags.Bool("core-dump", false, "Generate core dump in case of proxy leak (default: false)")
	// Note: On Linux with Yama LSM, you may get "ptrace: Operation not permitted" or "Could not attach to process" due to ptrace_scope.
	// Fix: sudo sysctl -w kernel.yama.ptrace_scope=0
	Flags.Bool("stack-trace", false, "Generate stack trace in case of proxy leak. Requires 'gdb' (default: false). On Linux with Yama, may need: sudo sysctl -w kernel.yama.ptrace_scope=0")
	Flags.Bool("proxydns", false, "Enable DNS proxying (default: false)")
	Flags.Bool("enforce-unix-socks", false, "Block all IPv4/IPv6 connections, enforce Unix sockets only")
	Flags.Bool("version", false, "Show version and exit")
	Flags.String("config", "", "Path to optional YAML config file")

	err := Flags.Parse(os.Args[1:])
	if err != nil {
		logger.Fatal().Msgf("Failed to parse flags: %v", err)
	}

	_ = K.Load(posflag.Provider(Flags, ".", K), nil)

	// Load from config file
	if cfg := K.String("config"); cfg != "" {
		err := K.Load(file.Provider(cfg), yaml.Parser())
		if err != nil {
			logger.Fatal().Msgf("Failed to load config file %s: %v", cfg, err)
		}
	}

	// Load from environment variables
	_ = K.Load(env.Provider("SOCKSTRACE_", "", func(s string) string {
		// Remove "SOCKSTRACE_" prefix manually
		s = strings.TrimPrefix(s, "SOCKSTRACE_")

		return strings.ToLower(strings.ReplaceAll(s, "_", "-"))
	}), nil)

	// Re-parse CLI flags again to ensure they override all
	_ = K.Load(posflag.Provider(Flags, ".", K), nil)

	// Show version
	if K.Bool("version") {
		logger.Info().Msg("sockstrace v1.2")
		os.Exit(0)
	}

	// Require target program
	if len(Flags.Args()) < 1 {
		Flags.Usage()
		logger.Fatal().Msg("No target program specified. Please provide a program to execute.")
	}

	bindConfigVars()
	validateCLI()
}

var localDNSAddrUDP *unix.SockaddrInet4
var localDNSAddrTCP *unix.SockaddrInet4

func initSeccomp() chan<- struct{} {
	api, err := libseccomp.GetAPI()
	if err != nil {
		logger.Fatal().Msg("Failed to get seccomp API level")
	} else if api < 5 {
		logger.Fatal().Msgf("need seccomp API level >= 5; it's currently %d", api)
	}

	fd, err := LoadFilter()
	if err != nil {
		logger.Fatal().Msgf("Failed to load seccomp filter: %v", err)
	}

	logger.Info().Msgf("Seccomp filter loaded with notification FD: %v", fd)

	handlers := map[string]SyscallHandler{"connect": HandleConnect, "sendto": HandleSendto, "bind": HandleBind, "listen": HandleListen}

	if proxydns {
		handlers["sendmsg"] = HandleSendmsg
		handlers["sendmmsg"] = HandleSendmsg

		go startDNSServers()
	}

	stop, errChan := Handle(fd, handlers)

	go func() {
		for err := range errChan {
			logger.Fatal().Msgf("Error in syscall monitoring: %v", err)
		}
	}()

	return stop
}

func main() {
	// Initialize logger
	logger = zerolog.New(
		zerolog.ConsoleWriter{
			Out:        os.Stderr,    // Output to stderr
			TimeFormat: time.RFC3339, // Time format
		},
	).Level(zerolog.TraceLevel).With().Timestamp().Caller().Logger()

	setupCLI()

	stop := initSeccomp()
	defer close(stop)

	proxyFullAddr4, err := NewFullAddress(socksTCPv4)
	if err != nil {
		logger.Fatal().Msgf("Failed to parse Proxy IPv4 address: %v", err)
	}

	proxyFullAddr6, err := NewFullAddress(socksTCPv6)
	if err != nil {
		logger.Fatal().Msgf("Failed to parse Proxy IPv6 address: %v", err)
	}

	proxySockaddr4 = netTCPAddrToSockAddr(*proxyFullAddr4)
	proxySockaddr6 = netTCPAddrToSockAddr(*proxyFullAddr6)

	loadAllowedAddresses(allowedAddressesMap, allowedAddresses)
	loadAllowedAddresses(allowedTCPOriginMap, allowedTCPOrigin)

	initializeAuthData()

	runProgram(Flags.Args()[0]) // Handle program execution after flags are processed
}

func runProgram(program string) {
	logger.Info().Msgf("Executing program: %s", program)

	// check if the program exists in the PATH
	checkBinaryInPath(program)
	cmd := exec.Command(program, args...) //nolint:gosec,noctx // # G204: Subprocess launched with variable or user-supplied input (Checked above)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr

	// Start the process
	err := cmd.Start()
	if err != nil {
		logger.Fatal().Msgf("Error starting program: %v", err)
	}

	tracee.Name = program
	tracee.Args = args
	tracee.PID = cmd.Process.Pid

	logger.Info().Msgf("Tracee PID: %d", tracee.PID)

	err = cmd.Wait()
	if err != nil {
		logger.Fatal().Msgf("Error executing program: %v", err)
	}
}

// LoadFilter initializes the seccomp filter, loads rules, and returns a notification FD.
func LoadFilter() (libseccomp.ScmpFd, error) {
	filter, err := libseccomp.NewFilter(libseccomp.ActErrno.SetReturnCode(int16(unix.EPERM)))
	if err != nil {
		return 0, fmt.Errorf("failed to create seccomp filter: %w", err)
	}

	// Define a set of syscalls that we want to block when blockIncomingTCP is true.
	incomingTCPSyscalls := map[string]bool{
		"bind":   true,
		"listen": true,
	}

	// Define a set of syscalls that we want to handle.
	handledSyscalls := map[string]SyscallHandler{
		"connect": HandleConnect,
	}

	// When enforcing Unix sockets, we need to intercept sendto/sendmsg/sendmmsg
	if enforceUnixSocks {
		handledSyscalls["sendto"] = HandleSendto
		handledSyscalls["sendmsg"] = HandleSendmsg
		handledSyscalls["sendmmsg"] = HandleSendmsg

		logger.Info().Msg("Unix socket enforcement enabled - intercepting sendto/sendmsg/sendmmsg")
	}

	if len(allowedTCPOrigin) > 0 {
		handledSyscalls["bind"] = HandleBind
		handledSyscalls["listen"] = HandleListen
		blockIncomingTCP = true // Enable blocking incoming TCP connections to skip whitelisting
	}

	// Allow on whitelist syscalls
	for sc := range whitelist {
		syscallID, err := libseccomp.GetSyscallFromName(whitelist[sc])
		if err != nil {
			return 0, fmt.Errorf("failed to get syscall ID for %s: %w", whitelist[sc], err)
		}

		if proxydns && (whitelist[sc] == "sendmsg" || whitelist[sc] == "sendmmsg") {
			handledSyscalls[whitelist[sc]] = HandleSendmsg

			continue
		}

		// Skip syscalls related to incoming TCP if blockIncomingTCP is true (default is EPERM)
		if blockIncomingTCP && incomingTCPSyscalls[whitelist[sc]] {
			continue
		}

		// Skip syscalls that are already being handled (e.g., sendto when enforceUnixSocks is enabled)
		if _, handled := handledSyscalls[whitelist[sc]]; handled {
			continue
		}

		err = filter.AddRule(syscallID, libseccomp.ActAllow)
		if err != nil {
			return 0, fmt.Errorf("failed to add rule for syscall %s: %w", whitelist[sc], err)
		}
	}

	logger.Info().Msgf("Syscall whitelist applied successfully.")

	// Notify on handled syscalls
	for sc := range handledSyscalls {
		syscallID, err := libseccomp.GetSyscallFromName(sc)
		if err != nil {
			return 0, fmt.Errorf("failed to get syscall ID for %s: %w", sc, err)
		}

		err = filter.AddRule(syscallID, libseccomp.ActNotify)
		if err != nil {
			return 0, fmt.Errorf("failed to add notify rule for syscall %s: %w", sc, err)
		}
	}

	if err := filter.Load(); err != nil {
		return 0, fmt.Errorf("failed to load seccomp filter: %w", err)
	}

	fd, err := filter.GetNotifFd()
	if err != nil {
		return 0, fmt.Errorf("failed to get notification FD: %w", err)
	}

	return fd, nil
}

// Handle starts processing syscall notifications for a given FD and handler map.
func Handle(fd libseccomp.ScmpFd, handlers map[string]SyscallHandler) (chan<- struct{}, <-chan error) {
	stop := make(chan struct{})
	errChan := make(chan error)

	go func() {
		for {
			req, err := libseccomp.NotifReceive(fd)
			if err != nil {
				if errors.Is(err, syscall.ENOENT) {
					logger.Fatal().Msgf("Notification no longer valid: %v", err)

					continue
				}

				logger.Fatal().Msgf("Failed to receive notification: %v", err)

				errChan <- err
				// If the error is ECANCELED, it means the notification was canceled.
				if errors.Is(err, unix.ECANCELED) {
					// The notification was canceled, likely due to the process exiting.
					return
				}

				continue
			}

			select {
			case <-stop:
				_ = libseccomp.NotifRespond(fd, &libseccomp.ScmpNotifResp{
					ID:    req.ID,
					Error: int32(unix.EPERM),
					Val:   0,
					Flags: 0,
				})

				return
			default:
			}

			err = libseccomp.NotifIDValid(fd, req.ID)
			if err != nil {
				logger.Fatal().Msgf("Failed to validate notification ID: %v", err)
			}

			go func(req *libseccomp.ScmpNotifReq) {
				syscallName, _ := req.Data.Syscall.GetName()

				handler, ok := handlers[syscallName]
				if !ok {
					logger.Fatal().Msgf("Unknown syscall: %s (PID: %d)", syscallName, req.Pid)
					_ = libseccomp.NotifRespond(fd, &libseccomp.ScmpNotifResp{
						ID:    req.ID,
						Error: int32(unix.ENOSYS),
						Val:   0,
						Flags: 0,
					})

					return
				}

				val, errno, flags := handler(fd, req)
				if err := libseccomp.NotifRespond(fd, &libseccomp.ScmpNotifResp{
					ID:    req.ID,
					Error: errno,
					Val:   val,
					Flags: flags,
				}); err != nil {
					errChan <- err
				}
			}(req)
		}
	}()

	return stop, errChan
}

// HandleConnect is a syscall handler for connect.
func HandleConnect(seccompNotifFd libseccomp.ScmpFd, req *libseccomp.ScmpNotifReq) (uint64, int32, uint32) {
	err := libseccomp.NotifIDValid(seccompNotifFd, req.ID)
	if err != nil {
		logger.Fatal().Msgf("failed to validate notification ID: %v", err)
	}

	tgid, err := getTgid(req.Pid)
	if err != nil {
		logger.Fatal().Msgf("Error getting tgid: %v", err)
	}

	pfd, err := pidfd.Open(tgid, 0)
	if err != nil {
		logger.Fatal().Msgf("Error opening pidfd %v", err)
	}

	localFd, err := pfd.GetFd(int(req.Data.Args[0]), 0)
	if err != nil {
		logger.Fatal().Msgf("Error getting fd %v", err)
	}

	defer func() {
		if err := unix.Close(localFd); err != nil {
			logger.Warn().Msgf("Error closing localFd: %v", err)
		}
	}()

	// Log the socket protocol for the syscall
	logSocketProtocol(localFd, int(req.Data.Args[0]), int(req.Pid), "connect")

	memFile := fmt.Sprintf("/proc/%d/mem", req.Pid)

	mem, err := os.Open(memFile) //nolint:gosec // G304: safe usage, not user-controlled
	if err != nil {
		logger.Fatal().Msgf("failed to open memory file: %v", err)
	}

	defer func() {
		if err := mem.Close(); err != nil {
			logger.Warn().Msgf("Error closing mem file: %v", err)
		}
	}()
	// Read the syscall arguments
	data := make([]byte, req.Data.Args[2])

	_, err = syscall.Pread(int(mem.Fd()), data, int64(req.Data.Args[1]))
	if err != nil {
		logger.Fatal().Msgf("failed to read memory: %v", err)
	}

	// Parse the address
	addr, err := ParseAddress(data)
	if err != nil {
		logger.Fatal().Msgf("failed to parse address: %v", err)
	}

	sockfd := req.Data.Args[0]
	pid := req.Pid

	return handleIPEvent(localFd, sockfd, pid, addr)
}

func HandleSendto(seccompNotifFd libseccomp.ScmpFd, req *libseccomp.ScmpNotifReq) (uint64, int32, uint32) {
	err := libseccomp.NotifIDValid(seccompNotifFd, req.ID)
	if err != nil {
		logger.Fatal().Msgf("failed to validate notification ID: %v", err)
	}

	tgid, err := getTgid(req.Pid)
	if err != nil {
		logger.Fatal().Msgf("Error getting tgid: %v", err)
	}

	pfd, err := pidfd.Open(tgid, 0)
	if err != nil {
		logger.Fatal().Msgf("Error opening pidfd %v", err)
	}

	localFd, err := pfd.GetFd(int(req.Data.Args[0]), 0)
	if err != nil {
		logger.Fatal().Msgf("Error getting fd %v", err)
	}

	defer func() {
		if err := unix.Close(localFd); err != nil {
			logger.Warn().Msgf("Error closing localFd: %v", err)
		}
	}()

	// Log the socket protocol for the syscall
	logSocketProtocol(localFd, int(req.Data.Args[0]), int(req.Pid), "sendto")

	// Check destination address for SOCKS5 enforcement
	// sendto args: fd, buf, len, flags, dest_addr, addrlen
	destAddrPtr := req.Data.Args[4]
	addrLen := req.Data.Args[5]

	if enforceUnixSocks && destAddrPtr != 0 && addrLen > 0 {
		memFile := fmt.Sprintf("/proc/%d/mem", req.Pid)

		mem, err := os.Open(memFile) //nolint:gosec // G304: safe usage, not user-controlled
		if err != nil {
			logger.Warn().Msgf("Failed to open memory file for sendto enforcement: %v", err)

			return 0, 0, 0 // Block on failure
		}

		addrData := make([]byte, addrLen)
		_, err = syscall.Pread(int(mem.Fd()), addrData, int64(destAddrPtr))
		_ = mem.Close()

		if err == nil {
			addr, parseErr := ParseAddress(addrData)
			if parseErr == nil {
				// Block ALL IPv4/IPv6 destinations
				if addr.Family == unix.AF_INET || addr.Family == unix.AF_INET6 {
					logger.Warn().Msgf("sendto blocked (Unix socket enforcement): %s", addr.String())

					return 0, 0, 0
				}
			}
		}
	}

	fd := int(req.Data.Args[0])
	// Check if the FD is relevant for SOCKS5 processing
	state, exists := socks5States[fd]
	if !exists || state.authCompleted {
		// Skip processing if FD is irrelevant or authentication is done
		return 0, 0, unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE
	}

	memFile := fmt.Sprintf("/proc/%d/mem", req.Pid)

	mem, err := os.Open(memFile) //nolint:gosec // G304: safe usage, not user-controlled
	if err != nil {
		logger.Fatal().Msgf("failed to open memory file: %v", err)
	}

	defer func() {
		if err := mem.Close(); err != nil {
			logger.Warn().Msgf("Error closing mem file: %v", err)
		}
	}()

	// Read the data from the memory at the buffer pointer
	bufferSize := req.Data.Args[2] // Length of data
	bufferAddr := req.Data.Args[1] // Pointer to data

	data := make([]byte, bufferSize)

	_, err = syscall.Pread(int(mem.Fd()), data, int64(bufferAddr))
	if err != nil {
		logger.Fatal().Msgf("failed to read memory: %v", err)
	}

	err = parseSOCKS5Data(fd, data)
	if err != nil {
		logger.Fatal().Msgf("failed to parse SOCKS5 handshake data %v", err)
	}

	return 0, 0, unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE
}

func HandleBind(seccompNotifFd libseccomp.ScmpFd, req *libseccomp.ScmpNotifReq) (uint64, int32, uint32) {
	logger.Info().Msgf("Intercepted 'bind' syscall from PID %d", req.Pid)

	err := libseccomp.NotifIDValid(seccompNotifFd, req.ID)
	if err != nil {
		logger.Fatal().Msgf("failed to validate notification ID: %v", err)
	}

	memFile := fmt.Sprintf("/proc/%d/mem", req.Pid)

	mem, err := os.Open(memFile) //nolint:gosec // G304: safe usage, not user-controlled
	if err != nil {
		logger.Fatal().Msgf("failed to open memory file: %v", err)
	}

	defer func() {
		if err := mem.Close(); err != nil {
			logger.Warn().Msgf("Error closing mem file: %v", err)
		}
	}()
	// Read the syscall arguments
	data := make([]byte, req.Data.Args[2])

	_, err = syscall.Pread(int(mem.Fd()), data, int64(req.Data.Args[1]))
	if err != nil {
		logger.Fatal().Msgf("failed to read memory: %v", err)
	}
	// Parse the address
	addr, err := ParseAddress(data)
	if err != nil {
		logger.Fatal().Msgf("failed to parse address: %v", err)
	}

	if isWhitelistedAddress(allowedTCPOriginMap, addr.String()) {
		logger.Info().Msgf("Allowed bind to %s", addr.String())

		return 0, 0, unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE
	}

	logger.Warn().Msgf("Blocked bind to %s", addr.String())

	return 0, 0, 0
}

func HandleListen(seccompNotifFd libseccomp.ScmpFd, req *libseccomp.ScmpNotifReq) (uint64, int32, uint32) {
	logger.Info().Msgf("Intercepted 'listen' syscall from PID %d", req.Pid)

	err := libseccomp.NotifIDValid(seccompNotifFd, req.ID)
	if err != nil {
		logger.Fatal().Msgf("failed to validate notification ID: %v", err)
	}

	tgid, err := getTgid(req.Pid)
	if err != nil {
		logger.Fatal().Msgf("Error getting tgid: %v", err)
	}

	pfd, err := pidfd.Open(tgid, 0)
	if err != nil {
		logger.Fatal().Msgf("Error opening pidfd %v", err)
	}

	localFd, err := pfd.GetFd(int(req.Data.Args[0]), 0)
	if err != nil {
		logger.Fatal().Msgf("Error getting fd %v", err)
	}

	defer func() {
		if err := unix.Close(localFd); err != nil {
			logger.Warn().Msgf("Error closing localFd: %v", err)
		}
	}()

	addr, _, _, err := getConnectionInfo(localFd, false)
	if err != nil {
		logger.Fatal().Msgf("Error getting connection info: %v", err)
	}

	if isWhitelistedAddress(allowedTCPOriginMap, addr) {
		logger.Info().Msgf("Allowed listen to %s", addr)

		return 0, 0, unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE
	}

	logger.Warn().Msgf("Blocked listen to %s", addr)

	return 0, 0, 0
}

func HandleSendmsg(seccompNotifFd libseccomp.ScmpFd, req *libseccomp.ScmpNotifReq) (uint64, int32, uint32) {
	err := libseccomp.NotifIDValid(seccompNotifFd, req.ID)
	if err != nil {
		logger.Fatal().Msgf("failed to validate notification ID: %v", err)
	}

	tgid, err := getTgid(req.Pid)
	if err != nil {
		logger.Fatal().Msgf("Error getting tgid: %v", err)
	}

	pfd, err := pidfd.Open(tgid, 0)
	if err != nil {
		logger.Fatal().Msgf("Error opening pidfd %v", err)
	}

	// For sendmsg and sendmmsg, the FD is the first argument
	localFd, err := pfd.GetFd(int(req.Data.Args[0]), 0)
	if err != nil {
		logger.Fatal().Msgf("Error getting fd %v", err)
	}

	defer func() {
		if err := unix.Close(localFd); err != nil {
			logger.Warn().Msgf("Error closing localFd: %v", err)
		}
	}()

	syscallName, _ := req.Data.Syscall.GetName()
	// Log the socket protocol for the syscall
	logSocketProtocol(localFd, int(req.Data.Args[0]), int(req.Pid), syscallName)

	memFile := fmt.Sprintf("/proc/%d/mem", req.Pid)

	mem, err := os.OpenFile(memFile, os.O_RDWR, 0) //nolint:gosec // G304: safe usage, not user-controlled
	if err != nil {
		logger.Fatal().Msgf("Failed to open tracee memory: %v", err)
	}

	defer func() {
		if err := mem.Close(); err != nil {
			logger.Warn().Msgf("Error closing mem file: %v", err)
		}
	}()

	msgPtr := req.Data.Args[1]
	count := uint64(1)
	stride := uint64(0)

	if syscallName == "sendmmsg" {
		count = req.Data.Args[2]
		// sizeof(struct mmsghdr) on 64-bit Linux is 64 bytes.
		stride = 64
	}

	for i := range count {
		currentMsgPtr := msgPtr + (i * stride)

		// Read msghdr from tracee memory.
		// Layout (x86_64): msg_name (8 bytes), msg_namelen (4 bytes).
		// We only need these first 12 bytes to determine destination.
		buf := make([]byte, 16)
		if _, err := syscall.Pread(int(mem.Fd()), buf, int64(currentMsgPtr)); err != nil {
			logger.Warn().Msgf("Failed to read msghdr for %s[%d]: %v", syscallName, i, err)

			return 0, 0, 0
		}

		namePtr := binary.LittleEndian.Uint64(buf[0:8])
		nameLen := binary.LittleEndian.Uint32(buf[8:12])

		// If no address is specified, it's likely a connected socket or valid non-dest case; allow it.
		// We use 'continue' to ensure we verify subsequent messages in the vector.
		if namePtr == 0 || nameLen == 0 {
			continue
		}

		addrBuf := make([]byte, nameLen)
		if _, err := syscall.Pread(int(mem.Fd()), addrBuf, int64(namePtr)); err != nil {
			logger.Warn().Msgf("Failed to read address for %s[%d]: %v", syscallName, i, err)

			return 0, 0, 0
		}

		addr, err := ParseAddress(addrBuf)
		if err != nil {
			logger.Warn().Msgf("Failed to parse address for %s[%d]: %v", syscallName, i, err)

			return 0, 0, 0
		}

		// Block ALL IPv4/IPv6 destinations
		if enforceUnixSocks {
			if addr.Family == unix.AF_INET || addr.Family == unix.AF_INET6 {
				logger.Warn().Msgf("%s blocked (Unix socket enforcement): %s", syscallName, addr.String())

				return 0, 0, 0
			}
		}

		// Intercept DNS queries (port 53) to redirect them through the local Tor proxy.
		if addr.Port == DNSPort && !isLocalDNSServer(addr) {
			// TODO: Implement IPv6 support.
			if addr.Family == unix.AF_INET6 {
				return 0, 0, 0
			}

			if addr.Family == unix.AF_INET {
				logger.Info().Msgf("Redirecting DNS query %s -> local DNS", addr.String())

				if err := writeSockaddrInet4(mem, namePtr, localDNSAddrUDP); err != nil {
					logger.Warn().Msgf("Failed to rewrite destination address: %v", err)

					return 0, 0, 0
				}
			}
		}
	}

	return 0, 0, unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE
}

func handleIPEvent(localFd int, fd uint64, pid uint32, address FullAddress) (uint64, int32, uint32) {
	switch {
	case IsAddressAllowed(address, fd):
		logger.Info().Msgf("Allowed connection to %s", address.String())

		return 0, 0, unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE
	case logLeaks:
		logger.Warn().Msgf("Proxy Leak detected, but allowed: %s", address.String())

		return 0, 0, unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE
	case coreDump:
		logger.Info().Msgf("Dumping core for PID %d", pid)

		err := generateCoreDump(int(pid))
		if err != nil {
			logger.Fatal().Msgf("Error generating core dump: %v", err)
		}

		os.Exit(0)
	case stackTrace:
		logger.Info().Msgf("Generating stack trace for PID %d", pid)

		err := generateStackTrace(int(pid), tracee.Name, tracee.Args)
		if err != nil {
			logger.Fatal().Msgf("Error generating stack trace: %v", err)
		}

		os.Exit(0)
	case proxydns && address.Port == DNSPort:
		return handleDNSRedirect(localFd, pid, address)
	default:
		if killProg {
			err := killProcessAndDescendants(tracee.PID)
			if err != nil {
				logger.Fatal().Msgf("Error killing process: %v", err)
			}

			os.Exit(0)
		}

		if allowNonTCP && !enforceUnixSocks {
			// Allow non-TCP connections e.g UDP connections (Tor Proxy only supports TCP)
			// Skip this bypass when enforceUnixSocks is enabled - block ALL IPv4/IPv6
			opt, err := syscall.GetsockoptInt(localFd, syscall.SOL_SOCKET, syscall.SO_TYPE)
			if err != nil {
				logger.Fatal().Msgf("[fd:%v] syscall.GetsockoptInt failed: %v", fd, err)
			}

			if opt != syscall.SOCK_STREAM {
				logger.Info().Msgf("Allowing non-TCP connection : %s", address.String())
				// Allow non-TCP connections
				return 0, 0, unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE
			}
		}

		// When enforceUnixSocks is enabled, block IPv4/IPv6 connections
		// TODO: Add option to redirect connections to a Unix socket SOCKS5 proxy (e.g., --socks-unix /run/tor/socks)
		if enforceUnixSocks {
			logger.Warn().Msgf("Connection blocked (Unix socket enforcement): %s", address.String())

			return 0, 0, 0
		}

		if redirect != "" {
			proxyAddress := socksTCPv4
			destinationAddr := proxySockaddr4
			// Check if the address is IPv6/ IPv4
			if address.Family == unix.AF_INET6 {
				proxyAddress = socksTCPv6
				destinationAddr = proxySockaddr6
			}

			logger.Info().Msgf("Redirecting connection from %s to %s\n", address.String(), proxyAddress)

			file := os.NewFile(uintptr(localFd), "")

			conn, err := net.FileConn(file)
			if err != nil {
				logger.Fatal().Msgf("Error getting file conn: %v", err)
			}

			defer func() {
				if err := conn.Close(); err != nil {
					logger.Warn().Msgf("Error closing connection: %v", err)
				}
			}()

			err = unix.Connect(localFd, destinationAddr)
			if err != nil {
				if errors.Is(err, unix.EINPROGRESS) {
					logger.Info().Msgf("Connection is in progress, waiting for completion")
				} else {
					logger.Fatal().Msgf("Error connecting to tor: %v", err)
				}
			}

			username, password, err := resolveCredentials()
			if err != nil {
				logger.Fatal().Msgf("Error resolving credentials: %v", err)
			}

			switch redirect {
			case "socks5":
				err = handleSocks5Proxy(address.String(), username, password, conn)
			case "http":
				err = handleHTTPProxy(proxyAddress, address.String(), username, password, conn)
			default:
				logger.Fatal().Msg("Invalid redirect option")
			}

			if err != nil {
				logger.Fatal().Msgf("Error connecting to %s proxy: %v", redirect, err)
			}
		}
	}
	// Default action is to block the connection
	return 0, 0, 0
}

// handleDNSRedirect handles DNS query redirection through local DNS server.
func handleDNSRedirect(localFd int, pid uint32, address FullAddress) (uint64, int32, uint32) {
	sockType, err := getSocketType(localFd)
	if err != nil {
		logger.Fatal().Msgf("Failed to get socket type for DNS redirection: %v", err)
	}

	switch sockType {
	case "UDP":
		logger.Info().Msgf("Redirecting UDP DNS question for %s (PID %d) through Tor Resolve via Local DNS Server (127.0.0.1:%d)", address.String(), pid, localDNSAddrUDP.Port)

		if err := unix.Connect(localFd, localDNSAddrUDP); err != nil {
			logger.Fatal().Msgf("Failed to connect redirected UDP socket: %v", err)
		}
	case "TCP":
		logger.Info().Msgf("Redirecting TCP DNS question for %s (PID %d) through Tor Resolve via Local DNS Server (127.0.0.1:%d)", address.String(), pid, localDNSAddrTCP.Port)

		if err := unix.Connect(localFd, localDNSAddrTCP); err != nil {
			if !errors.Is(err, unix.EINPROGRESS) {
				logger.Fatal().Msgf("Failed to connect redirected TCP socket: %v", err)
			}
		}
	default:
		logger.Warn().Msgf("Unsupported socket type for DNS redirection: %s", sockType)
	}

	return 0, 0, 0
}

// IsIPAddressAllowed checks if a connection to the given address should be allowed.
// It checks against SOCKS proxies, whitelists, loopback, and local DNS servers.
func IsIPAddressAllowed(address FullAddress, fd uint64) bool {
	addrStr := address.String()

	// If Unix socket enforcement is enabled, block ALL IPv4/IPv6 connections
	if enforceUnixSocks {
		logger.Warn().Msgf("IPv4/IPv6 connection rejected (Unix socket enforcement): %s", addrStr)

		return false
	}

	switch {
	case socksTCPv4 == addrStr || socksTCPv6 == addrStr:
		if enforceSocks5Auth {
			socks5States[int(fd)] = &SOCKS5State{authCompleted: false}
		}

		return true

	case isWhitelistedAddress(allowedAddressesMap, addrStr):
		return true

	case whitelistLoopback && address.IP.IsLoopback():
		return true

	// Allow connections to local DNS servers
	case isLocalDNSServer(address):
		return true

	default:
		return false
	}
}

// isLocalDNSServer checks if the address corresponds to one of our local DNS listeners (UDP or TCP).
func isLocalDNSServer(address FullAddress) bool {
	// Local DNS servers are always on 127.0.0.1
	if !address.IP.Equal(net.IPv4(127, 0, 0, 1)) {
		return false
	}

	port := int(address.Port)
	if localDNSAddrUDP != nil && port == localDNSAddrUDP.Port {
		return true
	}

	if localDNSAddrTCP != nil && port == localDNSAddrTCP.Port {
		return true
	}

	return false
}

func IsAddressAllowed(address FullAddress, fd uint64) bool {
	switch address.Family {
	case unix.AF_UNIX:
		// Unix sockets are always allowed
		return true
	case unix.AF_INET:
		return IsIPAddressAllowed(address, fd)
	case unix.AF_INET6:
		return IsIPAddressAllowed(address, fd)
	default:
		return false
	}
}

func NewFullAddress(address string) (*FullAddress, error) {
	// Split the address and port using SplitHostPort
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("failed to split address and port: %w", err)
	}

	// Parse the IP address (hostname or IP)
	ip := net.ParseIP(host)
	if ip == nil {
		// If it's not a valid IP, resolve the hostname to an IP
		ipAddr, err := net.ResolveIPAddr("ip", address)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve address: %w", err)
		}

		ip = ipAddr.IP
	}

	// Determine the address family (IPv4 or IPv6)
	family := uint16(2) // AF_INET (IPv4)
	if ip.To4() == nil {
		family = uint16(10) // AF_INET6 (IPv6)
	}

	// Parse the port
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("failed to parse port: %w", err)
	}

	// Create the FullAddress object
	fullAddr := &FullAddress{
		Addr:   address,
		IP:     ip,
		Family: family,
		Port:   uint16(port),
	}

	return fullAddr, nil
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

func netTCPAddrToSockAddr(address FullAddress) unix.Sockaddr { //nolint:ireturn // required to return unix.Sockaddr for syscall usage
	ip := address.IP
	ip4 := ip.To4()

	if ip4 != nil {
		return &unix.SockaddrInet4{
			Port: int(address.Port),
			Addr: [4]byte{
				ip4[0], ip4[1], ip4[2], ip4[3],
			},
		}
	}

	return &unix.SockaddrInet6{
		Port: int(address.Port),
		Addr: [16]byte{
			ip[0], ip[1], ip[2], ip[3], ip[4], ip[5], ip[6], ip[7],
			ip[8], ip[9], ip[10], ip[11], ip[12], ip[13], ip[14], ip[15],
		},
	}
}

func ParseAddress(socketaddr []byte) (FullAddress, error) {
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

func getTgid(pid uint32) (int, error) {
	file, err := os.Open(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0, fmt.Errorf("failed to open /proc/%d/status: %w", pid, err)
	}

	defer func() {
		if err := file.Close(); err != nil {
			logger.Warn().Msgf("Error closing file: %v", err)
		}
	}()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "Tgid:") {
			var tgid int
			if _, err := fmt.Sscanf(line, "Tgid:\t%d", &tgid); err != nil {
				return 0, fmt.Errorf("failed to parse Tgid: %w", err)
			}

			return tgid, nil
		}
	}

	return 0, fmt.Errorf("tgid not found in /proc/%d/status", pid)
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
	cl := NewHTTPClient(proxyAddr, username, password)

	if _, err := cl.Dial("tcp", ipPort, conn); err != nil {
		return fmt.Errorf("error during HTTP dial: %w", err)
	}

	return nil
}

func NewHTTPClient(addr, username, password string) *HTTPDialer {
	httpDialer := &HTTPDialer{
		Host:     addr,
		Username: username,
		Password: password,
	}

	return httpDialer
}

// Dial establishes a connection to the provided address through an HTTP proxy.
// It sends an HTTP CONNECT request to the proxy server and returns the established
// connection if successful. If an error occurs, the connection is closed and the error is returned.
func (h *HTTPDialer) Dial(_, addr string, httpconn net.Conn) (net.Conn, error) {
	conn := httpconn

	reqURL, err := url.Parse("http://" + addr)
	if err != nil {
		if err := conn.Close(); err != nil {
			return nil, fmt.Errorf("failed to close connection: %w", err)
		}

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
		if err := conn.Close(); err != nil {
			return nil, fmt.Errorf("failed to close connection: %w", err)
		}

		return nil, fmt.Errorf("failed to write request: %w", err)
	}

	r := bufio.NewReader(conn)

	resp, err := http.ReadResponse(r, req)
	if err != nil {
		if err := conn.Close(); err != nil {
			return nil, fmt.Errorf("failed to close connection: %w", err)
		}

		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if err := resp.Body.Close(); err != nil {
		if err := conn.Close(); err != nil {
			return nil, fmt.Errorf("failed to close connection after body close error: %w", err)
		}

		return nil, fmt.Errorf("failed to close response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		if err := conn.Close(); err != nil {
			return nil, fmt.Errorf("failed to close connection: %w", err)
		}

		return nil, fmt.Errorf("connect proxy error: %v", strings.SplitN(resp.Status, " ", 2)[1]) //nolint:mnd
	}

	return conn, nil
}

func parseSOCKS5Data(fd int, data []byte) error {
	state, exists := socks5States[fd]
	if !exists {
		return fmt.Errorf("unknown FD %d", fd)
	}

	state.buffer.Write(data) // Append new data to buffer
	buf := state.buffer.Bytes()

	// Process SOCKS5 handshake (first three bytes: 0x05, 0x01, 0x02)
	if !state.handshakeCompleted {
		// Ensure at least 3 bytes before checking handshake
		if len(buf) < 3 {
			return nil // Wait for more data
		}

		if buf[0] != 0x05 {
			return fmt.Errorf("invalid SOCKS5 version: %x", buf[0])
		}
		// Check if the number of methods is 0x01 (1 method)
		if buf[1] != 0x01 {
			return fmt.Errorf("invalid NMETHODS: expected 0x01, got 0x%x", buf[1])
		}
		// Check if the method is 0x02 (username/password)
		if buf[2] != 0x02 {
			return fmt.Errorf("invalid METHODS: expected 0x02, got 0x%x", buf[2])
		}

		state.buffer.Next(3) // Remove processed handshake bytes
		state.handshakeCompleted = true
	}

	// Process authentication if `enforceSocks5Auth` is enabled
	if state.handshakeCompleted && !state.authCompleted { // In case we'll check for post-handshake data, later down the line
		buf = state.buffer.Bytes()
		if len(buf) < 2 {
			return nil // Wait for more data
		}

		if buf[0] != 0x01 {
			return fmt.Errorf("invalid auth version: %x", buf[0])
		}

		usernameLen := int(buf[1])
		if len(buf) < 2+usernameLen+1 {
			return nil // Wait for more data
		}

		state.username = string(buf[2 : 2+usernameLen])

		passwordLen := int(buf[2+usernameLen])
		if len(buf) < 2+usernameLen+1+passwordLen {
			return nil // Wait for more data
		}

		state.password = string(buf[3+usernameLen : 3+usernameLen+passwordLen])
		state.authCompleted = true // Mark as completed

		// Validate the extracted username and password
		if err := validateSOCKS5Auth(state.username, state.password); err != nil {
			if logLeaks {
				logger.Warn().Msgf("SOCKS5 authentication failed for FD %d: %s", fd, err)
			} else {
				return err
			}
		}

		state.buffer.Next(3 + usernameLen + passwordLen) // Remove processed auth data
		logger.Info().Msgf("SOCKS5 authentication completed for FD %d: %s:%s", fd, state.username, state.password)
	}

	return nil
}

func resolveCredentials() (string, string, error) {
	username, password := proxyUser, proxyPass
	if username == "" && password == "" {
		var err error

		username, err = GenerateRandomCredentials()
		if err != nil {
			return "", "", fmt.Errorf("failed to generate random username: %w", err)
		}

		password, err = GenerateRandomCredentials()
		if err != nil {
			return "", "", fmt.Errorf("failed to generate random password: %w", err)
		}
	} else {
		return username, password, nil
	}

	if !oneCircuit {
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

func GenerateRandomCredentials() (string, error) {
	const credentialLength = 48

	bytes := make([]byte, credentialLength)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
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

func loadAllowedAddresses(addressMap map[string]struct{}, addresses []string) {
	for _, addr := range addresses {
		addressMap[addr] = struct{}{} // Empty struct uses zero memory
	}
}

func isWhitelistedAddress(addressMap map[string]struct{}, addr string) bool {
	_, allowed := addressMap[addr]

	return allowed
}

func killProcessAndDescendants(pid int) error {
	if killAllTracees {
		descendants, err := getDescendants(pid)
		if err != nil {
			return fmt.Errorf("error getting descendants: %w", err)
		}

		// Sort in reverse order to kill children before parents
		sort.Sort(sort.Reverse(sort.IntSlice(descendants)))

		// Kill each process
		for _, p := range descendants {
			if p != pid { // Avoid killing the initial PID prematurely
				err = killProcessByID(p)
				// Check if the process is already terminated
				if err != nil {
					if errors.Is(err, unix.ESRCH) {
						logger.Info().Msgf("Process %d already terminated\n", p)

						continue
					}

					return fmt.Errorf("error killing descendant process %d: %w", p, err)
				}
			}
		}
	}

	// Kill the main PID last (for KillAllTracees)
	err := killProcessByID(pid)
	if err != nil {
		// Check if the process is already terminated (For killAllTracees)
		if errors.Is(err, unix.ESRCH) && killAllTracees {
			logger.Info().Msgf("Process %d already terminated\n", pid)

			return nil
		}

		return err
	}

	return nil
}

// getThreads returns all TIDs (threads) of a given PID from /proc/[pid]/task/
func getThreads(pid int) ([]int, error) {
	path := fmt.Sprintf("/proc/%d/task", pid)

	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, fmt.Errorf("could not read task directory for PID %d: %w", pid, err)
	}

	var tids []int
	// Iterate through the entries in the task directory
	for _, entry := range entries {
		if tid, err := strconv.Atoi(entry.Name()); err == nil {
			tids = append(tids, tid)
		}
	}

	return tids, nil
}

// getChildren reads `/proc/[pid]/task/[tid]/children` for a given PID and thread ID
func getChildren(pid int, tid int) ([]int, error) {
	path := fmt.Sprintf("/proc/%d/task/%d/children", pid, tid)

	fd, err := os.Open(path)
	if err != nil {
		// It's possible that a thread doesn't have a children file
		if os.IsNotExist(err) {
			return nil, nil
		}

		return nil, fmt.Errorf("could not open children file for PID %d, TID %d: %w", pid, tid, err)
	}

	defer func() {
		if err := fd.Close(); err != nil {
			logger.Warn().Msgf("Error closing fd: %v", err)
		}
	}()

	buf := make([]byte, 4096)
	// Read the contents of the children file
	n, err := fd.Read(buf)
	if err != nil {
		if err.Error() == "EOF" || n == 0 {
			return nil, nil
		}

		return nil, fmt.Errorf("could not read children file for PID %d, TID %d: %w", pid, tid, err)
	}

	var children []int
	// Split the read buffer into fields (PIDs)
	// and convert them to integers
	for p := range strings.FieldsSeq(string(buf[:n])) {
		if childPid, err := strconv.Atoi(p); err == nil {
			children = append(children, childPid)
		}
	}

	return children, nil
}

// getDescendants recursively finds all children of a given PID
// It's important to check TIDs because a process may have multiple threads (TIDs),
// and child processes can be associated with any of these threads, not just the main thread (PID).
// If we only check the main PID's children, we might miss processes created by other threads.
func getDescendants(pid int) ([]int, error) {
	seen := make(map[int]struct{})

	var descendants []int
	// Stack for DFS-like traversal
	stack := []int{pid}

	for len(stack) > 0 {
		current := stack[len(stack)-1]
		stack = stack[:len(stack)-1]

		if _, exists := seen[current]; exists {
			continue
		}

		seen[current] = struct{}{}
		// Add the current PID to descendants
		descendants = append(descendants, current)

		tids, err := getThreads(current)
		if err != nil {
			return nil, fmt.Errorf("error getting threads for PID %d: %w", current, err)
		}

		for _, tid := range tids {
			children, err := getChildren(current, tid) // Pass the current PID
			if err != nil {
				return nil, fmt.Errorf("error getting children for PID %d, TID %d: %w", current, tid, err)
			}

			stack = append(stack, children...)
		}
	}

	return descendants, nil
}

// killProcessByID sends a SIGKILL signal to a process with the specified PID or TGID.
func killProcessByID(pid int) error {
	// Send SIGKILL to the main process (TGID)
	err := syscall.Kill(pid, syscall.SIGKILL)
	if err != nil {
		return fmt.Errorf("failed to kill process with ID %d: %w", pid, err)
	}

	logger.Warn().Msgf("Successfully killed process with ID %d\n", pid)

	return nil
}

// validateSOCKS5Auth checks if the username and password meet the requirements. (e.g Tor spec or a given regex)
func validateSOCKS5Auth(username, password string) error {
	if len(username) == 0 || len(password) == 0 {
		return fmt.Errorf("missing SOCKS5 authentication credentials (username: '%s', password: '%s')", username, password)
	}

	// Tor SOCKS5 authentication format is validated according to the specification:
	// https://spec.torproject.org/socks-extensions.html
	if enforceSocks5TorAuth {
		const torPrefix = "<torS0X>"

		if !strings.HasPrefix(username, torPrefix) {
			return fmt.Errorf("legacy SOCKS5 authentication detected: username='%s', password='%s'", username, password)
		}

		if len(username) <= len(torPrefix) {
			return fmt.Errorf("invalid SOCKS5 authentication: username '%s' too short, missing format type", username)
		}

		formatType := username[len(torPrefix)] // First character after <torS0X>
		usernameRest := username[len(torPrefix)+1:]

		switch formatType {
		case '0': // Format type [30]
			if len(usernameRest) > 0 {
				return errors.New("invalid SOCKS5 authentication: format type '0' must have an empty username field")
			}
		case '1': // Format type [31]
			if len(usernameRest) == 0 {
				return errors.New("invalid SOCKS5 authentication: format type '1' requires a non-empty RPC Object ID")
			}
		default:
			return fmt.Errorf("invalid SOCKS5 authentication: unrecognized format type '%c'", formatType)
		}

		logger.Info().Msgf(
			"SOCKS5 authentication passed Tor format check: username='%s', password='%s' (format type: '%c')",
			username, password, formatType,
		)
	}

	if compiledSocks5IsolationRegex != nil {
		if !compiledSocks5IsolationRegex.MatchString(password) {
			return fmt.Errorf("SOCKS5 authentication rejected: password does not match isolation regex (pattern: %q). username='%s', password='%s'", socks5IsolationRegex, username, password)
		}

		logger.Info().Msgf("SOCKS5 authentication passed regex check (pattern: %q): username='%s', password='%s'", socks5IsolationRegex, username, password)
	}

	return nil
}

// generateStackTrace uses gdb to generate a stack trace for the given PID and saves it to a file.
func generateStackTrace(pid int, name string, args []string) error {
	outFile := filepath.Join(".", fmt.Sprintf("stacktrace_%d_%s_%s_%s.txt", pid, name, strings.Join(args, "_"), time.Now().Format("20060102_150405")))
	// Create the output file
	f, err := os.Create(outFile)
	if err != nil {
		return fmt.Errorf("could not create output file: %w", err)
	}

	defer func() {
		if err := f.Close(); err != nil {
			logger.Warn().Msgf("Error closing stack trace file: %v", err)
		}
	}()

	cmd := exec.Command( //nolint:gosec,noctx // G204: input is not user-controlled
		"gdb", "-p", strconv.Itoa(pid), "--batch",
		"-ex", "set pagination off",
		"-ex", "thread apply all bt",
		"-ex", "detach",
		"-ex", "quit",
	)
	cmd.Stdout = f
	cmd.Stderr = f

	logger.Warn().Msgf("Dumping stack trace to %s...", outFile)

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to run command %q: %w", cmd.String(), err)
	}

	return nil
}

// generateCoreDump sends SIGABRT to the given PID to trigger a core dump.
// It does not attempt to move or rename the core dump file.
func generateCoreDump(pid int) error {
	// Send SIGABRT
	if err := syscall.Kill(pid, syscall.SIGABRT); err != nil {
		return fmt.Errorf("failed to send SIGABRT to PID %d: %w", pid, err)
	}

	return nil
}

// checkCoreDumpLimit ensures core dumps are enabled and warns if size is limited.
func checkCoreDumpLimit() error {
	var rlimit unix.Rlimit

	if err := unix.Getrlimit(unix.RLIMIT_CORE, &rlimit); err != nil {
		return fmt.Errorf("failed to get RLIMIT_CORE: %w", err)
	}

	switch {
	case rlimit.Cur == 0:
		return errors.New("core dumps are disabled (ulimit -c 0); enable with 'ulimit -c unlimited'")

	case rlimit.Cur != unix.RLIM_INFINITY:
		fmt.Fprintf(os.Stderr,
			"Warning: core dumps are limited to %d bytes.\n"+
				"For full dumps, consider setting 'ulimit -c unlimited'\n", rlimit.Cur)
	}

	// Core dumps are enabled
	return nil
}

// getConnectionInfo retrieves the connection information for a given file descriptor (fd).
// It returns the address, port, family, and any error encountered.
func getConnectionInfo(socketFD int, remote bool) (string, int, string, error) {
	var sa syscall.Sockaddr

	var err error
	if remote {
		sa, err = syscall.Getpeername(socketFD)
	} else {
		sa, err = syscall.Getsockname(socketFD)
	}

	if err != nil {
		return "", 0, "", fmt.Errorf("failed to get socket address: %w", err)
	}

	switch sa := sa.(type) {
	case *syscall.SockaddrInet4:
		ip := net.IP(sa.Addr[:]).String()

		return fmt.Sprintf("%s:%d", ip, sa.Port), sa.Port, "ipv4", nil
	case *syscall.SockaddrInet6:
		ip := net.IP(sa.Addr[:]).String()

		return fmt.Sprintf("[%s]:%d", ip, sa.Port), sa.Port, "ipv6", nil
	case *syscall.SockaddrUnix:
		return sa.Name, 0, "unix", nil
	default:
		return "", 0, fmt.Sprintf("%T", sa), nil
	}
}

func startDNSServers() {
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		logger.Fatal().Msgf("Failed to resolve local DNS server address: %v", err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		logger.Fatal().Msgf("Failed to start local DNS server: %v", err)
	}
	// Do not close conn here, it runs forever

	localAddr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		logger.Fatal().Msgf("Failed to cast local address to UDPAddr")
	}

	logger.Info().Msgf("Local DNS server listening on %s", localAddr.String())

	localDNSAddrUDP = &unix.SockaddrInet4{
		Port: localAddr.Port,
		Addr: [4]byte{127, 0, 0, 1},
	}

	// Start TCP Listener
	tcpAddr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:0")
	if err != nil {
		logger.Fatal().Msgf("Failed to resolve local TCP DNS server address: %v", err)
	}

	tcpListener, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		logger.Fatal().Msgf("Failed to start local TCP DNS server: %v", err)
	}

	localTCPAddr, ok := tcpListener.Addr().(*net.TCPAddr)
	if !ok {
		logger.Fatal().Msgf("Failed to cast local address to TCPAddr")
	}

	logger.Info().Msgf("Local DNS server listening on TCP %s", localTCPAddr.String())

	localDNSAddrTCP = &unix.SockaddrInet4{
		Port: localTCPAddr.Port,
		Addr: [4]byte{127, 0, 0, 1},
	}

	// Handle TCP connections in a separate goroutine
	go func() {
		for {
			conn, err := tcpListener.Accept()
			if err != nil {
				logger.Error().Msgf("Local TCP DNS server accept error: %v", err)

				continue
			}

			go handleDNSRequestTCP(conn)
		}
	}()

	buf := make([]byte, 4096)

	for {
		n, remoteAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			logger.Error().Msgf("Local DNS server read error: %v", err)

			continue
		}

		go handleDNSRequestUDP(conn, remoteAddr, buf[:n])
	}
}

// handleDNSRequestTCP handles incoming TCP DNS requests.
// It reads the RFC 1035 length prefix, processes the message, and writes the response back with the prefix.
func handleDNSRequestTCP(conn net.Conn) {
	defer func() {
		if err := conn.Close(); err != nil {
			logger.Warn().Msgf("Error closing TCP DNS connection: %v", err)
		}
	}()

	// Read 2-byte length prefix
	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		if err != io.EOF {
			logger.Error().Msgf("Failed to read TCP DNS length prefix: %v", err)
		}

		return
	}

	length := binary.BigEndian.Uint16(lenBuf)

	data := make([]byte, length)
	if _, err := io.ReadFull(conn, data); err != nil {
		logger.Error().Msgf("Failed to read TCP DNS message body: %v", err)

		return
	}

	respData, err := processDNSRequest(data)
	if err != nil {
		logger.Error().Msgf("Local DNS (TCP): Failed to process request: %v", err)

		return
	}

	if respData == nil {
		return
	}

	// Write 2-byte length prefix followed by response data
	respLen := make([]byte, 2)
	binary.BigEndian.PutUint16(respLen, uint16(len(respData)))

	if _, err := conn.Write(respLen); err != nil {
		logger.Error().Msgf("Local DNS (TCP): Failed to write response length: %v", err)

		return
	}

	if _, err := conn.Write(respData); err != nil {
		logger.Error().Msgf("Local DNS (TCP): Failed to write response data: %v", err)
	}
}

// handleDNSRequestUDP handles incoming UDP DNS requests.
// It processes the message and sends the response back to the client.
func handleDNSRequestUDP(conn *net.UDPConn, remoteAddr *net.UDPAddr, data []byte) {
	respData, err := processDNSRequest(data)
	if err != nil {
		logger.Error().Msgf("Local DNS (UDP): Failed to process request: %v", err)

		return
	}

	if respData == nil {
		return
	}

	_, err = conn.WriteToUDP(respData, remoteAddr)
	if err != nil {
		logger.Error().Msgf("Local DNS: Failed to write response: %v", err)
	}
}

// processDNSRequest unpacks the DNS message, resolves the query via Tor, and packs the response.
// It returns the raw response bytes or an error.
func processDNSRequest(data []byte) ([]byte, error) {
	msg := new(dns.Msg)
	if err := msg.Unpack(data); err != nil {
		return nil, fmt.Errorf("failed to unpack DNS message: %w", err)
	}

	if len(msg.Question) == 0 {
		return nil, nil
	}

	question := msg.Question[0]
	logger.Info().Msgf("Local DNS: Resolving %s (Type: %d)", question.Name, question.Qtype)

	domain := strings.TrimSuffix(question.Name, ".")
	ip, err := resolveOverTor(domain)

	resp := new(dns.Msg)
	resp.SetReply(msg)
	resp.RecursionAvailable = true
	resp.Authoritative = false

	if err != nil {
		logger.Error().Msgf("Local DNS: Failed to resolve %s: %v", question.Name, err)
		resp.SetRcode(msg, dns.RcodeServerFailure)
	} else {
		logger.Info().Msgf("Local DNS: Resolved %s to %s", question.Name, ip.String())

		ip4 := ip.To4()

		if question.Qtype == dns.TypeA && ip4 != nil {
			rr := new(dns.A)
			rr.Hdr = dns.RR_Header{Name: question.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}
			rr.A = ip4
			resp.Answer = append(resp.Answer, rr)
		} else if question.Qtype == dns.TypeAAAA && ip4 == nil {
			rr := new(dns.AAAA)
			rr.Hdr = dns.RR_Header{Name: question.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 300}
			rr.AAAA = ip
			resp.Answer = append(resp.Answer, rr)
		}
	}

	packed, err := resp.Pack()
	if err != nil {
		return nil, fmt.Errorf("failed to pack DNS response: %w", err)
	}

	return packed, nil
}

// resolveOverTor resolves a domain name using the Tor SOCKS5 RESOLVE command (0xF0).
// It connects to the configured Tor proxy and performs the lookup remotely.
func resolveOverTor(domain string) (net.IP, error) {
	// Connect to the Tor proxy with a timeout to avoid hanging connections.
	var d net.Dialer

	conn, err := d.DialContext(context.Background(), "tcp", socksTCPv4)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Tor proxy at %s: %w", socksTCPv4, err)
	}

	defer func() {
		if err := conn.Close(); err != nil {
			logger.Warn().Msgf("Failed to close connection: %v", err)
		}
	}()

	// SOCKS5 Handshake
	// VER=5, NMETHODS=1, METHODS=[0x00] (No Auth)
	// TODO: Support auth if configured (though Tor usually doesn't need it for local)
	if _, err = conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return nil, fmt.Errorf("failed to send SOCKS5 handshake: %w", err)
	}

	handshakeResp := make([]byte, 2)
	if _, err = io.ReadFull(conn, handshakeResp); err != nil {
		return nil, fmt.Errorf("failed to read SOCKS5 handshake response: %w", err)
	}

	if handshakeResp[0] != 0x05 || handshakeResp[1] != 0x00 {
		return nil, fmt.Errorf("SOCKS5 handshake failed: ver=%x, method=%x", handshakeResp[0], handshakeResp[1])
	}

	// Build and send RESOLVE request.
	// VER=5, CMD=0xF0 (RESOLVE), RSV=0, ATYP=3 (Domain), Len, Domain, Port(0)
	if len(domain) > 255 {
		return nil, fmt.Errorf("domain name too long: %s", domain)
	}

	req := make([]byte, 0, 5+len(domain)+2)
	req = append(req, 0x05, 0xF0, 0x00, 0x03, byte(len(domain)))
	req = append(req, []byte(domain)...)
	req = append(req, 0x00, 0x00) // Port 0

	if _, err = conn.Write(req); err != nil {
		return nil, fmt.Errorf("failed to send RESOLVE command: %w", err)
	}

	// Read response header (VER, REP, RSV, ATYP).
	respHeader := make([]byte, 4)
	if _, err = io.ReadFull(conn, respHeader); err != nil {
		return nil, fmt.Errorf("failed to read RESOLVE response header: %w", err)
	}

	if respHeader[0] != 0x05 {
		return nil, fmt.Errorf("unexpected SOCKS5 version in response: %x", respHeader[0])
	}

	if respHeader[1] != 0x00 {
		return nil, fmt.Errorf("tor resolve failed with error code: 0x%x", respHeader[1])
	}

	// Extract IP address based on ATYP.
	var ip net.IP

	switch respHeader[3] {
	case 0x01: // IPv4
		ipBuf := make([]byte, 4)
		if _, err = io.ReadFull(conn, ipBuf); err != nil {
			return nil, fmt.Errorf("failed to read IPv4 address: %w", err)
		}

		ip = net.IP(ipBuf)
	case 0x04: // IPv6
		ipBuf := make([]byte, 16)
		if _, err = io.ReadFull(conn, ipBuf); err != nil {
			return nil, fmt.Errorf("failed to read IPv6 address: %w", err)
		}

		ip = net.IP(ipBuf)
	default:
		return nil, fmt.Errorf("unsupported address type in RESOLVE response: 0x%x", respHeader[3])
	}

	// Consume the 2‑byte port field (usually zero) to keep the stream clean.
	portBuf := make([]byte, 2)
	if _, err = io.ReadFull(conn, portBuf); err != nil {
		return nil, fmt.Errorf("failed to read port from RESOLVE response: %w", err)
	}

	return ip, nil
}

// getSocketType retrieves the type of socket associated with the given file descriptor (fd).
func getSocketType(fd int) (string, error) {
	sockType, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_TYPE)
	if err != nil {
		// Check if it's because the FD is not a socket
		if errors.Is(err, unix.ENOTSOCK) {
			return "", unix.ENOTSOCK
		}

		return "", fmt.Errorf("getsockopt failed: %w", err)
	}

	switch sockType {
	case unix.SOCK_STREAM:
		return "TCP", nil
	case unix.SOCK_DGRAM:
		return "UDP", nil
	case unix.SOCK_RDM:
		return "RDM", nil
	case unix.SOCK_SEQPACKET:
		return "SEQPACKET", nil
	case unix.SOCK_PACKET:
		return "PACKET", nil
	default:
		return fmt.Sprintf("UNKNOWN(%d)", sockType), nil
	}
}

// logSocketProtocol logs the protocol type of a socket associated with a given file descriptor (dupFd).
func logSocketProtocol(dupFd int, traceeFd int, pid int, syscallName string) {
	proto, err := getSocketType(dupFd)

	switch {
	case err == nil:
		logger.Info().Msgf("Intercepted '%s' syscall from PID %d, FD %d (%s)", syscallName, pid, traceeFd, proto)
	case errors.Is(err, unix.ENOTSOCK):
		logger.Debug().Msgf("PID %d, FD %d is not a socket, skipping (syscall: %s)", pid, traceeFd, syscallName)
	default:
		logger.Fatal().Msgf("failed to get socket type for PID %d, FD %d (syscall: %s): %v", pid, traceeFd, syscallName, err)
	}
}

// bindConfigVars binds the configuration variables from the command line arguments to global variables
func bindConfigVars() {
	socksTCPv4 = K.String("socks-tcp")
	socksTCPv6 = K.String("socks-tcp6")
	redirect = K.String("redirect")
	args = K.Strings("args")
	killProg = K.Bool("kill-prog")
	logLeaks = K.Bool("logleaks")
	killAllTracees = K.Bool("kill-all-tracees")
	coreDump = K.Bool("core-dump")
	stackTrace = K.Bool("stack-trace")
	proxyUser = K.String("proxy-user")
	proxyPass = K.String("proxy-pass")
	enforceSocks5Auth = K.Bool("enforce-socks5-auth")
	enforceSocks5TorAuth = K.Bool("enforce-socks5-tor-auth")
	socks5IsolationRegex = K.String("socks5-isolation-regex")
	oneCircuit = K.Bool("one-circuit")
	allowedAddresses = K.Strings("allowed-addresses")
	allowedTCPOrigin = K.Strings("allowed-tcp-origin")
	whitelistLoopback = K.Bool("whitelist-loopback")
	allowNonTCP = K.Bool("allow-non-tcp")
	blockIncomingTCP = K.Bool("block-incoming-tcp")
	proxydns = K.Bool("proxydns")
	enforceUnixSocks = K.Bool("enforce-unix-socks")
}

func validateCLI() {
	if redirect != "socks5" && redirect != "http" {
		logger.Fatal().Msgf("Invalid redirect value: %s (must be 'socks5' or 'http')", redirect)
	}

	if stackTrace {
		checkBinaryInPath("gdb")
	}

	// Check if core dumps are allowed
	if coreDump {
		if err := checkCoreDumpLimit(); err != nil {
			logger.Fatal().Msgf("Core dump limit check failed: %v", err)
		}
	}

	// If enforceSocks5TorAuth is true or socks5IsolationRegex is provided, set enforceSocks5Auth to true.
	if enforceSocks5TorAuth || socks5IsolationRegex != "" {
		// If SOCKS5 authentication is enforced or regex is provided, we need to handle the "sendto" syscall.
		enforceSocks5Auth = true
		// Validate regex pattern for SOCKS5 isolation if provided
		if socks5IsolationRegex != "" {
			var err error

			compiledSocks5IsolationRegex, err = regexp.Compile(socks5IsolationRegex)
			if err != nil {
				logger.Fatal().Msgf("Invalid SOCKS5 isolation regex: %v", err)
			}
		}
	}
}

// checkBinaryInPath ensures that the given binary exists in $PATH.
// If not found, it exits the program with a fatal log.
func checkBinaryInPath(name string) {
	if _, err := exec.LookPath(name); err != nil {
		logger.Fatal().Msgf("%s not found in $PATH", name)
	}
}

func writeSockaddrInet4(mem *os.File, ptr uint64, addr *unix.SockaddrInet4) error {
	// Construct a standard IPv4 socket address structure (sockaddr_in) to write back to memory.
	// It consists of the family (AF_INET), the port (in network byte order), and the IP address.
	buf := make([]byte, 16)
	binary.LittleEndian.PutUint16(buf[0:2], unix.AF_INET)
	binary.BigEndian.PutUint16(buf[2:4], uint16(addr.Port))
	copy(buf[4:8], addr.Addr[:])

	if _, err := syscall.Pwrite(int(mem.Fd()), buf, int64(ptr)); err != nil {
		return fmt.Errorf("failed to write new address: %w", err)
	}

	return nil
}
