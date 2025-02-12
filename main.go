package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"bytes"
	"encoding/binary"
	"strings"
	"bufio"
	"net/http"
	"net/url"
	"crypto/rand"
	"encoding/hex"
	"time"

	libseccomp "github.com/seccomp/libseccomp-golang"
	"github.com/oraoto/go-pidfd"
	"github.com/spf13/cobra"
	"github.com/robertmin1/socks5/v4"
	"github.com/rs/zerolog"
	"golang.org/x/sys/unix"
)

// SyscallHandler defines the handler function for a syscall notification.
type SyscallHandler func(fd libseccomp.ScmpFd, req *libseccomp.ScmpNotifReq) (val uint64, errno int32, flags uint32)

var (
	socksTCPv4        string
	socksTCPv6        string
	args              []string
	killProg          bool
	logLeaks          bool
	envVar            bool
	redirect          string
	proxyUser         string
	proxyPass         string
	oneCircuit        bool
	whitelistLoopback bool
	allowNonTCP		  bool
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

var whitelist = []string{"ioctl", "getrandom", "pciconfig_read", "pciconfig_write", "sysctl", "membarrier", 
						"syslog", "bpf", "setgroups", "uname", "getcpu", "sysinfo", "personality", "ptrace", 
						"kexec_file_load", "kexec_load", "reboot", "delete_module", "init_module", "finit_module",
						"perf_event_op", "rseq", // System syscalls
						"futimesat", "utimes", "gettimeofday", "settimeofday", "getitimer", "setitimer", 
						"clock_settime", "clock_gettime", "clock_getres", "clock_nanosleep", "time", "stime", 
						"nanosleep", "timer_create", "timer_gettime", "timer_getoverrun", "timer_settime", 
						"timer_delete", "timerfd_create", "timerfd_settime", "timerfd_gettime", "eventfd2", 
						"eventfd", "utime", "times", "clock_adjtime", "adjtimex", // Time syscalls
						"fork", "vfork", "brk", "getpid", "getppid", "getpgrp", "execve", "execveat", "nice", 
						"getgroups", "getgid", "setgid", "getuid", "setuid", "getresuid", "setresuid", "getresgid", 
						"setresgid", "getsid", "setsid", "setpgid", "getpgid", "getegid", "geteuid", "setreuid", 
						"setregid", "pause", "alarm", "acct", "prctl", "clone", "sched_setscheduler", "sched_setparam", 
						"sched_setattr", "sched_getscheduler", "sched_getparam", "sched_getattr", "sched_setaffinity",
						"sched_rr_get_interval", "unshare", "setns", "sched_getaffinity", "sched_yield", "sched_get_priority_max", 
						"sched_get_priority_min", "set_tid_address", "exit_group", "setpriority", "getpriority", 
						"getrlimit", "setrlimit", "getrusage", "gettid", "kcmp", "capget", "capset", "exit", // Process syscalls
						"semget", "semctl", "semtimedop", "semop", "mq_open", "mq_unlink", "mq_timedsend", "mq_timedreceive", 
						"mq_notify", "msgget", "msgctl", "msgsnd", "msgrcv", "waitid", "wait4", "waitpid", "signalfd4", 
						"signalfd", "kill", "sigtimedwait", "sigaltstack", "sigpending", "sigprocmask", "sigaction", 
						"signal", "sigsuspend", "futex", "set_robust_list", "get_robust_list", "restart_syscall",
						"tgkill", "rt_sigqueueinfo", "rt_tgsigqueueinfo", "mq_getsetattr", // Synchronization syscalls
						"mbind", "set_mempolicy", "migrate_pages", "get_mempolicy", "move_pages", "msync", "mincore", 
						"munmap", "remap_file_pages", "mremap", "mlock", "mlock2", "munlock", "mlockall", "munlockall", 
						"mprotect", "pkey_mprotect", "pkey_alloc", "pkey_free", "madvise", "shmget", "shmctl", "shmat", 
						"shmdt", "swapoff", "swapon", "memfd_create", // Memory syscalls
						"setfsuid", "setfsgid", "add_key", "request_key", "keyctl", "seccomp", // Security syscalls
						"stat", "statfs", "fstatfs", "inotify_init1", "inotify_init", "inotify_add_watch", "inotify_rm_watch", 
						"fanotify_init", "fanotify_mark", "setxattr", "lsetxattr", "fsetxattr", "getxattr", "lgetxattr", 
						"fgetxattr", "listxattr", "llistxattr", "flistxattr", "removexattr", "lremovexattr", "fremovexattr", 
						"quotactl", "renameat", "rename", "statx", "io_getevents", "io_pgetevents", "fsopen", "fspick",
						"lookup_dcookie", "renameat2", "fsinfo", "open_tree", "fsmount", "move_mount", "pivot_root", "getdents",
						"vmsplice", "name_to_handle_at", "open_by_handle_at", "pselect6", "userfaultfd", "mmap_pgoff",
						"ioprio_set", "ioprio_get", // Metadata syscalls
						"open", "openat", "fcntl", "sync_file_range", "fallocate", "creat", "splice", "tee", "readahead", 
						"truncate", "ftruncate", "faccessat", "access", "fchdir", "chdir", "chroot", "fchownat", "chown", 
						"lchown", "fchown", "close", "vhangup", "pipe", "pipe2", "sync", "syncfs", "fsync", "fdatasync", 
						"dup", "dup2", "dup3", "lseek", "read", "write", "copy_file_range", "readv", "writev", "preadv", 
						"pwritev", "preadv2", "pwritev2", "process_vm_readv", "process_vm_writev", "flock", "mount", "umount", // Data syscalls
						"epoll_create1", "epoll_create", "epoll_ctl", "epoll_wait", "epoll_pwait", "select", "poll", 
						"ppoll", "io_setup", "io_destroy", "io_submit", "io_cancel", // Non-blocking I/O syscalls
						"socket", "socketpair", "bind", "listen", "accept", "accept4", "getsockname", "getpeername", 
						"send", "recv", "sendto", "recvfrom", "setsockopt", "getsockopt", "shutdown", "sendmsg", 
						"sendmmsg", "recvmsg", "recvmmsg", "socketcall", "sendfile", "sethostname", "gethostname", "setdomainname",} // Network syscalls (excluding connect)

// Sets up the CLI command structure
func setupCLI() *cobra.Command {
	var rootCmd = &cobra.Command{
		Use:   "sockstrace <program> [flags]",
		Short: "A CLI tool for managing network proxying and security",
		Long: `sockstrace allows you to run a program while applying network security features.
		
Usage:
  sockstrace <program> [flags]
  
Examples:
  sockstrace wget
  sockstrace wget --args example.com
  sockstrace curl --args "-X POST -d 'data=test' https://example.com"
  sockstrace wget --args example.com --logleaks true  (Allow Proxy Leaks and log them)

Note:
  - The first argument must always be the program you want to execute.
  - Use --args to pass extra arguments to the program.`,
		Args: cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
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

			initializeAuthData()

			runProgram(args[0]) // Handle program execution after flags are processed
		},
	}

	// Define flags
	rootCmd.Flags().StringVar(&socksTCPv4, "socks-tcp", "127.0.0.1:9050", "SOCKS TCP4 address")
	rootCmd.Flags().StringVar(&socksTCPv6, "socks-tcp6", "[::1]:9050", "SOCKS TCP6 address (IPv6)")
	rootCmd.Flags().StringSliceVar(&args, "args", []string{}, "Arguments to pass to the program")
	rootCmd.Flags().BoolVar(&killProg, "kill-prog", false, "Kill program on proxy leak (default: false)")
	rootCmd.Flags().BoolVar(&logLeaks, "logleaks", false, "Allow and log proxy leaks (default: false)")
	rootCmd.Flags().BoolVar(&envVar, "env-var", true, "Use environment variables for SOCKS")
	rootCmd.Flags().StringVar(&redirect, "redirect", "socks5", "Redirect leaked connections (options: socks5, http)")
	rootCmd.Flags().StringVar(&proxyUser, "proxy-user", "", "Proxy username")
	rootCmd.Flags().StringVar(&proxyPass, "proxy-pass", "", "Proxy password")
	rootCmd.Flags().BoolVar(&oneCircuit, "one-circuit", false, "Disable random SOCKS behavior (default: false) If a user provides a username or password, those credentials will be used for all connections.")
	rootCmd.Flags().BoolVar(&whitelistLoopback, "whitelist-loopback", false, "Allow loopback connections (default: false)")
	rootCmd.Flags().BoolVar(&allowNonTCP, "allow-non-tcp", true, "Allow non-TCP connections (Tor Proxy only supports TCP)")


	return rootCmd
}

func initSeccomp() chan <-struct{} {
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

	handlers := map[string]SyscallHandler{"connect": HandleConnect}

	stop, errChan := Handle(fd, handlers)
	go func() {
		for err := range errChan {
			logger.Fatal().Msgf("Error in syscall monitoring: %v", err)
		}
	}()
	return stop
}

func main() {
	// Set up the CLI
	rootCmd := setupCLI()

	logger = zerolog.New(
		zerolog.ConsoleWriter{
			Out:        os.Stderr,           // Output to stderr
			TimeFormat: time.RFC3339,        // Time format
		},
	).Level(zerolog.TraceLevel).With().Timestamp().Caller().Logger()

	// Execute the CLI command
	if err := rootCmd.Execute(); err != nil {
		logger.Fatal().Msgf("Error executing program: %v", err)
	}
}


func runProgram(program string) {
	logger.Info().Msgf("Executing program: %s", program)

	cmd := exec.Command(program, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr

	if err := cmd.Run(); err != nil {
		logger.Fatal().Msgf("Error executing program: %v", err)
	}
}

// LoadFilter initializes the seccomp filter, loads rules, and returns a notification FD.
func LoadFilter() (libseccomp.ScmpFd, error) {
	filter, err := libseccomp.NewFilter(libseccomp.ActAllow)
	if err != nil {
		return 0, err
	}

	// Allow on whitelist syscalls
	for sc := range whitelist {
		syscallID, err := libseccomp.GetSyscallFromName(whitelist[sc])
		if err != nil {
			return 0, err
		}
		if err := filter.AddRule(syscallID, libseccomp.ActAllow); err != nil {
			return 0, err
		}
	}

	// Notify on handled syscalls
	handledSyscalls := map[string]SyscallHandler{
		"connect": HandleConnect,
	}
	for sc := range handledSyscalls {
		syscallID, err := libseccomp.GetSyscallFromName(sc)
		if err != nil {
			return 0, err
		}
		if err := filter.AddRule(syscallID, libseccomp.ActNotify); err != nil {
			return 0, err
		}
	}

	if err := filter.Load(); err != nil {
		return 0, err
	}

	fd, err := filter.GetNotifFd()
	if err != nil {
		return 0, err
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
				if err == syscall.ENOENT {
					logger.Fatal().Msgf("Notification no longer valid: %v", err)
					continue
				}
				logger.Fatal().Msgf("Failed to receive notification: %v", err)
				errChan <- err
				if err == unix.ECANCELED {
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
	logger.Info().Msgf("Intercepted 'connect' syscall from PID %d", req.Pid)

	err := libseccomp.NotifIDValid(seccompNotifFd, req.ID)
	if err != nil {
		logger.Fatal().Msgf("failed to validate notification ID: %v", err)
	}

	memFile := fmt.Sprintf("/proc/%d/mem", req.Pid)
	mem, err := os.Open(memFile)
	if err != nil {
		logger.Fatal().Msgf("failed to open memory file: %v", err)
	}
	defer mem.Close()

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

	return handleIPEvent(sockfd, pid, addr)
}

func handleIPEvent(fd uint64, pid uint32, address FullAddress) (uint64, int32, uint32) {
	if IsAddressAllowed(address){
		logger.Info().Msgf("Allowed connection to %s", address.String())
		return 0, 0, unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE
	} else if logLeaks {
		logger.Warn().Msgf("Proxy Leak detected, but allowed: %s", address.String())
		return 0, 0, unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE
	} else {
		tgid, err := getTgid(pid)
		if err != nil {
			logger.Fatal().Msgf("Error getting tgid: %v", err)
		}

		if killProg {
			err = killProcessByID(tgid)
			if err != nil {
				logger.Fatal().Msgf("Error killing process: %v", err)
			}
		}

		tgidFD, err := pidfd.Open(tgid, 0)
		if err != nil {
			logger.Fatal().Msgf("Error opening pidfd %v", err)
		}

		connFD, err := tgidFD.GetFd(int(fd), 0)
		if err != nil {
			logger.Fatal().Msgf("Error getting fd %v", err)
		}
		defer unix.Close(connFD)

		if allowNonTCP {
			// Allow non-TCP connections e.g UDP connections (Tor Proxy only supports TCP)
			opt, err := syscall.GetsockoptInt(connFD, syscall.SOL_SOCKET, syscall.SO_TYPE)
			if err != nil {
				logger.Fatal().Msgf("[fd:%v] syscall.GetsockoptInt failed: %v", fd, err)
			}

			if opt != syscall.SOCK_STREAM {
				logger.Info().Msgf("Allowing non-TCP connection : %s", address.String())
				return 0, 0, unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE
			}
		}

		if redirect != "" {
			proxyAddress := socksTCPv4
			destinationAddr := proxySockaddr4
			if address.Family == unix.AF_INET6 {
				proxyAddress = socksTCPv6
				destinationAddr = proxySockaddr6
			}

			logger.Info().Msgf("Redirecting connection from %s to %s\n", address.String(), proxyAddress)

			file := os.NewFile(uintptr(connFD), "")

			conn, err := net.FileConn(file)
			if err != nil {
				logger.Fatal().Msgf("Error getting file conn: %v", err)
			}
			defer conn.Close() 
			
			err = unix.Connect(int(connFD), destinationAddr)
			if err != nil {
				if err == unix.EINPROGRESS {
					logger.Info().Msgf("Connection is in progress, waiting for completion")
				} else {
					logger.Fatal().Msgf("Error connecting to tor", err)
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
				logger.Fatal().Msgf("Error connecting to %s proxy", redirect, err)
			}
		}

		// Default action is to block the connection
		return 0, 0, 0
	}
}

func IsIPAddressAllowed(address FullAddress) bool {
	if socksTCPv4 == address.String() || socksTCPv6 == address.String() {
		return true
	}

	if whitelistLoopback && address.IP.IsLoopback() {
		return true
	}

	return false
}

func IsAddressAllowed(address FullAddress) bool {
	switch address.Family {
	case unix.AF_UNIX:
		return true
	case unix.AF_INET:
		return IsIPAddressAllowed(address)
	case unix.AF_INET6:
		return IsIPAddressAllowed(address)
	default:
		return false
	}
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

func NewFullAddress(address string) (*FullAddress, error) {
	// Split the address and port using SplitHostPort
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("failed to split address and port: %v", err)
	}

	// Parse the IP address (hostname or IP)
	ip := net.ParseIP(host)
	if ip == nil {
		// If it's not a valid IP, resolve the hostname to an IP
		ipAddr, err := net.ResolveIPAddr("ip", address)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve address: %v", err)
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
		return nil, fmt.Errorf("failed to parse port: %v", err)
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

func netTCPAddrToSockAddr(address FullAddress) unix.Sockaddr {
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

func ParseAddress(socketaddr []byte) (FullAddress, error) { //nolint
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

// killProcessByID sends a SIGKILL signal to a process with the specified PID or TGID.
func killProcessByID(pid int) error {
	// Send SIGKILL to the main process (TGID)
	err := syscall.Kill(pid, syscall.SIGKILL)
	if err != nil {
		return fmt.Errorf("failed to kill process with ID %d: %v", pid, err)
	}

	logger.Warn().Msgf("Successfully killed process with ID %d\n", pid)
	return nil
}

func getTgid(pid uint32) (int, error) {
	file, err := os.Open(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "Tgid:") {
			var tgid int
			fmt.Sscanf(line, "Tgid:\t%d", &tgid)
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
	cl, err := NewHTTPClient(proxyAddr, username, password)
	if err != nil {
		return fmt.Errorf("failed to create HTTP client: %w", err)
	}

	if _, err = cl.Dial("tcp", ipPort, conn); err != nil {
		return fmt.Errorf("error during HTTP dial: %w", err)
	}

	return nil
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
