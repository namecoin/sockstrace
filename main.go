package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/oraoto/go-pidfd"
	"github.com/robertmin1/socks5/v4"
	"github.com/rs/zerolog"
	libseccomp "github.com/seccomp/libseccomp-golang"
	"github.com/spf13/cobra"
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
	blockIncomingTCP  bool
	allowedAddresses  []string
	enforceSocks5Auth bool
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
	buffer       bytes.Buffer
	authCompleted bool // True after full authentication (replaces handshake flag)
	handshakeCompleted bool
	username     string
	password     string
}

// Tracks SOCKS5 state per FD
var socks5States = make(map[int]*SOCKS5State)

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
var allowedAddressesMap map[string]struct{}

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
	"quotactl", "membarrier", "rseq", "bpf", "getrandom", "ptrace", "getcpu","ioctl", 
	"finit_module", "personality", "setgroups", "uname",

	// Time
	"time", "gettimeofday", "settimeofday", "clock_settime", "clock_gettime", "clock_getres", 
	"clock_nanosleep", "timer_create", "timer_settime", "timer_gettime", "timer_getoverrun", 
	"timer_delete", "timerfd_create", "timerfd_settime", "timerfd_gettime", "clock_adjtime", 
	"adjtimex", "utime", "utimes", "utimensat", "futimesat", "nanosleep", "alarm", "getitimer", 
	"setitimer", "eventfd2", "eventfd", "times",

	// Processes
	"getpid", "getppid", "gettid", "getpgid", "setpgid", "getpgrp", "setsid", "getsid", "fork", 
	"vfork", "clone", "clone3", "execve", "getegid","execveat", "exit", "exit_group", "wait4", 
	"waitid", "getpriority", "setpriority", "getrlimit", "setrlimit", "prlimit64", "getrusage", 
	"sched_setparam", "sched_getparam", "sched_setscheduler", "sched_getscheduler", "sched_get_priority_max", 
	"sched_get_priority_min", "sched_rr_get_interval", "sched_setaffinity", "sched_getaffinity", 
	"sched_yield", "sched_setattr", "sched_getattr", "set_tid_address", "restart_syscall", "kill", 
	"pidfd_send_signal", "pidfd_open", "pidfd_getfd", "process_madvise", "process_mrelease", "kcmp", 
	"get_thread_area","getresgid", "setresuid", "unshare", "setregid", "getresuid", "setns", "geteuid", 
	"setreuid", "getgroups", "uselib", "setresgid", "setuid","set_thread_area", "getuid", "setgid", "getgid",

	// Synchronization
	"futex", "rt_sigaction", "rt_sigprocmask", "rt_sigreturn", "rt_sigpending", "rt_sigtimedwait",
	"rt_sigqueueinfo", "rt_sigsuspend", "rt_tgsigqueueinfo", "sigaltstack", "pause", "tkill", "tgkill", 
	"signalfd", "signalfd4", "semget", "semop", "mq_getsetattr","semctl", "semtimedop", "msgget", 
	"msgsnd", "msgrcv", "msgctl", "shmget", "shmat", "shmctl", "shmdt", "mq_timedreceive","set_robust_list", 
	"get_robust_list", "futex_wake", "futex_waitv", "futex_wait", "futex_requeue", "mq_timedsend", "mq_open",
	"mq_notify", "mq_unlink", 

	// Memory
	"mmap", "mprotect", "munmap", "mremap", "msync", "mincore", "madvise", "brk", "mlock",
	"munlock", "mlockall", "munlockall", "mlock2", "remap_file_pages","memfd_create", "memfd_secret", 
	"set_mempolicy_home_node", "pkey_mprotect", "pkey_alloc", "pkey_free", "cachestat", "map_shadow_stack",
	"migrate_pages", "get_mempolicy", "set_mempolicy", "mbind",

	// Metadata
	"stat", "fstat", "lstat", "newfstatat", "statx", "getdents", "getdents64", "getcwd", "chdir", 
	"fchdir", "rename", "renameat", "renameat2", "mkdir", "mkdirat", "rmdir", "unlink", "unlinkat", 
	"symlink", "symlinkat", "readlink", "readlinkat", "chmod", "fchmod", "fchmodat", "chown", "fchown", 
	"lchown", "fchownat", "umask", "truncate", "ftruncate", "fallocate", "sync_file_range", "vmsplice", 
	"inotify_init1","move_pages", "faccessat", "openat", "move_mount", "fsopen", "fsconfig", "fsmount", 
	"fspick", "inotify_init", "lookup_dcookie","name_to_handle_at", "open_by_handle_at", "statfs", 
	"fstatfs", "ustat", "getxattr", "lgetxattr", "fgetxattr", "listxattr", "llistxattr", "flistxattr", 
	"setxattr", "lsetxattr", "fsetxattr", "removexattr", "lremovexattr", "fremovexattr", "inotify_rm_watch",
	"userfaultfd", "io_pgetevents", "open_tree", "quotactl_fd", "ioprio_set", "inotify_add_watch", "ioprio_get",

	// Data
	"read", "write", "pread64", "pwrite64", "readv", "writev", "preadv", "pwritev", "preadv2", "pwritev2",
	"creat", "fsync","splice", "tee", "process_vm_readv", "process_vm_writev", "fchmodat2", "openat2", 
	"faccessat2", "close_range", "copy_file_range", "mount_setattr","fcntl", "chroot", "pipe2", "flock", 
	"open", "linkat", "pipe", "access", "mknod", "mknodat", "fadvise64", "readahead", "dup3", "dup", "dup2",
	"fdatasync", "lseek", "link", "close",

	// Network (Excluding connect syscall)
	"socket", "socketpair", "bind", "listen", "accept", "accept4", "getsockname", "getpeername", 
	"sendto", "recvfrom", "sendmsg", "recvmsg", "shutdown", "setsockopt", "getsockopt", "sendmmsg", 
	"recvmmsg", "fanotify_init", "fanotify_mark", "perf_event_open", "kexec_load", "kexec_file_load", 
	"socketcall", "sendfile", "sethostname", "setdomainname",

	// Security
	"capget", "capset", "prctl", "arch_prctl", "seccomp", "landlock_create_ruleset", "landlock_add_rule", 
	"keyctl","landlock_restrict_self", "setfsgid", "request_key", "add_key", "setfsuid",

	// Nonblocking IO
	"poll", "ppoll", "select", "pselect6", "epoll_create", "epoll_create1", "epoll_ctl", "epoll_ctl_old",
	"epoll_wait", "epoll_wait_old", "epoll_pwait", "epoll_pwait2", "io_setup", "io_destroy", "io_getevents", 
	"io_submit", "io_cancel", "io_uring_setup", "io_uring_enter", "io_uring_register",

	// unimplemented system calls
	//"afs_syscall", "break", "fattach", "fdetach", "ftime", "getmsg", "getpmsg", "gtty", "isastream", "lock", "madvise1", 
	//"mpx", "prof", "profil", "putmsg", "putpmsg", "security", "stty", "tuxcall", "ulimit", "vserver",
}

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
  sockstrace wget --args "--directory-prefix=/home/r/Desktop" --args="google.com" (Each argument must be passed separately)
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

			loadAllowedAddresses(allowedAddresses)

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
	rootCmd.Flags().BoolVar(&blockIncomingTCP, "block-incoming-tcp", false, "Block incoming TCP connections (default: false)")
	rootCmd.Flags().StringSliceVar(&allowedAddresses, "allowed-addresses", []string{}, "List of allowed addresses (--allowed-addrs 127.0.0.1:9150,192.168.1.100:1080)")
	rootCmd.Flags().BoolVar(&enforceSocks5Auth, "enforce-socks5-auth", false, "Enforce SOCKS5 authentication (default: false)")

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

	handlers := map[string]SyscallHandler{"connect": HandleConnect, "sendto": HandleSendto}

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
	filter, err := libseccomp.NewFilter(libseccomp.ActErrno.SetReturnCode(int16(unix.EPERM)))
	if err != nil {
		return 0, err
	}

	// Define a set of syscalls that we want to block when blockIncomingTCP is true.
	incomingTCPSyscalls := map[string]bool{
		"bind":    true,
		"listen":  true,
		"accept":  true,
		"accept4": true,
	}

	// Define a set of syscalls that we want to handle.
	handledSyscalls := map[string]SyscallHandler{
		"connect": HandleConnect,
	}

	// Allow on whitelist syscalls
	for sc := range whitelist {
		syscallID, err := libseccomp.GetSyscallFromName(whitelist[sc])
		if err != nil {
			return 0, err
		}

		if enforceSocks5Auth && whitelist[sc] == "sendto"{
			handledSyscalls["sendto"] = HandleSendto

			continue
		}

		// Skip syscalls related to incoming TCP if blockIncomingTCP is true (default is EPERM)
		if blockIncomingTCP && incomingTCPSyscalls[whitelist[sc]] {
			continue
		}

		if err := filter.AddRule(syscallID, libseccomp.ActAllow); err != nil {
			return 0, err
		}
	}

	logger.Info().Msgf("Syscall whitelist applied successfully.")

	// Notify on handled syscalls
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

func HandleSendto(seccompNotifFd libseccomp.ScmpFd, req *libseccomp.ScmpNotifReq) (uint64, int32, uint32) {
	logger.Info().Msgf("Intercepted 'sento' syscall from PID %d", req.Pid)

	fd := int(req.Data.Args[0])
	state, exists := socks5States[fd]
	if !exists || state.authCompleted {
		// Skip processing if FD is irrelevant or authentication is done
		return 0, 0, unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE
	}

	fmt.Println("Processing FD", fd)

	memFile := fmt.Sprintf("/proc/%d/mem", req.Pid)
	mem, err := os.Open(memFile)
	if err != nil {
		logger.Fatal().Msgf("failed to open memory file: %v", err)
	}
	defer mem.Close()

	// Read the data from the memory at the buffer pointer
	bufferSize := req.Data.Args[2] // Length of data
	bufferAddr := req.Data.Args[1] // Pointer to data

	
	data := make([]byte, bufferSize)
	_, err = syscall.Pread(int(mem.Fd()), data, int64(bufferAddr))
	if err != nil {
		logger.Fatal().Msgf("failed to read memory: %v", err)
	}

	fmt.Println(data)

	err = parseSOCKS5Data(fd, data)
	if err != nil {
		logger.Fatal().Msgf("failed to parse SOCKS5 handshake data %v", err)
	}

	return 0, 0, unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE
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
		if buf[1] != 0x01 {
			return fmt.Errorf("invalid NMETHODS: expected 0x01, got 0x%x", buf[1])
		}
		if buf[2] != 0x02 {
			return fmt.Errorf("invalid METHODS: expected 0x02, got 0x%x", buf[2])
		}

		state.buffer.Next(3) // Remove processed handshake bytes
		state.handshakeCompleted = true
		fmt.Println("SOCKS5 handshake completed.")
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

		state.buffer.Next(3 + usernameLen + passwordLen) // Remove processed auth data
		fmt.Printf("Valid SOCKS5 auth: username=%s, password=%s\n", state.username, state.password)
	}

	// Optional: Check for post-handshake data
	if state.authCompleted && state.buffer.Len() > 0 {
		fmt.Println("Post-handshake data detected: SOCKS5 handshake fully completed.")
	}

	return nil
}

func handleIPEvent(fd uint64, pid uint32, address FullAddress) (uint64, int32, uint32) {
	if IsAddressAllowed(address, fd){
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

		// Default action is to block the connection
		return 0, 0, 0
	}
}

func IsIPAddressAllowed(address FullAddress, fd uint64) bool {
	if socksTCPv4 == address.String() || socksTCPv6 == address.String() {
		if enforceSocks5Auth {
			socks5States[int(fd)] = &SOCKS5State{authCompleted: false}
		}

		return true
	}

	if isWhitelistedAddress(address.String()) {
		return true
	}

	if whitelistLoopback && address.IP.IsLoopback() {
		return true
	}

	return false
}

func IsAddressAllowed(address FullAddress, fd uint64) bool {
	switch address.Family {
	case unix.AF_UNIX:
		return true
	case unix.AF_INET:
		return IsIPAddressAllowed(address, fd)
	case unix.AF_INET6:
		return IsIPAddressAllowed(address, fd)
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

func loadAllowedAddresses(addresses []string) {
	allowedAddressesMap = make(map[string]struct{}, len(addresses))
	for _, addr := range addresses {
		allowedAddressesMap[addr] = struct{}{} // Empty struct uses zero memory
	}
}

func isWhitelistedAddress(addr string) bool {
	_, allowed := allowedAddressesMap[addr]
	return allowed
}
