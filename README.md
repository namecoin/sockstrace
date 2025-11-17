# SocksTrace
A Golang-based proxy leak detector. Outreachy project.

## Building
Prerequisites:

1. Ensure you have the `Go tools` installed. (Go 1.22+)

2. Install the `libseccomp` library, which is required for seccomp tracing:

3. `GCC` is required to compile C parts of `libseccomp` used by Go via cgo. (We are planning to use a Go-based reimplementation of `libseccomp` in the future)

4. `pkg-config` to locate libseccomp headers and libraries during build.

5. `Tor` (Preferred proxy)

On Debian/Ubuntu:
```
sudo apt update && sudo apt install -y gcc pkg-config libseccomp-dev tor
```
On Fedora/RHEL:
```
sudo dnf install libseccomp-devel
```

### Using Go build commands with Go modules
1. `git clone https://github.com/namecoin/sockstrace.git`

2. `cd sockstrace`

3. Set up Go modules
```
go mod tidy
```

3. Install `sockstrace` using `go build -o tracer main.go`


## Usage
Trace an application and log any leaks that occur:
```
./sockstrace <target application> --args "<target application argument>" --logleaks
```
For mutiple application arguments, use flag `args` for each argument:
```
./sockstrace wget --args "google.com" --args "--debug" --logleaks
```

### Optional tools

To extract stack traces after a leak, gdb is required:
```
sudo apt install gdb
```

To extract core dumps for, make sure your system allows them:
```
ulimit -c unlimited
```

### Tor setup for socksification
To socksify applications (such as browsers), you'll need Tor running with both IPv4 and IPv6 SOCKS ports. Many apps will prefer IPv6 if available.
Example `torrc`:
```
SocksPort 9050              # IPv4 localhost
SocksPort [::1]:9050        # IPv6 localhost (required for full socksification)
HTTPTunnelPort 9080         # Optional: HTTP proxy support
```
Don't forget to restart Tor after editing the config:
```
sudo systemctl restart tor
```

## Licence

Copyright (C) 2022 Namecoin Developers.

SocksTrace is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

SocksTrace is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with SocksTrace.  If not, see [https://www.gnu.org/licenses/](https://www.gnu.org/licenses/)

Namecoin is produced independently from the Tor® anonymity software and carries no guarantee from The Tor Project about quality, suitability or anything else.


## Security Risks and Precautions for Using SocksTrace

SocksTrace is a tool that provides a ptrace-based sandbox for executing untrusted programs. While this can be an effective way to enhance security and reduce the risk of malicious processes accessing sensitive information, there are also potential security risks associated with using SocksTrace.

One of the primary vulnerabilities of the ptrace-based sandbox is that a malicious process could potentially escape from the sandbox by abusing multithreading and/or shared memory. While this is still more difficult to accomplish than escaping from an LD_PRELOAD sandbox, it is still a potential risk that should be considered.

To mitigate this risk, it is recommended to implement a Linux Namespaces wrapper that drops any packets that don't go to the desired proxy. This solution can enhance security and reduce the risk of malicious processes escaping from the sandbox.
However, it is important to note that implementing a Linux Namespaces wrapper may also have potential impacts on performance and usability. Users should consider these potential impacts when deciding whether to implement this solution.

In any case, it is important for users to exercise caution when using SocksTrace, particularly when running untrusted or potentially malicious programs. Clear and comprehensive documentation of potential risks and necessary precautions is essential for users to make informed decisions about using SocksTrace and to ensure the security and integrity of their systems.
