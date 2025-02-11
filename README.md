# sockstrace
Go port of Heteronculous (Golang-based proxy leak detector). Outreachy project.

## Building
Prerequisites:

1. Ensure you have the Go tools installed.

2. Install the libseccomp library, which is required for seccomp tracing:

On Debian/Ubuntu:
```
sudo apt update && sudo apt install libseccomp-dev
```
On Fedora/RHEL:
```
sudo dnf install libseccomp-devel
```

### Using Go build commands with Go modules
1. Clone [sockstrace](https://github.com/namecoin/heteronculous-horklump) 

2. Set up Go modules
```
go mod tidy
```

3. Install `sockstrace` using `go build -o tracer main.go`


## DEMO
TODO

## Licence

Copyright (C) 2022 Namecoin Developers.

heteronculous-horklump is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

heteronculous-horklump is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with heteronculous-horklump.  If not, see [https://www.gnu.org/licenses/](https://www.gnu.org/licenses/)

Namecoin is produced independently from the Tor® anonymity software and carries no guarantee from The Tor Project about quality, suitability or anything else.


## Security Risks and Precautions for Using Horklump

Horklump is a tool that provides a ptrace-based sandbox for executing untrusted programs. While this can be an effective way to enhance security and reduce the risk of malicious processes accessing sensitive information, there are also potential security risks associated with using Horklump.

One of the primary vulnerabilities of the ptrace-based sandbox is that a malicious process could potentially escape from the sandbox by abusing multithreading and/or shared memory. While this is still more difficult to accomplish than escaping from an LD_PRELOAD sandbox, it is still a potential risk that should be considered.

To mitigate this risk, it is recommended to implement a Linux Namespaces wrapper that drops any packets that don't go to the desired proxy. This solution can enhance security and reduce the risk of malicious processes escaping from the sandbox.
However, it is important to note that implementing a Linux Namespaces wrapper may also have potential impacts on performance and usability. Users should consider these potential impacts when deciding whether to implement this solution.

In any case, it is important for users to exercise caution when using Horklump, particularly when running untrusted or potentially malicious programs. Clear and comprehensive documentation of potential risks and necessary precautions is essential for users to make informed decisions about using Horklump and to ensure the security and integrity of their systems.
