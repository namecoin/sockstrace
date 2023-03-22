# heteronculous-horklump
Go port of Heteronculous (ptrace-based proxy leak detector). Outreachy project.

## Building
Prerequisites:

1. Ensure you have the Go tools installed.

### Using Go build commands with Go modules
1. Clone [heteronculous-horklump](https://github.com/namecoin/heteronculous-horklump) 

2. Set up Go modules
```
go mod init github.com/namecoin/heteronculous-horklump
go mod tidy
```

3. Install `heteronculous-horklump` using `go build -o tracer main.go`


## DEMO
Assume you are running the SOCKS5 proxy with the default IP address: "localhost:9050". Trace for proxy leaks and Socksify your connecitons by running:
```
./tracer -horklump.program wget -horklump.args https://116.202.120.121 
-horklump.args --no-check-certificate -horklump.args 
--header=Host:check.torproject.org 
```
Since the default address is `localhost:9050` there is no need to set it.

Assume you are running the tor HTTP proxy with the default IP address: "localhost:9080". Trace for proxy leaks and Socksify your connecitons by running:
```
./tracer -horklump.program wget -horklump.redirect http -horklump.sockstcp 
127.0.0.1:9080 -horklump.args https://116.202.120.121 -horklump.args 
--no-check-certificate -horklump.args --header=Host:check.torproject.org 
```

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
