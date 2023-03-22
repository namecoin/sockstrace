# HTTTP Proxy

HTTP Proxy is a simple Go package that provides a basic implementation of an HTTP proxy dialer. This package uses an existing net.Conn connection.


## Installation
```
go get github.com/username/httpproxy
```

## Usage

To use the HTTPDialer struct, first create a new instance of it using NewClient method, which takes in three parameters:

`addr` : the address of the proxy server

`username` : the username for authentication

`password` : the password for authentication

Then, you can use the Dial method of the HTTPDialer to create a connection to a destination address through the HTTP proxy.