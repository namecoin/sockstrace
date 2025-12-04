// SPDX-FileCopyrightText: 2025 The Namecoin Project <www.namecoin.org>
//
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
    "log"
    "os"

    "github.com/armon/go-socks5"
)

func main() {
    disableAuth := os.Getenv("NO_AUTH") == "1"

    var conf *socks5.Config

    if disableAuth {
        log.Println("Starting SOCKS5 server with NO authentication (NO_AUTH=1)")
        conf = &socks5.Config{} // no auth
    } else {
        // Hardcoded credentials
        creds := socks5.StaticCredentials{
            "user": "pass",
        }

        auth := socks5.UserPassAuthenticator{Credentials: creds}
        conf = &socks5.Config{
            AuthMethods: []socks5.Authenticator{auth},
        }

        log.Println("Starting SOCKS5 proxy with authentication (user=user, pass=pass)")
    }

    server, err := socks5.New(conf)
    if err != nil {
        log.Fatalf("Error creating SOCKS5 server: %v", err)
    }

    log.Println("SOCKS5 proxy listening on 127.0.0.1:9050")
    if err := server.ListenAndServe("tcp", "127.0.0.1:9050"); err != nil {
        log.Fatalf("Error starting SOCKS5 server: %v", err)
    }
}
