package main

import (
	"log"

	"github.com/armon/go-socks5"
)

func main() {
	// Define username and password
	creds := socks5.StaticCredentials{
		"user": "pass",
	}

	auth := socks5.UserPassAuthenticator{Credentials: creds}

	conf := &socks5.Config{
		AuthMethods: []socks5.Authenticator{auth},
	}

	server, err := socks5.New(conf)
	if err != nil {
		log.Fatalf("Error creating SOCKS5 server: %v", err)
	}

	log.Println("SOCKS5 proxy listening on 127.0.0.1:9050 (user=user, pass=pass)")
	if err := server.ListenAndServe("tcp", "127.0.0.1:9050"); err != nil {
		log.Fatalf("Error starting SOCKS5 server: %v", err)
	}
}
