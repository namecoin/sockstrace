package http_prox

import (
	"fmt"
	"strings"
	"bufio"
	"net"
	"net/url"
	"net/http"
)

type HttpDialer struct {
	Host	string
	Username string
	Password string
}

// This is just create a client, you need to use Dial to create conn
func NewClient(addr, username, password string) (*HttpDialer, error) {
	c := &HttpDialer{
		Host: addr,
		Username: username,
		Password: password,
	}
	return c, nil
}

func (h *HttpDialer) Dial(network, addr string, httpconn net.Conn) (net.Conn, error) {
	conn := httpconn

	reqURL, err := url.Parse("http://" + addr)
	if err != nil {
		conn.Close()
		return nil, err
	}

	req := &http.Request{
		Method: "CONNECT",
		URL:    reqURL,
		Host:   addr,
		Header: make(http.Header),
	}
	
	// Set authentication details.
	req.SetBasicAuth(h.Username, h.Password)
	err = req.Write(conn)
	if err != nil {
		conn.Close()
		return nil, err
	}
	
	r := bufio.NewReader(conn)
	resp, err := http.ReadResponse(r, req)
	if err != nil {
		conn.Close()
		return nil, err
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		conn.Close()
		return nil, fmt.Errorf("connect proxy error: %v", strings.SplitN(resp.Status, " ", 2)[1])
	}
	return conn, nil
}

