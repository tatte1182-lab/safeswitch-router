package mitm

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

// Proxy is the MITM HTTPS proxy. It listens for HTTP CONNECT tunnels and
// either intercepts them (to check against the blocklist) or passes them
// through unchanged (for cert-pinned apps).
type Proxy struct {
	CA        *CA
	Blocklist BlocklistChecker
	Port      int
}

// BlocklistChecker is satisfied by the existing DNS blocklist engine.
// The proxy calls IsBlocked(hostname) for every intercepted request.
type BlocklistChecker interface {
	IsBlocked(hostname string) bool
}

// ListenAndServe starts the HTTP proxy listener.
func (p *Proxy) ListenAndServe() error {
	addr := fmt.Sprintf(":%d", p.Port)
	srv := &http.Server{
		Addr:         addr,
		Handler:      p,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
	}
	log.Printf("[mitm] proxy listening on %s", addr)
	return srv.ListenAndServe()
}

// ServeHTTP handles both plain HTTP and HTTPS CONNECT tunnels.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
		return
	}
	p.handleHTTP(w, r)
}

// handleConnect is called for HTTPS tunnel requests (CONNECT hostname:443).
func (p *Proxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	hostname := hostOnly(host)

	// --- Bypass: cert-pinned apps get a raw tunnel, no MITM ---
	if ShouldBypass(hostname) {
		p.rawTunnel(w, r, host)
		return
	}

	// --- Intercept: hijack the connection, wrap in our TLS ---
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack not supported", http.StatusInternalServerError)
		return
	}

	// Tell the client the tunnel is established
	w.WriteHeader(http.StatusOK)

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		log.Printf("[mitm] hijack error for %s: %v", host, err)
		return
	}
	defer clientConn.Close()

	// Wrap the client connection in our TLS using a signed leaf cert
	leafCert, err := p.CA.CertFor(hostname)
	if err != nil {
		log.Printf("[mitm] cert sign error for %s: %v", hostname, err)
		return
	}

	tlsConn := tls.Server(clientConn, &tls.Config{
		Certificates: []tls.Certificate{*leafCert},
		MinVersion:   tls.VersionTLS12,
	})
	if err := tlsConn.Handshake(); err != nil {
		// Client rejected our cert — likely not enrolled yet, or pinned
		log.Printf("[mitm] TLS handshake failed for %s: %v", hostname, err)
		return
	}
	defer tlsConn.Close()

	// Now read the actual HTTP request the client is making
	clientBuf := bufio.NewReader(tlsConn)
	req, err := http.ReadRequest(clientBuf)
	if err != nil {
		if err != io.EOF {
			log.Printf("[mitm] read request for %s: %v", hostname, err)
		}
		return
	}
	req.URL.Host = host
	req.URL.Scheme = "https"
	req.RequestURI = ""

	// --- Blocklist check ---
	if p.Blocklist != nil && p.Blocklist.IsBlocked(hostname) {
		log.Printf("[mitm] BLOCKED %s", hostname)
		tlsConn.Write(blockResponse(hostname))
		return
	}

	// --- Forward the request to the real server ---
	destConn, err := tls.Dial("tcp", host, &tls.Config{
		ServerName: hostname,
		MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		log.Printf("[mitm] connect to origin %s: %v", host, err)
		tlsConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n"))
		return
	}
	defer destConn.Close()

	// Write the request to origin
	if err := req.Write(destConn); err != nil {
		log.Printf("[mitm] write to origin %s: %v", host, err)
		return
	}

	// Pipe response back to client
	done := make(chan struct{}, 2)
	go func() { io.Copy(tlsConn, destConn); done <- struct{}{} }()
	go func() { io.Copy(destConn, tlsConn); done <- struct{}{} }()
	<-done
}

// handleHTTP handles plain HTTP (port 80) requests.
func (p *Proxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	hostname := hostOnly(r.Host)

	if p.Blocklist != nil && p.Blocklist.IsBlocked(hostname) {
		log.Printf("[mitm] BLOCKED (http) %s", hostname)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusForbidden)
		w.Write(blockPageHTML(hostname))
		return
	}

	// Forward the plain HTTP request
	r.RequestURI = ""
	if r.URL.Scheme == "" {
		r.URL.Scheme = "http"
	}
	if r.URL.Host == "" {
		r.URL.Host = r.Host
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Do(r)
	if err != nil {
		http.Error(w, "upstream error", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// rawTunnel opens a direct TCP connection to the destination and pipes bytes
// in both directions without any inspection (bypass mode).
func (p *Proxy) rawTunnel(w http.ResponseWriter, r *http.Request, host string) {
	destConn, err := net.DialTimeout("tcp", host, 10*time.Second)
	if err != nil {
		http.Error(w, "upstream unreachable", http.StatusBadGateway)
		return
	}
	defer destConn.Close()

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack not supported", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)

	clientConn, buf, err := hijacker.Hijack()
	if err != nil {
		return
	}
	defer clientConn.Close()

	// Flush any buffered bytes first
	if buf.Reader.Buffered() > 0 {
		buffered, _ := buf.Reader.Peek(buf.Reader.Buffered())
		destConn.Write(buffered)
	}

	done := make(chan struct{}, 2)
	go func() { io.Copy(destConn, clientConn); done <- struct{}{} }()
	go func() { io.Copy(clientConn, destConn); done <- struct{}{} }()
	<-done
}

// hostOnly strips port from "host:port" returning just "host".
func hostOnly(hostPort string) string {
	h := hostPort
	if strings.Contains(h, ":") {
		host, _, err := net.SplitHostPort(h)
		if err == nil {
			return host
		}
	}
	return h
}
