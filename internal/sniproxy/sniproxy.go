package sniproxy

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"time"
)

type Blocklist interface {
	IsBlocked(domain string) bool
}

type Server struct {
	addr      string
	blocklist Blocklist
	logger    *log.Logger
}

func NewServer(addr string, bl Blocklist, logger *log.Logger) *Server {
	return &Server{addr: addr, blocklist: bl, logger: logger}
}

func (s *Server) Start(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("sniproxy listen %s: %w", s.addr, err)
	}
	s.logger.Printf("[sniproxy] started addr=%s", s.addr)
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				select {
				case <-ctx.Done():
					return
				default:
					continue
				}
			}
			go s.handle(ctx, conn)
		}
	}()
	return nil
}

func (s *Server) Stop(ctx context.Context) error { return nil }
func (s *Server) Name() string { return "sniproxy" }
func (s *Server) Health(ctx context.Context) error { return nil }

func (s *Server) handle(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	srcIP, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	conn.SetReadDeadline(time.Time{})
	if err != nil || n == 0 {
		return
	}
	peeked := buf[:n]
	sni := extractSNI(peeked)
	if sni != "" && s.blocklist.IsBlocked(sni) {
		s.logger.Printf("[sniproxy] blocked sni=%s src=%s", sni, srcIP)
		conn.Write([]byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28})
		// Force RST so browser cannot reuse connection
		if tc, ok := conn.(*net.TCPConn); ok {
			tc.SetLinger(0)
		}
		return
	}
	dst, err := originalDst(conn)
	if err != nil {
		if sni != "" {
			dst = sni + ":443"
		} else {
			return
		}
	}
	remote, err := net.DialTimeout("tcp", dst, 10*time.Second)
	if err != nil {
		return
	}
	defer remote.Close()
	remote.Write(peeked)
	done := make(chan struct{}, 2)
	go func() { io.Copy(remote, conn); done <- struct{}{} }()
	go func() { io.Copy(conn, remote); done <- struct{}{} }()
	<-done
}

func extractSNI(data []byte) string {
	if len(data) < 5 || data[0] != 0x16 {
		return ""
	}
	recLen := int(data[3])<<8 | int(data[4])
	if len(data) < 5+recLen {
		return ""
	}
	hs := data[5:]
	if len(hs) < 4 || hs[0] != 0x01 {
		return ""
	}
	hsLen := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
	if len(hs) < 4+hsLen {
		return ""
	}
	body := hs[4 : 4+hsLen]
	if len(body) < 34 {
		return ""
	}
	pos := 34
	if pos >= len(body) { return "" }
	sidLen := int(body[pos]); pos += 1 + sidLen
	if pos+2 > len(body) { return "" }
	csLen := int(body[pos])<<8 | int(body[pos+1]); pos += 2 + csLen
	if pos >= len(body) { return "" }
	cmLen := int(body[pos]); pos += 1 + cmLen
	if pos+2 > len(body) { return "" }
	extLen := int(body[pos])<<8 | int(body[pos+1]); pos += 2
	end := pos + extLen
	for pos+4 <= end {
		extType := int(body[pos])<<8 | int(body[pos+1])
		extDataLen := int(body[pos+2])<<8 | int(body[pos+3])
		pos += 4
		if extType == 0x00 {
			if pos+5 > end { return "" }
			nameLen := int(body[pos+3])<<8 | int(body[pos+4])
			if pos+5+nameLen > end { return "" }
			return string(body[pos+5 : pos+5+nameLen])
		}
		pos += extDataLen
	}
	return ""
}
