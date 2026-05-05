//go:build linux

package sniproxy

import (
	"fmt"
	"net"
	"syscall"
	"unsafe"
)

const SO_ORIGINAL_DST = 80

func originalDst(conn net.Conn) (string, error) {
	tc, ok := conn.(*net.TCPConn)
	if !ok {
		return "", fmt.Errorf("not a TCPConn")
	}
	raw, err := tc.SyscallConn()
	if err != nil {
		return "", err
	}
	var addr syscall.RawSockaddrInet4
	var addrLen uint32 = uint32(unsafe.Sizeof(addr))
	var getsockoptErr error
	raw.Control(func(fd uintptr) {
		_, _, errno := syscall.Syscall6(
			syscall.SYS_GETSOCKOPT,
			fd,
			syscall.SOL_IP,
			SO_ORIGINAL_DST,
			uintptr(unsafe.Pointer(&addr)),
			uintptr(unsafe.Pointer(&addrLen)),
			0,
		)
		if errno != 0 {
			getsockoptErr = errno
		}
	})
	if getsockoptErr != nil {
		return "", getsockoptErr
	}
	ip := net.IP(addr.Addr[:])
	port := int(addr.Port>>8) | int(addr.Port&0xff)<<8
	return fmt.Sprintf("%s:%d", ip.String(), port), nil
}
