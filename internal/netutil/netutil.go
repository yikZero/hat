// Package netutil holds small shared networking helpers.
package netutil

import (
	"io"
	"net"
	"os"
	"sync"

	"golang.org/x/sys/unix"
)

// Pipe copies data in both directions until both sides are done,
// half-closing each destination when its source reaches EOF, then closes
// both connections.
func Pipe(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	cp := func(dst, src net.Conn) {
		defer wg.Done()
		io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		} else {
			dst.Close()
		}
	}
	go cp(a, b)
	go cp(b, a)
	wg.Wait()
	a.Close()
	b.Close()
}

// TerminalDeliversSignals reports whether keyboard signals (^C, ^\) are
// delivered by the terminal to our whole process group: stdin is a
// terminal and we are its foreground process group. When false (scripts,
// agents, `kill -INT <pid>`), signals must be forwarded explicitly.
func TerminalDeliversSignals() bool {
	fd := int(os.Stdin.Fd())
	pgrp, err := unix.IoctlGetInt(fd, unix.TIOCGPGRP)
	if err != nil {
		return false
	}
	return pgrp == unix.Getpgrp()
}
