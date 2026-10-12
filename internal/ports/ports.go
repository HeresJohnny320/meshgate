// Package ports finds free ports during setup, so meshgate can install next
// to an existing WireGuard, a web server on 8080, and so on.
package ports

import (
	"net"
	"strconv"
)

// UDPFree reports whether UDP port p can be bound on all IPv4 addresses.
func UDPFree(p int) bool {
	c, err := net.ListenPacket("udp4", ":"+strconv.Itoa(p))
	if err != nil {
		return false
	}
	c.Close()
	return true
}

// TCPFree reports whether TCP port p can be bound on all IPv4 addresses.
func TCPFree(p int) bool {
	l, err := net.Listen("tcp4", ":"+strconv.Itoa(p))
	if err != nil {
		return false
	}
	l.Close()
	return true
}

// Probe offset: peers probe a node on its WireGuard port + 2 (see package
// probe), so the WireGuard port is only usable if both are free.
const probeOffset = 2

// WireGuard returns want if UDP want and want+2 are free, otherwise the next
// free pair in steps of 10 (51830, 51840, ...). ok is false if none is free.
func WireGuard(want int) (port int, ok bool) {
	for c := want; c < want+1000 && c+probeOffset < 65536; c += 10 {
		if UDPFree(c) && UDPFree(c+probeOffset) {
			return c, true
		}
	}
	return 0, false
}

// TCP returns want if it is free, otherwise the next free port that is not in
// taken (ports already chosen during this setup).
func TCP(want int, taken map[int]bool) (port int, ok bool) {
	for c := want; c < want+1000 && c < 65536; c++ {
		if !taken[c] && TCPFree(c) {
			return c, true
		}
	}
	return 0, false
}
