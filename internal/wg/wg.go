// Package wg manages the WireGuard interface on Linux and FreeBSD
// (pfSense) nodes. It uses the kernel implementation when available and
// falls back to an embedded wireguard-go, so nothing has to be installed
// besides the meshgate binary.
package wg

import (
	"net"
	"net/netip"
	"time"
)

// MTU leaves room for IPv6 outer headers and PPPoE/LTE links.
const MTU = 1280

// PeerStat is runtime information about a peer.
type PeerStat struct {
	PublicKey     string    `json:"public_key"`
	Endpoint      string    `json:"endpoint,omitempty"`
	LastHandshake time.Time `json:"last_handshake"`
	RxBytes       int64     `json:"rx_bytes"`
	TxBytes       int64     `json:"tx_bytes"`
}

// LocalAddrs lists IPv4 addresses on interfaces other than the mesh.
func LocalAddrs(skip string) []netip.Addr {
	var out []netip.Addr
	ifs, _ := net.Interfaces()
	for _, i := range ifs {
		if i.Name == skip || i.Flags&net.FlagUp == 0 || i.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := i.Addrs()
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok {
				if ip, ok := netip.AddrFromSlice(n.IP.To4()); ok && n.IP.To4() != nil {
					out = append(out, ip)
				}
			}
		}
	}
	return out
}

func prefixToIPNet(p netip.Prefix) *net.IPNet {
	return &net.IPNet{IP: p.Addr().AsSlice(), Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen())}
}
