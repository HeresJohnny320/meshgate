package wg

import (
	"strconv"
	"strings"
	"time"
)

// parseDump parses `wg show <iface> dump`: the first line describes the
// interface, every following line a peer:
// public-key preshared-key endpoint allowed-ips latest-handshake rx tx keepalive
func parseDump(out string) map[string]PeerStat {
	res := map[string]PeerStat{}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	for i, l := range lines {
		f := strings.Split(l, "\t")
		if i == 0 || len(f) < 8 {
			continue
		}
		s := PeerStat{PublicKey: f[0]}
		if f[2] != "(none)" {
			s.Endpoint = f[2]
		}
		if ts, _ := strconv.ParseInt(f[4], 10, 64); ts > 0 {
			s.LastHandshake = time.Unix(ts, 0)
		}
		s.RxBytes, _ = strconv.ParseInt(f[5], 10, 64)
		s.TxBytes, _ = strconv.ParseInt(f[6], 10, 64)
		res[s.PublicKey] = s
	}
	return res
}
