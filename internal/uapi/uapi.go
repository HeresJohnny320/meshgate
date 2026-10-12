// Package uapi renders and parses wireguard-go's configuration protocol. It
// is used where meshgate embeds wireguard-go directly (phones, Windows).
package uapi

import (
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/heresjohnny320/meshgate/internal/meshcfg"
)

// HexKey converts a base64 WireGuard key to UAPI hex.
func HexKey(b64 string) (string, error) {
	k, err := wgtypes.ParseKey(b64)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(k[:]), nil
}

// Config renders peer changes. Peers are updated in place (never
// replace_peers) so live sessions and endpoints learned by roaming survive.
// prev holds the hex keys configured last time; the returned set replaces it.
func Config(cfg meshcfg.Config, prev map[string]bool) (string, map[string]bool) {
	var b strings.Builder
	keys := map[string]bool{}
	for _, p := range cfg.Peers {
		h, err := HexKey(p.PublicKey)
		if err != nil {
			continue
		}
		keys[h] = true
		fmt.Fprintf(&b, "public_key=%s\n", h)
		if p.Endpoint != "" {
			if ua, err := net.ResolveUDPAddr("udp", p.Endpoint); err == nil {
				fmt.Fprintf(&b, "endpoint=%s\n", ua.String())
			}
		}
		fmt.Fprintf(&b, "persistent_keepalive_interval=%d\nreplace_allowed_ips=true\n", p.Keepalive)
		for _, a := range p.AllowedIPs {
			fmt.Fprintf(&b, "allowed_ip=%s\n", a)
		}
	}
	var gone []string
	for h := range prev {
		if !keys[h] {
			gone = append(gone, h)
		}
	}
	sort.Strings(gone)
	for _, h := range gone {
		fmt.Fprintf(&b, "public_key=%s\nremove=true\n", h)
	}
	return b.String(), keys
}

// Remove renders removal of the given base64 keys.
func Remove(keys []string) string {
	var b strings.Builder
	for _, k := range keys {
		if h, err := HexKey(k); err == nil {
			fmt.Fprintf(&b, "public_key=%s\nremove=true\n", h)
		}
	}
	return b.String()
}

// Peer is runtime data from an IpcGet dump.
type Peer struct {
	Endpoint      string
	LastHandshake time.Time
	RxBytes       int64
	TxBytes       int64
}

// Parse splits IpcGet output into peers keyed by hex public key.
func Parse(txt string) map[string]Peer {
	out := map[string]Peer{}
	var cur string
	for _, line := range strings.Split(txt, "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		if k == "public_key" {
			cur = v
			out[cur] = Peer{}
			continue
		}
		if cur == "" {
			continue
		}
		p := out[cur]
		switch k {
		case "endpoint":
			p.Endpoint = v
		case "last_handshake_time_sec":
			if s, _ := strconv.ParseInt(v, 10, 64); s > 0 {
				p.LastHandshake = time.Unix(s, 0)
			}
		case "rx_bytes":
			p.RxBytes, _ = strconv.ParseInt(v, 10, 64)
		case "tx_bytes":
			p.TxBytes, _ = strconv.ParseInt(v, 10, 64)
		}
		out[cur] = p
	}
	return out
}
