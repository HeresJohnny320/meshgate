package uapi

import (
	"net/netip"
	"strings"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/heresjohnny320/meshgate/internal/meshcfg"
)

func key() string { k, _ := wgtypes.GeneratePrivateKey(); return k.PublicKey().String() }

func TestConfigAndRemoval(t *testing.T) {
	a, b := key(), key()
	cfg := meshcfg.Config{Peers: []meshcfg.Peer{
		{PublicKey: a, Endpoint: "203.0.113.10:51820", Keepalive: 20, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("100.88.0.1/32"), netip.MustParsePrefix("192.168.1.0/24")}},
		{PublicKey: b},
	}}
	txt, keys := Config(cfg, nil)
	ha, _ := HexKey(a)
	for _, want := range []string{"public_key=" + ha, "endpoint=203.0.113.10:51820", "persistent_keepalive_interval=20", "allowed_ip=192.168.1.0/24", "replace_allowed_ips=true"} {
		if !strings.Contains(txt, want) {
			t.Errorf("missing %q in\n%s", want, txt)
		}
	}
	if strings.Contains(txt, "replace_peers") {
		t.Error("must never replace all peers")
	}
	txt2, _ := Config(meshcfg.Config{Peers: cfg.Peers[1:]}, keys)
	if !strings.Contains(txt2, "public_key="+ha+"\nremove=true") {
		t.Errorf("removed peer not dropped:\n%s", txt2)
	}
}

func TestParse(t *testing.T) {
	out := Parse("private_key=aa\nlisten_port=1\npublic_key=bb\nendpoint=1.2.3.4:5\nlast_handshake_time_sec=100\nrx_bytes=7\ntx_bytes=9\npublic_key=cc\nlast_handshake_time_sec=0\n")
	if p := out["bb"]; p.Endpoint != "1.2.3.4:5" || p.LastHandshake.Unix() != 100 || p.RxBytes != 7 || p.TxBytes != 9 {
		t.Fatalf("bb: %+v", p)
	}
	if p := out["cc"]; !p.LastHandshake.IsZero() {
		t.Fatalf("cc: %+v", p)
	}
}
