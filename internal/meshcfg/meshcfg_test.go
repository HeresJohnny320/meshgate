package meshcfg

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/heresjohnny320/meshgate/internal/model"
	"github.com/heresjohnny320/meshgate/internal/pathsel"
)

var (
	network = model.Network{CIDR: "100.88.0.0/16"}
	phone   = model.Node{ID: "phone", Name: "phone", Kind: model.NodeClient, PublicKey: "Kp", MeshIP: "100.88.0.4"}
	home    = model.Node{ID: "home", Name: "home", Kind: model.NodeServer, PublicKey: "Kh", MeshIP: "100.88.0.2",
		Endpoints: []string{"192.168.1.10:51820"}, Routes: []string{"192.168.1.0/24"}}
	vps = model.Node{ID: "vps", Name: "vps", Kind: model.NodeServer, Relay: true, PublicKey: "Kv", MeshIP: "100.88.0.1",
		Endpoints: []string{"1.1.1.1:51820"}}
	nodes = []model.Node{phone, home, vps}
)

func peer(t *testing.T, c Config, id string) Peer {
	t.Helper()
	for _, p := range c.Peers {
		if p.NodeID == id {
			return p
		}
	}
	t.Fatalf("no peer %s", id)
	return Peer{}
}

func ips(p Peer) string {
	var s []string
	for _, a := range p.AllowedIPs {
		s = append(s, a.String())
	}
	return strings.Join(s, ",")
}

func TestPhoneViaRelayGetsHomeSubnetOnRelayPeer(t *testing.T) {
	c, err := Build(Input{Network: network, Self: phone, Nodes: nodes, Paths: pathsel.Result{
		HomeRelay: "vps",
		Paths:     map[string]pathsel.Path{"home": {Via: "vps"}, "vps": {Endpoint: "1.1.1.1:51820"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if got := ips(peer(t, c, "vps")); got != "100.88.0.1/32,100.88.0.2/32,192.168.1.0/24" {
		t.Fatalf("vps allowed = %s", got)
	}
	if got := ips(peer(t, c, "home")); got != "" {
		t.Fatalf("home allowed = %s", got)
	}
	if p := peer(t, c, "vps"); p.Keepalive == 0 || p.Endpoint != "1.1.1.1:51820" {
		t.Fatalf("vps peer %+v", p)
	}
	if len(c.Routes) != 1 || c.Routes[0].String() != "192.168.1.0/24" {
		t.Fatalf("routes %v", c.Routes)
	}
	if c.Address.String() != "100.88.0.4/16" {
		t.Fatalf("addr %s", c.Address)
	}
}

func TestPhoneOnHomeLANSkipsSubnet(t *testing.T) {
	c, _ := Build(Input{Network: network, Self: phone, Nodes: nodes,
		LocalAddrs: []netip.Addr{netip.MustParseAddr("192.168.1.77")},
		Paths: pathsel.Result{Paths: map[string]pathsel.Path{
			"home": {Endpoint: "192.168.1.10:51820"}, "vps": {Endpoint: "1.1.1.1:51820"}}}})
	if got := ips(peer(t, c, "home")); got != "100.88.0.2/32" {
		t.Fatalf("home allowed = %s", got)
	}
	if len(c.Routes) != 0 {
		t.Fatalf("routes %v", c.Routes)
	}
}

func TestPreserveClientIPGivesEdgeDefault(t *testing.T) {
	fw := []model.Forward{{ID: "mc", Name: "minecraft", Proto: model.ProtoTCP, EdgeNode: "vps", ListenPort: 25565,
		TargetNode: "home", TargetPort: 25565, PreserveClientIP: true, Enabled: true}}
	c, _ := Build(Input{Network: network, Self: home, Nodes: nodes, Forwards: fw, Paths: pathsel.Result{
		Paths: map[string]pathsel.Path{"vps": {Endpoint: "1.1.1.1:51820"}, "phone": {Via: "vps"}}}})
	if got := ips(peer(t, c, "vps")); got != "0.0.0.0/0,100.88.0.1/32,100.88.0.4/32" {
		t.Fatalf("vps allowed = %s", got)
	}
	if c.DefaultViaPeer != "vps" {
		t.Fatal("expected policy default via vps")
	}
}

func TestCafeWithHomeRangeKeepsSubnetInTunnel(t *testing.T) {
	// The café also uses 192.168.1.0/24, but home answers only via the relay.
	c, _ := Build(Input{Network: network, Self: phone, Nodes: nodes,
		LocalAddrs: []netip.Addr{netip.MustParseAddr("192.168.1.77")},
		Paths: pathsel.Result{Paths: map[string]pathsel.Path{
			"home": {Via: "vps"}, "vps": {Endpoint: "1.1.1.1:51820"}}}})
	if c.Home {
		t.Fatal("café LAN taken for home")
	}
	if got := ips(peer(t, c, "vps")); got != "100.88.0.1/32,100.88.0.2/32,192.168.1.0/24" {
		t.Fatalf("vps allowed = %s", got)
	}
	if len(c.Routes) != 1 || c.Routes[0].String() != "192.168.1.0/24" {
		t.Fatalf("routes %v", c.Routes)
	}
}

func exitInput(local string, homePath pathsel.Path) Input {
	p := phone
	p.ExitVia = "vps"
	v := vps
	v.Exit = true
	in := Input{Network: network, Self: p, Nodes: []model.Node{p, home, v}, ExitCapable: true,
		Paths: pathsel.Result{Paths: map[string]pathsel.Path{"home": homePath, "vps": {Endpoint: "1.1.1.1:51820"}}}}
	if local != "" {
		in.LocalAddrs = []netip.Addr{netip.MustParseAddr(local)}
	}
	return in
}

func TestExitNodeAway(t *testing.T) {
	c, _ := Build(exitInput("10.20.0.5", pathsel.Path{Via: "vps"}))
	if c.ExitVia != "vps" || c.Home {
		t.Fatalf("exit=%q home=%v", c.ExitVia, c.Home)
	}
	if got := ips(peer(t, c, "vps")); got != "0.0.0.0/0,100.88.0.1/32,100.88.0.2/32,192.168.1.0/24" {
		t.Fatalf("vps allowed = %s", got)
	}
	if got := c.Routes[0].String(); got != "0.0.0.0/0" {
		t.Fatalf("routes %v", c.Routes)
	}
}

func TestExitNodeNotUsedAtHome(t *testing.T) {
	c, _ := Build(exitInput("192.168.1.77", pathsel.Path{Endpoint: "192.168.1.10:51820"}))
	if !c.Home || c.ExitVia != "" {
		t.Fatalf("home=%v exit=%q", c.Home, c.ExitVia)
	}
	for _, r := range c.Routes {
		if r.Bits() == 0 {
			t.Fatalf("default route at home: %v", c.Routes)
		}
	}
}

func TestExitNodeNeedsCapablePlatform(t *testing.T) {
	in := exitInput("10.20.0.5", pathsel.Path{Via: "vps"})
	in.ExitCapable = false
	c, _ := Build(in)
	if c.ExitVia != "" || strings.Contains(ips(peer(t, c, "vps")), "0.0.0.0/0") || len(c.Warnings) == 0 {
		t.Fatalf("exit used on an incapable platform: %+v", c)
	}
}
