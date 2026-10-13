package fw

import (
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/heresjohnny320/meshgate/internal/model"
)

var (
	network = model.Network{CIDR: "100.88.0.0/16"}
	vps     = model.Node{ID: "vps", MeshIP: "100.88.0.1", Relay: true, Endpoints: []string{"1.2.3.4:51820"}}
	home    = model.Node{ID: "home", MeshIP: "100.88.0.2", Routes: []string{"192.168.1.0/24"}}
	phone   = model.Node{ID: "phone", MeshIP: "100.88.0.4"}
	laptop  = model.Node{ID: "laptop", MeshIP: "100.88.0.5"}
	nodes   = []model.Node{vps, home, phone, laptop}
	fwds    = []model.Forward{
		{ID: "1", Name: "minecraft", Proto: model.ProtoTCP, EdgeNode: "vps", ListenPort: 25565, TargetNode: "home", TargetPort: 25565, PreserveClientIP: true, Enabled: true},
		{ID: "2", Name: "valheim", Proto: model.ProtoUDP, EdgeNode: "vps", ListenPort: 2456, ListenEnd: 2458, TargetNode: "home", TargetPort: 2456, Enabled: true},
		{ID: "3", Name: "nas-web", Proto: model.ProtoBoth, EdgeNode: "vps", ListenPort: 8443, TargetNode: "home", TargetIP: "192.168.1.20", TargetPort: 443, Enabled: true},
		{ID: "4", Name: "off", Proto: model.ProtoTCP, EdgeNode: "vps", ListenPort: 7777, TargetNode: "home", TargetPort: 7777},
		{ID: "5", Name: "old minecraft", Proto: model.ProtoTCP, EdgeNode: "vps", ListenPort: 25565, TargetNode: "home", TargetPort: 25566},
	}
	acls = []model.ACL{
		{ID: "a", Name: "laptop to nas", Node: "home", From: []string{"laptop"}, To: "192.168.1.20", Proto: "tcp", Ports: "80,443,8000-8100", Enabled: true},
		{ID: "b", Name: "anyone to iot vlan dns", Node: "home", To: "192.168.20.0/24", Proto: "udp", Ports: "53", Enabled: true},
		{ID: "c", Name: "ping home", Node: "home", From: []string{"phone"}, To: "self", Proto: "icmp", Enabled: true},
		{ID: "d", Name: "gone device", Node: "home", From: []string{"deleted"}, To: "self", Proto: "any", Enabled: true},
	}
)

func in(self model.Node) Input {
	return Input{Iface: "mg0", Network: network, Self: self, Nodes: nodes, Forwards: fwds, ACLs: acls,
		WGPort: 51820, ProbePort: 51822, MeshPort: 51823, JoinPort: 51821}
}

func TestEdgeRules(t *testing.T) {
	p := Build(in(vps))
	s := RenderNFT(p)
	for _, want := range []string{
		`iifname != "mg0" fib daddr type local meta l4proto tcp th dport 25565 ct mark set 0x4d48 dnat ip to 100.88.0.2:25565`,
		`meta l4proto udp th dport 2456-2458 dnat ip to 100.88.0.2 `,
		`meta l4proto tcp th dport 8443 dnat ip to 192.168.1.20:443`,
		`meta l4proto udp th dport 8443 dnat ip to 192.168.1.20:443`,
		`oifname "mg0" ct status dnat ct mark != 0x4d48 masquerade`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in\n%s", want, s)
		}
	}
	if strings.Contains(s, "dnat ip to 100.88.0.2:7777") || strings.Contains(s, "lan_in") {
		t.Error("disabled forward or lockdown rendered on open edge")
	}
	if !strings.Contains(s, `meta l4proto tcp th dport 7777 drop comment "disabled: off"`) {
		t.Errorf("disabled forward not blocked:\n%s", s)
	}
	if strings.Contains(s, "th dport 25565 drop") {
		t.Error("blocked a port that an enabled forward uses")
	}
	nftCheck(t, s)
}

func TestTargetOpen(t *testing.T) {
	i := in(home)
	i.PreserveEdge = "vps"
	s := RenderNFT(Build(i))
	for _, want := range []string{
		`iifname "mg0" oifname != "mg0" ip daddr { 192.168.1.0/24 } masquerade`,
		`iifname "mg0" ip saddr != 100.88.0.0/16 ct state new ct mark set 0x4d47`,
		`ct mark 0x4d47 meta mark set 0x4d47`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in\n%s", want, s)
		}
	}
	if strings.Contains(s, "dnat") || strings.Contains(s, "drop") {
		t.Error("open target must not dnat or drop")
	}
	nftCheck(t, s)
}

func TestTargetRestricted(t *testing.T) {
	h := home
	h.LANPolicy = model.PolicyRestricted
	i := in(h)
	i.PreserveEdge = "vps"
	p := Build(i)
	if len(p.Warnings) != 1 || !strings.Contains(p.Warnings[0], "gone device") {
		t.Fatalf("warnings %v", p.Warnings)
	}
	s := RenderNFT(p)
	for _, want := range []string{
		// LAN host rule, ports list incl. range
		`iifname "mg0" ip saddr { 100.88.0.5 } ip daddr 192.168.1.20/32 meta l4proto tcp th dport { 80, 443, 8000-8100 } counter name "a_a" accept`,
		// VLAN subnet for anyone
		`iifname "mg0" ip daddr 192.168.20.0/24 meta l4proto udp th dport { 53 } counter name "a_b" accept`,
		// self rule (input chain has no daddr)
		`iifname "mg0" ip saddr { 100.88.0.4 } meta l4proto icmp counter name "a_c" accept`,
		// forwards ending here are allowed automatically
		`iifname "mg0" meta l4proto tcp th dport { 25565 } accept comment "forward minecraft"`,
		`iifname "mg0" ip daddr 192.168.1.20/32 meta l4proto tcp th dport { 443 } accept comment "forward nas-web"`,
		// meshgate sync stays reachable
		`iifname "mg0" ip saddr { 100.88.0.0/16 } meta l4proto tcp th dport { 51823 } accept`,
		`iifname "mg0" oifname "mg0" accept`,
		`iifname "mg0" drop`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in\n%s", want, s)
		}
	}
	if strings.Contains(s, "deleted") || strings.Contains(s, `comment "rule gone device"`) {
		t.Error("rule with only deleted devices must not become an allow-all")
	}
	nftCheck(t, s)
}

func TestPFRestrictedTarget(t *testing.T) {
	h := home
	h.LANPolicy = model.PolicyRestricted
	i := in(h)
	i.PreserveEdge = "vps"
	i.WANIface = "igb0"
	p := Build(i)
	p.LANs = []LANRoute{{CIDR: "192.168.1.0/24", Iface: "igb1"}}
	nat, _, filter := RenderPF(p)
	for _, want := range []string{
		"nat on igb1 inet from 100.88.0.0/16 to 192.168.1.0/24 -> (igb1:0)",
	} {
		if !strings.Contains(nat, want) {
			t.Errorf("nat missing %q in\n%s", want, nat)
		}
	}
	for _, want := range []string{
		"pass in quick on mg0 reply-to (mg0 100.88.0.1) inet proto tcp from ! 100.88.0.0/16 to self port { 25565 } keep state",
		"pass in quick on mg0 inet proto icmp from { 100.88.0.4 } to self keep state",
		"block in quick on mg0 inet from any to self",
		"pass in quick on mg0 inet from 100.88.0.0/16 to 100.88.0.0/16 keep state",
		"pass in quick on mg0 inet proto tcp from { 100.88.0.5 } to 192.168.1.20/32 port { 80, 443, 8000:8100 } keep state",
		"block in quick on mg0 all",
	} {
		if !strings.Contains(filter, want) {
			t.Errorf("filter missing %q in\n%s", want, filter)
		}
	}
	// Self rules must come before the self block, LAN rules after it.
	if strings.Index(filter, "proto icmp") > strings.Index(filter, "to self #") {
		t.Error("self rule after block")
	}
}

func TestPFFirewallManaged(t *testing.T) {
	h := home
	h.LANPolicy = model.PolicyFirewall
	i := in(h)
	i.Iface = "tun_mg0"
	i.PreserveEdge = "vps"
	i.WANIface = "igb0"
	p := Build(i)
	p.LANs = []LANRoute{{CIDR: "192.168.1.0/24", Iface: "igb1"}}
	nat, _, filter := RenderPF(p)
	if !strings.Contains(nat, "nat on igb1 inet from 100.88.0.0/16 to 192.168.1.0/24") {
		t.Errorf("LAN nat missing:\n%s", nat)
	}
	for _, want := range []string{
		"pass in quick on tun_mg0 reply-to (tun_mg0 100.88.0.1) inet proto tcp from ! 100.88.0.0/16 to self port { 25565 }",
		"pass in quick on tun_mg0 inet proto tcp from { 100.88.0.0/16 } to self port { 51823 } keep state # meshgate sync",
	} {
		if !strings.Contains(filter, want) {
			t.Errorf("filter missing %q in\n%s", want, filter)
		}
	}
	// pfSense GUI rules decide everything else: no blanket pass/block, no ACLs.
	for _, bad := range []string{"block in quick on tun_mg0", "pass in quick on tun_mg0 all", "laptop to nas", "192.168.1.20"} {
		if strings.Contains(filter, bad) {
			t.Errorf("firewall-managed filter contains %q:\n%s", bad, filter)
		}
	}
}

func TestPFEdge(t *testing.T) {
	i := in(vps)
	i.WANIface = "vtnet0"
	nat, rdr, filter := RenderPF(Build(i))
	for _, want := range []string{
		"nat on mg0 inet proto udp from ! 100.88.0.0/16 to 100.88.0.2 port 2456:2458 -> (mg0:0)",
		"nat on mg0 inet proto tcp from ! 100.88.0.0/16 to 192.168.1.20 port 443 -> (mg0:0)",
	} {
		if !strings.Contains(nat, want) {
			t.Errorf("nat missing %q in\n%s", want, nat)
		}
	}
	for _, want := range []string{
		"rdr pass on vtnet0 inet proto tcp from any to (vtnet0) port 25565 -> 100.88.0.2 port 25565",
		"rdr pass on vtnet0 inet proto udp from any to (vtnet0) port 2456:2458 -> 100.88.0.2 port 2456:*",
	} {
		if !strings.Contains(rdr, want) {
			t.Errorf("rdr missing %q in\n%s", want, rdr)
		}
	}
	if !strings.Contains(filter, "block drop in quick on vtnet0 inet proto tcp from any to (vtnet0) port 7777") {
		t.Errorf("pf: disabled forward not blocked:\n%s", filter)
	}
	if strings.Contains(nat, "to 100.88.0.2 port 25565 ->") {
		t.Error("preserve-IP forward must not be masqueraded")
	}
	if strings.Contains(nat, "rdr ") || strings.Contains(rdr, "nat on") {
		t.Error("nat and rdr rules must be rendered separately")
	}
	for _, want := range []string{
		"pass in quick on vtnet0 inet proto udp from any to (vtnet0) port { 51820, 51822 } keep state",
		"pass in quick on vtnet0 inet proto tcp from any to (vtnet0) port { 51821 } keep state",
		"pass in quick on mg0 all keep state",
	} {
		if !strings.Contains(filter, want) {
			t.Errorf("filter missing %q in\n%s", want, filter)
		}
	}
}

// nftCheck validates syntax with `nft -c` inside an unprivileged network
// namespace when the host allows it.
func nftCheck(t *testing.T, script string) {
	t.Helper()
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("nft not installed")
	}
	if _, err := exec.LookPath("unshare"); err != nil {
		t.Skip("unshare not installed")
	}
	f, _ := os.CreateTemp(t.TempDir(), "*.nft")
	// The leading "delete table" fails on an empty namespace under -c, so
	// check only the table definition.
	body := script[strings.Index(script, "table inet meshgate {"):]
	f.WriteString(body)
	f.Close()
	out, err := exec.Command("unshare", "-rn", "nft", "-c", "-f", f.Name()).CombinedOutput()
	if err != nil {
		if strings.Contains(string(out), "Operation not permitted") || strings.Contains(string(out), "unshare failed") {
			t.Skipf("cannot create netns: %s", out)
		}
		t.Fatalf("nft -c: %v\n%s\n%s", err, out, body)
	}
}

func TestExitNode(t *testing.T) {
	v := vps
	v.Exit = true
	ph := phone
	ph.ExitVia = "vps"
	i := in(v)
	i.Nodes = []model.Node{v, home, ph, laptop}
	s := RenderNFT(Build(i))
	if !strings.Contains(s, `iifname "mg0" oifname != "mg0" ip saddr { 100.88.0.4 } masquerade comment "exit node"`) {
		t.Errorf("exit masquerade missing:\n%s", s)
	}
	nftCheck(t, s)

	// Restricted exit node: internet only, never its private networks.
	v.LANPolicy = model.PolicyRestricted
	i = in(v)
	i.Nodes = []model.Node{v, home, ph, laptop}
	s = RenderNFT(Build(i))
	if !strings.Contains(s, `ip saddr { 100.88.0.4 } ip daddr != { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10, 169.254.0.0/16 } accept`) {
		t.Errorf("restricted exit forward missing:\n%s", s)
	}
	nftCheck(t, s)

	i.WANIface = "igb0"
	nat, _, filter := RenderPF(Build(i))
	for _, want := range []string{"nat on igb0 inet from { 100.88.0.4 } to any -> (igb0:0)"} {
		if !strings.Contains(nat, want) {
			t.Errorf("pf nat missing %q:\n%s", want, nat)
		}
	}
	if !strings.HasPrefix(filter, "table <meshgate_private> const") ||
		!strings.Contains(filter, "pass in quick on mg0 inet from { 100.88.0.4 } to ! <meshgate_private> keep state") {
		t.Errorf("pf exit filter wrong:\n%s", filter)
	}

	// Not offered as exit: nothing, even if a device still points at it.
	v.Exit = false
	i = in(v)
	i.Nodes = []model.Node{v, home, ph}
	if s := RenderNFT(Build(i)); strings.Contains(s, "exit node") {
		t.Errorf("exit rules on a node that is not an exit:\n%s", s)
	}
}

func TestIsTunnel(t *testing.T) {
	for _, c := range []struct {
		name  string
		flags net.Flags
		want  bool
	}{
		{"wg0", net.FlagUp, true},
		{"tun_wg0", net.FlagUp, true}, // pfSense WireGuard package
		{"ovpns1", net.FlagUp, true},
		{"tailscale0", net.FlagUp, true},
		{"myvpn", net.FlagUp | net.FlagPointToPoint, true},
		{"eth0", net.FlagUp | net.FlagBroadcast, false},
		{"igb1.20", net.FlagUp | net.FlagBroadcast, false},
		{"br0", net.FlagUp | net.FlagBroadcast, false},
	} {
		if got := IsTunnel(c.name, c.flags); got != c.want {
			t.Errorf("IsTunnel(%q) = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestTestServiceStaysReachable(t *testing.T) {
	h := home
	h.LANPolicy = model.PolicyFirewall
	i := in(h)
	i.TestPort = 8099
	_, _, filter := RenderPF(Build(i))
	for _, want := range []string{
		"pass in quick on mg0 inet proto tcp from any to self port { 8099 } keep state # meshgate test service",
		"pass in quick on mg0 inet proto udp from any to self port { 8099 } keep state # meshgate test service",
	} {
		if !strings.Contains(filter, want) {
			t.Errorf("missing %q:\n%s", want, filter)
		}
	}
	h.LANPolicy = model.PolicyRestricted
	i = in(h)
	i.TestPort = 8099
	s := RenderNFT(Build(i))
	if !strings.Contains(s, `meta l4proto udp th dport { 8099 } accept comment "meshgate test service"`) {
		t.Errorf("restricted nft lacks test service:\n%s", s)
	}
	nftCheck(t, s)
}

func TestForwardCounters(t *testing.T) {
	s := RenderNFT(Build(in(vps)))
	for _, want := range []string{
		"\tcounter f_1_in {\n\t}",
		`meta l4proto tcp ct status dnat ct original proto-dst 25565 ct direction original counter name "f_1_in"`,
		`meta l4proto tcp ct status dnat ct original proto-dst 25565 ct direction reply counter name "f_1_out"`,
		`meta l4proto udp ct status dnat ct original proto-dst 2456-2458 ct direction reply counter name "f_2_out"`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in\n%s", want, s)
		}
	}
	nftCheck(t, s)
}

func TestRuleTCPAndUDP(t *testing.T) {
	h := home
	h.LANPolicy = model.PolicyRestricted
	i := in(h)
	i.ACLs = []model.ACL{{ID: "g", Name: "game", Node: "home", From: []string{"laptop"}, To: "192.168.1.205", Proto: "both", Ports: "27015-27030", Enabled: true}}
	if err := i.ACLs[0].Validate(); err != nil {
		t.Fatal(err)
	}
	s := RenderNFT(Build(i))
	for _, pr := range []string{"tcp", "udp"} {
		want := `ip saddr { 100.88.0.5 } ip daddr 192.168.1.205/32 meta l4proto ` + pr + ` th dport { 27015-27030 } counter name "a_g" accept`
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in\n%s", want, s)
		}
	}
	if strings.Count(s, "counter a_g {") != 1 {
		t.Errorf("counter object not declared exactly once:\n%s", s)
	}
	nftCheck(t, s)
	_, _, filter := RenderPF(Build(i))
	for _, pr := range []string{"tcp", "udp"} {
		if !strings.Contains(filter, "inet proto "+pr+" from { 100.88.0.5 } to 192.168.1.205/32 port { 27015:27030 }") {
			t.Errorf("pf missing %s rule:\n%s", pr, filter)
		}
	}
}
