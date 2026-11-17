package fw

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/heresjohnny320/meshgate/internal/model"
)

// TestWriteGolden records inputs and the exact rules Go renders for them,
// so the Rust build can prove it renders the same bytes. Run with
// MESHGATE_GOLDEN=../rust/testdata (from go/) to refresh.
func TestWriteGolden(t *testing.T) {
	dir := os.Getenv("MESHGATE_GOLDEN")
	if dir == "" {
		t.Skip("MESHGATE_GOLDEN not set")
	}
	type out struct {
		Name     string
		Input    Input
		NFT      string
		PFNat    string
		PFRdr    string
		PFFilter string
		Iptables [][]string
		HostOpen []HostPort
		Warnings []string
	}
	var cases []out
	add := func(name string, i Input) {
		p := Build(i)
		for k := range p.LANs { // the host's interfaces must not leak into the files
			p.LANs[k].Iface = fmt.Sprintf("lan%d", k)
		}
		n, r, f := RenderPF(p)
		cases = append(cases, out{name, i, RenderNFT(p), n, r, f, p.IptablesRules(), p.HostOpen, p.Warnings})
	}
	routes := []model.HTTPRoute{{ID: "r", Hostname: "jellyfin.example.com", EdgeNode: "vps", TargetNode: "home", TargetPort: 8096, Enabled: true},
		{ID: "r2", Hostname: "nas.example.com", EdgeNode: "vps", TargetNode: "home", TargetIP: "192.168.1.20", TargetPort: 443, Enabled: true}}
	mons := []model.Monitor{
		{ID: "mc", Name: "survival", Node: "vps", IP: "192.168.1.51", Proto: "tcp", Ports: "25566"},
		{ID: "geyser", Name: "bedrock", Node: "vps", Proto: "both", Ports: "19132,25565-25570"},
		{ID: "nas", Name: "nas \"quoted\"", Node: "vps", IP: "192.168.1.0/24", Proto: "any"},
		{ID: "elsewhere", Name: "home only", Node: "home", Proto: "tcp", Ports: "80"},
	}
	for _, wan := range []string{"", "vtnet0"} {
		i := in(vps)
		i.WANIface = wan
		add("edge "+wan, i)
		i.Routes, i.Monitors, i.WebPort, i.TestPort = routes, mons, 8080, 8099
		add("edge full "+wan, i)
		for _, pol := range []string{"", model.PolicyRestricted, model.PolicyFirewall} {
			h := home
			h.LANPolicy = pol
			j := in(h)
			j.PreserveEdge, j.WANIface, j.Routes, j.WebPort = "vps", wan, routes, 8443
			add("home "+pol+" "+wan, j)
			j.Iface = "tun_mg0"
			j.TestPort = 8099
			add("home tun "+pol+" "+wan, j)
		}
		v := vps
		v.Exit = true
		ph := phone
		ph.ExitVia = "vps"
		lt := laptop
		lt.ExitsAllowed = []string{"vps2"}
		hm := home
		hm.LANExits = []model.LANExit{{Src: "192.168.1.205", Via: "vps"}}
		for _, pol := range []string{"", model.PolicyRestricted} {
			v.LANPolicy = pol
			k := in(v)
			k.Nodes = []model.Node{v, hm, ph, lt}
			k.WANIface = wan
			k.ExitRoutes = []model.ExitRoute{{ID: "x", Router: "laptop", Src: "10.1.0.0/24", Via: "vps", Enabled: true}}
			add("exit "+pol+" "+wan, k)
		}
		l := in(home)
		l.WANIface = wan
		l.LANExitSrcs, l.LANExitGW = []string{"192.168.1.205/32", "192.168.20.0/24", "bad", "2001:db8::/32"}, "100.88.0.1"
		add("lanexit "+wan, l)
		l.LANExitGW, l.LANExitSrcs, l.LANExitBlock = "", nil, []string{"192.168.1.205/32", "192.168.20.9/24"}
		add("lanexit down "+wan, l)
		r := home
		r.LANPolicy = model.PolicyRestricted
		m := in(r)
		m.WANIface = wan
		m.ACLs = append(m.ACLs, model.ACL{ID: "g-1", Name: "game", Node: "home", From: []string{"laptop"}, To: "192.168.1.205", Proto: "both", Ports: "27015-27030", Enabled: true},
			model.ACL{ID: "bad", Name: "broken", Node: "home", To: "x", Proto: "tcp", Enabled: true})
		add("acl both "+wan, m)
	}
	b, _ := json.MarshalIndent(cases, "", " ")
	if err := os.WriteFile(filepath.Join(dir, "fw.json"), b, 0o644); err != nil {
		t.Fatal(err)
	}
}
