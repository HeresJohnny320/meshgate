package pathsel

import (
	"testing"
	"time"

	"github.com/heresjohnny320/meshgate/internal/model"
)

var (
	now   = time.Unix(100000, 0)
	phone = model.Node{ID: "phone", Kind: model.NodeClient}
	home  = model.Node{ID: "home", Kind: model.NodeServer, Endpoints: []string{"192.168.1.10:51820"}, Routes: []string{"192.168.1.0/24"}}
	vps1  = model.Node{ID: "vps1", Kind: model.NodeServer, Relay: true, Endpoints: []string{"1.1.1.1:51820"}}
	vps2  = model.Node{ID: "vps2", Kind: model.NodeServer, Relay: true, Endpoints: []string{"2.2.2.2:51820"}}
	nodes = []model.Node{phone, home, vps1, vps2}
)

func ok(rtt int) Probe {
	return Probe{LastOK: now.Add(-time.Second), RTT: time.Duration(rtt) * time.Millisecond}
}

func TestPhoneOnHomeWifiGoesDirect(t *testing.T) {
	r := Decide(Input{Self: phone, Nodes: nodes, Now: now, Probes: map[string]Probe{
		"192.168.1.10:51820": ok(2), "1.1.1.1:51820": ok(30), "2.2.2.2:51820": ok(60),
	}})
	if p := r.Paths["home"]; !p.Direct() || p.Endpoint != "192.168.1.10:51820" {
		t.Fatalf("phone->home = %+v", p)
	}
	// Home sees the phone's probes and goes direct as well.
	h := Decide(Input{Self: home, Nodes: nodes, Now: now, Inbound: map[string]time.Time{"phone": now.Add(-2 * time.Second)},
		Probes: map[string]Probe{"1.1.1.1:51820": ok(30), "2.2.2.2:51820": ok(40)}})
	if p := h.Paths["phone"]; !p.Direct() || p.Endpoint != "" {
		t.Fatalf("home->phone = %+v", p)
	}
}

func TestPhoneOnLTEUsesNearestRelaySymmetrically(t *testing.T) {
	r := Decide(Input{Self: phone, Nodes: nodes, Now: now, Probes: map[string]Probe{
		"1.1.1.1:51820": ok(80), "2.2.2.2:51820": ok(20),
	}})
	if r.HomeRelay != "vps2" {
		t.Fatalf("home relay %q", r.HomeRelay)
	}
	if p := r.Paths["home"]; p.Via != "vps2" {
		t.Fatalf("phone->home = %+v", p)
	}
	// Home prefers vps1 for itself, but the phone anchors the pair.
	h := Decide(Input{Self: home, Nodes: nodes, Now: now,
		Statuses: map[string]model.Status{"phone": {NodeID: "phone", HomeRelay: r.HomeRelay}},
		Probes:   map[string]Probe{"1.1.1.1:51820": ok(5), "2.2.2.2:51820": ok(50)}})
	if h.HomeRelay != "vps1" {
		t.Fatalf("home's own relay %q", h.HomeRelay)
	}
	if p := h.Paths["phone"]; p.Via != "vps2" {
		t.Fatalf("home->phone = %+v (asymmetric)", p)
	}
	// Relays are always direct.
	if p := h.Paths["vps2"]; !p.Direct() || p.Endpoint != "2.2.2.2:51820" {
		t.Fatalf("home->vps2 = %+v", p)
	}
}

func TestRelayTalksDirectToEveryone(t *testing.T) {
	r := Decide(Input{Self: vps1, Nodes: nodes, Now: now})
	for _, id := range []string{"phone", "home", "vps2"} {
		if !r.Paths[id].Direct() {
			t.Fatalf("relay->%s not direct: %+v", id, r.Paths[id])
		}
	}
	if r.HomeRelay != "" {
		t.Fatal("relays have no home relay")
	}
}

func TestHomeRelayHysteresis(t *testing.T) {
	prev := &Result{HomeRelay: "vps1", Paths: map[string]Path{}}
	// vps2 is slightly faster: stay.
	r := Decide(Input{Self: phone, Nodes: nodes, Now: now, Prev: prev, Probes: map[string]Probe{
		"1.1.1.1:51820": ok(30), "2.2.2.2:51820": ok(26),
	}})
	if r.HomeRelay != "vps1" {
		t.Fatalf("flapped to %q", r.HomeRelay)
	}
	// vps2 is much faster: switch.
	r = Decide(Input{Self: phone, Nodes: nodes, Now: now, Prev: prev, Probes: map[string]Probe{
		"1.1.1.1:51820": ok(60), "2.2.2.2:51820": ok(15),
	}})
	if r.HomeRelay != "vps2" {
		t.Fatalf("did not switch: %q", r.HomeRelay)
	}
	// vps1 died: switch even though prev.
	r = Decide(Input{Self: phone, Nodes: nodes, Now: now, Prev: prev, Probes: map[string]Probe{
		"1.1.1.1:51820": {LastOK: now.Add(-time.Minute)}, "2.2.2.2:51820": ok(90),
	}})
	if r.HomeRelay != "vps2" {
		t.Fatalf("did not fail over: %q", r.HomeRelay)
	}
}

func TestStaticDeviceRoutedViaItsRelay(t *testing.T) {
	static := model.Node{ID: "laptop", Kind: model.NodeStatic, ViaRelay: "vps1"}
	all := append(append([]model.Node{}, nodes...), static)
	h := Decide(Input{Self: home, Nodes: all, Now: now})
	if p := h.Paths["laptop"]; p.Via != "vps1" {
		t.Fatalf("home->static = %+v", p)
	}
	v := Decide(Input{Self: vps1, Nodes: all, Now: now})
	if p := v.Paths["laptop"]; !p.Direct() {
		t.Fatalf("vps1->static = %+v", p)
	}
	v2 := Decide(Input{Self: vps2, Nodes: all, Now: now})
	if p := v2.Paths["laptop"]; p.Via != "vps1" {
		t.Fatalf("vps2->static = %+v", p)
	}
}

func TestAnchorSymmetric(t *testing.T) {
	pairs := [][2]model.Node{{phone, home}, {home, vps1}, {vps1, vps2}}
	for _, p := range pairs {
		if Anchor(p[0], p[1]).ID != Anchor(p[1], p[0]).ID {
			t.Fatalf("anchor not symmetric for %s/%s", p[0].ID, p[1].ID)
		}
	}
}
