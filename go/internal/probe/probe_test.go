package probe

import (
	"context"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"
)

func TestProbeRoundTrip(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mesh := netip.MustParsePrefix("100.88.0.0/16")

	// Find a free port pair: WireGuard port N, probe port N+2.
	l, _ := net.ListenPacket("udp4", "127.0.0.1:0")
	probePort := l.LocalAddr().(*net.UDPAddr).Port
	l.Close()
	wgPort := probePort - Offset

	server := New("home", mesh, nil)
	go server.Serve(ctx, probePort)
	time.Sleep(50 * time.Millisecond)

	client := New("phone", mesh, nil)
	ep := net.JoinHostPort("127.0.0.1", strconv.Itoa(wgPort))
	go client.Run(ctx, func() []Target { return []Target{{NodeID: "home", Endpoint: ep}} })

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		res, _ := client.Snapshot()
		_, in := server.Snapshot()
		if r, ok := res[ep]; ok && !r.LastOK.IsZero() && !in["phone"].IsZero() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("probe did not complete")
}

func TestParseRejectsGarbage(t *testing.T) {
	if _, _, _, _, ok := parse([]byte("MGP1\x01short")); ok {
		t.Fatal("parsed garbage")
	}
	b := encode(typeReq, 42, "a", "bb")
	typ, n, s, tg, ok := parse(b)
	if !ok || typ != typeReq || n != 42 || s != "a" || tg != "bb" {
		t.Fatal("round trip failed")
	}
}

// Probes that arrive through the tunnel (mesh source) must not be answered,
// otherwise a phone on LTE would think the home LAN endpoint is direct.
func TestMeshSourcedProbeIgnored(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	l, _ := net.ListenPacket("udp4", "127.0.0.1:0")
	probePort := l.LocalAddr().(*net.UDPAddr).Port
	l.Close()
	server := New("home", netip.MustParsePrefix("127.0.0.0/8"), nil)
	go server.Serve(ctx, probePort)
	time.Sleep(50 * time.Millisecond)
	client := New("phone", netip.MustParsePrefix("127.0.0.0/8"), nil)
	ep := net.JoinHostPort("127.0.0.1", strconv.Itoa(probePort-Offset))
	go client.Run(ctx, func() []Target { return []Target{{NodeID: "home", Endpoint: ep}} })
	time.Sleep(300 * time.Millisecond)
	if res, _ := client.Snapshot(); !res[ep].LastOK.IsZero() {
		t.Fatal("server answered a probe from inside the mesh")
	}
	if _, in := server.Snapshot(); !in["phone"].IsZero() {
		t.Fatal("mesh-sourced probe counted as inbound direct")
	}
}

func TestBootIDChangeDetected(t *testing.T) {
	p := New("me", netip.MustParsePrefix("100.88.0.0/16"), nil)
	feed := func(nonce uint64, boot string) {
		p.mu.Lock()
		p.pending[nonce] = pending{endpoint: "x:1", sent: time.Now()}
		p.mu.Unlock()
		p.handleResponse(encode(typeResp, nonce, "peer", boot), time.Now())
	}
	feed(1, "a")
	feed(2, "a")
	if r := p.TakeRestarted(); len(r) != 0 {
		t.Fatalf("false restart: %v", r)
	}
	feed(3, "b")
	if r := p.TakeRestarted(); len(r) != 1 || r[0] != "peer" {
		t.Fatalf("restart not detected: %v", r)
	}
	// Unsolicited responses are ignored entirely.
	p.handleResponse(encode(typeResp, 99, "peer", "c"), time.Now())
	if r := p.TakeRestarted(); len(r) != 0 {
		t.Fatalf("unsolicited response counted: %v", r)
	}
}
