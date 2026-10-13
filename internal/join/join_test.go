package join

import (
	"context"
	"crypto/tls"
	"net"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/heresjohnny320/meshgate/internal/model"
	"github.com/heresjohnny320/meshgate/internal/store"
)

func newMesh(t *testing.T) *store.Store {
	t.Helper()
	s, _ := store.Open("", "srv")
	s.Put(model.Key(model.KindNetwork, "main"), model.Network{CIDR: "100.88.0.0/16"}, store.Cluster)
	s.Put(model.Key(model.KindNode, "srv"), model.Node{ID: "srv", Name: "vps", Kind: model.NodeServer,
		MeshIP: "100.88.0.1", JoinAddr: "x:1", JoinFP: "ab", Relay: true, Endpoints: []string{"1.1.1.1:51820"}}, store.Cluster)
	s.Put(model.Key(model.KindAdmin, "admin"), model.Admin{Username: "admin", PasswordHash: "secret-hash"}, store.Cluster)
	return s
}

func pub() string { k, _ := wgtypes.GeneratePrivateKey(); return k.PublicKey().String() }

func TestTokenLifecycle(t *testing.T) {
	s := newMesh(t)
	str, _, err := NewToken(s, model.NodeClient, 1, time.Hour, "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	tok, err := Decode(str)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Admit(s, Request{TokenID: tok.ID, Secret: "wrong", Name: "x", PublicKey: pub()}, time.Now()); err == nil {
		t.Fatal("wrong secret accepted")
	}
	if _, err := Admit(s, Request{TokenID: tok.ID, Secret: tok.Secret, Name: "box", Kind: model.NodeServer, PublicKey: pub()}, time.Now()); err == nil {
		t.Fatal("client token admitted a server")
	}
	resp, err := Admit(s, Request{TokenID: tok.ID, Secret: tok.Secret, Name: "phone", PublicKey: pub()}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if resp.Node.Kind != model.NodeClient || resp.APISecret == "" || resp.Node.MeshIP == "" {
		t.Fatalf("bad response %+v", resp.Node)
	}
	for _, e := range resp.Entries {
		if k, _ := model.SplitKey(e.Key); k == model.KindAdmin || k == model.KindToken {
			t.Fatalf("client received %s", e.Key)
		}
	}
	if _, err := Admit(s, Request{TokenID: tok.ID, Secret: tok.Secret, Name: "phone2", PublicKey: pub()}, time.Now()); err == nil {
		t.Fatal("single-use token reused")
	}
	exp, _, _ := NewToken(s, model.NodeClient, 5, time.Minute, "", time.Now())
	et, _ := Decode(exp)
	if _, err := Admit(s, Request{TokenID: et.ID, Secret: et.Secret, Name: "late", PublicKey: pub()}, time.Now().Add(2*time.Minute)); err == nil {
		t.Fatal("expired token accepted")
	}
}

func TestAllocateIPAvoidsUsed(t *testing.T) {
	netw := model.Network{CIDR: "10.9.0.0/30"} // 2 usable addresses
	a, err := AllocateIP(netw, []model.Node{{MeshIP: "10.9.0.1"}})
	if err != nil || a.String() != "10.9.0.2" {
		t.Fatalf("got %v %v", a, err)
	}
	if _, err := AllocateIP(netw, []model.Node{{MeshIP: "10.9.0.1"}, {MeshIP: "10.9.0.2"}}); err == nil {
		t.Fatal("expected full")
	}
}

// End to end over TLS: pinned certificate, then client sync with its secret.
func TestJoinAndClientSyncOverTLS(t *testing.T) {
	s := newMesh(t)
	dir := t.TempDir()
	cert, fp, err := EnsureCert(dir+"/c.crt", dir+"/c.key")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(Handler(s))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	srv.StartTLS()
	defer srv.Close()
	addr := srv.Listener.Addr().String()

	str, _, _ := NewToken(s, model.NodeClient, 1, 0, "", time.Now())
	tok, _ := Decode(str)
	tok.Servers = []Server{{Addr: addr, FP: fp}}
	var d net.Dialer
	ctx := context.Background()
	resp, err := Do(ctx, tok, Request{Name: "phone", Kind: model.NodeClient, PublicKey: pub()}, d.DialContext)
	if err != nil {
		t.Fatal(err)
	}

	// Wrong fingerprint must fail (no MITM).
	bad := tok
	bad.Servers = []Server{{Addr: addr, FP: "00"}}
	if _, err := Do(ctx, bad, Request{Name: "x", PublicKey: pub()}, d.DialContext); err == nil {
		t.Fatal("pinning not enforced")
	}

	st := store.Entry{Key: model.Key(model.KindStatus, resp.Node.ID), Value: []byte(`{"node_id":"` + resp.Node.ID + `","home_relay":"srv"}`), Version: 1 << 60, Origin: resp.Node.ID}
	evil := store.Entry{Key: model.Key(model.KindForward, "evil"), Value: []byte(`{}`), Version: 1 << 60, Origin: resp.Node.ID}
	srvInfo := Server{Addr: addr, FP: fp}
	out, err := SyncClient(ctx, srvInfo, resp.Node.ID, resp.APISecret, ClientSync{Entries: []store.Entry{st, evil}}, d.DialContext)
	if err != nil {
		t.Fatal(err)
	}
	if out.Since == 0 || len(out.Entries) == 0 {
		t.Fatal("no entries returned")
	}
	if got, ok := store.Get[model.Status](s, model.Key(model.KindStatus, resp.Node.ID)); !ok || got.HomeRelay != "srv" {
		t.Fatal("status not stored")
	}
	if _, ok := s.Raw(model.Key(model.KindForward, "evil")); ok {
		t.Fatal("client wrote config")
	}
	if _, err := SyncClient(ctx, srvInfo, resp.Node.ID, "wrong", ClientSync{}, d.DialContext); err == nil {
		t.Fatal("bad secret accepted")
	}
}

// A phone token plus a server's (public) key must not return the server's
// snapshot, which holds the admin password hash.
func TestRetriedJoinCannotBorrowServerIdentity(t *testing.T) {
	s := newMesh(t)
	serverKey := pub()
	s.Put(model.Key(model.KindNode, "srv"), model.Node{ID: "srv", Name: "vps", Kind: model.NodeServer, PublicKey: serverKey,
		MeshIP: "100.88.0.1", JoinAddr: "x:1", JoinFP: "ab", Relay: true, Endpoints: []string{"1.1.1.1:51820"}}, store.Cluster)
	str, _, _ := NewToken(s, model.NodeClient, 5, time.Hour, "", time.Now())
	tok, _ := Decode(str)
	resp, err := Admit(s, Request{TokenID: tok.ID, Secret: tok.Secret, Name: "evil", PublicKey: serverKey}, time.Now())
	if err == nil {
		t.Fatalf("phone token returned the server's identity: %+v", resp.Node)
	}
	for _, e := range resp.Entries {
		if strings.HasPrefix(e.Key, model.KindAdmin) {
			t.Fatal("admin hash leaked")
		}
	}
}

func TestJoinRejectsBadInput(t *testing.T) {
	s := newMesh(t)
	str, _, _ := NewToken(s, model.NodeServer, 10, time.Hour, "", time.Now())
	tok, _ := Decode(str)
	for _, req := range []Request{
		{Name: "evil\x1b[2Jname"},
		{Name: "rtl‮txt.exe"},
		{Name: "ok", Endpoints: []string{"1.2.3.4:51820\nallowed_ip=0.0.0.0/0"}},
		{Name: "ok2", Endpoints: []string{"1.2.3.4:99999"}},
		{Name: "ok3", LANPolicy: "wide-open"},
	} {
		req.TokenID, req.Secret, req.PublicKey, req.Kind = tok.ID, tok.Secret, pub(), model.NodeServer
		if _, err := Admit(s, req, time.Now()); err == nil {
			t.Errorf("accepted %+v", req)
		}
	}
}
