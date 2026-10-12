package syncer

import (
	"context"
	"net"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/heresjohnny320/meshgate/internal/model"
	"github.com/heresjohnny320/meshgate/internal/store"
)

// A client may only publish its own status; servers accept the rest.
func TestClientPushIsRestricted(t *testing.T) {
	srvStore, _ := store.Open("", "srv")
	srv := New(srvStore, "srv", 0)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	_, portStr, _ := net.SplitHostPort(ts.Listener.Addr().String())
	port, _ := strconv.Atoi(portStr)

	server := model.Node{ID: "srv", Kind: model.NodeServer, MeshIP: "127.0.0.1"}
	phone := model.Node{ID: "phone", Kind: model.NodeClient, MeshIP: "127.0.0.1"}
	// The server sees requests from 127.0.0.1 as the phone.
	srvStore.Put(model.Key(model.KindNode, "phone"), phone, store.Cluster)

	cliStore, _ := store.Open("", "phone")
	cliStore.Put(model.Key(model.KindNode, "srv"), server, store.Cluster)
	cliStore.Put(model.Key(model.KindNode, "phone"), phone, store.Cluster)
	cliStore.Put(model.Key(model.KindStatus, "phone"), model.Status{NodeID: "phone", HomeRelay: "vps"}, store.Cluster)
	cliStore.Put(model.Key(model.KindForward, "evil"), model.Forward{ID: "evil"}, store.Cluster)

	cli := New(cliStore, "phone", port)
	cli.round(context.Background(), true)

	if st, ok := store.Get[model.Status](srvStore, model.Key(model.KindStatus, "phone")); !ok || st.HomeRelay != "vps" {
		t.Fatal("status not accepted")
	}
	if _, ok := srvStore.Raw(model.Key(model.KindForward, "evil")); ok {
		t.Fatal("client wrote cluster config")
	}
}

func TestServersReplicateEverything(t *testing.T) {
	aStore, _ := store.Open("", "a")
	a := New(aStore, "a", 0)
	ts := httptest.NewServer(a.Handler())
	defer ts.Close()
	_, portStr, _ := net.SplitHostPort(ts.Listener.Addr().String())
	port, _ := strconv.Atoi(portStr)

	nodeA := model.Node{ID: "a", Kind: model.NodeServer, MeshIP: "127.0.0.2"}
	nodeB := model.Node{ID: "b", Kind: model.NodeServer, MeshIP: "127.0.0.1"}
	aStore.Put(model.Key(model.KindNode, "a"), nodeA, store.Cluster)
	aStore.Put(model.Key(model.KindNode, "b"), nodeB, store.Cluster)
	aStore.Put(model.Key(model.KindForward, "mc"), model.Forward{ID: "mc", Name: "minecraft"}, store.Cluster)

	bStore, _ := store.Open("", "b")
	// b only knows about a, and reaches it on 127.0.0.1 for the test.
	bStore.Put(model.Key(model.KindNode, "a"), model.Node{ID: "a", Kind: model.NodeServer, MeshIP: "127.0.0.1"}, store.Cluster)
	bStore.Put(model.Key(model.KindNode, "b"), nodeB, store.Cluster)
	bStore.Put(model.Key(model.KindRoute, "web"), model.HTTPRoute{ID: "web"}, store.Cluster)
	b := New(bStore, "b", port)
	b.round(context.Background(), true)

	if f, ok := store.Get[model.Forward](bStore, model.Key(model.KindForward, "mc")); !ok || f.Name != "minecraft" {
		t.Fatal("pull failed")
	}
	if _, ok := aStore.Raw(model.Key(model.KindRoute, "web")); !ok {
		t.Fatal("push failed")
	}
}
