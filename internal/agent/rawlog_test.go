package agent

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/heresjohnny320/meshgate/internal/config"
	"github.com/heresjohnny320/meshgate/internal/model"
	"github.com/heresjohnny320/meshgate/internal/store"
)

func TestRawLogOverMesh(t *testing.T) {
	// "pf" answers on a local port standing in for its mesh IP.
	pfStore, _ := store.Open(t.TempDir()+"/s.json", "pf")
	pfStore.Put(model.Key(model.KindNode, "vps"), model.Node{ID: "vps", Name: "vps", Kind: model.NodeServer, MeshIP: "127.0.0.1"}, store.Cluster)
	pf := &Agent{Cfg: config.Node{NodeID: "pf"}, Store: pfStore}
	srv := httptest.NewServer(http.HandlerFunc(pf.serveRawLog))
	defer srv.Close()
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	p, _ := strconv.Atoi(port)

	s, _ := store.Open(t.TempDir()+"/s.json", "vps")
	s.Put(model.Key(model.KindNode, "pf"), model.Node{ID: "pf", Name: "pfsense", Kind: model.NodeServer, MeshIP: "127.0.0.1", MeshPort: p}, store.Cluster)
	s.Put(model.Key(model.KindNode, "gone"), model.Node{ID: "gone", Name: "home2", Kind: model.NodeServer, MeshIP: "127.0.0.1", MeshPort: 1}, store.Cluster)
	s.Put(model.Key(model.KindNode, "phone"), model.Node{ID: "phone", Name: "phone", Kind: model.NodeClient}, store.Cluster)
	a := &Agent{Cfg: config.Node{NodeID: "vps"}, Store: s}

	got, err := a.RawLog("pf", 50)
	if err != nil {
		t.Fatal(err)
	}
	// pf read its own log (journalctl here, which may or may not have
	// lines); what matters is that the answer came from pf.
	if ans := got.(rawLogAnswer); ans.Node != "pf" {
		t.Fatalf("answer not from pf: %+v", ans)
	}
	got, _ = a.RawLog("gone", 50)
	if ans := got.(rawLogAnswer); !strings.Contains(ans.Error, "home2 is not reachable over the mesh") {
		t.Fatalf("unreachable node: %+v", ans)
	}
	if _, err := a.RawLog("phone", 50); err == nil {
		t.Fatal("a phone has no log file")
	}

	// Only servers may read a node's log.
	req := httptest.NewRequest("GET", "/v1/rawlog", nil)
	req.RemoteAddr = "100.88.0.9:1234"
	rec := httptest.NewRecorder()
	pf.serveRawLog(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("stranger got %d", rec.Code)
	}
}
