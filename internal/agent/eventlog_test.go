package agent

import (
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/heresjohnny320/meshgate/internal/config"
	"github.com/heresjohnny320/meshgate/internal/model"
	"github.com/heresjohnny320/meshgate/internal/store"
)

func TestEventLogDelivery(t *testing.T) {
	dir := t.TempDir()
	s, err := store.Open(dir+"/state.json", "vps")
	if err != nil {
		t.Fatal(err)
	}
	s.Put(model.Key(model.KindNode, "vps"), model.Node{ID: "vps", Name: "vps", Kind: model.NodeServer, Relay: true, MeshIP: "100.88.0.1"}, store.Cluster)
	s.Put(model.Key(model.KindNode, "pf"), model.Node{ID: "pf", Name: "pfsense", Kind: model.NodeServer, MeshIP: "100.88.0.2"}, store.Cluster)
	a := &Agent{Cfg: config.Node{NodeID: "vps", DataDir: dir}, Store: s}
	a.captureLog()
	defer log.SetOutput(os.Stderr)

	// pfSense delivers lines it held in RAM, claiming to be someone else.
	req := httptest.NewRequest("POST", "/v1/events", strings.NewReader(`[{"t":1800000000,"node":"vps","text":"link to vps DOWN: no WireGuard handshake"}]`))
	req.RemoteAddr = "100.88.0.2:40000"
	rec := httptest.NewRecorder()
	a.serveEvents(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("post: %d %s", rec.Code, rec.Body)
	}
	// A phone or stranger may not post.
	req = httptest.NewRequest("POST", "/v1/events", strings.NewReader(`[]`))
	req.RemoteAddr = "100.88.0.9:40000"
	rec = httptest.NewRecorder()
	a.serveEvents(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("unknown caller got %d", rec.Code)
	}

	// This node (the log server) logs, then delivers to itself.
	log.Print("link to pfsense UP again after 35m0s")
	if st := a.ev.buf.Snapshot(); len(st.Pending) != 1 {
		t.Fatalf("not captured: %+v", st)
	}
	a.flushEvents()
	if st := a.ev.buf.Snapshot(); len(st.Pending) != 0 {
		t.Fatalf("not delivered: %+v", st.Pending)
	}

	got, _ := a.Events(url.Values{"important": {"1"}})
	ans := got.(eventsAnswer)
	if ans.Error != "" || len(ans.Entries) != 2 {
		t.Fatalf("answer: %+v", ans)
	}
	byNode := map[string]string{}
	for _, e := range ans.Entries {
		byNode[e.Node] = e.Text
	}
	if !strings.Contains(byNode["pf"], "DOWN") || !strings.Contains(byNode["vps"], "UP again") {
		t.Fatalf("lines not attributed to their senders: %+v", byNode)
	}
}
