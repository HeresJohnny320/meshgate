package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/heresjohnny320/meshgate/internal/model"
	"github.com/heresjohnny320/meshgate/internal/ops"
	"github.com/heresjohnny320/meshgate/internal/store"
)

// Two servers with replicated config: a token from one works on the other.
func TestAppAPIAcrossServers(t *testing.T) {
	sa, _ := store.Open("", "pfsense")
	sa.Put(model.Key(model.KindNode, "pfsense"), model.Node{ID: "pfsense", Name: "pfsense", Kind: model.NodeServer}, store.Cluster)
	sa.Put(model.Key(model.KindNode, "vps"), model.Node{ID: "vps", Name: "vps", Kind: model.NodeServer}, store.Cluster)
	oa := &ops.Service{Store: sa, SelfID: "pfsense"}
	if err := oa.SetAdmin("admin", "correct horse"); err != nil {
		t.Fatal(err)
	}
	sb, _ := store.Open("", "vps")
	replicate := func() {
		all, _ := sa.Since(0)
		sb.Merge(all)
	}
	replicate()
	ob := &ops.Service{Store: sb, SelfID: "vps"}
	vpsOff := false
	ha := AppAPI(oa, func() bool { return false })
	hb := AppAPI(ob, func() bool { return vpsOff })

	do := func(h http.Handler, method, path, body, token, ip string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.RemoteAddr = ip + ":40000"
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	w := do(ha, "POST", "/admin/login", `{"username":"admin","password":"correct horse"}`, "", "100.88.0.4")
	var lr struct{ Token string }
	json.NewDecoder(w.Body).Decode(&lr)
	if w.Code != 200 || lr.Token == "" {
		t.Fatalf("login: %d %s", w.Code, w.Body)
	}
	if w := do(hb, "GET", "/admin/api/view", "", lr.Token, "100.88.0.4"); w.Code != 200 || !strings.Contains(w.Body.String(), `"self_id":"vps"`) {
		t.Fatalf("token from pfsense rejected by vps: %d %s", w.Code, w.Body)
	}
	if w := do(hb, "POST", "/admin/api/qr", `{"text":"mg1.x"}`, lr.Token, "100.88.0.4"); w.Code != 200 {
		t.Fatalf("qr: %d", w.Code)
	}
	for _, bad := range []string{"", "garbage", lr.Token[:len(lr.Token)-2] + "00", strings.Replace(lr.Token, ".", ".9", 1)} {
		if w := do(hb, "GET", "/admin/api/view", "", bad, "100.88.0.4"); w.Code != 401 {
			t.Errorf("token %q accepted: %d", bad, w.Code)
		}
	}

	// Wrong passwords lock the address out after 5 tries.
	for i := 0; i < 5; i++ {
		if w := do(ha, "POST", "/admin/login", `{"username":"admin","password":"nope"}`, "", "100.88.0.9"); w.Code != 401 {
			t.Fatalf("wrong password: %d", w.Code)
		}
	}
	if w := do(ha, "POST", "/admin/login", `{"username":"admin","password":"correct horse"}`, "", "100.88.0.9"); w.Code != 429 {
		t.Fatalf("no lockout: %d", w.Code)
	}

	// A password change (replicated) invalidates old tokens everywhere.
	oa.SetAdmin("admin", "new password!")
	replicate()
	if w := do(hb, "GET", "/admin/api/view", "", lr.Token, "100.88.0.4"); w.Code != 401 {
		t.Fatalf("old token still valid after password change: %d", w.Code)
	}

	// A server that opted out does not answer.
	vpsOff = true
	if w := do(hb, "POST", "/admin/login", `{"username":"admin","password":"new password!"}`, "", "100.88.0.4"); w.Code != 404 {
		t.Fatalf("opted-out node answered: %d", w.Code)
	}
}
