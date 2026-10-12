package webui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/heresjohnny320/meshgate/internal/model"
	"github.com/heresjohnny320/meshgate/internal/ops"
	"github.com/heresjohnny320/meshgate/internal/store"
)

func TestLoginAndAPI(t *testing.T) {
	s, _ := store.Open("", "n1")
	s.Put(model.Key(model.KindNode, "n1"), model.Node{ID: "n1", Name: "vps", Kind: model.NodeServer}, store.Cluster)
	o := &ops.Service{Store: s, SelfID: "n1"}
	if err := o.SetAdmin("admin", "correct horse"); err != nil {
		t.Fatal(err)
	}
	h := New(o)

	do := func(method, path, body string, hdr map[string]string, cookie *http.Cookie) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		for k, v := range hdr {
			r.Header.Set(k, v)
		}
		if cookie != nil {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	if w := do("GET", "/", "", nil, nil); w.Code != 200 || !strings.Contains(w.Body.String(), "meshgate") {
		t.Fatalf("index: %d", w.Code)
	}
	if w := do("GET", "/api/view", "", nil, nil); w.Code != 401 {
		t.Fatalf("unauthenticated view: %d", w.Code)
	}
	if w := do("POST", "/auth/login", `{"username":"admin","password":"wrong"}`, nil, nil); w.Code != 401 {
		t.Fatalf("bad login: %d", w.Code)
	}
	w := do("POST", "/auth/login", `{"username":"admin","password":"correct horse"}`, nil, nil)
	if w.Code != 200 {
		t.Fatalf("login: %d %s", w.Code, w.Body)
	}
	c := w.Result().Cookies()[0]
	if w := do("GET", "/api/view", "", nil, c); w.Code != 200 || !strings.Contains(w.Body.String(), `"self_id":"n1"`) {
		t.Fatalf("view: %d %s", w.Code, w.Body)
	}
	if w := do("POST", "/api/network", `{"acme_email":"a@b.c"}`, nil, c); w.Code != 403 {
		t.Fatalf("csrf not enforced: %d", w.Code)
	}
	if w := do("POST", "/api/network", `{"acme_email":"a@b.c"}`, map[string]string{"X-Meshgate": "1"}, c); w.Code != 200 {
		t.Fatalf("network: %d %s", w.Code, w.Body)
	}
}
