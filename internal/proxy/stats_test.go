package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestCountedRequests(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		if r.URL.Path == "/boom" {
			http.Error(w, "boom", 500)
			return
		}
		w.Write([]byte("hello world"))
	}))
	defer backend.Close()
	u, _ := url.Parse(backend.URL)
	p := &Proxy{}
	l := &live{route: Route{Hostname: "Jelly.example.com", Target: u}, rp: newReverseProxy(u)}
	for _, path := range []string{"/", "/boom"} {
		r := httptest.NewRequest("POST", "https://jelly.example.com"+path, strings.NewReader("12345"))
		r.RemoteAddr = "198.18.1.5:4000"
		p.counted(httptest.NewRecorder(), r, l)
	}
	hosts, recent := p.Stats()
	h := hosts["jelly.example.com"]
	if h.Requests != 2 || h.Errors != 1 || h.In != 10 || h.Out < 11 {
		t.Fatalf("stats %+v", h)
	}
	if len(recent) != 2 || recent[0].Client != "198.18.1.5" || recent[1].Status != 500 || recent[1].Path != "/boom" {
		t.Fatalf("recent %+v", recent)
	}
}
