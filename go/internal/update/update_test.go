package update

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func fakeRelease(t *testing.T, tag string, files map[string][]byte, tamper bool) {
	t.Helper()
	sums := ""
	for name, b := range files {
		h := sha256.Sum256(b)
		if tamper {
			h[0] ^= 1
		}
		sums += hex.EncodeToString(h[:]) + "  " + name + "\n"
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/releases/tag/"+tag, http.StatusFound)
	})
	mux.HandleFunc("/releases/download/"+tag+"/", func(w http.ResponseWriter, r *http.Request) {
		name := filepath.Base(r.URL.Path)
		if name == "SHA256SUMS" {
			w.Write([]byte(sums))
			return
		}
		if b, ok := files[name]; ok {
			w.Write(b)
			return
		}
		http.NotFound(w, r)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	old := BaseURL
	BaseURL = srv.URL
	t.Cleanup(func() { BaseURL = old })
}

func TestNewer(t *testing.T) {
	for _, c := range []struct {
		cur, latest string
		want        bool
	}{
		{"v0.2.3", "v0.2.4", true},
		{"v0.2.9", "v0.2.10", true},
		{"v0.3.0", "v0.2.10", false},
		{"v1.0.0", "v1.0.0", false},
		{"dev", "v9.9.9", false},
		{"67e3410", "v0.2.4", false},
	} {
		if got := Newer(c.cur, c.latest); got != c.want {
			t.Errorf("Newer(%q, %q) = %v", c.cur, c.latest, got)
		}
	}
}

func TestInstall(t *testing.T) {
	fakeRelease(t, "v0.9.1", map[string][]byte{Asset(): []byte("new binary")}, false)
	tag, err := Latest(context.Background())
	if err != nil || tag != "v0.9.1" {
		t.Fatalf("latest %q %v", tag, err)
	}
	exe := filepath.Join(t.TempDir(), "meshgate")
	os.WriteFile(exe, []byte("old binary"), 0o755)
	if err := Install(context.Background(), tag, exe); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(exe); string(b) != "new binary" {
		t.Fatalf("binary not replaced: %q", b)
	}
}

func TestInstallRefusesTamperedDownload(t *testing.T) {
	fakeRelease(t, "v0.9.1", map[string][]byte{Asset(): []byte("evil binary")}, true)
	exe := filepath.Join(t.TempDir(), "meshgate")
	os.WriteFile(exe, []byte("old binary"), 0o755)
	if err := Install(context.Background(), "v0.9.1", exe); err == nil {
		t.Fatal("installed a download that does not match SHA256SUMS")
	}
	if b, _ := os.ReadFile(exe); string(b) != "old binary" {
		t.Fatalf("binary touched: %q", b)
	}
}
