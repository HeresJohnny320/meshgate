package webtls

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCertRenewsWhenNeeded(t *testing.T) {
	dir := t.TempDir()
	c := &Cert{CertPath: filepath.Join(dir, "web.crt"), KeyPath: filepath.Join(dir, "web.key"), Hosts: []string{"100.88.1.1", "localhost"}}
	now := time.Now()
	if err := c.Refresh(now); err != nil {
		t.Fatal(err)
	}
	fp := c.Fingerprint()
	if len(fp) != 95 {
		t.Fatalf("fingerprint %q", fp)
	}
	c.Refresh(now.Add(24 * time.Hour))
	if c.Fingerprint() != fp {
		t.Fatal("renewed a good certificate")
	}
	c.Hosts = append(c.Hosts, "192.168.1.1")
	c.Refresh(now)
	if c.Fingerprint() == fp {
		t.Fatal("kept a certificate missing an address")
	}
	fp = c.Fingerprint()
	c.Refresh(now.Add(validity - 10*24*time.Hour))
	if c.Fingerprint() == fp {
		t.Fatal("kept a certificate about to expire")
	}
}

func TestHTTPSAndRedirectOnOnePort(t *testing.T) {
	dir := t.TempDir()
	c := &Cert{CertPath: filepath.Join(dir, "web.crt"), KeyPath: filepath.Join(dir, "web.key"), Hosts: []string{"127.0.0.1"}}
	if err := c.Refresh(time.Now()); err != nil {
		t.Fatal(err)
	}
	raw, _ := net.Listen("tcp", "127.0.0.1:0")
	l := Listener(raw, c.TLSConfig())
	srv := &http.Server{Handler: Redirect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "secure "+r.URL.Path)
	}))}
	go srv.Serve(l)
	defer srv.Close()
	// A silent client must not hold up others.
	idle, _ := net.Dial("tcp", raw.Addr().String())
	defer idle.Close()

	addr := raw.Addr().String()
	cl := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := cl.Get("https://" + addr + "/x")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if string(b) != "secure /x" {
		t.Fatalf("https: %q", b)
	}
	res, err = cl.Get("http://" + addr + "/y?z=1")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusPermanentRedirect || res.Header.Get("Location") != "https://"+addr+"/y?z=1" {
		t.Fatalf("http: %d %s", res.StatusCode, res.Header.Get("Location"))
	}
}

func TestHostsIncludesListenAddresses(t *testing.T) {
	h := strings.Join(Hosts([]string{"127.0.0.1:8080", "100.88.1.1:8080"}, "johnnysvps1"), " ")
	for _, want := range []string{"100.88.1.1", "127.0.0.1", "localhost", "johnnysvps1"} {
		if !strings.Contains(h, want) {
			t.Errorf("missing %s in %s", want, h)
		}
	}
}
