package webtls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newCert(dir string, hosts ...string) *Cert {
	return &Cert{CertPath: filepath.Join(dir, "web.crt"), KeyPath: filepath.Join(dir, "web.key"),
		CACertPath: filepath.Join(dir, "ca.crt"), CAKeyPath: filepath.Join(dir, "ca.key"),
		Name: "vps1", Hosts: hosts, Mesh: netip.MustParsePrefix("100.88.0.0/16")}
}

// verify checks c's certificate the way a browser that installed the CA
// would (Go enforces the CA's name constraints too).
func verify(t *testing.T, c *Cert, host string) error {
	t.Helper()
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(c.caPEM) {
		t.Fatal("bad CA PEM")
	}
	leaf, err := x509.ParseCertificate(c.cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	_, err = leaf.Verify(x509.VerifyOptions{DNSName: host, Roots: pool})
	return err
}

func TestTrustedOnceCAInstalled(t *testing.T) {
	dir := t.TempDir()
	c := newCert(dir, "100.88.1.1", "127.0.0.1", "localhost", "vps1", "203.0.113.7")
	if err := c.Refresh(time.Now()); err != nil {
		t.Fatal(err)
	}
	for _, h := range []string{"100.88.1.1", "127.0.0.1", "localhost", "vps1", "203.0.113.7"} {
		if err := verify(t, c, h); err != nil {
			t.Errorf("%s: %v", h, err)
		}
	}
	if err := verify(t, c, "100.88.1.2"); err == nil {
		t.Error("certificate valid for another mesh address")
	}
	// The CA survives a restart; the certificate is kept too.
	fp, caFP := c.fp, c.caFP
	c2 := newCert(dir, c.Hosts...)
	c2.Refresh(time.Now())
	if c2.fp != fp || c2.caFP != caFP {
		t.Fatal("restart replaced the certificate or CA")
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "ca.key")); len(b) == 0 {
		t.Fatal("no CA key")
	}
	if st, _ := os.Stat(filepath.Join(dir, "ca.key")); st.Mode().Perm() != 0o600 {
		t.Fatalf("CA key mode %v", st.Mode())
	}
}

func TestCACannotVouchForOtherSites(t *testing.T) {
	dir := t.TempDir()
	c := newCert(dir, "100.88.1.1", "localhost", "vps1", "192.168.1.10")
	if err := c.Refresh(time.Now()); err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(c.caPEM)
	// Someone with the CA key signs certificates for other sites.
	for _, h := range []string{"example.com", "192.168.1.1", "8.8.8.8", "vps1.example.com.evil"} {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(9), Subject: pkix.Name{CommonName: h},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = []net.IP{ip}
		} else {
			tmpl.DNSNames = []string{h}
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, c.ca, &key.PublicKey, c.caKey)
		if err != nil {
			t.Fatal(err)
		}
		leaf, _ := x509.ParseCertificate(der)
		if _, err := leaf.Verify(x509.VerifyOptions{DNSName: h, Roots: pool}); err == nil {
			t.Errorf("CA vouched for %s", h)
		}
	}
}

func TestReplacesSelfSignedAndSkipsUncoveredHosts(t *testing.T) {
	dir := t.TempDir()
	c := newCert(dir, "100.88.1.1", "localhost")
	// A certificate this CA did not sign (from before the CA, or another).
	old := &Cert{CertPath: c.CertPath, KeyPath: c.KeyPath, CACertPath: filepath.Join(dir, "x.crt"), CAKeyPath: filepath.Join(dir, "x.key"), Hosts: c.Hosts}
	if err := old.Refresh(time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := c.Refresh(time.Now()); err != nil {
		t.Fatal(err)
	}
	if c.fp == old.fp || verify(t, c, "100.88.1.1") != nil {
		t.Fatal("kept a certificate the CA did not sign")
	}
	// An address that appears after the CA was made stays out (the CA may
	// not sign for it) and is reported, without remaking the certificate
	// on every refresh.
	c.Hosts = append(c.Hosts, "192.168.7.7")
	c.Refresh(time.Now())
	fp := c.fp
	c.Refresh(time.Now())
	if got := c.Skipped(); len(got) != 1 || got[0] != "192.168.7.7" || c.fp != fp {
		t.Fatalf("skipped %v, fp changed %v", got, c.fp != fp)
	}
}

func TestCertRenewsWhenNeeded(t *testing.T) {
	dir := t.TempDir()
	c := newCert(dir, "100.88.1.1", "localhost")
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
	c.Hosts = append(c.Hosts, "100.88.1.2")
	c.Refresh(now)
	if c.Fingerprint() == fp {
		t.Fatal("kept a certificate missing an address")
	}
	fp = c.Fingerprint()
	// An address that goes away and comes back keeps the certificate.
	c.Hosts = []string{"100.88.1.1", "localhost"}
	c.Refresh(now)
	c.Hosts = append(c.Hosts, "100.88.1.2")
	c.Refresh(now)
	if c.Fingerprint() != fp {
		t.Fatal("replaced the certificate for an address it had before")
	}
	c.Refresh(now.Add(validity - 10*24*time.Hour))
	if c.Fingerprint() == fp {
		t.Fatal("kept a certificate about to expire")
	}
}

func TestHTTPSAndRedirectOnOnePort(t *testing.T) {
	dir := t.TempDir()
	c := newCert(dir, "127.0.0.1")
	if err := c.Refresh(time.Now()); err != nil {
		t.Fatal(err)
	}
	raw, _ := net.Listen("tcp", "127.0.0.1:0")
	l := Listener(raw, c.TLSConfig())
	srv := &http.Server{Handler: Redirect(c.ServeCA(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "secure "+r.URL.Path)
	})))}
	go srv.Serve(l)
	defer srv.Close()
	// A silent client must not hold up others.
	idle, _ := net.Dial("tcp", raw.Addr().String())
	defer idle.Close()

	addr := raw.Addr().String()
	// Trusting only the CA, as a device that installed it.
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(c.caPEM)
	cl := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}},
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
	res, err = cl.Get("https://" + addr + CAPath)
	if err != nil {
		t.Fatal(err)
	}
	b, _ = io.ReadAll(res.Body)
	res.Body.Close()
	if string(b) != string(c.caPEM) {
		t.Fatalf("CA download: %q", b)
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
