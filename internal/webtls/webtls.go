// Package webtls serves the web UI over HTTPS without any setup: it keeps a
// self-signed certificate for the addresses the web UI answers on (renewed
// before it expires or when an address is missing from it) and lets HTTPS
// and plain HTTP share the port, so old http:// links get redirected.
package webtls

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"time"
)

// validity stays under the 398 days browsers accept for a certificate.
const (
	validity = 397 * 24 * time.Hour
	renewAt  = 30 * 24 * time.Hour // renew this long before expiry
)

// Cert is the web UI certificate, reloaded by Refresh.
type Cert struct {
	CertPath, KeyPath string
	Hosts             []string // IPs and names it must cover

	mu   sync.Mutex
	cert *tls.Certificate
	fp   string
}

// Refresh loads the certificate, creating a new one when there is none, it
// expires within 30 days or it does not cover every host.
func (c *Cert) Refresh(now time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if cert, err := tls.LoadX509KeyPair(c.CertPath, c.KeyPath); err == nil {
		if leaf, err := x509.ParseCertificate(cert.Certificate[0]); err == nil && now.Add(renewAt).Before(leaf.NotAfter) && covers(leaf, c.Hosts) {
			c.set(cert)
			return nil
		}
	}
	cert, err := create(c.CertPath, c.KeyPath, c.Hosts, now)
	if err != nil {
		return err
	}
	c.set(cert)
	return nil
}

func (c *Cert) set(cert tls.Certificate) {
	sum := sha256.Sum256(cert.Certificate[0])
	hexs := make([]string, len(sum))
	for i, b := range sum {
		hexs[i] = fmt.Sprintf("%02X", b)
	}
	c.cert, c.fp = &cert, strings.Join(hexs, ":")
}

// Fingerprint is the SHA-256 fingerprint browsers show for the certificate.
func (c *Cert) Fingerprint() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.fp
}

// TLSConfig serves the current certificate (renewals apply without a restart).
func (c *Cert) TLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			c.mu.Lock()
			defer c.mu.Unlock()
			if c.cert == nil {
				return nil, errors.New("no certificate yet")
			}
			return c.cert, nil
		},
	}
}

func covers(leaf *x509.Certificate, hosts []string) bool {
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			if !slices.ContainsFunc(leaf.IPAddresses, ip.Equal) {
				return false
			}
		} else if !slices.Contains(leaf.DNSNames, h) {
			return false
		}
	}
	return true
}

func create(certPath, keyPath string, hosts []string, now time.Time) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "meshgate web UI", Organization: []string{"meshgate"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(validity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else if h != "" {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	kb, _ := x509.MarshalECPrivateKey(key)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})
	if err := writeFile(keyPath, keyPEM, 0o600); err != nil {
		return tls.Certificate{}, err
	}
	if err := writeFile(certPath, certPEM, 0o644); err != nil {
		return tls.Certificate{}, err
	}
	return tls.X509KeyPair(certPEM, keyPEM)
}

func writeFile(path string, b []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Hosts is what the certificate covers for the given listen addresses:
// their IPs (every interface's for 0.0.0.0 / ::), localhost and the
// machine's name.
func Hosts(listen []string, extra ...string) []string {
	set := map[string]bool{"127.0.0.1": true, "::1": true, "localhost": true}
	if h, err := os.Hostname(); err == nil && h != "" {
		set[strings.ToLower(h)] = true
	}
	for _, e := range extra {
		if e != "" {
			set[e] = true
		}
	}
	for _, addr := range listen {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			continue
		}
		if ip := net.ParseIP(host); host == "" || (ip != nil && ip.IsUnspecified()) {
			addrs, _ := net.InterfaceAddrs()
			for _, a := range addrs {
				if n, ok := a.(*net.IPNet); ok && !n.IP.IsLinkLocalUnicast() {
					set[n.IP.String()] = true
				}
			}
		} else {
			set[host] = true
		}
	}
	out := make([]string, 0, len(set))
	for h := range set {
		out = append(out, h)
	}
	slices.Sort(out)
	return out
}

// Listener hands out HTTPS connections, and plain HTTP ones (for Redirect)
// on the same port: a TLS handshake starts with byte 0x16.
func Listener(l net.Listener, cfg *tls.Config) net.Listener {
	ml := &mixed{Listener: l, conns: make(chan net.Conn), done: make(chan struct{})}
	go ml.loop(cfg)
	return ml
}

type mixed struct {
	net.Listener
	conns chan net.Conn
	done  chan struct{}
	once  sync.Once
	err   error
}

func (m *mixed) loop(cfg *tls.Config) {
	for {
		c, err := m.Listener.Accept()
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			m.err = err
			m.Close()
			return
		}
		// Sniff off the accept loop, so a silent client blocks nobody.
		go func() {
			c.SetReadDeadline(time.Now().Add(10 * time.Second))
			br := bufio.NewReader(c)
			first, err := br.Peek(1)
			c.SetReadDeadline(time.Time{})
			if err != nil {
				c.Close()
				return
			}
			var out net.Conn = &peeked{Conn: c, r: br}
			if first[0] == 0x16 {
				out = tls.Server(out, cfg)
			}
			select {
			case m.conns <- out:
			case <-m.done:
				c.Close()
			}
		}()
	}
}

func (m *mixed) Accept() (net.Conn, error) {
	select {
	case c := <-m.conns:
		return c, nil
	case <-m.done:
		if m.err != nil {
			return nil, m.err
		}
		return nil, net.ErrClosed
	}
}

func (m *mixed) Close() error {
	var err error
	m.once.Do(func() { close(m.done); err = m.Listener.Close() })
	return err
}

type peeked struct {
	net.Conn
	r *bufio.Reader
}

func (p *peeked) Read(b []byte) (int, error) { return p.r.Read(b) }

// Redirect sends plain-HTTP requests to the same address over HTTPS.
func Redirect(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil {
			http.Redirect(w, r, "https://"+r.Host+r.URL.RequestURI(), http.StatusPermanentRedirect)
			return
		}
		h.ServeHTTP(w, r)
	})
}
