// Package webtls serves the web UI over HTTPS without any setup: it keeps a
// certificate for the addresses the web UI answers on (renewed before it
// expires or when an address is missing from it), signed by the server's own
// small CA, and lets HTTPS and plain HTTP share the port, so old http://
// links get redirected.
//
// Without the CA installed the browser warns, as for any self-signed
// certificate. With it installed (once per device) there is no warning, and
// a man in the middle gets a hard error instead of a warning to click
// through. The CA is name-constrained to this server's names, its listen
// addresses, loopback and the mesh range, so a stolen CA key cannot be used
// to impersonate other sites to the devices that trust it.
package webtls

import (
	"bufio"
	"crypto"
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
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"time"
)

// validity stays under the 398 days browsers accept for a certificate.
const (
	validity   = 397 * 24 * time.Hour
	caValidity = 10 * 365 * 24 * time.Hour
	renewAt    = 30 * 24 * time.Hour // renew this long before expiry
)

// CAPath is where the web UI serves its CA certificate for download.
const CAPath = "/meshgate-ca.crt"

// Cert is the web UI certificate, reloaded by Refresh.
type Cert struct {
	CertPath, KeyPath     string
	CACertPath, CAKeyPath string
	Name                  string       // server name, for the CA's subject
	Hosts                 []string     // IPs and names it must cover
	Mesh                  netip.Prefix // the CA may sign for any mesh address

	mu      sync.Mutex
	cert    *tls.Certificate
	fp      string
	ca      *x509.Certificate
	caKey   crypto.Signer
	caPEM   []byte
	caFP    string
	skipped []string // hosts outside the CA's name constraints
}

// Refresh loads the certificate, creating a new one when there is none, it
// expires within 30 days or it does not cover every host. A new certificate
// keeps the addresses of the old one too, so an address that comes and goes
// (DHCP, a VPN interface) does not change it each time: every change makes
// browsers warn again, and warnings people learn to click through are what
// a man in the middle relies on.
func (c *Cert) Refresh(now time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	newCA, err := c.loadCA(now)
	if err != nil {
		return err
	}
	hosts, skipped := permitted(c.ca, c.Hosts)
	c.skipped = skipped
	if cert, err := tls.LoadX509KeyPair(c.CertPath, c.KeyPath); err == nil && !newCA {
		// A certificate from before the CA (self-signed) or from an
		// older CA is replaced.
		if leaf, err := x509.ParseCertificate(cert.Certificate[0]); err == nil && leaf.CheckSignatureFrom(c.ca) == nil {
			if now.Add(renewAt).Before(leaf.NotAfter) && covers(leaf, hosts) {
				c.set(cert)
				return nil
			}
			hosts, _ = permitted(c.ca, union(hosts, leaf))
		}
	}
	cert, err := c.create(hosts, now)
	if err != nil {
		return err
	}
	c.set(cert)
	return nil
}

// loadCA loads the CA, creating it when there is none or it expires within
// 30 days; it reports whether it made a new one.
func (c *Cert) loadCA(now time.Time) (bool, error) {
	if c.ca != nil && now.Add(renewAt).Before(c.ca.NotAfter) {
		return false, nil
	}
	if pair, err := tls.LoadX509KeyPair(c.CACertPath, c.CAKeyPath); err == nil {
		ca, err := x509.ParseCertificate(pair.Certificate[0])
		key, ok := pair.PrivateKey.(crypto.Signer)
		if err == nil && ok && ca.IsCA && now.Add(renewAt).Before(ca.NotAfter) {
			c.setCA(ca, key)
			return false, nil
		}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return false, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: strings.TrimSpace("meshgate web UI CA " + c.Name), Organization: []string{"meshgate"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(caValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	tmpl.PermittedDNSDomainsCritical = true
	tmpl.PermittedDNSDomains, tmpl.PermittedIPRanges = constraints(c.Hosts, c.Mesh)
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return false, err
	}
	ca, err := x509.ParseCertificate(der)
	if err != nil {
		return false, err
	}
	kb, _ := x509.MarshalECPrivateKey(key)
	if err := writeFile(c.CAKeyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600); err != nil {
		return false, err
	}
	if err := writeFile(c.CACertPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		return false, err
	}
	c.setCA(ca, key)
	return true, nil
}

func (c *Cert) setCA(ca *x509.Certificate, key crypto.Signer) {
	c.ca, c.caKey = ca, key
	c.caPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw})
	c.caFP = fingerprint(ca.Raw)
}

// constraints is what the CA may sign for: the names among hosts, loopback,
// the mesh range and each other listen address exactly.
func constraints(hosts []string, mesh netip.Prefix) (names []string, ranges []*net.IPNet) {
	names = []string{"localhost"}
	ranges = []*net.IPNet{
		{IP: net.IPv4(127, 0, 0, 0).To4(), Mask: net.CIDRMask(8, 32)},
		{IP: net.IPv6loopback, Mask: net.CIDRMask(128, 128)},
	}
	if mesh.IsValid() {
		mesh = mesh.Masked()
		ranges = append(ranges, &net.IPNet{IP: mesh.Addr().AsSlice(), Mask: net.CIDRMask(mesh.Bits(), mesh.Addr().BitLen())})
	}
	inRanges := func(ip net.IP) bool {
		return slices.ContainsFunc(ranges, func(r *net.IPNet) bool { return r.Contains(ip) })
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			if !inRanges(ip) {
				bits := 128
				if ip4 := ip.To4(); ip4 != nil {
					ip, bits = ip4, 32
				}
				ranges = append(ranges, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
			}
		} else if h != "" && !slices.Contains(names, h) {
			names = append(names, h)
		}
	}
	return names, ranges
}

// permitted splits hosts into those the CA may sign for and the rest.
func permitted(ca *x509.Certificate, hosts []string) (ok, skipped []string) {
	for _, h := range hosts {
		allowed := false
		if ip := net.ParseIP(h); ip != nil {
			allowed = slices.ContainsFunc(ca.PermittedIPRanges, func(r *net.IPNet) bool { return r.Contains(ip) })
		} else {
			allowed = slices.ContainsFunc(ca.PermittedDNSDomains, func(d string) bool {
				return strings.EqualFold(h, d) || strings.HasSuffix(strings.ToLower(h), "."+strings.ToLower(d))
			})
		}
		if allowed {
			ok = append(ok, h)
		} else {
			skipped = append(skipped, h)
		}
	}
	return ok, skipped
}

func fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	hexs := make([]string, len(sum))
	for i, b := range sum {
		hexs[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(hexs, ":")
}

func (c *Cert) set(cert tls.Certificate) {
	c.cert, c.fp = &cert, fingerprint(cert.Certificate[0])
}

// Fingerprint is the SHA-256 fingerprint browsers show for the certificate.
func (c *Cert) Fingerprint() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.fp
}

// CAFingerprint is the SHA-256 fingerprint of the CA certificate, to check
// a downloaded copy before installing it.
func (c *Cert) CAFingerprint() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.caFP
}

// Skipped lists the hosts the certificate leaves out because the CA (made
// before they appeared) may not sign for them.
func (c *Cert) Skipped() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.skipped)
}

// ServeCA answers CAPath with the CA certificate (public, so no login).
func (c *Cert) ServeCA(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != CAPath {
			h.ServeHTTP(w, r)
			return
		}
		c.mu.Lock()
		b := c.caPEM
		c.mu.Unlock()
		w.Header().Set("Content-Type", "application/x-x509-ca-cert")
		w.Header().Set("Content-Disposition", `attachment; filename="meshgate-ca.crt"`)
		w.Write(b)
	})
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

// maxHosts bounds how many addresses a certificate keeps from its
// predecessors.
const maxHosts = 64

func union(hosts []string, leaf *x509.Certificate) []string {
	out := slices.Clone(hosts)
	add := func(h string) {
		if len(out) < maxHosts && !slices.Contains(out, h) {
			out = append(out, h)
		}
	}
	for _, ip := range leaf.IPAddresses {
		add(ip.String())
	}
	for _, d := range leaf.DNSNames {
		add(d)
	}
	return out
}

func (c *Cert) create(hosts []string, now time.Time) (tls.Certificate, error) {
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
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.ca, &key.PublicKey, c.caKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	kb, _ := x509.MarshalECPrivateKey(key)
	// The file holds the chain, so browsers that trust the CA can build it.
	certPEM := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), c.caPEM...)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})
	if err := writeFile(c.KeyPath, keyPEM, 0o600); err != nil {
		return tls.Certificate{}, err
	}
	if err := writeFile(c.CertPath, certPEM, 0o644); err != nil {
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
