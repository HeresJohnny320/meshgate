// Package proxy is the HTTPS edge: it terminates TLS for configured hostnames
// with automatic Let's Encrypt certificates and reverse-proxies requests
// through the mesh to the target service — a self-hosted Cloudflare Tunnel.
package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/certmagic"

	"github.com/heresjohnny320/meshgate/internal/traffic"
)

// Route is a resolved HTTP route.
type Route struct {
	Hostname   string
	Target     *url.URL // http(s)://mesh-or-lan-ip:port
	ForceHTTPS bool
	Disabled   bool // switched off: answer 403 instead of proxying
}

// Proxy serves :80 and :443.
type Proxy struct {
	StorageDir string

	mu      sync.RWMutex
	routes  map[string]*live
	magic   *certmagic.Config
	issuer  *certmagic.ACMEIssuer
	managed map[string]bool
	started bool

	statsMu sync.Mutex
	stats   map[string]*traffic.HostStats
	recent  []traffic.Request // newest last, at most recentMax
}

const recentMax = 50

// Stats returns per-hostname counters and the most recent requests.
func (p *Proxy) Stats() (map[string]traffic.HostStats, []traffic.Request) {
	p.statsMu.Lock()
	defer p.statsMu.Unlock()
	m := map[string]traffic.HostStats{}
	for h, s := range p.stats {
		m[h] = *s
	}
	return m, append([]traffic.Request(nil), p.recent...)
}

// counted serves r through l and records it.
func (p *Proxy) counted(w http.ResponseWriter, r *http.Request, l *live) {
	start := time.Now()
	cw := &countWriter{ResponseWriter: w, status: http.StatusOK}
	var in uint64
	if r.Body != nil {
		r.Body = &countReader{ReadCloser: r.Body, n: &in}
	}
	l.rp.ServeHTTP(cw, r)
	host := strings.ToLower(l.route.Hostname)
	path := r.URL.Path
	if len(path) > 100 {
		path = path[:100] + "…"
	}
	client := r.RemoteAddr
	if h, _, err := net.SplitHostPort(client); err == nil {
		client = h
	}
	p.statsMu.Lock()
	defer p.statsMu.Unlock()
	if p.stats == nil {
		p.stats = map[string]*traffic.HostStats{}
	}
	s := p.stats[host]
	if s == nil {
		s = &traffic.HostStats{}
		p.stats[host] = s
	}
	s.Requests++
	s.In += in
	s.Out += cw.n
	if cw.status >= 500 {
		s.Errors++
	}
	p.recent = append(p.recent, traffic.Request{Time: start.Unix(), Client: client, Method: r.Method, Host: host, Path: path,
		Status: cw.status, Bytes: cw.n, Ms: time.Since(start).Milliseconds()})
	if len(p.recent) > recentMax {
		p.recent = p.recent[len(p.recent)-recentMax:]
	}
}

type countWriter struct {
	http.ResponseWriter
	status int
	n      uint64
}

func (c *countWriter) WriteHeader(code int) { c.status = code; c.ResponseWriter.WriteHeader(code) }
func (c *countWriter) Write(b []byte) (int, error) {
	n, err := c.ResponseWriter.Write(b)
	c.n += uint64(n)
	return n, err
}

// Unwrap lets http.ResponseController flush and hijack (streaming, websockets).
func (c *countWriter) Unwrap() http.ResponseWriter { return c.ResponseWriter }

type countReader struct {
	io.ReadCloser
	n *uint64
}

func (c *countReader) Read(b []byte) (int, error) {
	n, err := c.ReadCloser.Read(b)
	*c.n += uint64(n)
	return n, err
}

type live struct {
	route Route
	rp    *httputil.ReverseProxy
}

// Update replaces the route set. The listeners start on the first non-empty
// update so nodes without HTTP routes never bind :80/:443.
func (p *Proxy) Update(ctx context.Context, routes []Route, email string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(routes) == 0 && !p.started {
		return nil
	}
	next := map[string]*live{}
	for _, r := range routes {
		host := strings.ToLower(r.Hostname)
		old := p.routes[host]
		if old != nil && old.route.Target.String() == r.Target.String() {
			old.route = r
			next[host] = old
			continue
		}
		next[host] = &live{route: r, rp: newReverseProxy(r.Target)}
	}
	p.routes = next

	if !p.started {
		if err := p.start(ctx, email); err != nil {
			return err
		}
	}
	var add []string
	for h := range next {
		if !p.managed[h] {
			add = append(add, h)
			p.managed[h] = true
		}
	}
	sort.Strings(add)
	if len(add) > 0 {
		if err := p.magic.ManageAsync(context.Background(), add); err != nil {
			return fmt.Errorf("certificates for %v: %w", add, err)
		}
	}
	return nil
}

func (p *Proxy) start(ctx context.Context, email string) error {
	if email == "" {
		return fmt.Errorf("set an ACME email (network settings) before adding HTTPS routes")
	}
	certmagic.Default.Storage = &certmagic.FileStorage{Path: p.StorageDir}
	p.magic = certmagic.NewDefault()
	p.issuer = certmagic.NewACMEIssuer(p.magic, certmagic.ACMEIssuer{
		CA:     certmagic.LetsEncryptProductionCA,
		Email:  email,
		Agreed: true,
	})
	p.magic.Issuers = []certmagic.Issuer{p.issuer}
	// Only hand out certificates for hostnames we route.
	p.managed = map[string]bool{}

	httpSrv := &http.Server{
		Addr:              ":80",
		Handler:           p.issuer.HTTPChallengeHandler(http.HandlerFunc(p.serveHTTP)),
		ReadHeaderTimeout: 10 * time.Second,
	}
	tlsCfg := p.magic.TLSConfig()
	tlsCfg.NextProtos = append([]string{"h2", "http/1.1"}, tlsCfg.NextProtos...)
	httpsSrv := &http.Server{
		Addr:              ":443",
		Handler:           http.HandlerFunc(p.serveHTTPS),
		TLSConfig:         tlsCfg,
		ReadHeaderTimeout: 10 * time.Second,
	}
	l80, err := net.Listen("tcp", ":80")
	if err != nil {
		return fmt.Errorf("listen :80 (is nginx/apache running?): %w", err)
	}
	l443, err := net.Listen("tcp", ":443")
	if err != nil {
		l80.Close()
		return fmt.Errorf("listen :443: %w", err)
	}
	go httpSrv.Serve(l80)
	go httpsSrv.Serve(tls.NewListener(l443, tlsCfg))
	go func() {
		<-ctx.Done()
		httpSrv.Close()
		httpsSrv.Close()
	}()
	p.started = true
	log.Printf("proxy: listening on :80 and :443")
	return nil
}

func (p *Proxy) lookup(r *http.Request) *live {
	host := strings.ToLower(r.Host)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.routes[host]
}

func disabled(w http.ResponseWriter, l *live) bool {
	if !l.route.Disabled {
		return false
	}
	http.Error(w, "This site is disabled.", http.StatusForbidden)
	return true
}

func (p *Proxy) serveHTTP(w http.ResponseWriter, r *http.Request) {
	l := p.lookup(r)
	if l == nil {
		http.NotFound(w, r)
		return
	}
	if !l.route.ForceHTTPS && disabled(w, l) {
		return
	}
	if l.route.ForceHTTPS {
		u := *r.URL
		u.Scheme, u.Host = "https", l.route.Hostname
		http.Redirect(w, r, u.String(), http.StatusPermanentRedirect)
		return
	}
	p.counted(w, r, l)
}

func (p *Proxy) serveHTTPS(w http.ResponseWriter, r *http.Request) {
	l := p.lookup(r)
	if l == nil {
		http.NotFound(w, r)
		return
	}
	if disabled(w, l) {
		return
	}
	if l.route.ForceHTTPS {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
	}
	p.counted(w, r, l)
}

func newReverseProxy(target *url.URL) *httputil.ReverseProxy {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	// Home services commonly use self-signed certificates; the hop between
	// edge and service is already encrypted by WireGuard.
	tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	return &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.SetXForwarded()
			pr.Out.Host = pr.In.Host
		},
		Transport: tr,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("proxy %s -> %s: %v", r.Host, target, err)
			http.Error(w, "upstream unavailable", http.StatusBadGateway)
		},
	}
}
