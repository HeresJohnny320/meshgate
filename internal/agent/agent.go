// Package agent runs a meshgate node: it keeps the WireGuard interface,
// firewall rules and HTTPS proxy in line with the replicated config and the
// live path measurements, and serves the sync, join, local and web APIs.
package agent

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/heresjohnny320/meshgate/internal/config"
	"github.com/heresjohnny320/meshgate/internal/diag"
	"github.com/heresjohnny320/meshgate/internal/fw"
	"github.com/heresjohnny320/meshgate/internal/hostfw"
	"github.com/heresjohnny320/meshgate/internal/join"
	"github.com/heresjohnny320/meshgate/internal/meshcfg"
	"github.com/heresjohnny320/meshgate/internal/model"
	"github.com/heresjohnny320/meshgate/internal/ops"
	"github.com/heresjohnny320/meshgate/internal/pathsel"
	"github.com/heresjohnny320/meshgate/internal/pfsense"
	"github.com/heresjohnny320/meshgate/internal/probe"
	"github.com/heresjohnny320/meshgate/internal/proxy"
	"github.com/heresjohnny320/meshgate/internal/store"
	"github.com/heresjohnny320/meshgate/internal/syncer"
	"github.com/heresjohnny320/meshgate/internal/webtls"
	"github.com/heresjohnny320/meshgate/internal/webui"
	"github.com/heresjohnny320/meshgate/internal/wg"
)

// Version is set at build time.
var Version = "dev"

// Agent is a running node.
type Agent struct {
	Cfg   config.Node
	Store *store.Store

	wg     *wg.Manager
	prober *probe.Prober
	sync   *syncer.Syncer
	proxy  *proxy.Proxy
	ops    *ops.Service

	mu       sync.Mutex
	prev     *pathsel.Result
	lastWG   *meshcfg.Config
	lastFW   string
	lastFWAt time.Time
	lastIpt  string // iptables MESHGATE rules last applied
	// ufw/firewalld rules last synced, when, and the error if any.
	lastHost   string
	lastHostAt time.Time
	hostErr    string
	webCert    *webtls.Cert // web UI certificate (nil: plain http)
	warnings   []string
	proxyErr   string
	startedAt  time.Time
	// Test service (diag.Serve) currently running, and how to stop it.
	testPort int
	testStop context.CancelFunc
	testErr  string
	meters   meters     // traffic counters (traffic.go)
	hist     histState  // traffic history (history.go)
	links    linkWatch  // drops and path changes in the log (linkwatch.go)
	ev       eventState // the event log (eventlog.go)
}

// New prepares an agent from the node config.
func New(cfg config.Node) (*Agent, error) {
	s, err := store.Open(cfg.StatePath(), cfg.NodeID)
	if err != nil {
		return nil, err
	}
	key, err := wgtypes.ParseKey(cfg.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("private key: %w", err)
	}
	a := &Agent{
		Cfg:       cfg,
		Store:     s,
		wg:        wg.New(cfg.Iface, key),
		sync:      syncer.New(s, cfg.NodeID, cfg.MeshPort),
		proxy:     &proxy.Proxy{StorageDir: cfg.CertMagicDir()},
		startedAt: time.Now(),
	}
	a.ops = &ops.Service{Store: s, SelfID: cfg.NodeID, Runtime: a.Runtime, Traffic: a.Traffic, Update: a.Update, History: a.History, Events: a.Events, RawLog: a.RawLog}
	a.captureLog()
	return a, nil
}

func (a *Agent) self() (model.Node, error) {
	n, ok := store.Get[model.Node](a.Store, model.Key(model.KindNode, a.Cfg.NodeID))
	if !ok {
		return n, errors.New("this node is not registered in the mesh (removed?)")
	}
	return n, nil
}

// Run blocks until ctx is cancelled.
func (a *Agent) Run(ctx context.Context) error {
	self, err := a.self()
	if err != nil {
		return err
	}
	netw, ok := store.Get[model.Network](a.Store, model.Key(model.KindNetwork, "main"))
	if !ok {
		return errors.New("no network config; run `meshgate init` or `meshgate join`")
	}
	mesh, err := netw.Prefix()
	if err != nil {
		return err
	}
	if err := a.wg.Up(a.Cfg.Userspace); err != nil {
		return fmt.Errorf("wireguard: %w", err)
	}
	// The kernel tunnel outlives this process: a restart or update does not
	// interrupt traffic (meshgate stop / leave take it down).
	defer a.wg.Release()
	if self.Kind == model.NodeServer {
		wg.EnableForwarding()
		a.syncSelf(self)
	}
	if runtime.GOOS == "freebsd" && fw.IsPfSense() {
		fw.PFRdrAnchor = fw.DefaultPFSenseRdrAnchor
	}
	if a.Cfg.PFNatAnchor != "" {
		fw.PFNatAnchor = a.Cfg.PFNatAnchor
	}
	if a.Cfg.PFRdrAnchor != "" {
		fw.PFRdrAnchor = a.Cfg.PFRdrAnchor
	}
	if a.Cfg.PFFilterAnchor != "" {
		fw.PFFilterAnchor = a.Cfg.PFFilterAnchor
	}
	log.Printf("meshgate %s: node %s (%s) mesh ip %s", Version, self.Name, self.Kind, self.MeshIP)

	a.prober = probe.New(a.Cfg.NodeID, mesh, wg.MarkSocket)
	a.prober.SetBootID(a.tunnelID(a.wg.Created))
	listen := self.ListenPort
	if listen == 0 {
		listen = model.DefaultWGPort
	}
	go func() {
		for ctx.Err() == nil {
			err := a.prober.Serve(ctx, listen+probe.Offset)
			if err == nil {
				return
			}
			log.Printf("probe server: %v (retrying)", err)
			select {
			case <-ctx.Done():
			case <-time.After(3 * time.Second):
			}
		}
	}()
	go a.prober.Run(ctx, a.probeTargets)
	go a.eventsLoop(ctx)

	a.reconcile(ctx) // brings up the mesh address before we bind to it

	var wgrp sync.WaitGroup
	start := func(name string, f func() error) {
		wgrp.Add(1)
		go func() {
			defer wgrp.Done()
			if err := f(); err != nil && !errors.Is(err, http.ErrServerClosed) && ctx.Err() == nil {
				log.Printf("%s: %v", name, err)
			}
		}()
	}
	start("mesh api", func() error {
		// Server-to-server sync, plus the phone app's management API.
		mux := http.NewServeMux()
		mux.Handle("/", a.sync.Handler())
		mux.HandleFunc("GET /v1/traffic", a.serveTraffic)
		mux.HandleFunc("POST /v1/update", a.serveUpdate)
		mux.HandleFunc("/v1/history", a.serveHistory)
		mux.HandleFunc("POST /v1/history/import", a.serveHistoryImport)
		mux.HandleFunc("/v1/events", a.serveEvents)
		mux.HandleFunc("GET /v1/rawlog", a.serveRawLog)
		mux.Handle("/admin/", webui.AppAPI(a.ops, func() bool {
			s, err := a.self()
			return err != nil || s.AppAdminOff
		}))
		return serve(ctx, net.JoinHostPort(self.MeshIP, strconv.Itoa(a.Cfg.MeshPort)), mux, nil)
	})
	start("local api", func() error { return a.serveLocal(ctx) })
	if self.Kind == model.NodeServer && a.Cfg.JoinListen != "" {
		start("join api", func() error {
			cert, _, err := join.EnsureCert(a.Cfg.CertPath(), a.Cfg.KeyPath())
			if err != nil {
				return err
			}
			tc := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}
			return serve(ctx, a.Cfg.JoinListen, join.Handler(a.Store), tc)
		})
	}
	if self.Kind == model.NodeServer {
		var ui http.Handler = webui.New(a.ops)
		if len(a.Cfg.WebListen) > 0 && !a.Cfg.WebPlainHTTP {
			// HTTPS with a certificate from this server's own CA for every
			// address the web UI answers on; http:// on the same port
			// redirects.
			a.webCert = &webtls.Cert{CertPath: a.Cfg.WebCertPath(), KeyPath: a.Cfg.WebKeyPath(),
				CACertPath: a.Cfg.WebCACertPath(), CAKeyPath: a.Cfg.WebCAKeyPath(), Name: self.Name, Mesh: mesh,
				Hosts: webtls.Hosts(a.Cfg.WebListen, self.MeshIP, strings.ToLower(self.Name))}
			if err := a.webCert.Refresh(time.Now()); err != nil {
				return fmt.Errorf("web UI certificate: %w", err)
			}
			log.Printf("web ui: https, certificate fingerprint (SHA-256) %s, CA %s", a.webCert.Fingerprint(), a.webCert.CAFingerprint())
			a.syncSelfNow()
			go func() {
				for {
					select {
					case <-ctx.Done():
						return
					case <-time.After(12 * time.Hour):
						if err := a.webCert.Refresh(time.Now()); err != nil {
							log.Printf("web ui certificate: %v", err)
						}
						a.syncSelfNow()
					}
				}
			}()
			ui = webtls.Redirect(a.webCert.ServeCA(ui))
		}
		for _, addr := range a.Cfg.WebListen {
			addr := addr
			start("web ui "+addr, func() error {
				if a.webCert != nil {
					return serveListener(ctx, addr, ui, func(l net.Listener) net.Listener { return webtls.Listener(l, a.webCert.TLSConfig()) })
				}
				return serve(ctx, addr, ui, nil)
			})
		}
	}
	go a.sync.Run(ctx)
	if self.Kind == model.NodeServer {
		go a.trafficLoop(ctx)
		go a.latestLoop(ctx)
	}
	if fw.IsPfSense() && pfsense.Installed() {
		// After an update: bring VPN > meshgate's pages to this version.
		if err := pfsense.WriteFiles(webui.Static(), a.Cfg.Socket, Version); err != nil {
			log.Printf("pfsense gui: %v", err)
		}
	}

	changes := a.Store.Subscribe()
	tick := time.NewTicker(probe.Interval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			wgrp.Wait()
			return nil
		case <-changes:
			a.reconcile(ctx)
		case <-tick.C:
			a.reconcile(ctx)
		}
	}
}

func (a *Agent) probeTargets() []probe.Target {
	var out []probe.Target
	for _, n := range store.List[model.Node](a.Store, model.KindNode) {
		if n.ID == a.Cfg.NodeID || n.Kind == model.NodeStatic {
			continue
		}
		for _, ep := range n.Endpoints {
			out = append(out, probe.Target{NodeID: n.ID, Endpoint: ep})
		}
	}
	return out
}

// reconcile recomputes paths and applies WireGuard, firewall and proxy.
func (a *Agent) reconcile(ctx context.Context) {
	a.mu.Lock()
	defer a.mu.Unlock()
	var warn []string

	self, err := a.self()
	if err != nil {
		a.warnings = []string{err.Error()}
		return
	}
	netw, _ := store.Get[model.Network](a.Store, model.Key(model.KindNetwork, "main"))
	nodes := store.List[model.Node](a.Store, model.KindNode)
	forwards := store.List[model.Forward](a.Store, model.KindForward)
	statuses := map[string]model.Status{}
	for _, st := range store.List[model.Status](a.Store, model.KindStatus) {
		statuses[st.NodeID] = st
	}
	probes, inbound := a.prober.Snapshot()
	if restarted := a.prober.TakeRestarted(); len(restarted) > 0 {
		var keys []string
		for _, n := range nodes {
			for _, id := range restarted {
				if n.ID == id {
					keys = append(keys, n.PublicKey)
					log.Printf("peer %s restarted; re-handshaking", n.Name)
				}
			}
		}
		if err := a.wg.ResetPeers(keys); err != nil {
			log.Printf("reset peers: %v", err)
		}
		a.lastWG = nil
	}

	res := pathsel.Decide(pathsel.Input{
		Self: self, Nodes: nodes, Statuses: statuses,
		Probes: probes, Inbound: inbound, Prev: a.prev, Now: time.Now(),
	})
	a.publishStatus(res, statuses[self.ID])
	a.prev = &res

	exitRoutes := store.List[model.ExitRoute](a.Store, model.KindExitRoute)
	cfg, err := meshcfg.Build(meshcfg.Input{
		Network: netw, Self: self, Nodes: nodes, Forwards: forwards, Paths: res,
		LocalAddrs:     wg.LocalAddrs(a.Cfg.Iface),
		LANExitCapable: runtime.GOOS == "linux" || runtime.GOOS == "freebsd",
		ExitRoutes:     exitRoutes,
	})
	if err != nil {
		a.warnings = []string{err.Error()}
		return
	}
	warn = append(warn, cfg.Warnings...)
	if recreated, err := a.wg.Ensure(a.Cfg.Userspace); err != nil {
		warn = append(warn, "wireguard interface: "+err.Error())
	} else if recreated {
		log.Printf("wg: interface %s was removed by something else; recreated it", a.Cfg.Iface)
		a.lastWG, a.lastFW = nil, ""
		a.prober.SetBootID(a.tunnelID(true)) // peers: our sessions are gone
	}
	a.wg.SyncUnderlay()
	if a.lastWG == nil || !reflect.DeepEqual(*a.lastWG, cfg) {
		if err := a.wg.Apply(cfg); err != nil {
			warn = append(warn, "wireguard: "+err.Error())
		} else {
			a.lastWG = &cfg
		}
	}

	if self.Kind == model.NodeServer {
		listen := self.ListenPort
		if listen == 0 {
			listen = model.DefaultWGPort
		}
		plan := fw.Build(fw.Input{
			Iface: a.Cfg.Iface, Network: netw, Self: self, Nodes: nodes,
			Forwards: forwards, Routes: store.List[model.HTTPRoute](a.Store, model.KindRoute),
			ACLs: store.List[model.ACL](a.Store, model.KindACL), Monitors: store.List[model.Monitor](a.Store, model.KindMonitor), PreserveEdge: cfg.DefaultViaPeer,
			WGPort: listen, ProbePort: listen + probe.Offset, MeshPort: a.Cfg.MeshPort,
			JoinPort: joinPort(a.Cfg.JoinListen), WebPort: webPort(a.Cfg.WebListen), WANIface: fw.DetectWAN(),
			TestPort:    self.TestPort,
			LANExitSrcs: prefixStrings(cfg.LANExitSrcs), LANExitGW: meshIPOf(nodes, cfg.LANExitVia), LANExitBlock: prefixStrings(cfg.LANExitBlock),
			ExitRoutes: exitRoutes,
		})
		warn = append(warn, plan.Warnings...)
		if runtime.GOOS == "windows" {
			if len(plan.DNAT) > 0 || len(plan.LANs) > 0 || plan.Restricted || plan.PreserveEdgeIP != "" {
				warn = append(warn, "Windows nodes cannot be a forward edge, share LAN subnets, enforce a restricted LAN policy or receive real client IPs; use Linux or pfSense for that")
			}
		}
		for _, l := range plan.LANs {
			if l.Iface == "" && runtime.GOOS == "freebsd" {
				warn = append(warn, "shared subnet "+l.CIDR+" is not on any local interface")
			}
		}
		script := fw.Render(plan)
		// Reload on change, and once a minute in case something flushed our
		// table/anchors (e.g. `nft flush ruleset`, a manual pfctl -F all).
		ipt := plan.IptablesRules()
		iptKey := fmt.Sprint(self.IptablesOff, ipt)
		if script != a.lastFW || iptKey != a.lastIpt || time.Since(a.lastFWAt) > time.Minute {
			a.readTraffic() // reloading restarts the counters; keep what they hold
			var iptErr error
			if self.IptablesOff {
				fw.RemoveIptables()
			}
			if err := fw.Load(script); err != nil {
				warn = append(warn, "firewall: "+err.Error())
			} else {
				if !self.IptablesOff {
					iptErr = fw.SyncIptables(ipt)
				}
				if iptErr != nil {
					warn = append(warn, "firewall (iptables FORWARD): "+iptErr.Error())
				}
				a.lastFW, a.lastFWAt, a.lastIpt = script, time.Now(), iptKey
			}
		}
		// Open what this node needs in ufw/firewalld; re-checked every
		// minute so a firewall turned on later is picked up.
		hostRules := hostfw.Wanted(plan)
		if hostKey := fmt.Sprint(self.HostFirewallOff, hostRules); hostKey != a.lastHost || time.Since(a.lastHostAt) > time.Minute {
			a.hostErr = ""
			if _, err := hostfw.Sync(a.Cfg.HostFirewallStatePath(), hostRules, self.HostFirewallOff); err != nil {
				a.hostErr = err.Error()
			}
			a.lastHost, a.lastHostAt = hostKey, time.Now()
		}
		if a.hostErr != "" {
			warn = append(warn, "host firewall (ufw/firewalld): "+a.hostErr)
		}
		a.updateProxy(ctx, netw, nodes)
		a.updateTest(ctx, self)
	}
	if a.testErr != "" {
		warn = append(warn, "test service: "+a.testErr)
	}
	if a.proxyErr != "" {
		warn = append(warn, "https proxy: "+a.proxyErr)
	}
	a.watchLinks(nodes, res, warn)
	a.warnings = warn
}

func (a *Agent) publishStatus(res pathsel.Result, cur model.Status) {
	paths := map[string]string{}
	for id, p := range res.Paths {
		if p.Direct() {
			paths[id] = "direct"
		} else {
			paths[id] = p.Via
		}
	}
	lans := fw.LocalLANs(a.Cfg.Iface)
	if fw.IsPfSense() {
		// Offer LAN/VLAN interfaces as rule targets, not the WAN.
		wan := fw.DetectWAN()
		kept := lans[:0]
		for _, l := range lans {
			if l.Iface != wan {
				kept = append(kept, l)
			}
		}
		lans = kept
	}
	if cur.HomeRelay == res.HomeRelay && samePaths(cur.Paths, paths) && cur.Version == Version &&
		reflect.DeepEqual(cur.LANs, lans) && time.Since(time.Unix(cur.UpdatedAt, 0)) < 10*time.Minute {
		return
	}
	st := model.Status{NodeID: a.Cfg.NodeID, HomeRelay: res.HomeRelay, Paths: paths, Version: Version,
		LANs: lans, OS: runtime.GOOS, UpdatedAt: time.Now().Unix()}
	if _, err := a.Store.Put(model.Key(model.KindStatus, a.Cfg.NodeID), st, store.Cluster); err != nil {
		log.Printf("status: %v", err)
	}
}

func joinPort(listen string) int {
	_, p, err := net.SplitHostPort(listen)
	if err != nil {
		return 0
	}
	n, _ := strconv.Atoi(p)
	return n
}

func webPort(listen []string) int {
	if len(listen) == 0 {
		return 0
	}
	return joinPort(listen[0])
}

// syncSelf keeps this node's record in line with its local config (web UI
// on/off, and the default LAN policy).
func (a *Agent) syncSelf(self model.Node) {
	want, port := len(a.Cfg.WebListen) > 0, webPort(a.Cfg.WebListen)
	webTLS := want && !a.Cfg.WebPlainHTTP
	webFP, caFP := "", ""
	switch {
	case a.webCert != nil:
		webFP, caFP = a.webCert.Fingerprint(), a.webCert.CAFingerprint()
	case webTLS:
		webFP, caFP = self.WebFP, self.WebCAFP // certificate not loaded yet: keep the last one
	}
	if self.WebUI == want && self.WebPort == port && self.MeshPort == a.Cfg.MeshPort && self.WebTLS == webTLS && self.WebFP == webFP && self.WebCAFP == caFP {
		return
	}
	if self.Kind != model.NodeServer {
		// Clients cannot write their node record; they keep the default
		// sync port (phones do not serve it at all).
		return
	}
	self.WebUI, self.WebPort, self.MeshPort, self.WebTLS, self.WebFP, self.WebCAFP = want, port, a.Cfg.MeshPort, webTLS, webFP, caFP
	if _, err := a.Store.Put(model.Key(model.KindNode, self.ID), self, store.Cluster); err != nil {
		log.Printf("update self: %v", err)
	}
}

// syncSelfNow runs syncSelf on the current node record.
func (a *Agent) syncSelfNow() {
	if self, err := a.self(); err == nil && self.Kind == model.NodeServer {
		a.syncSelf(self)
	}
}

func samePaths(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// updateTest starts, moves or stops the test service to match self.TestPort.
// Called with a.mu held.
func (a *Agent) updateTest(ctx context.Context, self model.Node) {
	if self.TestPort == a.testPort {
		return
	}
	if a.testStop != nil {
		a.testStop()
		a.testStop = nil
	}
	a.testPort, a.testErr = self.TestPort, ""
	if self.TestPort == 0 {
		return
	}
	tctx, stop := context.WithCancel(ctx)
	a.testStop = stop
	port, name := self.TestPort, self.Name
	go func() {
		log.Printf("test service on port %d (tcp+udp)", port)
		if err := diag.Serve(tctx, port, name); err != nil {
			log.Printf("test service: %v", err)
			a.mu.Lock()
			if a.testPort == port {
				a.testErr = err.Error()
			}
			a.mu.Unlock()
		}
	}()
}

func (a *Agent) updateProxy(ctx context.Context, netw model.Network, nodes []model.Node) {
	byID := map[string]model.Node{}
	for _, n := range nodes {
		byID[n.ID] = n
	}
	var routes []proxy.Route
	for _, r := range store.List[model.HTTPRoute](a.Store, model.KindRoute) {
		if r.EdgeNode != a.Cfg.NodeID {
			continue
		}
		t, ok := byID[r.TargetNode]
		if !ok {
			continue
		}
		host := r.TargetIP
		if host == "" {
			host = t.MeshIP
		}
		scheme := "http"
		if r.TargetTLS {
			scheme = "https"
		}
		u, err := url.Parse(scheme + "://" + net.JoinHostPort(host, strconv.Itoa(r.TargetPort)))
		if err != nil {
			continue
		}
		routes = append(routes, proxy.Route{Hostname: r.Hostname, Target: u, ForceHTTPS: r.ForceHTTPS, Disabled: !r.Enabled})
	}
	if err := a.proxy.Update(ctx, routes, netw.ACMEEmail); err != nil {
		a.proxyErr = err.Error()
	} else {
		a.proxyErr = ""
	}
}

// Runtime reports live state for the UIs.
func (a *Agent) Runtime() ops.Runtime {
	a.mu.Lock()
	prev, warnings, cfg := a.prev, append([]string(nil), a.warnings...), a.lastWG
	a.mu.Unlock()
	rt := ops.Runtime{Peers: map[string]ops.PeerRuntime{}, Warnings: warnings, LastSync: a.sync.LastContact(),
		Userspace: a.wg.Userspace, StartedAt: a.startedAt, Latest: latestRelease()}
	if a.webCert != nil {
		rt.WebCertFP, rt.WebCAFP = a.webCert.Fingerprint(), a.webCert.CAFingerprint()
		if sk := a.webCert.Skipped(); len(sk) > 0 {
			// Clip: the slice is shared with a.warnings.
			rt.Warnings = append(slices.Clip(rt.Warnings), "web UI certificate leaves out "+strings.Join(sk, ", ")+
				" (newer than this server's CA): `sudo meshgate webui ca --new`, then install the new CA")
		}
	}
	stats := a.wg.Stats()
	if prev != nil {
		rt.HomeRelay = prev.HomeRelay
	}
	if cfg != nil {
		for _, p := range cfg.Peers {
			pr := ops.PeerRuntime{}
			if prev != nil {
				if path := prev.Paths[p.NodeID]; path.Direct() {
					pr.Path = "direct"
				} else {
					pr.Path = "via " + path.Via
				}
			}
			if s, ok := stats[p.PublicKey]; ok {
				pr.Endpoint, pr.LastHandshake, pr.RxBytes, pr.TxBytes = s.Endpoint, s.LastHandshake, s.RxBytes, s.TxBytes
			}
			rt.Peers[p.NodeID] = pr
		}
	}
	return rt
}

func (a *Agent) serveLocal(ctx context.Context) error {
	config.SecureDir(filepath.Dir(a.Cfg.Socket))
	os.Remove(a.Cfg.Socket)
	l, err := net.Listen("unix", a.Cfg.Socket)
	if err != nil {
		return err
	}
	os.Chmod(a.Cfg.Socket, 0o600)
	mux := http.NewServeMux()
	mux.Handle("/v1/", a.ops.Handler("/v1/"))
	mux.HandleFunc("POST /v1/qr", webui.QR) // for the pfSense GUI page (meshgate pfsense)
	srv := &http.Server{Handler: mux}
	go func() { <-ctx.Done(); srv.Close() }()
	return srv.Serve(l)
}

// serve listens on addr, retrying while the address is not yet available
// (the mesh IP appears once WireGuard is configured).
func serve(ctx context.Context, addr string, h http.Handler, tc *tls.Config) error {
	if tc == nil {
		return serveListener(ctx, addr, h, nil)
	}
	return serveListener(ctx, addr, h, func(l net.Listener) net.Listener { return tls.NewListener(l, tc) })
}

// serveListener serves h on addr (retrying until the address is free),
// through wrap when given.
func serveListener(ctx context.Context, addr string, h http.Handler, wrap func(net.Listener) net.Listener) error {
	var l net.Listener
	var err error
	for {
		l, err = net.Listen("tcp", addr)
		if err == nil {
			break
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(2 * time.Second):
		}
	}
	if wrap != nil {
		l = wrap(l)
	}
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second}
	go func() { <-ctx.Done(); srv.Close() }()
	return srv.Serve(l)
}

func prefixStrings(ps []netip.Prefix) []string {
	var out []string
	for _, p := range ps {
		out = append(out, p.String())
	}
	return out
}

func meshIPOf(nodes []model.Node, id string) string {
	for _, n := range nodes {
		if n.ID == id {
			return n.MeshIP
		}
	}
	return ""
}
