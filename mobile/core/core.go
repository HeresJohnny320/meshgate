// Package meshcore is the shared engine of the meshgate Android and iOS apps,
// exported with gomobile:
//
//	gomobile bind -target=android -javapkg=dev.meshgate -o meshcore.aar ./mobile/core
//	gomobile bind -target=ios -o Meshcore.xcframework ./mobile/core
//
// It runs the same path selection as Linux nodes (direct on home Wi-Fi,
// nearest relay elsewhere) on top of wireguard-go. The platform layer only
// creates the TUN device and reports network changes.
//
// Phones sync through the public join API of server nodes (TLS pinned to
// the certificate fingerprint from the join token), because on iOS a VPN
// extension's own connections never go through its own tunnel.
package meshcore

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/heresjohnny320/meshgate/internal/diag"
	"github.com/heresjohnny320/meshgate/internal/join"
	"github.com/heresjohnny320/meshgate/internal/meshcfg"
	"github.com/heresjohnny320/meshgate/internal/model"
	"github.com/heresjohnny320/meshgate/internal/pathsel"
	"github.com/heresjohnny320/meshgate/internal/probe"
	"github.com/heresjohnny320/meshgate/internal/store"
	"github.com/heresjohnny320/meshgate/internal/uapi"
)

// MTU of the tunnel interface.
const MTU = 1280

// Platform is implemented in Kotlin (Android) and Swift (iOS).
type Platform interface {
	// Protect keeps a socket outside the VPN (Android VpnService.protect).
	// iOS returns true without doing anything.
	Protect(fd int32) bool
	// ConfigureTunnel applies TunnelSettings JSON (address, routes, mtu) and
	// returns the TUN file descriptor. Android builds a new interface each
	// time; iOS updates the settings and returns the same utun descriptor.
	// Return -1 on failure.
	ConfigureTunnel(settingsJSON string) int32
	// LocalAddresses returns this device's non-VPN IPv4 addresses,
	// comma separated (used to notice "I am on the home LAN").
	LocalAddresses() string
	// Log receives diagnostic lines.
	Log(msg string)
}

// TunnelSettings is passed to Platform.ConfigureTunnel.
type TunnelSettings struct {
	Address string   `json:"address"` // e.g. 100.88.12.34
	Prefix  int      `json:"prefix"`  // e.g. 16
	Routes  []string `json:"routes"`  // CIDRs to send into the tunnel
	MTU     int      `json:"mtu"`
	// DNS servers to use while an exit node carries all traffic (so lookups
	// leave through the exit too, not through the local network).
	DNS []string `json:"dns,omitempty"`
}

// wgMark is set on platforms where WireGuard's sockets may be marked.
var wgMark uint32

// exitDNS are the resolvers used through an exit node.
var exitDNS = []string{"1.1.1.1", "9.9.9.9"}

type identity struct {
	NodeID     string        `json:"node_id"`
	PrivateKey string        `json:"private_key"`
	APISecret  string        `json:"api_secret"`
	Servers    []join.Server `json:"servers"`
}

// Engine is one device's mesh client.
type Engine struct {
	dir  string
	plat Platform

	mu       sync.Mutex
	id       *identity
	store    *store.Store
	key      wgtypes.Key
	dev      *device.Device
	tunFD    int32
	settings string
	applied  map[string]bool // peer public keys configured on the device
	lastCfg  *meshcfg.Config
	prev     *pathsel.Result
	prober   *probe.Prober
	cancel   context.CancelFunc
	seq      uint64
	pushed   uint64
	lastErr  string
	lastSync time.Time
	kick     chan struct{}
	syncKick chan struct{}
}

// NewEngine opens (or prepares) state in dir, e.g. the app's files dir or
// the iOS App Group container.
func NewEngine(dir string, plat Platform) (*Engine, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	e := &Engine{dir: dir, plat: plat, tunFD: -1, kick: make(chan struct{}, 1), syncKick: make(chan struct{}, 1)}
	if b, err := os.ReadFile(e.idPath()); err == nil {
		var id identity
		if err := json.Unmarshal(b, &id); err != nil {
			return nil, err
		}
		if err := e.load(&id); err != nil {
			return nil, err
		}
	}
	return e, nil
}

func (e *Engine) idPath() string    { return filepath.Join(e.dir, "identity.json") }
func (e *Engine) statePath() string { return filepath.Join(e.dir, "state.json") }

func (e *Engine) load(id *identity) error {
	k, err := wgtypes.ParseKey(id.PrivateKey)
	if err != nil {
		return err
	}
	s, err := store.Open(e.statePath(), id.NodeID)
	if err != nil {
		return err
	}
	e.id, e.key, e.store = id, k, s
	return nil
}

// IsJoined reports whether this device has joined a mesh.
func (e *Engine) IsJoined() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.id != nil
}

// Join redeems a token (from the QR code) and stores the identity.
func (e *Engine) Join(token, deviceName string) error {
	tok, err := join.Decode(token)
	if err != nil {
		return err
	}
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	d := net.Dialer{Control: e.control}
	resp, err := join.Do(ctx, tok, join.Request{Name: deviceName, Kind: model.NodeClient, PublicKey: key.PublicKey().String()}, d.DialContext)
	if err != nil {
		return err
	}
	if resp.APISecret == "" {
		return errors.New("server did not issue a sync secret (is it up to date?)")
	}
	id := &identity{NodeID: resp.Node.ID, PrivateKey: key.String(), APISecret: resp.APISecret, Servers: tok.Servers}
	b, _ := json.MarshalIndent(id, "", " ")
	os.Remove(e.statePath())
	if err := os.WriteFile(e.idPath(), b, 0o600); err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.load(id); err != nil {
		return err
	}
	_, err = e.store.Merge(resp.Entries)
	return err
}

// Leave stops the tunnel and forgets the mesh.
func (e *Engine) Leave() error {
	e.Stop()
	e.mu.Lock()
	defer e.mu.Unlock()
	e.id, e.store = nil, nil
	os.Remove(e.statePath())
	return os.Remove(e.idPath())
}

// Start brings the tunnel up and keeps it tuned until Stop.
func (e *Engine) Start() error {
	e.mu.Lock()
	if e.id == nil {
		e.mu.Unlock()
		return errors.New("not joined")
	}
	if e.cancel != nil {
		e.mu.Unlock()
		return nil
	}
	netw, ok := store.Get[model.Network](e.store, model.Key(model.KindNetwork, "main"))
	if !ok {
		e.mu.Unlock()
		return errors.New("no network config")
	}
	mesh, err := netw.Prefix()
	if err != nil {
		e.mu.Unlock()
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	e.cancel = cancel
	e.prober = probe.New(e.id.NodeID, mesh, e.control)
	e.mu.Unlock()

	go e.prober.Run(ctx, e.probeTargets)
	if err := e.reconcile(); err != nil {
		e.Stop()
		return err
	}
	go e.loop(ctx)
	go e.syncLoop(ctx)
	return nil
}

// Stop tears the tunnel down.
func (e *Engine) Stop() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.cancel != nil {
		e.cancel()
		e.cancel = nil
	}
	if e.dev != nil {
		e.dev.Close()
		e.dev = nil
	}
	e.tunFD, e.settings, e.applied, e.lastCfg, e.prev = -1, "", nil, nil, nil
}

// NetworkChanged should be called when Wi-Fi/cellular changes. It drops old
// measurements and re-probes immediately so the path switches quickly.
func (e *Engine) NetworkChanged() {
	e.mu.Lock()
	p := e.prober
	e.mu.Unlock()
	if p != nil {
		p.Forget()
	}
	for _, ch := range []chan struct{}{e.kick, e.syncKick} {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

// loop keeps paths and the tunnel up to date. It never does network I/O
// itself, so a slow server cannot delay switching paths.
func (e *Engine) loop(ctx context.Context) {
	tick := time.NewTicker(probe.Interval)
	defer tick.Stop()
	for {
		if err := e.reconcile(); err != nil {
			e.plat.Log("reconcile: " + err.Error())
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		case <-e.kick:
			// Network changed: first adapt routes to the new network (e.g.
			// stop tunnelling the home LAN), then re-probe and decide again
			// once the answers are in.
			e.reconcile()
			e.mu.Lock()
			p := e.prober
			e.mu.Unlock()
			if p != nil {
				p.Kick()
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(700 * time.Millisecond):
			}
		}
	}
}

// syncLoop exchanges state with servers in the background.
func (e *Engine) syncLoop(ctx context.Context) {
	for {
		wait := 15 * time.Second
		if err := e.sync(ctx); err != nil {
			e.plat.Log("sync: " + err.Error())
			wait = 5 * time.Second
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		case <-e.syncKick:
		}
	}
}

func (e *Engine) control(network, address string, c syscall.RawConn) error {
	return c.Control(func(fd uintptr) { e.plat.Protect(int32(fd)) })
}

func (e *Engine) probeTargets() []probe.Target {
	e.mu.Lock()
	s, self := e.store, ""
	if e.id != nil {
		self = e.id.NodeID
	}
	e.mu.Unlock()
	if s == nil {
		return nil
	}
	var out []probe.Target
	for _, n := range store.List[model.Node](s, model.KindNode) {
		if n.ID == self || n.Kind == model.NodeStatic {
			continue
		}
		for _, ep := range n.Endpoints {
			out = append(out, probe.Target{NodeID: n.ID, Endpoint: ep})
		}
	}
	return out
}

// sync exchanges state with the first reachable server: our status goes up,
// topology changes come down.
func (e *Engine) sync(ctx context.Context) error {
	e.mu.Lock()
	if e.id == nil {
		e.mu.Unlock()
		return nil
	}
	id, s, since, pushed := *e.id, e.store, e.seq, e.pushed
	e.mu.Unlock()

	servers := e.servers(s, id)
	mine, cur := s.Since(pushed)
	var up []store.Entry
	own := model.Key(model.KindStatus, id.NodeID)
	for _, en := range mine {
		if en.Key == own && en.Origin == id.NodeID {
			up = append(up, en)
		}
	}
	d := net.Dialer{Control: e.control, Timeout: 5 * time.Second}
	var lastErr error
	for _, srv := range servers {
		cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		res, err := join.SyncClient(cctx, srv, id.NodeID, id.APISecret, join.ClientSync{Since: since, Entries: up}, d.DialContext)
		cancel()
		if err != nil {
			lastErr = err
			continue
		}
		if _, err := s.Merge(res.Entries); err != nil {
			return err
		}
		e.mu.Lock()
		e.pushed = cur
		if res.Since < since {
			res.Since = 0 // server state reset; resync fully next time
		}
		e.seq, e.lastSync = res.Since, time.Now()
		e.mu.Unlock()
		return nil
	}
	if lastErr == nil {
		lastErr = errors.New("no server with a join address")
	}
	return lastErr
}

// servers lists join APIs to sync with, preferring our current relay.
func (e *Engine) servers(s *store.Store, id identity) []join.Server {
	e.mu.Lock()
	home := ""
	if e.prev != nil {
		home = e.prev.HomeRelay
	}
	e.mu.Unlock()
	var first, rest []join.Server
	seen := map[string]bool{}
	for _, n := range store.List[model.Node](s, model.KindNode) {
		if n.JoinAddr == "" || n.JoinFP == "" || seen[n.JoinAddr] {
			continue
		}
		seen[n.JoinAddr] = true
		srv := join.Server{Addr: n.JoinAddr, FP: n.JoinFP}
		if n.ID == home {
			first = append(first, srv)
		} else {
			rest = append(rest, srv)
		}
	}
	for _, srv := range id.Servers {
		if !seen[srv.Addr] {
			rest = append(rest, srv)
		}
	}
	return append(first, rest...)
}

func (e *Engine) reconcile() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.id == nil || e.prober == nil {
		return nil
	}
	self, ok := store.Get[model.Node](e.store, model.Key(model.KindNode, e.id.NodeID))
	if !ok {
		e.lastErr = "this device was removed from the mesh"
		return errors.New(e.lastErr)
	}
	netw, _ := store.Get[model.Network](e.store, model.Key(model.KindNetwork, "main"))
	nodes := store.List[model.Node](e.store, model.KindNode)
	statuses := map[string]model.Status{}
	for _, st := range store.List[model.Status](e.store, model.KindStatus) {
		statuses[st.NodeID] = st
	}
	probes, inbound := e.prober.Snapshot()
	if restarted := e.prober.TakeRestarted(); len(restarted) > 0 && e.dev != nil {
		var b strings.Builder
		for _, n := range nodes {
			for _, id := range restarted {
				if k, err := wgtypes.ParseKey(n.PublicKey); err == nil && n.ID == id {
					h := hex.EncodeToString(k[:])
					fmt.Fprintf(&b, "public_key=%s\nremove=true\n", h)
					delete(e.applied, h)
				}
			}
		}
		e.dev.IpcSet(b.String())
		e.lastCfg = nil
	}
	res := pathsel.Decide(pathsel.Input{Self: self, Nodes: nodes, Statuses: statuses, Probes: probes, Inbound: inbound, Prev: e.prev, Now: time.Now()})
	e.publishStatus(res, statuses[self.ID])
	e.prev = &res

	cfg, err := meshcfg.Build(meshcfg.Input{Network: netw, Self: self, Nodes: nodes, Paths: res,
		LocalAddrs: parseAddrs(e.plat.LocalAddresses()), ExitCapable: true})
	if err != nil {
		return err
	}
	ts := TunnelSettings{Address: cfg.Address.Addr().String(), Prefix: cfg.Address.Bits(), Routes: []string{netw.CIDR}, MTU: MTU}
	for _, r := range cfg.Routes {
		ts.Routes = append(ts.Routes, r.String())
	}
	if cfg.ExitVia != "" {
		ts.DNS = exitDNS
	}
	b, _ := json.Marshal(ts)
	if string(b) != e.settings || e.dev == nil {
		fd := e.plat.ConfigureTunnel(string(b))
		if fd < 0 {
			e.lastErr = "could not configure the VPN interface"
			return errors.New(e.lastErr)
		}
		e.settings = string(b)
		if fd != e.tunFD || e.dev == nil {
			if err := e.newDevice(fd); err != nil {
				e.lastErr = err.Error()
				return err
			}
		}
	}
	if e.lastCfg == nil || !sameConfig(*e.lastCfg, cfg) {
		text, keys := uapi.Config(cfg, e.applied)
		if err := e.dev.IpcSet(text); err != nil {
			e.lastErr = "wireguard: " + err.Error()
			return err
		}
		e.applied, e.lastCfg = keys, &cfg
	}
	e.lastErr = ""
	return nil
}

func (e *Engine) newDevice(fd int32) error {
	if e.dev != nil {
		e.dev.Close()
		e.dev = nil
	}
	t, err := openTUN(fd)
	if err != nil {
		return fmt.Errorf("tun: %w", err)
	}
	logger := &device.Logger{
		Verbosef: func(string, ...any) {},
		Errorf:   func(f string, a ...any) { e.plat.Log("wg: " + fmt.Sprintf(f, a...)) },
	}
	bind := conn.NewDefaultBind()
	dev := device.NewDevice(t, bind, logger)
	if err := dev.IpcSet("private_key=" + hex.EncodeToString(e.key[:]) + "\nlisten_port=0\n"); err != nil {
		dev.Close()
		return err
	}
	// Desktop Linux (phonesim) keeps WireGuard's own traffic out of a tunnel
	// that carries everything by marking its sockets. Never on Android: it
	// refuses the mark (EPERM), which then breaks every bind; Protect below
	// does that job there.
	if wgMark != 0 {
		dev.IpcSet(fmt.Sprintf("fwmark=%d\n", wgMark))
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return err
	}
	// Keep WireGuard's own UDP sockets out of the tunnel (Android).
	if p, ok := bind.(conn.PeekLookAtSocketFd); ok {
		if fd, err := p.PeekLookAtSocketFd4(); err == nil {
			e.plat.Protect(int32(fd))
		}
		if fd, err := p.PeekLookAtSocketFd6(); err == nil {
			e.plat.Protect(int32(fd))
		}
	}
	e.dev, e.tunFD, e.applied, e.lastCfg = dev, fd, nil, nil
	return nil
}

func (e *Engine) publishStatus(res pathsel.Result, cur model.Status) {
	paths := map[string]string{}
	for id, p := range res.Paths {
		if p.Direct() {
			paths[id] = "direct"
		} else {
			paths[id] = p.Via
		}
	}
	same := cur.HomeRelay == res.HomeRelay && len(cur.Paths) == len(paths)
	for k, v := range paths {
		same = same && cur.Paths[k] == v
	}
	if same && time.Since(time.Unix(cur.UpdatedAt, 0)) < 10*time.Minute {
		return
	}
	e.store.Put(model.Key(model.KindStatus, e.id.NodeID), model.Status{
		NodeID: e.id.NodeID, HomeRelay: res.HomeRelay, Paths: paths, Version: "mobile", UpdatedAt: time.Now().Unix(),
	}, store.Cluster)
	select {
	case e.syncKick <- struct{}{}: // push the new relay choice right away
	default:
	}
}

func sameConfig(a, b meshcfg.Config) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}

func parseAddrs(s string) []netip.Addr {
	var out []netip.Addr
	for _, f := range strings.Split(s, ",") {
		if a, err := netip.ParseAddr(strings.TrimSpace(f)); err == nil {
			out = append(out, a)
		}
	}
	return out
}

// PeerStatus is one row of StatusJSON.
type peerStatus struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Kind          string `json:"kind"`
	MeshIP        string `json:"mesh_ip"`
	Path          string `json:"path"` // "direct", "via <name>", ""
	Endpoint      string `json:"endpoint,omitempty"`
	LastHandshake int64  `json:"last_handshake"` // unix seconds, 0 = never
	RxBytes       int64  `json:"rx_bytes"`
	TxBytes       int64  `json:"tx_bytes"`
}

type status struct {
	Joined    bool         `json:"joined"`
	Running   bool         `json:"running"`
	Name      string       `json:"name,omitempty"`
	MeshIP    string       `json:"mesh_ip,omitempty"`
	HomeRelay string       `json:"home_relay,omitempty"`
	LastSync  int64        `json:"last_sync"`
	Error     string       `json:"error,omitempty"`
	Peers     []peerStatus `json:"peers"`
	// Admin lists web UIs reachable through the mesh (login required).
	Admin []adminLink `json:"admin"`
	// Home: on the LAN of a node that shares it. Exit: the exit node now
	// carrying internet traffic; ExitWanted: the one picked for this device.
	Home       bool     `json:"home"`
	Exit       string   `json:"exit,omitempty"`
	ExitWanted string   `json:"exit_wanted,omitempty"`
	Warnings   []string `json:"warnings,omitempty"`
}

type adminLink struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

// Diag runs a check from the phone (kind: myip, ping, tcp, udp, http; see
// package diag) and returns diag.Result as JSON. It blocks for up to a
// minute, so call it off the UI thread. Its traffic goes through the VPN
// like any app's, so "myip" shows whether an exit node is in use.
func (e *Engine) Diag(kind, target string, port int) string {
	r := diag.Run(context.Background(), diag.Check{Kind: kind, Target: target, Port: port})
	if kind == "myip" && r.OK {
		r.Output += e.exitVerdict(r.Output)
	}
	b, _ := json.Marshal(r)
	return string(b)
}

// exitVerdict says whether a public-IP answer matches the exit node in use.
func (e *Engine) exitVerdict(out string) string {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.lastCfg == nil || e.lastCfg.ExitVia == "" || e.store == nil {
		return "\nNo exit node in use: that is this phone's own network."
	}
	ex, ok := store.Get[model.Node](e.store, model.Key(model.KindNode, e.lastCfg.ExitVia))
	if !ok {
		return ""
	}
	for _, ep := range ex.Endpoints {
		if host, _, err := net.SplitHostPort(ep); err == nil && strings.HasSuffix(strings.TrimSpace(out), " "+host) {
			return "\nThat is " + ex.Name + ": your traffic leaves through the exit node."
		}
	}
	return "\nExit node " + ex.Name + " is on, but that IP is not one of its addresses (its traffic may leave from another IP, or the exit is not working)."
}

// StatusJSON describes the current state for the app UI.
func (e *Engine) StatusJSON() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	st := status{Joined: e.id != nil, Running: e.dev != nil, Error: e.lastErr, Peers: []peerStatus{}, Admin: []adminLink{}}
	if !e.lastSync.IsZero() {
		st.LastSync = e.lastSync.Unix()
	}
	if e.id == nil {
		b, _ := json.Marshal(st)
		return string(b)
	}
	stats := map[string]uapi.Peer{}
	if e.dev != nil {
		if txt, err := e.dev.IpcGet(); err == nil {
			stats = uapi.Parse(txt)
		}
	}
	names := map[string]string{}
	nodes := store.List[model.Node](e.store, model.KindNode)
	for _, n := range nodes {
		names[n.ID] = n.Name
	}
	if e.prev != nil {
		st.HomeRelay = names[e.prev.HomeRelay]
	}
	if e.lastCfg != nil {
		st.Home, st.Exit, st.Warnings = e.lastCfg.Home, names[e.lastCfg.ExitVia], e.lastCfg.Warnings
	}
	for _, n := range nodes {
		if n.ID == e.id.NodeID {
			st.Name, st.MeshIP, st.ExitWanted = n.Name, n.MeshIP, names[n.ExitVia]
			continue
		}
		if n.WebUI && n.MeshIP != "" {
			port := n.WebPort
			if port == 0 {
				port = model.DefaultWebPort
			}
			st.Admin = append(st.Admin, adminLink{Name: n.Name, URL: fmt.Sprintf("http://%s:%d/", n.MeshIP, port)})
		}
		ps := peerStatus{ID: n.ID, Name: n.Name, Kind: string(n.Kind), MeshIP: n.MeshIP}
		if e.prev != nil {
			if p, ok := e.prev.Paths[n.ID]; ok {
				if p.Direct() {
					ps.Path = "direct"
				} else {
					ps.Path = "via " + names[p.Via]
				}
			}
		}
		if k, err := wgtypes.ParseKey(n.PublicKey); err == nil {
			if s, ok := stats[hex.EncodeToString(k[:])]; ok {
				ps.Endpoint, ps.RxBytes, ps.TxBytes = s.Endpoint, s.RxBytes, s.TxBytes
				if !s.LastHandshake.IsZero() {
					ps.LastHandshake = s.LastHandshake.Unix()
				}
			}
		}
		st.Peers = append(st.Peers, ps)
	}
	sort.Slice(st.Peers, func(i, j int) bool { return st.Peers[i].Name < st.Peers[j].Name })
	b, _ := json.Marshal(st)
	return string(b)
}
