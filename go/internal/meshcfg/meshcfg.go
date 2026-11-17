// Package meshcfg turns cluster state plus path decisions into the exact
// WireGuard interface config for one node. It is pure so it can be tested and
// shared with the mobile core.
package meshcfg

import (
	"fmt"
	"net/netip"
	"sort"

	"github.com/heresjohnny320/meshgate/internal/model"
	"github.com/heresjohnny320/meshgate/internal/pathsel"
)

// Keepalive keeps NAT mappings open towards relays and direct peers.
const Keepalive = 20

// Peer is one WireGuard peer.
type Peer struct {
	NodeID     string
	PublicKey  string
	Endpoint   string // "" = keep whatever WireGuard learned
	AllowedIPs []netip.Prefix
	Keepalive  int
}

// Config is the full desired interface state.
type Config struct {
	Address    netip.Prefix // mesh IP with the network's prefix length
	ListenPort int
	Peers      []Peer
	// Routes are extra OS routes through the interface (peer subnets).
	// The mesh CIDR itself is covered by Address.
	Routes []netip.Prefix
	// DefaultViaPeer is set when replies for preserve-client-IP forwards
	// must go back through an edge: the agent installs a policy-routing
	// table with a default route over the interface for marked traffic.
	DefaultViaPeer string
	// Home is set when this device is on the LAN of a node that shares it
	// (that node answers directly on its LAN endpoint).
	Home bool
	// ExitVia is the exit node now carrying this device's internet traffic
	// (Routes then include 0.0.0.0/0); "" while at home or without one.
	ExitVia string
	// ExitBlocked: no exit node reachable and the device is "exit only":
	// 0.0.0.0/0 still enters the tunnel, where no peer takes it, so its
	// internet traffic (DNS included) is dropped.
	ExitBlocked bool
	// LANExitSrcs are LAN devices/subnets behind this router whose internet
	// traffic goes to exit node LANExitVia (whose peer then holds
	// 0.0.0.0/0).
	LANExitSrcs []netip.Prefix
	LANExitVia  string
	// LANExitBlock are LAN devices that must not reach the internet at all
	// right now: "exit only" while no exit node is reachable.
	LANExitBlock []netip.Prefix
	Warnings     []string
}

// Input for Build.
type Input struct {
	Network  model.Network
	Self     model.Node
	Nodes    []model.Node
	Forwards []model.Forward
	Paths    pathsel.Result
	// LocalAddrs are this device's own LAN addresses. An advertised subnet
	// that contains one of them is skipped when its node also answers
	// directly on an endpoint inside it: we are on that LAN, so the traffic
	// should not enter the tunnel (e.g. phone on home Wi-Fi). A café LAN that
	// merely uses the same range does not count.
	LocalAddrs []netip.Addr
	// ExitCapable: the platform can send all traffic into the tunnel (the
	// phone apps). Elsewhere Self.ExitVia only produces a warning.
	ExitCapable bool
	// ExitChoice is the device's own pick (phone app): an exit node ID it
	// is allowed to use, "off" for its own connection, "" for the admin's
	// default (Self.ExitVia).
	ExitChoice string
	// LANExitCapable: the OS layer can policy-route LAN devices into the
	// mesh (Linux, FreeBSD/pfSense).
	LANExitCapable bool
	// ExitRoutes are all exit routes; those with Router == Self apply here.
	ExitRoutes []model.ExitRoute
}

// Build computes the config.
func Build(in Input) (Config, error) {
	netPfx, err := in.Network.Prefix()
	if err != nil {
		return Config{}, fmt.Errorf("network cidr: %w", err)
	}
	selfIP, err := netip.ParseAddr(in.Self.MeshIP)
	if err != nil {
		return Config{}, fmt.Errorf("self mesh ip: %w", err)
	}
	cfg := Config{
		Address:    netip.PrefixFrom(selfIP, netPfx.Bits()),
		ListenPort: in.Self.ListenPort,
	}

	byID := map[string]model.Node{}
	peers := map[string]*Peer{}
	var ids []string
	for _, n := range in.Nodes {
		byID[n.ID] = n
		if n.ID == in.Self.ID || n.PublicKey == "" {
			continue
		}
		ids = append(ids, n.ID)
		peers[n.ID] = &Peer{NodeID: n.ID, PublicKey: n.PublicKey}
	}
	sort.Strings(ids)

	// Endpoints and keepalives.
	selfRelay := pathsel.IsRelay(in.Self)
	for _, id := range ids {
		p := peers[id]
		path := in.Paths.Paths[id]
		if path.Direct() {
			p.Endpoint = path.Endpoint
			if !selfRelay && p.Endpoint != "" {
				p.Keepalive = Keepalive
			}
		}
	}

	// AllowedIPs: each node's mesh IP and subnets go to the peer we reach it
	// through (itself if direct, otherwise its relay).
	claimed := map[netip.Prefix]string{}
	for _, id := range ids {
		n := byID[id]
		path := in.Paths.Paths[id]
		holder := peers[id]
		if !path.Direct() {
			if rp, ok := peers[path.Via]; ok {
				holder = rp
			} else {
				cfg.Warnings = append(cfg.Warnings, fmt.Sprintf("%s: relay %s unknown", n.Name, path.Via))
			}
		}
		ip, err := netip.ParseAddr(n.MeshIP)
		if err != nil {
			cfg.Warnings = append(cfg.Warnings, fmt.Sprintf("%s: bad mesh ip %q", n.Name, n.MeshIP))
			continue
		}
		holder.AllowedIPs = append(holder.AllowedIPs, netip.PrefixFrom(ip, 32))

		for _, r := range n.Routes {
			pfx, err := netip.ParsePrefix(r)
			if err != nil {
				cfg.Warnings = append(cfg.Warnings, fmt.Sprintf("%s: bad route %q", n.Name, r))
				continue
			}
			pfx = pfx.Masked()
			if pfx.Overlaps(netPfx) {
				cfg.Warnings = append(cfg.Warnings, fmt.Sprintf("%s: route %s overlaps the mesh", n.Name, pfx))
				continue
			}
			if ownRoute(in.Self, pfx) {
				continue
			}
			if containsAny(pfx, in.LocalAddrs) && onLAN(path, pfx) {
				cfg.Home = true
				continue
			}
			if other, dup := claimed[pfx]; dup {
				cfg.Warnings = append(cfg.Warnings, fmt.Sprintf("route %s advertised by %s and %s; using %s", pfx, other, n.Name, other))
				continue
			}
			claimed[pfx] = n.Name
			holder.AllowedIPs = append(holder.AllowedIPs, pfx)
			cfg.Routes = append(cfg.Routes, pfx)
		}
	}

	// Preserve-client-IP forwards targeting us: packets arrive from the edge
	// with the player's real source address, so the edge peer must accept
	// any source. Only one peer can hold 0.0.0.0/0.
	edge := preserveEdge(in)
	if edge != "" {
		if p, ok := peers[edge]; ok && in.Paths.Paths[edge].Direct() {
			p.AllowedIPs = append(p.AllowedIPs, netip.MustParsePrefix("0.0.0.0/0"))
			cfg.DefaultViaPeer = edge
		} else {
			cfg.Warnings = append(cfg.Warnings, fmt.Sprintf("preserve-client-IP: edge %s is not directly connected; disabled", edge))
		}
	}
	if !cfg.Home && (in.Self.ExitVia != "" || in.ExitChoice != "" || len(in.Self.ExitsAllowed) > 0) {
		cfg.deviceExit(in, byID, peers)
	}
	cfg.lanExits(in, byID, peers)
	for _, f := range in.Forwards {
		if f.Enabled && f.PreserveClientIP && f.TargetNode == in.Self.ID && f.EdgeNode != edge {
			cfg.Warnings = append(cfg.Warnings, fmt.Sprintf("forward %s: only one edge (%s) can preserve client IPs into this node", f.Name, byID[edge].Name))
		}
	}

	for _, id := range ids {
		p := peers[id]
		sort.Slice(p.AllowedIPs, func(i, j int) bool { return p.AllowedIPs[i].String() < p.AllowedIPs[j].String() })
		cfg.Peers = append(cfg.Peers, *p)
	}
	sort.Slice(cfg.Routes, func(i, j int) bool { return cfg.Routes[i].String() < cfg.Routes[j].String() })
	return cfg, nil
}

// preserveEdge picks the edge allowed to deliver real client IPs to us.
func preserveEdge(in Input) string {
	var edges []string
	for _, f := range in.Forwards {
		if f.Enabled && f.PreserveClientIP && f.TargetNode == in.Self.ID {
			edges = append(edges, f.EdgeNode)
		}
	}
	if len(edges) == 0 {
		return ""
	}
	sort.Strings(edges)
	return edges[0]
}

// onLAN reports whether path reaches its node directly on an endpoint
// inside pfx, which proves we share that LAN with it.
func onLAN(path pathsel.Path, pfx netip.Prefix) bool {
	if !path.Direct() || path.Endpoint == "" {
		return false
	}
	ap, err := netip.ParseAddrPort(path.Endpoint)
	return err == nil && pfx.Contains(ap.Addr())
}

func containsAny(p netip.Prefix, addrs []netip.Addr) bool {
	for _, a := range addrs {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func ownRoute(self model.Node, p netip.Prefix) bool {
	for _, r := range self.Routes {
		if q, err := netip.ParsePrefix(r); err == nil && q.Masked() == p {
			return true
		}
	}
	return false
}

// pickExit returns the first usable exit node: preferred, then the others
// by name (failover). Usable: offered as exit, a peer, reached directly,
// answering probes, and allowed for this device (routers' exit routes are
// set by admins, so they may use any exit).
func pickExit(in Input, byID map[string]model.Node, peers map[string]*Peer, preferred string, only string, router bool) string {
	cands := []string{preferred}
	var others []model.Node
	for _, n := range in.Nodes {
		if n.Exit && n.ID != preferred && n.ID != in.Self.ID {
			others = append(others, n)
		}
	}
	sort.Slice(others, func(i, j int) bool { return others[i].Name < others[j].Name })
	for _, n := range others {
		cands = append(cands, n.ID)
	}
	for _, id := range cands {
		n, ok := byID[id]
		_, hasPeer := peers[id]
		up := in.Paths.Up == nil || in.Paths.Up[id]
		if ok && n.Exit && hasPeer && in.Paths.Paths[id].Direct() && up && (only == "" || id == only) && (router || in.Self.MayUseExit(id)) {
			return id
		}
	}
	return ""
}

func (cfg *Config) name(byID map[string]model.Node, id string) string {
	if n, ok := byID[id]; ok && n.Name != "" {
		return n.Name
	}
	return id
}

// deviceExit sends this device's internet traffic to an exit node (phones).
func (cfg *Config) deviceExit(in Input, byID map[string]model.Node, peers map[string]*Peer) {
	want := in.Self.ExitVia
	switch c := in.ExitChoice; {
	case c == "off":
		want = ""
	case c != "" && in.Self.MayUseExit(c):
		want = c
	}
	if want == "" && !in.Self.ExitOnly {
		return // own connection, by choice
	}
	if !in.ExitCapable {
		cfg.Warnings = append(cfg.Warnings, "exit nodes are only supported in the phone app so far")
		return
	}
	if cfg.DefaultViaPeer != "" {
		cfg.Warnings = append(cfg.Warnings, "exit node ignored: this node receives real client IPs, which needs the default route")
		return
	}
	all := netip.MustParsePrefix("0.0.0.0/0")
	ex := ""
	if want != "" || in.ExitChoice != "off" {
		ex = pickExit(in, byID, peers, want, "", false)
	}
	if ex == "" {
		if in.Self.ExitOnly {
			cfg.ExitBlocked = true
			cfg.Routes = append(cfg.Routes, all)
			cfg.Warnings = append(cfg.Warnings, "no exit node is reachable: internet blocked (exit only)")
		} else {
			cfg.Warnings = append(cfg.Warnings, "no exit node is reachable ("+cfg.name(byID, want)+" is down): using this device's own connection")
		}
		return
	}
	if want != "" && ex != want {
		cfg.Warnings = append(cfg.Warnings, cfg.name(byID, want)+" is down: using exit node "+cfg.name(byID, ex))
	}
	peers[ex].AllowedIPs = append(peers[ex].AllowedIPs, all)
	cfg.Routes = append(cfg.Routes, all)
	cfg.ExitVia = ex
}

// lanExits routes LAN devices' internet traffic (exit routes on this
// router, and the older per-router LANExits list) to one exit node, failing
// over to other exit nodes; with none left, "exit only" devices are blocked
// and the rest use the normal connection.
func (cfg *Config) lanExits(in Input, byID map[string]model.Node, peers map[string]*Peer) {
	type src struct {
		pfx      netip.Prefix
		exitOnly bool
	}
	var srcs []src
	want := ""
	for _, e := range in.Self.LANExits {
		if p, err := e.Prefix(); err == nil {
			srcs = append(srcs, src{p, in.Self.ExitOnly})
			if want == "" {
				want = e.Via
			}
		}
	}
	for _, r := range in.ExitRoutes {
		if r.Router != in.Self.ID || !r.Enabled {
			continue
		}
		if p, err := r.Prefix(); err == nil {
			srcs = append(srcs, src{p, r.ExitOnly})
			if want == "" {
				want = r.Via
			}
		}
	}
	if len(srcs) == 0 {
		return
	}
	if !in.LANExitCapable {
		cfg.Warnings = append(cfg.Warnings, "exit routes need a Linux or pfSense router")
		return
	}
	// Only one peer can hold 0.0.0.0/0: with real client IPs arriving
	// through an edge, that edge is the only possible exit.
	ex := pickExit(in, byID, peers, want, cfg.DefaultViaPeer, true)
	if ex == "" {
		why := cfg.name(byID, want) + " is not reachable"
		if cfg.DefaultViaPeer != "" && cfg.DefaultViaPeer != want {
			why = "this node receives real client IPs through " + cfg.name(byID, cfg.DefaultViaPeer) + ", which must then be the exit"
		}
		for _, s := range srcs {
			if s.exitOnly {
				cfg.LANExitBlock = append(cfg.LANExitBlock, s.pfx)
			}
		}
		cfg.Warnings = append(cfg.Warnings, "exit routes: "+why+"; exit-only devices have no internet, the others use the normal connection")
		return
	}
	if ex != want {
		cfg.Warnings = append(cfg.Warnings, "exit routes: "+cfg.name(byID, want)+" is down: using exit node "+cfg.name(byID, ex))
	}
	if ex != cfg.DefaultViaPeer {
		peers[ex].AllowedIPs = append(peers[ex].AllowedIPs, netip.MustParsePrefix("0.0.0.0/0"))
	}
	for _, s := range srcs {
		cfg.LANExitSrcs = append(cfg.LANExitSrcs, s.pfx)
	}
	cfg.LANExitVia = ex
}
