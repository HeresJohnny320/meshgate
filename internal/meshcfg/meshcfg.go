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
	Warnings       []string
}

// Input for Build.
type Input struct {
	Network  model.Network
	Self     model.Node
	Nodes    []model.Node
	Forwards []model.Forward
	Paths    pathsel.Result
	// LocalAddrs are this device's own LAN addresses. Advertised subnets that
	// contain one of them are skipped: we are on that LAN already, so the
	// traffic should not enter the tunnel (e.g. phone on home Wi-Fi).
	LocalAddrs []netip.Addr
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
			if containsAny(pfx, in.LocalAddrs) || ownRoute(in.Self, pfx) {
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
