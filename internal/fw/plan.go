// Package fw turns mesh config into firewall rules for one node: port
// forwards on edge nodes, LAN masquerading on subnet routers, replies for
// preserve-client-IP forwards and access rules (ACLs) that lock down what
// mesh devices may reach.
//
// Build produces an OS-neutral Plan; RenderNFT (Linux) and RenderPF
// (FreeBSD/pfSense) turn it into rules. meshgate only ever touches its own
// nftables table or pf anchors, never rules you wrote yourself.
package fw

import (
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"

	"github.com/heresjohnny320/meshgate/internal/model"
)

// Marks and routing tables shared with the wg package (Linux).
const (
	MarkBypass   = 0x4d46 // sockets that must not use mesh routes (WireGuard, probes)
	MarkPreserve = 0x4d47 // replies of preserve-client-IP connections (target side)
	MarkEdgeKeep = 0x4d48 // edge: DNATed connection that must not be masqueraded
	TableRoutes  = 51820  // subnet routes through the mesh
	TableReply   = 51821  // default route over the mesh for MarkPreserve
)

// Input describes what this node needs.
type Input struct {
	Iface    string
	Network  model.Network
	Self     model.Node
	Nodes    []model.Node
	Forwards []model.Forward
	Routes   []model.HTTPRoute
	ACLs     []model.ACL
	// PreserveEdge is the edge whose real-client-IP traffic we accept
	// (meshcfg.Config.DefaultViaPeer). Empty disables reply handling.
	PreserveEdge string
	// Ports meshgate itself serves on this node.
	WGPort, ProbePort, MeshPort, JoinPort, WebPort int
	// WANIface is the internet-facing interface (pf only).
	WANIface string
}

// DNAT is one forward on an edge node.
type DNAT struct {
	Name     string
	Protos   []string
	Lo, Hi   int    // public port range (Lo == Hi for one port)
	Dst      string // target address
	DstPort  int    // 0 = keep the original port (ranges)
	Preserve bool   // do not masquerade: target sees the client's IP
}

// Allow is one accepted flow from the mesh into this node or its LANs.
type Allow struct {
	Comment string
	Src     []string // source IPs; empty = any
	Self    bool     // destination is this node itself
	Dst     string   // destination prefix when !Self
	Proto   string   // tcp, udp, icmp, any
	Ports   []string // "443", "8000-8100"
}

// Plan is the OS-neutral rule set.
type Plan struct {
	Iface    string
	Mesh     string
	WANIface string
	DNAT     []DNAT
	// Blocked are public ports of disabled forwards: dropped so that
	// turning a forward off really shuts the port.
	Blocked []DNAT
	// LANs maps shared subnets to the local interface that reaches them.
	LANs []LANRoute
	// PreserveEdgeIP is the mesh IP of the edge delivering real client IPs.
	PreserveEdgeIP string
	// PreserveIn lists those inbound services (pf needs them for reply-to).
	PreserveIn []Allow
	// WANOpen lists meshgate's own public ports (pf only; Linux leaves the
	// host firewall alone).
	WANOpen []Allow
	// Restricted drops everything from the mesh that Allow does not match.
	Restricted bool
	// Firewall leaves mesh access to the host firewall's own rules (pfSense
	// GUI rules on the assigned interface); meshgate only keeps Own open.
	Firewall bool
	Allow    []Allow
	// Own are meshgate's own services over the mesh (sync, web UI).
	Own      []Allow
	Warnings []string
}

// LANRoute is a shared subnet and the interface it lives on.
type LANRoute struct {
	CIDR  string
	Iface string
}

// Build computes the plan.
func Build(in Input) Plan {
	p := Plan{Iface: in.Iface, Mesh: in.Network.CIDR, WANIface: in.WANIface, Restricted: in.Self.Restricted(), Firewall: in.Self.FirewallManaged()}
	byID := map[string]model.Node{}
	for _, n := range in.Nodes {
		byID[n.ID] = n
	}
	targetAddr := func(nodeID, ip string) (string, bool) {
		if ip != "" {
			return ip, true
		}
		n, ok := byID[nodeID]
		return n.MeshIP, ok && n.MeshIP != ""
	}

	// Forwards where we are the edge.
	fwds := append([]model.Forward(nil), in.Forwards...)
	sort.Slice(fwds, func(i, j int) bool { return fwds[i].ID < fwds[j].ID })
	for _, f := range fwds {
		if !f.Enabled {
			if f.EdgeNode == in.Self.ID && f.Validate() == nil {
				lo, hi := f.Ports()
				p.Blocked = append(p.Blocked, DNAT{Name: f.Name, Protos: protos(f.Proto), Lo: lo, Hi: hi})
			}
			continue
		}
		if err := f.Validate(); err != nil {
			if f.EdgeNode == in.Self.ID {
				p.Warnings = append(p.Warnings, fmt.Sprintf("forward %s skipped: %v", f.Name, err))
			}
			continue
		}
		if f.EdgeNode == in.Self.ID {
			dst, ok := targetAddr(f.TargetNode, f.TargetIP)
			if !ok {
				p.Warnings = append(p.Warnings, fmt.Sprintf("forward %s skipped: unknown target node", f.Name))
				continue
			}
			lo, hi := f.Ports()
			d := DNAT{Name: f.Name, Protos: protos(f.Proto), Lo: lo, Hi: hi, Dst: dst, DstPort: f.TargetPort, Preserve: f.PreserveClientIP}
			if hi > lo {
				d.DstPort = 0
			}
			p.DNAT = append(p.DNAT, d)
		}
		// Forwards that end here must get through a restricted policy.
		if f.TargetNode == in.Self.ID {
			lo, hi := f.Ports()
			port := fmt.Sprint(f.TargetPort)
			if hi > lo {
				port = fmt.Sprintf("%d-%d", lo, hi)
			}
			for _, pr := range protos(f.Proto) {
				a := Allow{Comment: "forward " + f.Name, Proto: pr, Ports: []string{port}}
				if f.TargetIP == "" {
					a.Self = true
				} else {
					a.Dst = f.TargetIP + "/32"
				}
				p.Allow = append(p.Allow, a)
				if f.PreserveClientIP && f.EdgeNode == in.PreserveEdge && a.Self {
					p.PreserveIn = append(p.PreserveIn, a)
				}
			}
		}
	}
	if e, ok := byID[in.PreserveEdge]; ok {
		p.PreserveEdgeIP = e.MeshIP
	}
	// Never block a port an enabled forward is using.
	kept := p.Blocked[:0]
	for _, b := range p.Blocked {
		clash := false
		for _, d := range p.DNAT {
			for _, bp := range b.Protos {
				for _, dp := range d.Protos {
					if bp == dp && b.Lo <= d.Hi && d.Lo <= b.Hi {
						clash = true
					}
				}
			}
		}
		if !clash {
			kept = append(kept, b)
		}
	}
	p.Blocked = kept

	// HTTPS routes whose backend is here.
	for _, r := range in.Routes {
		if !r.Enabled || r.TargetNode != in.Self.ID {
			continue
		}
		a := Allow{Comment: "https " + r.Hostname, Proto: "tcp", Ports: []string{fmt.Sprint(r.TargetPort)}}
		if src, ok := byID[r.EdgeNode]; ok {
			a.Src = []string{src.MeshIP}
		}
		if r.TargetIP == "" {
			a.Self = true
		} else {
			a.Dst = r.TargetIP + "/32"
		}
		p.Allow = append(p.Allow, a)
	}

	// meshgate's own services over the mesh.
	if in.MeshPort > 0 {
		p.Own = append(p.Own, Allow{Comment: "meshgate sync", Src: []string{in.Network.CIDR}, Self: true, Proto: "tcp", Ports: []string{fmt.Sprint(in.MeshPort)}})
	}
	if in.WebPort > 0 {
		p.Own = append(p.Own, Allow{Comment: "meshgate web ui", Src: []string{in.Network.CIDR}, Self: true, Proto: "tcp", Ports: []string{fmt.Sprint(in.WebPort)}})
	}
	p.Allow = append(p.Allow, p.Own...)

	// User access rules enforced here.
	acls := append([]model.ACL(nil), in.ACLs...)
	sort.Slice(acls, func(i, j int) bool { return acls[i].ID < acls[j].ID })
	for _, a := range acls {
		if !a.Enabled || a.Node != in.Self.ID {
			continue
		}
		if err := a.Validate(); err != nil {
			p.Warnings = append(p.Warnings, fmt.Sprintf("rule %s skipped: %v", a.Name, err))
			continue
		}
		var src []string
		for _, id := range a.From {
			if n, ok := byID[id]; ok && n.MeshIP != "" {
				src = append(src, n.MeshIP)
			}
		}
		if len(a.From) > 0 && len(src) == 0 {
			// Never widen a rule to "any" because its devices were removed.
			p.Warnings = append(p.Warnings, fmt.Sprintf("rule %s skipped: none of its devices exist", a.Name))
			continue
		}
		al := Allow{Comment: "rule " + a.Name, Src: src, Proto: a.Proto, Ports: a.PortList()}
		if d, ok := a.DestPrefix(); ok {
			al.Dst = d.String()
		} else {
			al.Self = true
		}
		p.Allow = append(p.Allow, al)
	}
	if !p.Restricted {
		// Open policy: nothing to enforce; keep only what pf needs.
		p.Allow = nil
	}

	// Subnet routing.
	for _, r := range in.Self.Routes {
		pfx, err := netip.ParsePrefix(r)
		if err != nil {
			continue
		}
		p.LANs = append(p.LANs, LANRoute{CIDR: pfx.Masked().String(), Iface: IfaceFor(pfx)})
	}

	// Public meshgate ports (pf).
	if in.Self.Relay || len(in.Self.Endpoints) > 0 {
		udp := []string{fmt.Sprint(in.WGPort), fmt.Sprint(in.ProbePort)}
		p.WANOpen = append(p.WANOpen, Allow{Comment: "meshgate wireguard+probes", Proto: "udp", Ports: udp})
		if in.JoinPort > 0 {
			p.WANOpen = append(p.WANOpen, Allow{Comment: "meshgate joins", Proto: "tcp", Ports: []string{fmt.Sprint(in.JoinPort)}})
		}
	}
	return p
}

// IfaceFor finds the local interface with an address inside pfx.
func IfaceFor(pfx netip.Prefix) string {
	ifs, _ := net.Interfaces()
	for _, i := range ifs {
		addrs, _ := i.Addrs()
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok {
				if ip, ok := netip.AddrFromSlice(n.IP.To4()); ok && n.IP.To4() != nil && pfx.Contains(ip) {
					return i.Name
				}
			}
		}
	}
	return ""
}

// LocalLANs lists private IPv4 networks on this machine with their
// interfaces (VLANs show up as their own interfaces).
func LocalLANs(skip string) []model.LAN {
	var out []model.LAN
	ifs, _ := net.Interfaces()
	for _, i := range ifs {
		if i.Name == skip || i.Flags&net.FlagUp == 0 || i.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := i.Addrs()
		for _, a := range addrs {
			n, ok := a.(*net.IPNet)
			if !ok || n.IP.To4() == nil {
				continue
			}
			ip, _ := netip.AddrFromSlice(n.IP.To4())
			if !ip.IsPrivate() {
				continue
			}
			ones, _ := n.Mask.Size()
			out = append(out, model.LAN{Iface: i.Name, CIDR: netip.PrefixFrom(ip, ones).Masked().String()})
		}
	}
	return out
}

func protos(p model.Proto) []string {
	switch p {
	case model.ProtoTCP:
		return []string{"tcp"}
	case model.ProtoUDP:
		return []string{"udp"}
	default:
		return []string{"tcp", "udp"}
	}
}

func sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '"' || r == '\\' || r < 32 {
			return -1
		}
		return r
	}, s)
}
