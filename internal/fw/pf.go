package fw

import (
	"fmt"
	"strings"
)

// pf anchors. pfSense (CE 2.7+ and Plus) always generates
//
//	nat-anchor "natrules/*"
//	rdr-anchor "tftp-proxy/*"
//	anchor "userrules/*"
//
// and leaves sub-anchors loaded with pfctl alone when it reloads its own
// rules, so meshgate loads into those. (tftp-proxy names its own sub-anchors
// after process IDs, so "tftp-proxy/meshgate" cannot collide.) On plain
// FreeBSD add these to /etc/pf.conf:
//
//	nat-anchor "natrules/*"
//	rdr-anchor "natrules/*"
//	anchor "userrules/*"
const (
	DefaultPFNatAnchor      = "natrules/meshgate"
	DefaultPFFilterAnchor   = "userrules/meshgate"
	DefaultPFRdrAnchor      = "natrules/meshgate"
	DefaultPFSenseRdrAnchor = "tftp-proxy/meshgate"
)

// Anchors used on FreeBSD/pfSense (overridable from the node config).
var (
	PFNatAnchor    = DefaultPFNatAnchor
	PFRdrAnchor    = DefaultPFRdrAnchor
	PFFilterAnchor = DefaultPFFilterAnchor
)

// RenderPF renders the plan as three pf rule sets: nat, rdr and filter.
func RenderPF(p Plan) (nat, rdr, filter string) {
	var n, r, f []string
	add := func(dst *[]string, format string, a ...any) { *dst = append(*dst, fmt.Sprintf(format, a...)) }
	mesh := p.Mesh
	wg := p.Iface

	for _, d := range p.DNAT {
		if d.Preserve {
			continue
		}
		for _, proto := range d.Protos {
			port := pfPort(d.Lo, d.Hi)
			if d.DstPort != 0 {
				port = fmt.Sprint(d.DstPort)
			}
			add(&n, "nat on %s inet proto %s from ! %s to %s port %s -> (%s:0) # %s", wg, proto, mesh, d.Dst, port, wg, pfComment(d.Name))
		}
	}
	if len(p.LANExitSrcs) > 0 {
		add(&n, "table <meshgate_private> const { %s }", strings.Join(PrivateNets, ", "))
		add(&n, "nat on %s inet from { %s } to ! <meshgate_private> -> (%s:0) # LAN exit", wg, strings.Join(p.LANExitSrcs, ", "), wg)
	}
	if len(p.ExitClients) > 0 && p.WANIface != "" {
		add(&n, "nat on %s inet from { %s } to any -> (%s:0) # exit node", p.WANIface, strings.Join(p.ExitClients, ", "), p.WANIface)
	}
	for _, l := range p.LANs {
		if l.Iface == "" {
			continue
		}
		add(&n, "nat on %s inet from %s to %s -> (%s:0) # mesh to LAN", l.Iface, mesh, l.CIDR, l.Iface)
	}
	for _, d := range p.DNAT {
		if p.WANIface == "" {
			break
		}
		for _, proto := range d.Protos {
			target := fmt.Sprintf("%s port %d", d.Dst, d.DstPort)
			if d.Hi > d.Lo {
				target = fmt.Sprintf("%s port %d:*", d.Dst, d.Lo)
			}
			add(&r, "rdr pass on %s inet proto %s from any to (%s) port %s -> %s # %s",
				p.WANIface, proto, p.WANIface, pfPort(d.Lo, d.Hi), target, pfComment(d.Name))
		}
	}

	// Filter rules.
	if (len(p.ExitClients) > 0 && p.Restricted) || len(p.LANExitSrcs) > 0 {
		add(&f, "table <meshgate_private> const { %s }", strings.Join(PrivateNets, ", "))
	}
	// Anti-spoofing: mesh addresses only ever arrive through the tunnel.
	add(&f, "pass in quick on lo0 inet from %s to any # local traffic", mesh)
	add(&f, "block drop in quick on ! %s inet from %s to any # mesh address from outside", wg, mesh)
	// LAN exits: route those devices' internet traffic to the exit node;
	// without a usable exit they get no internet (never the home line).
	if len(p.LANExitSrcs) > 0 {
		srcs := strings.Join(p.LANExitSrcs, ", ")
		if p.LANExitGW != "" {
			add(&f, "pass in quick route-to (%s %s) inet from { %s } to ! <meshgate_private> keep state # LAN exit", wg, p.LANExitGW, srcs)
		}
		add(&f, "block drop in quick inet from { %s } to ! <meshgate_private> # LAN exit: internet only through the exit node", srcs)
	}
	if p.WANIface != "" {
		for _, a := range p.WANOpen {
			add(&f, "pass in quick on %s inet proto %s from any to (%s) port { %s } keep state # %s",
				p.WANIface, a.Proto, p.WANIface, pfPorts(a.Ports), pfComment(a.Comment))
		}
	}
	// Disabled forwards: drop their public ports.
	if p.WANIface != "" {
		for _, d := range p.Blocked {
			for _, proto := range d.Protos {
				add(&f, "block drop in quick on %s inet proto %s from any to (%s) port %s # disabled: %s",
					p.WANIface, proto, p.WANIface, pfPort(d.Lo, d.Hi), pfComment(d.Name))
			}
		}
	}
	// Replies to real client IPs go back through the edge that delivered them.
	if p.PreserveEdgeIP != "" {
		for _, a := range p.PreserveIn {
			add(&f, "pass in quick on %s reply-to (%s %s) inet proto %s from ! %s to self port { %s } keep state # %s",
				wg, wg, p.PreserveEdgeIP, a.Proto, mesh, pfPorts(a.Ports), pfComment(a.Comment))
		}
	}
	if p.Firewall {
		// The pfSense rules on the assigned interface decide; only keep
		// meshgate's own services reachable whatever they say.
		for _, a := range p.Own {
			f = append(f, pfAllow(wg, a))
		}
		return join(n), join(r), join(f)
	}
	if !p.Restricted {
		add(&f, "pass in quick on %s all keep state # LAN policy: open", wg)
		return join(n), join(r), join(f)
	}
	for _, a := range p.Allow {
		if a.Self {
			f = append(f, pfAllow(wg, a))
		}
	}
	add(&f, "block in quick on %s inet from any to self # this node: only what rules allow", wg)
	if len(p.ExitClients) > 0 {
		add(&f, "pass in quick on %s inet from { %s } to ! <meshgate_private> keep state # exit node: internet only", wg, strings.Join(p.ExitClients, ", "))
	}
	add(&f, "pass in quick on %s inet from %s to %s keep state # relay between mesh nodes", wg, mesh, mesh)
	for _, a := range p.Allow {
		if !a.Self {
			f = append(f, pfAllow(wg, a))
		}
	}
	add(&f, "block in quick on %s all # LAN policy: restricted", wg)
	return join(n), join(r), join(f)
}

func pfAllow(wg string, a Allow) string {
	var b strings.Builder
	fmt.Fprintf(&b, "pass in quick on %s inet", wg)
	switch a.Proto {
	case "tcp", "udp", "icmp":
		b.WriteString(" proto " + a.Proto)
	}
	if len(a.Src) > 0 {
		b.WriteString(" from { " + strings.Join(a.Src, ", ") + " }")
	} else {
		b.WriteString(" from any")
	}
	if a.Self {
		b.WriteString(" to self")
	} else {
		b.WriteString(" to " + a.Dst)
	}
	if len(a.Ports) > 0 && (a.Proto == "tcp" || a.Proto == "udp") {
		b.WriteString(" port { " + pfPorts(a.Ports) + " }")
	}
	b.WriteString(" keep state # " + pfComment(a.Comment))
	return b.String()
}

func pfPort(lo, hi int) string {
	if hi > lo {
		return fmt.Sprintf("%d:%d", lo, hi)
	}
	return fmt.Sprint(lo)
}

// pfPorts converts "8000-8100" ranges to pf's "8000:8100".
func pfPorts(ports []string) string {
	out := make([]string, len(ports))
	for i, p := range ports {
		out[i] = strings.Replace(p, "-", ":", 1)
	}
	return strings.Join(out, ", ")
}

func pfComment(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' {
			return ' '
		}
		return r
	}, s)
}

func join(lines []string) string {
	if len(lines) == 0 {
		return ""
	}
	return strings.Join(lines, "\n") + "\n"
}
