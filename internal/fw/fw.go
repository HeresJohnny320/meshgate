package fw

import (
	"bytes"
	"fmt"
	"sort"
	"strings"
)

// RenderNFT renders the plan as an nft script that replaces the
// "inet meshgate" table atomically.
func RenderNFT(p Plan) string {
	q := func(s string) string { return `"` + s + `"` }
	var dnat, post, mark, in, fwd, block, counters []string
	fwdChain := []string{fmt.Sprintf("\t\toifname %s tcp flags syn tcp option maxseg size set rt mtu", q(p.Iface))}

	for _, d := range p.Blocked {
		port := fmt.Sprint(d.Lo)
		if d.Hi > d.Lo {
			port = fmt.Sprintf("%d-%d", d.Lo, d.Hi)
		}
		for _, proto := range d.Protos {
			block = append(block, fmt.Sprintf("\t\tiifname != %s fib daddr type local meta l4proto %s th dport %s drop comment %s",
				q(p.Iface), proto, port, q("disabled: "+sanitize(d.Name))))
		}
	}

	for _, d := range p.DNAT {
		port := fmt.Sprint(d.Lo)
		to := fmt.Sprintf("%s:%d", d.Dst, d.DstPort)
		if d.Hi > d.Lo {
			port = fmt.Sprintf("%d-%d", d.Lo, d.Hi)
			to = d.Dst // keep the original destination port
		}
		keep := ""
		if d.Preserve {
			keep = fmt.Sprintf("ct mark set 0x%x ", MarkEdgeKeep)
		}
		// Traffic per forward, both directions of its connections.
		cin, cout := CounterName("f", d.ID, "in"), CounterName("f", d.ID, "out")
		counters = append(counters, cin, cout)
		for _, proto := range d.Protos {
			for _, c := range [][2]string{{"original", cin}, {"reply", cout}} {
				fwdChain = append(fwdChain, fmt.Sprintf("\t\tmeta l4proto %s ct status dnat ct original proto-dst %s ct direction %s counter name %s",
					proto, port, c[0], q(c[1])))
			}
		}
		for _, proto := range d.Protos {
			// Only traffic addressed to this host: never hijack connections
			// that merely pass through (containers, LAN clients).
			dnat = append(dnat, fmt.Sprintf("\t\tiifname != %s fib daddr type local meta l4proto %s th dport %s %sdnat ip to %s comment %s",
				q(p.Iface), proto, port, keep, to, q(sanitize(d.Name))))
		}
	}
	if len(p.DNAT) > 0 {
		post = append(post, fmt.Sprintf("\t\toifname %s ct status dnat ct mark != 0x%x masquerade", q(p.Iface), MarkEdgeKeep))
	}

	// Subnet router: hide mesh sources behind our LAN address so LAN devices
	// need no extra routes.
	if len(p.LANs) > 0 {
		var cidrs []string
		for _, l := range p.LANs {
			cidrs = append(cidrs, l.CIDR)
		}
		post = append(post, fmt.Sprintf("\t\tiifname %s oifname != %s ip daddr { %s } masquerade",
			q(p.Iface), q(p.Iface), strings.Join(cidrs, ", ")))
	}

	// Exit node: devices that picked us reach the internet from our address.
	if len(p.ExitClients) > 0 {
		post = append(post, fmt.Sprintf("\t\tiifname %s oifname != %s ip saddr { %s } masquerade comment %s",
			q(p.Iface), q(p.Iface), strings.Join(p.ExitClients, ", "), q("exit node")))
	}

	// Router side of LAN exits: their internet traffic leaves through the
	// tunnel from our mesh address; anything else of theirs bound for the
	// internet is dropped (no leak while the exit is down).
	priv := strings.Join(PrivateNets, ", ")
	if len(p.LANExitSrcs) > 0 {
		post = append(post, fmt.Sprintf("\t\toifname %s ip saddr { %s } ip daddr != { %s } masquerade comment %s",
			q(p.Iface), strings.Join(p.LANExitSrcs, ", "), priv, q("LAN exit")))
	}
	if all := append(append([]string(nil), p.LANExitSrcs...), p.LANExitBlock...); len(all) > 0 {
		fwdChain = append(fwdChain, fmt.Sprintf("\t\toifname != %s ip saddr { %s } ip daddr != { %s } drop comment %s",
			q(p.Iface), strings.Join(all, ", "), priv, q("LAN exit: internet only through the exit node")))
	}

	// Target side of preserve-client-IP: remember connections that arrived
	// over the mesh from outside the mesh range, and route replies back.
	if p.PreserveEdgeIP != "" {
		mark = append(mark, fmt.Sprintf("\t\tiifname %s ip saddr != %s ct state new ct mark set 0x%x",
			q(p.Iface), p.Mesh, MarkPreserve))
	}

	if p.Restricted {
		in = append(in, fmt.Sprintf("\t\tiifname %s ct state established,related accept", q(p.Iface)))
		fwd = append(fwd,
			fmt.Sprintf("\t\tiifname %s oifname %s accept comment %s", q(p.Iface), q(p.Iface), q("relay between mesh nodes")),
			fmt.Sprintf("\t\tiifname %s ct state established,related accept", q(p.Iface)))
		if len(p.ExitClients) > 0 {
			fwd = append(fwd, fmt.Sprintf("\t\tiifname %s oifname != %s ip saddr { %s } ip daddr != { %s } accept comment %s",
				q(p.Iface), q(p.Iface), strings.Join(p.ExitClients, ", "), strings.Join(PrivateNets, ", "), q("exit node: internet only")))
		}
		for _, a := range p.Allow {
			if a.Counter != "" {
				counters = append(counters, a.Counter)
			}
			r := nftAllow(p.Iface, a)
			if a.Self {
				in = append(in, r)
			} else {
				fwd = append(fwd, r)
			}
		}
		in = append(in, fmt.Sprintf("\t\tiifname %s drop", q(p.Iface)))
		fwd = append(fwd, fmt.Sprintf("\t\tiifname %s drop", q(p.Iface)))
	}

	var b bytes.Buffer
	b.WriteString("table inet meshgate\ndelete table inet meshgate\ntable inet meshgate {\n")
	sort.Strings(counters)
	for i, c := range counters {
		if i == 0 || counters[i-1] != c {
			fmt.Fprintf(&b, "\tcounter %s {\n\t}\n", c)
		}
	}
	chain := func(name, hook string, lines []string) {
		fmt.Fprintf(&b, "\tchain %s {\n\t\t%s; policy accept;\n", name, hook)
		for _, l := range lines {
			b.WriteString(l + "\n")
		}
		b.WriteString("\t}\n")
	}
	// Anti-spoofing: mesh addresses only ever arrive through the tunnel
	// (where WireGuard vouches for them). Servers identify each other by
	// mesh IP, so never accept one from any other interface.
	if p.Mesh != "" {
		block = append([]string{fmt.Sprintf("\t\tiifname != { %s, \"lo\" } ip saddr %s drop comment \"mesh address from outside\"", q(p.Iface), p.Mesh)}, block...)
	}
	if len(block) > 0 {
		chain("blocked", "type filter hook prerouting priority raw", block)
	}
	chain("prerouting", "type nat hook prerouting priority dstnat", dnat)
	chain("postrouting", "type nat hook postrouting priority srcnat", post)
	chain("forward", "type filter hook forward priority mangle", fwdChain)
	if len(mark) > 0 {
		chain("premark", "type filter hook prerouting priority mangle", mark)
		chain("outmark", "type route hook output priority mangle",
			[]string{fmt.Sprintf("\t\tct mark 0x%x meta mark set 0x%x", MarkPreserve, MarkPreserve)})
	}
	if p.Restricted {
		chain("lan_in", "type filter hook input priority filter", in)
		chain("lan_fwd", "type filter hook forward priority filter", fwd)
	}
	b.WriteString("}\n")
	return b.String()
}

func nftAllow(iface string, a Allow) string {
	parts := []string{fmt.Sprintf(`iifname "%s"`, iface)}
	if len(a.Src) > 0 {
		parts = append(parts, "ip saddr { "+strings.Join(a.Src, ", ")+" }")
	}
	if !a.Self {
		parts = append(parts, "ip daddr "+a.Dst)
	}
	switch a.Proto {
	case "tcp", "udp", "icmp":
		parts = append(parts, "meta l4proto "+a.Proto)
	}
	if len(a.Ports) > 0 && (a.Proto == "tcp" || a.Proto == "udp") {
		parts = append(parts, "th dport { "+strings.Join(a.Ports, ", ")+" }")
	}
	if a.Counter != "" {
		parts = append(parts, fmt.Sprintf(`counter name "%s"`, a.Counter))
	}
	parts = append(parts, "accept", fmt.Sprintf(`comment "%s"`, sanitize(a.Comment)))
	return "\t\t" + strings.Join(parts, " ")
}
