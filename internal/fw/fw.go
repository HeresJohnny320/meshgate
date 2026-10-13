package fw

import (
	"bytes"
	"fmt"
	"strings"
)

// RenderNFT renders the plan as an nft script that replaces the
// "inet meshgate" table atomically.
func RenderNFT(p Plan) string {
	q := func(s string) string { return `"` + s + `"` }
	var dnat, post, mark, in, fwd, block []string

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
	chain := func(name, hook string, lines []string) {
		fmt.Fprintf(&b, "\tchain %s {\n\t\t%s; policy accept;\n", name, hook)
		for _, l := range lines {
			b.WriteString(l + "\n")
		}
		b.WriteString("\t}\n")
	}
	if len(block) > 0 {
		chain("blocked", "type filter hook prerouting priority raw", block)
	}
	chain("prerouting", "type nat hook prerouting priority dstnat", dnat)
	chain("postrouting", "type nat hook postrouting priority srcnat", post)
	chain("forward", "type filter hook forward priority mangle",
		[]string{fmt.Sprintf("\t\toifname %s tcp flags syn tcp option maxseg size set rt mtu", q(p.Iface))})
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
	parts = append(parts, "accept", fmt.Sprintf(`comment "%s"`, sanitize(a.Comment)))
	return "\t\t" + strings.Join(parts, " ")
}
