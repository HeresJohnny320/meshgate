package fw

import "fmt"

// IptablesRules are the iptables FORWARD rules (for meshgate's MESHGATE
// chain) that let exactly this node's meshgate traffic past a FORWARD
// policy of DROP (ufw, Docker): each enabled port forward this node is the
// edge of, by protocol and port; relaying on relays; exit traffic of the
// devices allowed to use this exit; shared LANs and exit routes on routers.
// A disabled or deleted forward simply has no rule.
func (p Plan) IptablesRules() [][]string {
	wg := p.Iface
	var out [][]string
	add := func(r ...string) { out = append(out, r) }
	for _, d := range p.DNAT {
		ports := fmt.Sprint(d.Lo)
		if d.Hi > d.Lo {
			ports = fmt.Sprintf("%d:%d", d.Lo, d.Hi)
		}
		note := "meshgate forward " + sanitize(d.Name)
		for _, proto := range d.Protos {
			add("-o", wg, "-p", proto, "-m", "conntrack", "--ctstate", "DNAT", "--ctorigdstport", ports, "-m", "comment", "--comment", note, "-j", "ACCEPT")
			add("-i", wg, "-p", proto, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "--ctorigdstport", ports, "-m", "comment", "--comment", note, "-j", "ACCEPT")
		}
	}
	if p.Relay {
		add("-i", wg, "-o", wg, "-m", "comment", "--comment", "meshgate relay", "-j", "ACCEPT")
	}
	for _, c := range p.ExitClients {
		add("-i", wg, "-s", c, "-m", "comment", "--comment", "meshgate exit node", "-j", "ACCEPT")
		add("-o", wg, "-d", c, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-m", "comment", "--comment", "meshgate exit node", "-j", "ACCEPT")
	}
	for _, l := range p.LANs {
		add("-i", wg, "-d", l.CIDR, "-m", "comment", "--comment", "meshgate shared LAN", "-j", "ACCEPT")
		add("-o", wg, "-s", l.CIDR, "-m", "comment", "--comment", "meshgate shared LAN", "-j", "ACCEPT")
	}
	for _, s := range p.LANExitSrcs {
		add("-o", wg, "-s", s, "-m", "comment", "--comment", "meshgate exit route", "-j", "ACCEPT")
		add("-i", wg, "-d", s, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-m", "comment", "--comment", "meshgate exit route", "-j", "ACCEPT")
	}
	return out
}
