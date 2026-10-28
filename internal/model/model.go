// Package model defines the records that make up a meshgate network.
//
// Every record is stored in the replicated store (see internal/store) under a
// key of the form "<kind>/<id>". Records are plain JSON so that the web UI,
// TUI, nodes and the mobile core all speak the same format.
package model

import (
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Record kinds. The kind is the first segment of a store key.
const (
	KindNetwork   = "network" // singleton: "network/main"
	KindNode      = "node"
	KindStatus    = "status" // runtime status a node publishes about itself
	KindForward   = "forward"
	KindRoute     = "httproute"
	KindToken     = "token"
	KindAdmin     = "admin"     // web UI admin user(s)
	KindACL       = "acl"       // access rules for traffic leaving the mesh
	KindExitRoute = "exitroute" // a LAN device/subnet sent through an exit node
	KindMonitor   = "monitor"   // traffic counter only: never routes or opens anything
)

// NodeKind separates infrastructure from roaming devices.
type NodeKind string

const (
	// NodeServer is a Linux box (VPS, home server). Servers replicate config,
	// may write cluster config, accept joins and run forwards/proxies.
	NodeServer NodeKind = "server"
	// NodeClient is a laptop or phone. Clients read config, choose paths and
	// publish only their own status.
	NodeClient NodeKind = "client"
	// NodeStatic is a device using the stock WireGuard app. It has a fixed
	// config pointing at a single relay (ViaRelay) and never runs meshgate.
	NodeStatic NodeKind = "static"
)

// Default ports.
const (
	DefaultWGPort    = 51820 // UDP WireGuard
	DefaultJoinPort  = 51821 // TCP TLS join API (public, server nodes only)
	DefaultProbePort = 51822 // UDP path probes
	DefaultMeshPort  = 51823 // TCP mesh API (sync/status), mesh IPs only
	DefaultWebPort   = 8080  // web UI
)

// Network is the singleton describing the mesh.
type Network struct {
	Name      string `json:"name"`
	CIDR      string `json:"cidr"`       // e.g. 100.88.0.0/16
	ACMEEmail string `json:"acme_email"` // for HTTPS routes (Let's Encrypt)
	CreatedAt int64  `json:"created_at"`
	// LogServer stores the traffic history ("" = automatic: the first relay
	// by name, else the first server); LogDays is how long (default 365).
	LogServer string `json:"log_server,omitempty"`
	LogDays   int    `json:"log_days,omitempty"`
}

// HistoryDays is the traffic history retention.
func (n Network) HistoryDays() int {
	if n.LogDays > 0 {
		return n.LogDays
	}
	return 365
}

// Prefix parses CIDR.
func (n Network) Prefix() (netip.Prefix, error) { return netip.ParsePrefix(n.CIDR) }

// Node is a member of the mesh.
type Node struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Kind       NodeKind `json:"kind"`
	PublicKey  string   `json:"public_key"`
	MeshIP     string   `json:"mesh_ip"`
	ListenPort int      `json:"listen_port,omitempty"`
	// Endpoints are candidate "host:port" WireGuard addresses, best first:
	// public IP/DNS for VPSes, LAN address for home servers, a router
	// port-forward if one exists. Probes decide which ones work.
	Endpoints []string `json:"endpoints,omitempty"`
	// Relay marks a node with a public, always reachable endpoint. Relays
	// carry traffic between nodes that cannot reach each other directly.
	Relay bool `json:"relay,omitempty"`
	// Routes are subnets reachable through this node (e.g. home LAN).
	Routes []string `json:"routes,omitempty"`
	// LANPolicy controls what mesh devices may reach through this node
	// (its shared subnets and the node itself): PolicyOpen allows
	// everything, PolicyRestricted only what ACL records allow,
	// PolicyFirewall leaves it to the host firewall (pfSense GUI rules).
	LANPolicy string `json:"lan_policy,omitempty"`
	// ViaRelay pins a node behind one relay (used for NodeStatic).
	ViaRelay string `json:"via_relay,omitempty"`
	// Exit offers this server as an exit node: devices that pick it send
	// their internet traffic out through it.
	Exit bool `json:"exit,omitempty"`
	// ExitVia is the exit node this device uses for internet traffic while
	// it is away from home ("" = its own connection).
	ExitVia string `json:"exit_via,omitempty"`
	// LANExits sends the internet traffic of LAN devices behind this router
	// (pfSense or a Linux subnet router) out through an exit node. Their
	// internet access then depends on that exit: if it is unreachable they
	// get none, rather than leaking out of the home connection.
	LANExits []LANExit `json:"lan_exits,omitempty"`
	// ExitsAllowed lists the exit nodes this device may use ("*" = any).
	// Exit nodes only pass internet traffic for allowed devices; the device
	// picks among them itself (ExitVia is the admin's default). Empty with
	// ExitVia set means any exit (as before permissions existed).
	ExitsAllowed []string `json:"exits_allowed,omitempty"`
	// ExitOnly: when no exit node is reachable (the chosen one and every
	// other exit it could fail over to), block internet for this device /
	// its LAN exits instead of using the normal connection.
	ExitOnly bool `json:"exit_only,omitempty"`
	// AppAdminOff stops this server from answering the phone app's
	// management requests (by default every server does, so the app keeps
	// working when one is down).
	AppAdminOff bool `json:"app_admin_off,omitempty"`
	// BeepOff silences the PC speaker tune this node plays when a link to
	// another server goes down or comes back (pfSense/FreeBSD).
	BeepOff bool `json:"beep_off,omitempty"`
	// IptablesOff: meshgate leaves iptables alone on this node (Linux). By
	// default it keeps a MESHGATE chain in iptables' FORWARD chain that lets
	// this node's port forwards, relaying and exit traffic past ufw/Docker.
	IptablesOff bool `json:"iptables_off,omitempty"`
	// HostFirewallOff: meshgate leaves ufw/firewalld alone on this node
	// (Linux). By default it opens there what the node needs from outside:
	// its own ports, 80/443 on an HTTPS edge and its port forwards.
	HostFirewallOff bool `json:"host_firewall_off,omitempty"`
	// TestPort runs meshgate's test service on this TCP+UDP port (0 = off).
	TestPort int `json:"test_port,omitempty"`
	// JoinAddr/JoinFP let other devices join through this node.
	JoinAddr string `json:"join_addr,omitempty"`
	JoinFP   string `json:"join_fp,omitempty"`
	WebUI    bool   `json:"webui,omitempty"`
	WebPort  int    `json:"web_port,omitempty"`
	WebTLS   bool   `json:"web_tls,omitempty"` // web UI over https
	// WebFP is the SHA-256 fingerprint of the web UI certificate. It travels
	// with the node record over the mesh, so other nodes can show it to
	// check a browser's certificate against.
	WebFP    string `json:"web_fp,omitempty"`
	WebCAFP  string `json:"web_ca_fp,omitempty"` // the CA that signs it
	MeshPort int    `json:"mesh_port,omitempty"` // sync API port (default 51823)
	// APIHash authenticates a mobile client's sync requests (sha256 of the
	// secret handed to it at join).
	APIHash   string `json:"api_hash,omitempty"`
	CreatedAt int64  `json:"created_at"`
}

// Writer reports whether the node may write cluster-wide config.
func (n Node) Writer() bool { return n.Kind == NodeServer }

// Status is what a node reports about itself at runtime. It is written only
// by the node it describes and replicated so peers can agree on paths.
type Status struct {
	NodeID string `json:"node_id"`
	// HomeRelay is the relay this node currently prefers. When two nodes
	// cannot talk directly they both use the home relay of the pair's
	// "anchor" node (see pathsel), so traffic is symmetric.
	HomeRelay string `json:"home_relay,omitempty"`
	// Paths is the node's current view: peer ID -> "direct" or relay ID.
	Paths map[string]string `json:"paths,omitempty"`
	// LANs lists the node's local networks (VLANs) so UIs can offer them
	// as rule destinations.
	LANs      []LAN  `json:"lans,omitempty"`
	OS        string `json:"os,omitempty"`
	Version   string `json:"version,omitempty"`
	UpdatedAt int64  `json:"updated_at"`
}

// Proto is a forward protocol.
type Proto string

const (
	ProtoTCP  Proto = "tcp"
	ProtoUDP  Proto = "udp"
	ProtoBoth Proto = "both"
)

// Forward exposes a port on an edge node (VPS) and sends it through the mesh
// to a target node — the built-in replacement for hand-written iptables DNAT.
type Forward struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Proto      Proto  `json:"proto"`
	EdgeNode   string `json:"edge_node"`   // node that listens publicly
	ListenPort int    `json:"listen_port"` // public port on the edge
	ListenEnd  int    `json:"listen_end,omitempty"`
	TargetNode string `json:"target_node"`
	TargetIP   string `json:"target_ip,omitempty"` // LAN host behind target; empty = target's mesh IP
	TargetPort int    `json:"target_port"`
	// PreserveClientIP keeps players' real IPs visible to the game server.
	// It requires the service to run on the target node itself (not another
	// LAN host) and uses policy routing on the target for replies.
	PreserveClientIP bool `json:"preserve_client_ip,omitempty"`
	Enabled          bool `json:"enabled"`
}

// Ports returns the inclusive listen range.
func (f Forward) Ports() (int, int) {
	if f.ListenEnd > f.ListenPort {
		return f.ListenPort, f.ListenEnd
	}
	return f.ListenPort, f.ListenPort
}

// Validate checks a forward for obvious mistakes.
func (f Forward) Validate() error {
	switch f.Proto {
	case ProtoTCP, ProtoUDP, ProtoBoth:
	default:
		return fmt.Errorf("proto must be tcp, udp or both")
	}
	if f.EdgeNode == "" || f.TargetNode == "" {
		return fmt.Errorf("edge and target node are required")
	}
	if f.EdgeNode == f.TargetNode {
		return fmt.Errorf("edge and target must be different nodes")
	}
	if !validPort(f.ListenPort) || !validPort(f.TargetPort) {
		return fmt.Errorf("ports must be 1-65535")
	}
	if f.ListenEnd != 0 && (f.ListenEnd < f.ListenPort || !validPort(f.ListenEnd)) {
		return fmt.Errorf("invalid listen range")
	}
	if f.ListenEnd > f.ListenPort && f.TargetPort != f.ListenPort {
		return fmt.Errorf("port ranges are forwarded 1:1, so target port must equal the first listen port")
	}
	if f.TargetIP != "" {
		a, err := netip.ParseAddr(f.TargetIP)
		if err != nil || !a.Is4() {
			return fmt.Errorf("target ip must be an IPv4 address")
		}
		if f.PreserveClientIP {
			return fmt.Errorf("preserve client IP only works when the service runs on the target node itself (leave target ip empty)")
		}
	}
	return nil
}

// HTTPRoute publishes an HTTP service through an edge node with automatic
// HTTPS, like a self-hosted Cloudflare Tunnel.
type HTTPRoute struct {
	ID         string `json:"id"`
	Hostname   string `json:"hostname"` // e.g. jellyfin.example.com (DNS -> edge)
	EdgeNode   string `json:"edge_node"`
	TargetNode string `json:"target_node"`
	TargetIP   string `json:"target_ip,omitempty"` // LAN host; empty = target mesh IP
	TargetPort int    `json:"target_port"`
	TargetTLS  bool   `json:"target_tls,omitempty"` // backend speaks https
	ForceHTTPS bool   `json:"force_https"`          // redirect http -> https
	Enabled    bool   `json:"enabled"`
}

// Validate checks an HTTP route.
func (r HTTPRoute) Validate() error {
	h := strings.ToLower(strings.TrimSpace(r.Hostname))
	if len(h) > 253 || !hostnameRE.MatchString(h) {
		return fmt.Errorf("hostname must be a DNS name like app.example.com")
	}
	if r.EdgeNode == "" || r.TargetNode == "" {
		return fmt.Errorf("edge and target node are required")
	}
	if !validPort(r.TargetPort) {
		return fmt.Errorf("target port must be 1-65535")
	}
	if r.TargetIP != "" {
		if _, err := netip.ParseAddr(r.TargetIP); err != nil {
			return fmt.Errorf("invalid target ip")
		}
	}
	return nil
}

// Token is a join token. Only the hash of the secret is stored, so a leaked
// state file cannot be used to join.
type Token struct {
	ID         string   `json:"id"`
	SecretHash string   `json:"secret_hash"` // hex sha256(secret)
	Kind       NodeKind `json:"kind"`        // kind of node allowed to join
	UsesLeft   int      `json:"uses_left"`   // -1 = unlimited
	ExpiresAt  int64    `json:"expires_at"`
	Note       string   `json:"note,omitempty"`
	CreatedAt  int64    `json:"created_at"`
}

// Usable reports whether the token can still be used at t.
func (t Token) Usable(now time.Time) bool {
	return (t.UsesLeft != 0) && (t.ExpiresAt == 0 || now.Unix() < t.ExpiresAt)
}

// Admin is a web UI login.
type Admin struct {
	Username     string `json:"username"`
	PasswordHash string `json:"password_hash"` // bcrypt
}

// Key builds a store key.
func Key(kind, id string) string { return kind + "/" + id }

// SplitKey splits a store key into kind and id.
func SplitKey(k string) (kind, id string) {
	kind, id, _ = strings.Cut(k, "/")
	return
}

func validPort(p int) bool { return p > 0 && p < 65536 }

// LAN policies.
const (
	PolicyOpen       = "open"
	PolicyRestricted = "restricted"
	// PolicyFirewall: meshgate adds no access rules of its own; the pfSense
	// rules on the MESHGATE interface decide (see `meshgate pfsense`).
	PolicyFirewall = "firewall"
)

// Restricted reports whether access through n is limited to ACL rules.
func (n Node) Restricted() bool { return n.LANPolicy == PolicyRestricted }

// FirewallManaged reports whether the host firewall's own rules decide.
func (n Node) FirewallManaged() bool { return n.LANPolicy == PolicyFirewall }

// LAN is a local network on a node, e.g. a VLAN interface.
type LAN struct {
	Iface string `json:"iface"`
	CIDR  string `json:"cidr"`
}

// ACL allows mesh devices to reach a destination through a node whose
// LANPolicy is restricted. Rules only allow; everything else is dropped.
type ACL struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// Node enforces the rule: the node that routes into the LAN.
	Node string `json:"node"`
	// From lists node IDs allowed to use the rule; empty means any device.
	From []string `json:"from,omitempty"`
	// To is a host IP, a CIDR (e.g. a VLAN subnet) or "self" for the node
	// itself.
	To    string `json:"to"`
	Proto string `json:"proto"` // tcp, udp, both (tcp+udp), icmp or any
	// Ports is "", "443", "8000-8100" or "80,443" (tcp/udp only).
	Ports   string `json:"ports,omitempty"`
	Enabled bool   `json:"enabled"`
}

// Monitor counts the traffic one server node carries to an IP, a port or
// both, without changing how it is routed. It matches the real server end
// of each connection (after any port forward's DNAT), so a proxy on a VPS
// talking to a home server is counted as well as players reaching the
// proxy. Linux nodes only (nft counters).
type Monitor struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// Node measures: the server the traffic passes through or ends on.
	Node string `json:"node"`
	// IP is the server address or subnet; empty matches any.
	IP    string `json:"ip,omitempty"`
	Proto string `json:"proto"` // tcp, udp, both or any
	// Ports is "", "25565", "25565-25570" or "80,443" (tcp/udp only).
	Ports string `json:"ports,omitempty"`
}

// PortList splits Ports into single ports and ranges.
func (m Monitor) PortList() []string { return ACL{Ports: m.Ports}.PortList() }

// Validate checks a monitor.
func (m Monitor) Validate() error {
	if m.Node == "" {
		return fmt.Errorf("pick the node that measures")
	}
	if m.IP == "" && m.Ports == "" {
		return fmt.Errorf("give an IP, a port, or both")
	}
	if m.IP != "" {
		if p, err := netip.ParsePrefix(m.IP); err != nil || !p.Addr().Is4() {
			if ip, err := netip.ParseAddr(m.IP); err != nil || !ip.Is4() {
				return fmt.Errorf("IP must be an IPv4 address or a subnet like 192.168.1.0/24")
			}
		}
	}
	switch m.Proto {
	case "tcp", "udp", "both", "any":
	default:
		return fmt.Errorf("protocol must be tcp, udp, both or any")
	}
	if m.Ports != "" && m.Proto == "any" {
		return fmt.Errorf("ports need protocol tcp, udp or both")
	}
	for _, p := range m.PortList() {
		lo, hi, isRange := strings.Cut(p, "-")
		if !portStr(lo) || (isRange && (!portStr(hi) || atoi(hi) < atoi(lo))) {
			return fmt.Errorf("bad port %q", p)
		}
	}
	return nil
}

// ToSelf is the ACL destination meaning "the enforcing node itself".
const ToSelf = "self"

// PortList splits Ports into single ports and ranges ("8000-8100").
func (a ACL) PortList() []string {
	var out []string
	for _, p := range strings.Split(a.Ports, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// Validate checks an ACL.
func (a ACL) Validate() error {
	if a.Node == "" {
		return fmt.Errorf("pick the node that enforces the rule")
	}
	switch a.Proto {
	case "tcp", "udp", "both", "icmp", "any":
	default:
		return fmt.Errorf("protocol must be tcp, udp, both, icmp or any")
	}
	if a.To != ToSelf {
		if _, err := netip.ParsePrefix(a.To); err != nil {
			if ip, err2 := netip.ParseAddr(a.To); err2 != nil || !ip.Is4() {
				return fmt.Errorf("destination must be an IPv4 address, a subnet like 192.168.20.0/24, or self")
			}
		}
	}
	ports := a.PortList()
	if len(ports) > 0 && a.Proto != "tcp" && a.Proto != "udp" && a.Proto != "both" {
		return fmt.Errorf("ports need protocol tcp, udp or both")
	}
	for _, p := range ports {
		lo, hi, isRange := strings.Cut(p, "-")
		if !portStr(lo) || (isRange && (!portStr(hi) || atoi(hi) < atoi(lo))) {
			return fmt.Errorf("bad port %q", p)
		}
	}
	return nil
}

// DestPrefix returns To as a prefix (a host becomes /32); ok is false for self.
func (a ACL) DestPrefix() (netip.Prefix, bool) {
	if a.To == ToSelf {
		return netip.Prefix{}, false
	}
	if p, err := netip.ParsePrefix(a.To); err == nil {
		return p.Masked(), true
	}
	ip, err := netip.ParseAddr(a.To)
	if err != nil {
		return netip.Prefix{}, false
	}
	return netip.PrefixFrom(ip, 32), true
}

func portStr(s string) bool { n := atoi(s); return n > 0 && n < 65536 }

func atoi(s string) int {
	n := 0
	if s == "" || len(s) > 5 {
		return -1
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return -1
		}
		n = n*10 + int(c-'0')
	}
	return n
}

var hostnameRE = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// CheckName validates a display name (nodes, forwards, routes, rules):
// 1-63 characters, no control or invisible formatting characters, which
// could rewrite terminal output in the TUI or disguise the name.
func CheckName(name string) error {
	if name == "" || len(name) > 63 {
		return fmt.Errorf("name must be 1-63 characters")
	}
	for _, r := range name {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == utf8.RuneError {
			return fmt.Errorf("name contains a control or invisible character")
		}
	}
	return nil
}

// CheckEndpoint validates "host:port" (IPv4 address or DNS name).
func CheckEndpoint(ep string) error {
	host, port, err := net.SplitHostPort(ep)
	if err != nil {
		return fmt.Errorf("endpoint %q: want host:port", ep)
	}
	p, err := strconv.Atoi(port)
	if err != nil || !validPort(p) {
		return fmt.Errorf("endpoint %q: bad port", ep)
	}
	if host == "" || len(host) > 253 || strings.ContainsFunc(host, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '-' || r == ':')
	}) {
		return fmt.Errorf("endpoint %q: bad host", ep)
	}
	return nil
}

// LANExit is one LAN device or subnet whose internet traffic leaves through
// exit node Via.
type LANExit struct {
	Src string `json:"src"` // "192.168.1.205" or "192.168.20.0/24"
	Via string `json:"via"` // exit node ID
}

// Prefix parses Src as an IPv4 address or subnet.
func (e LANExit) Prefix() (netip.Prefix, error) {
	if p, err := netip.ParsePrefix(e.Src); err == nil && p.Addr().Is4() {
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(e.Src)
	if err != nil || !a.Is4() {
		return netip.Prefix{}, fmt.Errorf("%q: want an IPv4 address or subnet", e.Src)
	}
	return netip.PrefixFrom(a, 32), nil
}

// MayUseExit reports whether n may send internet traffic through exit node
// ex (LAN exits on routers are set by admins and always allowed).
func (n Node) MayUseExit(ex string) bool {
	if len(n.LANExits) > 0 {
		return true
	}
	if len(n.ExitsAllowed) == 0 {
		return n.ExitVia != ""
	}
	for _, a := range n.ExitsAllowed {
		if a == "*" || a == ex {
			return true
		}
	}
	return false
}

// ExitRoute sends the internet traffic of a LAN device or subnet behind a
// router (Router, a server sharing that LAN) out through exit node Via. One
// router uses one exit node at a time; if it is down the router fails over
// to another exit, and with none left ExitOnly routes are blocked while the
// others use the normal connection.
type ExitRoute struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Src      string `json:"src"`    // "192.168.200.11" or "192.168.20.0/24"
	Router   string `json:"router"` // node ID
	Via      string `json:"via"`    // exit node ID
	ExitOnly bool   `json:"exit_only,omitempty"`
	Enabled  bool   `json:"enabled"`
}

// Prefix parses Src.
func (r ExitRoute) Prefix() (netip.Prefix, error) { return LANExit{Src: r.Src}.Prefix() }
