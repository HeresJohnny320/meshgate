package wg

import (
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ipc"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/heresjohnny320/meshgate/internal/fw"
	"github.com/heresjohnny320/meshgate/internal/meshcfg"
)

const (
	// Before other VPNs' rules (NetBird uses 105/110, wg-quick and
	// Tailscale come later), so they cannot pull the mesh into their tunnel.
	prioUnderlay = 90
	prioReply    = 5200
	prioRoutes   = 5210
	// LAN exits: per source, first the main table without its default
	// route (LAN, VLAN and local routes win), then the exit table.
	prioLANLocal = 5220
	prioLANExit  = 5221
	prioLANBlock = 5222
)

// Manager owns one interface.
type Manager struct {
	Iface     string
	Key       wgtypes.Key
	Userspace bool // true if using wireguard-go
	// Created: Up made a new interface (false: it took over the one a
	// previous meshgate left running, sessions and all).
	Created bool

	mu       sync.Mutex
	client   *wgctrl.Client
	dev      *device.Device
	uapi     net.Listener
	underlay bool              // connmark rules loaded
	nftTried time.Time         // last failed attempt (retried every 10 minutes)
	routeErr map[string]string // last underlay error per route (logged once)
}

// New creates a manager; call Up before Apply.
func New(iface string, key wgtypes.Key) *Manager {
	return &Manager{Iface: iface, Key: key}
}

// Up creates the interface if needed.
func (m *Manager) Up(forceUserspace bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.client == nil {
		c, err := wgctrl.New()
		if err != nil {
			return err
		}
		m.client = c
	}
	link, err := netlink.LinkByName(m.Iface)
	m.Created = err != nil
	if err != nil {
		if !forceUserspace {
			la := netlink.NewLinkAttrs()
			la.Name = m.Iface
			err = netlink.LinkAdd(&netlink.Wireguard{LinkAttrs: la})
		}
		if forceUserspace || err != nil {
			if err != nil {
				log.Printf("wg: kernel WireGuard unavailable (%v); using built-in wireguard-go", err)
			}
			if err := m.startUserspace(); err != nil {
				return err
			}
			m.Userspace = true
		}
		if link, err = netlink.LinkByName(m.Iface); err != nil {
			return err
		}
	}
	if err := netlink.LinkSetMTU(link, MTU); err != nil {
		return err
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return err
	}
	sysctl("net/ipv4/conf/all/src_valid_mark", "1")
	sysctl("net/ipv4/conf/"+m.Iface+"/rp_filter", "2")
	return nil
}

// Ensure recreates the interface when something else removed it (`ip link
// del`, another VPN tool cleaning up). recreated tells the caller to apply
// the whole config again.
func (m *Manager) Ensure(forceUserspace bool) (recreated bool, err error) {
	m.mu.Lock()
	if m.client == nil {
		m.mu.Unlock()
		return false, nil // not up yet
	}
	if _, err := netlink.LinkByName(m.Iface); err == nil {
		m.mu.Unlock()
		return false, nil
	}
	if m.uapi != nil {
		m.uapi.Close()
		m.uapi = nil
	}
	if m.dev != nil {
		m.dev.Close()
		m.dev = nil
	}
	m.Userspace = false
	m.mu.Unlock()
	if err := m.Up(forceUserspace); err != nil {
		return true, err
	}
	m.Created = true
	return true, nil
}

// EnableForwarding turns on IPv4 routing (server nodes).
func EnableForwarding() { sysctl("net/ipv4/ip_forward", "1") }

func (m *Manager) startUserspace() error {
	t, err := tun.CreateTUN(m.Iface, MTU)
	if err != nil {
		return fmt.Errorf("create tun: %w", err)
	}
	logger := device.NewLogger(device.LogLevelError, "wg: ")
	m.dev = device.NewDevice(t, conn.NewDefaultBind(), logger)
	f, err := ipc.UAPIOpen(m.Iface)
	if err != nil {
		m.dev.Close()
		return fmt.Errorf("uapi: %w", err)
	}
	l, err := ipc.UAPIListen(m.Iface, f)
	if err != nil {
		m.dev.Close()
		return fmt.Errorf("uapi listen: %w", err)
	}
	m.uapi = l
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go m.dev.IpcHandle(c)
		}
	}()
	return m.dev.Up()
}

// Apply makes the interface match cfg. Peers not in cfg are removed;
// endpoints WireGuard learned by roaming are kept when cfg has none.
func (m *Manager) Apply(cfg meshcfg.Config) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.client == nil {
		return errors.New("wg: not up")
	}
	cur, err := m.client.Device(m.Iface)
	if err != nil {
		return err
	}
	want := map[wgtypes.Key]bool{}
	var peers []wgtypes.PeerConfig
	for _, p := range cfg.Peers {
		k, err := wgtypes.ParseKey(p.PublicKey)
		if err != nil {
			continue
		}
		want[k] = true
		pc := wgtypes.PeerConfig{PublicKey: k, ReplaceAllowedIPs: true}
		for _, a := range p.AllowedIPs {
			pc.AllowedIPs = append(pc.AllowedIPs, *prefixToIPNet(a))
		}
		if p.Endpoint != "" {
			if ua, err := net.ResolveUDPAddr("udp4", p.Endpoint); err == nil {
				pc.Endpoint = ua
			}
		}
		ka := time.Duration(p.Keepalive) * time.Second
		pc.PersistentKeepaliveInterval = &ka
		peers = append(peers, pc)
	}
	for _, p := range cur.Peers {
		if !want[p.PublicKey] {
			peers = append(peers, wgtypes.PeerConfig{PublicKey: p.PublicKey, Remove: true})
		}
	}
	mark := fw.MarkBypass
	port := cfg.ListenPort
	wc := wgtypes.Config{PrivateKey: &m.Key, FirewallMark: &mark, Peers: peers}
	if port > 0 {
		wc.ListenPort = &port
	}
	if err := m.client.ConfigureDevice(m.Iface, wc); err != nil {
		return fmt.Errorf("configure %s: %w", m.Iface, err)
	}
	return m.applyNetwork(cfg)
}

func (m *Manager) applyNetwork(cfg meshcfg.Config) error {
	link, err := netlink.LinkByName(m.Iface)
	if err != nil {
		return err
	}
	// Address.
	want := &netlink.Addr{IPNet: prefixToIPNet(cfg.Address)}
	addrs, _ := netlink.AddrList(link, netlink.FAMILY_V4)
	for _, a := range addrs {
		if a.IPNet.String() != want.IPNet.String() {
			netlink.AddrDel(link, &a)
		}
	}
	if err := netlink.AddrReplace(link, want); err != nil {
		return fmt.Errorf("address: %w", err)
	}

	// Subnet routes live in their own table, consulted by every packet
	// except WireGuard's own and probe sockets (MarkBypass). That stops
	// encrypted traffic or probes from looping into the tunnel.
	if err := syncRoutes(link, fw.TableRoutes, cfg.Routes); err != nil {
		return err
	}
	ensureRule(prioRoutes, fw.TableRoutes, fw.MarkBypass, true, len(cfg.Routes) > 0)

	// Preserve-client-IP replies: marked packets use a table whose default
	// route is the tunnel, where the edge peer holds 0.0.0.0/0.
	var reply []netip.Prefix
	if cfg.DefaultViaPeer != "" {
		reply = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}
	}
	if err := syncRoutes(link, fw.TableReply, reply); err != nil {
		return err
	}
	ensureRule(prioReply, fw.TableReply, fw.MarkPreserve, false, len(reply) > 0)

	// LAN devices sent to an exit node: their default route is the tunnel,
	// or a blackhole while the exit is unusable (no leak via the home line).
	if err := syncLANExitTable(link, cfg); err != nil {
		return err
	}
	var routed []netip.Prefix
	if cfg.LANExitVia != "" {
		routed = cfg.LANExitSrcs
	}
	syncSrcRules(prioLANLocal, unix.RT_TABLE_MAIN, true, append(append([]netip.Prefix(nil), routed...), cfg.LANExitBlock...))
	syncSrcRules(prioLANExit, fw.TableLANExit, false, routed)
	syncSrcRules(prioLANBlock, fw.TableLANBlock, false, cfg.LANExitBlock)
	return nil
}

func syncLANExitTable(link netlink.Link, cfg meshcfg.Config) error {
	all := prefixToIPNet(netip.MustParsePrefix("0.0.0.0/0"))
	var tunnel, block *netlink.Route
	if cfg.LANExitVia != "" {
		tunnel = &netlink.Route{LinkIndex: link.Attrs().Index, Dst: all, Table: fw.TableLANExit, Scope: netlink.SCOPE_LINK}
	}
	if len(cfg.LANExitBlock) > 0 {
		block = &netlink.Route{Dst: all, Table: fw.TableLANBlock, Type: unix.RTN_BLACKHOLE}
	}
	if err := syncDefault(fw.TableLANExit, tunnel); err != nil {
		return err
	}
	return syncDefault(fw.TableLANBlock, block)
}

// syncDefault makes want the only route in table (none when want is nil).
func syncDefault(table int, want *netlink.Route) error {
	have, _ := netlink.RouteListFiltered(netlink.FAMILY_V4, &netlink.Route{Table: table}, netlink.RT_FILTER_TABLE)
	for _, r := range have {
		if want == nil || r.Type != want.Type || r.LinkIndex != want.LinkIndex {
			netlink.RouteDel(&r)
		}
	}
	if want == nil {
		return nil
	}
	if err := netlink.RouteReplace(want); err != nil {
		return fmt.Errorf("lan exit route: %w", err)
	}
	return nil
}

// syncSrcRules keeps exactly one "from <src> lookup table" rule per source
// at prio (with suppress_prefixlength 0 when suppressDefault).
func syncSrcRules(prio, table int, suppressDefault bool, srcs []netip.Prefix) {
	want := map[string]bool{}
	for _, s := range srcs {
		want[s.String()] = true
	}
	rules, _ := netlink.RuleList(netlink.FAMILY_V4)
	for _, r := range rules {
		if r.Priority != prio {
			continue
		}
		if r.Src != nil && want[r.Src.String()] && r.Table == table {
			delete(want, r.Src.String())
			continue
		}
		netlink.RuleDel(&r)
	}
	for s := range want {
		r := netlink.NewRule()
		r.Family = netlink.FAMILY_V4
		r.Priority, r.Table, r.Src = prio, table, prefixToIPNet(netip.MustParsePrefix(s))
		if suppressDefault {
			r.SuppressPrefixlen = 0
		}
		if err := netlink.RuleAdd(r); err != nil {
			log.Printf("wg: ip rule from %s: %v", s, err)
		}
	}
}

func syncRoutes(link netlink.Link, table int, want []netip.Prefix) error {
	have, err := netlink.RouteListFiltered(netlink.FAMILY_V4,
		&netlink.Route{Table: table, LinkIndex: link.Attrs().Index}, netlink.RT_FILTER_TABLE|netlink.RT_FILTER_OIF)
	if err != nil {
		return err
	}
	keep := map[string]bool{}
	for _, p := range want {
		keep[p.String()] = true
	}
	for _, r := range have {
		dst := "0.0.0.0/0"
		if r.Dst != nil {
			dst = r.Dst.String()
		}
		if !keep[dst] {
			netlink.RouteDel(&r)
		}
	}
	for _, p := range want {
		r := &netlink.Route{LinkIndex: link.Attrs().Index, Dst: prefixToIPNet(p), Table: table, Scope: netlink.SCOPE_LINK}
		if err := netlink.RouteReplace(r); err != nil {
			return fmt.Errorf("route %s: %w", p, err)
		}
	}
	return nil
}

// ensureRule adds or removes "[not] fwmark M lookup T".
func ensureRule(prio, table int, mark uint32, invert, present bool) {
	rules, _ := netlink.RuleList(netlink.FAMILY_V4)
	var found []netlink.Rule
	for _, r := range rules {
		if r.Priority == prio && r.Table == table {
			found = append(found, r)
		}
	}
	if present && len(found) > 0 {
		return
	}
	for _, r := range found {
		netlink.RuleDel(&r)
	}
	if !present {
		return
	}
	r := netlink.NewRule()
	r.Family = netlink.FAMILY_V4
	r.Priority, r.Table, r.Mark, r.Invert = prio, table, mark, invert
	mask := uint32(0xffffffff)
	r.Mask = &mask
	if err := netlink.RuleAdd(r); err != nil {
		log.Printf("wg: ip rule %d: %v", prio, err)
	}
}

// ResetPeers drops the sessions of the given peers. The next Apply adds them
// back, which makes WireGuard handshake right away (used when a peer
// restarted and lost its session state).
func (m *Manager) ResetPeers(keys []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.client == nil || len(keys) == 0 {
		return nil
	}
	var peers []wgtypes.PeerConfig
	for _, k := range keys {
		if pk, err := wgtypes.ParseKey(k); err == nil {
			peers = append(peers, wgtypes.PeerConfig{PublicKey: pk, Remove: true})
		}
	}
	return m.client.ConfigureDevice(m.Iface, wgtypes.Config{Peers: peers})
}

// Stats returns peer runtime data keyed by public key.
func (m *Manager) Stats() map[string]PeerStat {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[string]PeerStat{}
	if m.client == nil {
		return out
	}
	d, err := m.client.Device(m.Iface)
	if err != nil {
		return out
	}
	for _, p := range d.Peers {
		s := PeerStat{PublicKey: p.PublicKey.String(), LastHandshake: p.LastHandshakeTime, RxBytes: p.ReceiveBytes, TxBytes: p.TransmitBytes}
		if p.Endpoint != nil {
			s.Endpoint = p.Endpoint.String()
		}
		out[s.PublicKey] = s
	}
	return out
}

// Release lets go of the interface when meshgate exits but leaves a kernel
// interface running with its peers, routes and rules, the way plain
// WireGuard keeps going: traffic is not interrupted by a restart or update,
// and the next start takes it over. (wireguard-go ends with the process.)
// `meshgate stop` and `leave` take it down with Teardown.
func (m *Manager) Release() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.dev != nil {
		m.down0()
		return
	}
	if m.client != nil {
		m.client.Close()
		m.client = nil
	}
}

// Teardown removes the interface, its rules and tables (meshgate stop).
func Teardown(iface string) {
	m := New(iface, wgtypes.Key{})
	m.underlay = true
	m.Down()
}

// Down removes the interface, rules and firewall table.
func (m *Manager) Down() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.down0()
}

// down0 is Down with m.mu held.
func (m *Manager) down0() {
	ensureRule(prioRoutes, fw.TableRoutes, 0, true, false)
	ensureRule(prioReply, fw.TableReply, 0, false, false)
	syncSrcRules(prioLANLocal, unix.RT_TABLE_MAIN, true, nil)
	syncSrcRules(prioLANExit, fw.TableLANExit, false, nil)
	syncSrcRules(prioLANBlock, fw.TableLANBlock, false, nil)
	ensureRule(prioUnderlay, fw.TableUnderlay, 0, false, false)
	syncTable(fw.TableUnderlay, nil, nil)
	if m.underlay {
		nft("table inet meshgate_underlay\ndelete table inet meshgate_underlay\n", true)
		m.underlay = false
	}
	if m.uapi != nil {
		m.uapi.Close()
	}
	if m.dev != nil {
		m.dev.Close()
	}
	if link, err := netlink.LinkByName(m.Iface); err == nil {
		netlink.LinkDel(link)
	}
	if m.client != nil {
		m.client.Close()
		m.client = nil
	}
}

// SyncUnderlay keeps WireGuard's own packets and the path probes on this
// machine's real connection when another VPN (wg-quick, NetBird,
// Tailscale, OpenVPN) takes over the default route, so the mesh is a
// separate tunnel instead of running inside that one. Their sockets carry
// MarkBypass and look up TableUnderlay first: a copy of the main table's
// routes over real interfaces. Subnets that exist only inside another VPN
// get a throw route, so a peer reachable only there still works. Called
// every reconcile, so DHCP and interface changes are followed.
func (m *Manager) SyncUnderlay() {
	m.mu.Lock()
	defer m.mu.Unlock()
	links, _ := netlink.LinkList()
	real := map[int]bool{}
	for _, l := range links {
		a := l.Attrs()
		real[a.Index] = a.Name != m.Iface && !fw.IsTunnel(a.Name, a.Flags)
	}
	all, _ := netlink.RouteListFiltered(netlink.FAMILY_V4, &netlink.Route{Table: unix.RT_TABLE_UNSPEC}, netlink.RT_FILTER_TABLE)
	var want []netlink.Route
	have := map[string]bool{}
	for _, r := range all {
		if r.Table != unix.RT_TABLE_MAIN || r.Type != unix.RTN_UNICAST || !viaReal(r, real) || r.Flags&unix.RTNH_F_LINKDOWN != 0 {
			continue // a down link (e.g. an idle Docker bridge) cannot take routes
		}
		// Only ONLINK may be set by us; LINKDOWN, DEAD etc. are the kernel's.
		hops := make([]*netlink.NexthopInfo, 0, len(r.MultiPath))
		for _, h := range r.MultiPath {
			c := *h
			c.Flags &= unix.RTNH_F_ONLINK
			hops = append(hops, &c)
		}
		if len(hops) == 0 {
			hops = nil
		}
		want = append(want, netlink.Route{LinkIndex: r.LinkIndex, Dst: r.Dst, Gw: r.Gw, Src: r.Src, Scope: r.Scope,
			Priority: r.Priority, MultiPath: hops, Flags: r.Flags & unix.RTNH_F_ONLINK, Type: unix.RTN_UNICAST, Table: fw.TableUnderlay})
		have[dstKey(r.Dst)] = true
	}
	for _, r := range all {
		// Another VPN's own subnets (not its 0/0 or 0/1 takeover routes).
		if r.Table == fw.TableUnderlay || r.Dst == nil || r.LinkIndex == 0 || real[r.LinkIndex] || have[dstKey(r.Dst)] {
			continue
		}
		if ones, _ := r.Dst.Mask.Size(); ones < 8 || r.Type != unix.RTN_UNICAST {
			continue
		}
		if l, err := netlink.LinkByIndex(r.LinkIndex); err != nil || l.Attrs().Name == m.Iface {
			continue
		}
		have[dstKey(r.Dst)] = true
		want = append(want, netlink.Route{Dst: r.Dst, Type: unix.RTN_THROW, Table: fw.TableUnderlay})
	}
	if m.routeErr == nil {
		m.routeErr = map[string]string{}
	}
	syncTable(fw.TableUnderlay, want, m.routeErr)
	ensureRule(prioUnderlay, fw.TableUnderlay, fw.MarkBypass, false, len(want) > 0)
	if !m.underlay && time.Since(m.nftTried) > 10*time.Minute {
		logged := !m.nftTried.IsZero()
		m.nftTried = time.Now()
		// Replies carry no mark; restore it from the connection so strict
		// rp_filter (with src_valid_mark) checks them against the same
		// table, as wg-quick does.
		m.underlay = nft(fmt.Sprintf(`table inet meshgate_underlay
delete table inet meshgate_underlay
table inet meshgate_underlay {
	chain out {
		type route hook output priority mangle;
		meta l4proto udp meta mark 0x%[1]x ct mark set meta mark
	}
	chain pre {
		type filter hook prerouting priority mangle;
		meta l4proto udp ct mark 0x%[1]x meta mark set ct mark
	}
}
`, fw.MarkBypass), logged) == nil
	}
}

func viaReal(r netlink.Route, real map[int]bool) bool {
	if len(r.MultiPath) > 0 {
		for _, h := range r.MultiPath {
			if !real[h.LinkIndex] {
				return false
			}
		}
		return true
	}
	return real[r.LinkIndex]
}

func dstKey(d *net.IPNet) string {
	if d == nil {
		return "0.0.0.0/0"
	}
	return d.String()
}

func routeKey(r netlink.Route) string {
	k := fmt.Sprintf("%d %s %s %d %d %s", r.Type, dstKey(r.Dst), r.Gw, r.LinkIndex, r.Priority, r.Src)
	for _, h := range r.MultiPath {
		k += fmt.Sprintf(" %s@%d", h.Gw, h.LinkIndex)
	}
	return k
}

// syncTable makes table hold exactly want. A route that keeps failing is
// logged once (errs remembers it), not on every pass.
func syncTable(table int, want []netlink.Route, errs map[string]string) {
	keep := map[string]bool{}
	for _, r := range want {
		keep[routeKey(r)] = true
	}
	have, _ := netlink.RouteListFiltered(netlink.FAMILY_V4, &netlink.Route{Table: table}, netlink.RT_FILTER_TABLE)
	for _, r := range have {
		if keep[routeKey(r)] {
			delete(keep, routeKey(r))
			continue
		}
		netlink.RouteDel(&r)
	}
	for _, r := range want {
		if keep[routeKey(r)] {
			k := routeKey(r)
			if err := netlink.RouteReplace(&r); err != nil {
				if errs != nil && errs[k] != err.Error() {
					log.Printf("wg: underlay route %s: %v", dstKey(r.Dst), err)
				}
				if errs != nil {
					errs[k] = err.Error()
				}
			} else if errs != nil {
				delete(errs, k)
			}
		}
	}
}

// nft loads rules; quiet skips logging a failure already reported.
func nft(rules string, quiet bool) error {
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(rules)
	if out, err := cmd.CombinedOutput(); err != nil {
		if !quiet {
			log.Printf("wg: nft: %v: %s (replies may hit strict rp_filter while another VPN holds the default route)", err, strings.TrimSpace(string(out)))
		}
		return err
	}
	return nil
}

// MarkSocket is a net.Dialer/ListenConfig Control func that tags sockets
// with MarkBypass so they ignore mesh routes.
func MarkSocket(network, address string, c syscall.RawConn) error {
	var serr error
	err := c.Control(func(fd uintptr) {
		serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, fw.MarkBypass)
	})
	if err != nil {
		return err
	}
	return serr
}

func sysctl(key, val string) {
	if err := os.WriteFile("/proc/sys/"+key, []byte(val), 0o644); err != nil {
		log.Printf("sysctl %s=%s: %v", key, val, err)
	}
}

// DestroyInterface removes the interface (used by `meshgate leave`).
func DestroyInterface(name string) {
	if link, err := netlink.LinkByName(name); err == nil {
		netlink.LinkDel(link)
	}
}
