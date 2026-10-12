package wg

import (
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
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
	prioReply  = 5200
	prioRoutes = 5210
)

// Manager owns one interface.
type Manager struct {
	Iface     string
	Key       wgtypes.Key
	Userspace bool // true if using wireguard-go

	mu     sync.Mutex
	client *wgctrl.Client
	dev    *device.Device
	uapi   net.Listener
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
	return nil
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

// Down removes the interface, rules and firewall table.
func (m *Manager) Down() {
	m.mu.Lock()
	defer m.mu.Unlock()
	ensureRule(prioRoutes, fw.TableRoutes, 0, true, false)
	ensureRule(prioReply, fw.TableReply, 0, false, false)
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
