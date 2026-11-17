package wg

import (
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ipc"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/heresjohnny320/meshgate/internal/meshcfg"
)

// Manager owns one interface. On FreeBSD/pfSense it uses the if_wg kernel
// module (FreeBSD 13.2+/pfSense 2.7+) and falls back to wireguard-go. It is
// configured with the `wg` tool (wireguard-tools), which talks to both, so
// the binary stays static (wgctrl needs cgo on FreeBSD).
//
// Preserve-client-IP replies are handled by pf's reply-to (see package fw),
// so no policy routing is needed here.
type Manager struct {
	Iface     string
	Key       wgtypes.Key
	Userspace bool
	Created   bool // see the Linux Manager

	mu     sync.Mutex
	up     bool
	dev    *device.Device
	uapi   net.Listener
	routes map[netip.Prefix]bool
}

// New creates a manager; call Up before Apply.
func New(iface string, key wgtypes.Key) *Manager {
	return &Manager{Iface: iface, Key: key, routes: map[netip.Prefix]bool{}}
}

func run(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return strings.TrimSpace(string(out)), nil
}

// Up creates the interface if needed.
func (m *Manager) Up(forceUserspace bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, err := exec.LookPath("wg"); err != nil {
		return errors.New("the `wg` tool is missing: pkg install wireguard-tools")
	}
	_, err := net.InterfaceByName(m.Iface)
	m.Created = err != nil
	if err != nil {
		kernelErr := errors.New("userspace forced")
		if !forceUserspace {
			kernelErr = m.createKernel()
		}
		if kernelErr != nil {
			log.Printf("wg: kernel WireGuard unavailable (%v); using built-in wireguard-go", kernelErr)
			if err := m.startUserspace(); err != nil {
				return err
			}
			m.Userspace = true
		}
	}
	if _, err := run("ifconfig", m.Iface, "mtu", strconv.Itoa(MTU), "up"); err != nil {
		return err
	}
	// FreeBSD puts every if_wg interface in the "wg" group, which pfSense's
	// WireGuard package treats as its own tunnels: stopping or resyncing it
	// destroyed ours. Leave the group (fails harmlessly for wireguard-go).
	run("ifconfig", m.Iface, "-group", "wg")
	m.up = true
	return nil
}

// Ensure recreates the interface when something else removed it (it must
// exist for as long as meshgate runs). recreated tells the caller to apply
// the whole config again.
func (m *Manager) Ensure(forceUserspace bool) (recreated bool, err error) {
	m.mu.Lock()
	if !m.up {
		m.mu.Unlock()
		return false, nil
	}
	if _, err := net.InterfaceByName(m.Iface); err == nil {
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
	m.up, m.Userspace, m.routes = false, false, map[netip.Prefix]bool{}
	m.mu.Unlock()
	if err := m.Up(forceUserspace); err != nil {
		return true, err
	}
	m.Created = true
	return true, nil
}

func (m *Manager) createKernel() error {
	run("kldload", "-n", "if_wg")
	name, err := run("ifconfig", "wg", "create")
	if err != nil {
		return err
	}
	if _, err := run("ifconfig", name, "name", m.Iface); err != nil {
		run("ifconfig", name, "destroy")
		return err
	}
	return nil
}

func (m *Manager) startUserspace() error {
	t, err := tun.CreateTUN(m.Iface, MTU)
	if err != nil {
		return fmt.Errorf("create tun: %w", err)
	}
	m.dev = device.NewDevice(t, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "wg: "))
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

// EnableForwarding turns on IPv4 routing.
func EnableForwarding() { run("sysctl", "net.inet.ip.forwarding=1") }

// Apply makes the interface match cfg. Peers are updated in place with
// `wg set` so sessions and roaming endpoints survive.
func (m *Manager) Apply(cfg meshcfg.Config) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.up {
		return errors.New("wg: not up")
	}
	cur, err := m.dump()
	if err != nil {
		return err
	}
	args := []string{"set", m.Iface, "private-key", "/dev/stdin"}
	if cfg.ListenPort > 0 {
		args = append(args, "listen-port", strconv.Itoa(cfg.ListenPort))
	}
	want := map[string]bool{}
	for _, p := range cfg.Peers {
		if _, err := wgtypes.ParseKey(p.PublicKey); err != nil {
			continue
		}
		want[p.PublicKey] = true
		var ips []string
		for _, a := range p.AllowedIPs {
			ips = append(ips, a.String())
		}
		args = append(args, "peer", p.PublicKey, "allowed-ips", strings.Join(ips, ","),
			"persistent-keepalive", keepalive(p.Keepalive))
		if p.Endpoint != "" {
			if ua, err := net.ResolveUDPAddr("udp4", p.Endpoint); err == nil {
				args = append(args, "endpoint", ua.String())
			}
		}
	}
	for k := range cur {
		if !want[k] {
			args = append(args, "peer", k, "remove")
		}
	}
	cmd := exec.Command("wg", args...)
	cmd.Stdin = strings.NewReader(m.Key.String() + "\n")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("wg set: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return m.applyNetwork(cfg)
}

func keepalive(s int) string {
	if s <= 0 {
		return "off"
	}
	return strconv.Itoa(s)
}

// dump parses `wg show <iface> dump` into per-peer stats.
func (m *Manager) dump() (map[string]PeerStat, error) {
	out, err := run("wg", "show", m.Iface, "dump")
	if err != nil {
		return nil, err
	}
	return parseDump(out), nil
}

func (m *Manager) applyNetwork(cfg meshcfg.Config) error {
	ifi, err := net.InterfaceByName(m.Iface)
	if err != nil {
		return err
	}
	addrs, _ := ifi.Addrs()
	have := false
	for _, a := range addrs {
		n, ok := a.(*net.IPNet)
		if !ok || n.IP.To4() == nil {
			continue
		}
		ones, _ := n.Mask.Size()
		if n.IP.String() == cfg.Address.Addr().String() && ones == cfg.Address.Bits() {
			have = true
			continue
		}
		run("ifconfig", m.Iface, "inet", n.IP.String(), "-alias")
	}
	if !have {
		if _, err := run("ifconfig", m.Iface, "inet", cfg.Address.String(), "alias"); err != nil {
			return err
		}
	}
	keep := map[netip.Prefix]bool{}
	for _, p := range cfg.Routes {
		keep[p] = true
		if !m.routes[p] {
			// "change" fails if the route does not exist; then add it.
			if _, err := run("route", "-q", "-n", "change", "-net", p.String(), "-interface", m.Iface); err != nil {
				if _, err := run("route", "-q", "-n", "add", "-net", p.String(), "-interface", m.Iface); err != nil {
					return err
				}
			}
			m.routes[p] = true
		}
	}
	for p := range m.routes {
		if !keep[p] {
			run("route", "-q", "-n", "delete", "-net", p.String(), "-interface", m.Iface)
			delete(m.routes, p)
		}
	}
	return nil
}

// ResetPeers drops the sessions of the given peers (see Linux version).
func (m *Manager) ResetPeers(keys []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.up || len(keys) == 0 {
		return nil
	}
	args := []string{"set", m.Iface}
	for _, k := range keys {
		args = append(args, "peer", k, "remove")
	}
	_, err := run("wg", args...)
	return err
}

// Stats returns peer runtime data keyed by public key.
func (m *Manager) Stats() map[string]PeerStat {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.up {
		return map[string]PeerStat{}
	}
	st, err := m.dump()
	if err != nil {
		return map[string]PeerStat{}
	}
	return st
}

// SyncUnderlay is Linux only for now.
func (m *Manager) SyncUnderlay() {}

// Release lets go of the interface when meshgate exits; a kernel interface
// keeps running (see the Linux version).
func (m *Manager) Release() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.dev != nil {
		m.down0()
	}
}

// Teardown destroys the interface (meshgate stop).
func Teardown(iface string) { DestroyInterface(iface) }

// Down destroys the interface.
func (m *Manager) Down() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.down0()
}

func (m *Manager) down0() {
	if m.uapi != nil {
		m.uapi.Close()
	}
	if m.dev != nil {
		m.dev.Close()
	} else {
		run("ifconfig", m.Iface, "destroy")
	}
	m.up = false
	m.routes = map[netip.Prefix]bool{}
}

// MarkSocket is a no-op on FreeBSD: server nodes (pfSense) do not need
// probe sockets to bypass mesh routes, and probes arriving through the tunnel
// are ignored by the receiver anyway.
func MarkSocket(network, address string, c syscall.RawConn) error { return nil }

// DestroyInterface removes the interface (used by `meshgate leave`).
func DestroyInterface(name string) { run("ifconfig", name, "destroy") }
