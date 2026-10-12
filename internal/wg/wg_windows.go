package wg

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"syscall"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"

	"github.com/heresjohnny320/meshgate/internal/meshcfg"
	"github.com/heresjohnny320/meshgate/internal/uapi"
)

// Manager runs wireguard-go on a Wintun adapter. wintun.dll must sit next to
// meshgate.exe (the release zip ships it).
type Manager struct {
	Iface     string
	Key       wgtypes.Key
	Userspace bool

	mu      sync.Mutex
	dev     *device.Device
	tun     tun.Device
	luid    winipcfg.LUID
	applied map[string]bool
}

// New creates a manager; call Up before Apply.
func New(iface string, key wgtypes.Key) *Manager {
	return &Manager{Iface: iface, Key: key, Userspace: true}
}

// Up creates the Wintun adapter and starts WireGuard.
func (m *Manager) Up(bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.dev != nil {
		return nil
	}
	if exe, err := os.Executable(); err == nil {
		if _, err := os.Stat(filepath.Join(filepath.Dir(exe), "wintun.dll")); err != nil {
			return errors.New("wintun.dll is missing next to meshgate.exe (download it from https://www.wintun.net)")
		}
	}
	t, err := tun.CreateTUN(m.Iface, MTU)
	if err != nil {
		return fmt.Errorf("create Wintun adapter (run as Administrator): %w", err)
	}
	nt, ok := t.(*tun.NativeTun)
	if !ok {
		t.Close()
		return errors.New("unexpected tun type")
	}
	m.tun, m.luid = t, winipcfg.LUID(nt.LUID())
	m.dev = device.NewDevice(t, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "wg: "))
	if err := m.dev.IpcSet("private_key=" + hexKey(m.Key) + "\n"); err != nil {
		m.dev.Close()
		return err
	}
	return m.dev.Up()
}

func hexKey(k wgtypes.Key) string {
	h, _ := uapi.HexKey(k.String())
	return h
}

// EnableForwarding is not supported on Windows nodes (no subnet routing).
func EnableForwarding() {}

// Apply makes the adapter match cfg.
func (m *Manager) Apply(cfg meshcfg.Config) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.dev == nil {
		return errors.New("wg: not up")
	}
	set := ""
	if cfg.ListenPort > 0 {
		set = fmt.Sprintf("listen_port=%d\n", cfg.ListenPort)
	}
	text, keys := uapi.Config(cfg, m.applied)
	if err := m.dev.IpcSet(set + text); err != nil {
		return fmt.Errorf("configure: %w", err)
	}
	m.applied = keys
	if err := m.luid.SetIPAddressesForFamily(windows.AF_INET, []netip.Prefix{cfg.Address}); err != nil {
		return fmt.Errorf("address: %w", err)
	}
	var routes []*winipcfg.RouteData
	for _, r := range cfg.Routes {
		routes = append(routes, &winipcfg.RouteData{Destination: r, NextHop: netip.IPv4Unspecified(), Metric: 0})
	}
	if err := m.luid.SetRoutesForFamily(windows.AF_INET, routes); err != nil {
		return fmt.Errorf("routes: %w", err)
	}
	return nil
}

// ResetPeers drops the sessions of the given peers.
func (m *Manager) ResetPeers(keys []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.dev == nil || len(keys) == 0 {
		return nil
	}
	for _, k := range keys {
		if h, err := uapi.HexKey(k); err == nil {
			delete(m.applied, h)
		}
	}
	return m.dev.IpcSet(uapi.Remove(keys))
}

// Stats returns peer runtime data keyed by base64 public key.
func (m *Manager) Stats() map[string]PeerStat {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[string]PeerStat{}
	if m.dev == nil {
		return out
	}
	txt, err := m.dev.IpcGet()
	if err != nil {
		return out
	}
	for h, p := range uapi.Parse(txt) {
		k, err := wgtypes.ParseKey(hexToB64(h))
		if err != nil {
			continue
		}
		out[k.String()] = PeerStat{PublicKey: k.String(), Endpoint: p.Endpoint, LastHandshake: p.LastHandshake, RxBytes: p.RxBytes, TxBytes: p.TxBytes}
	}
	return out
}

func hexToB64(h string) string {
	b, err := hex.DecodeString(h)
	if err != nil || len(b) != 32 {
		return ""
	}
	var k wgtypes.Key
	copy(k[:], b)
	return k.String()
}

// Down removes the adapter.
func (m *Manager) Down() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.dev != nil {
		m.dev.Close() // also closes the Wintun adapter
		m.dev = nil
	}
}

// MarkSocket is a no-op on Windows; receivers ignore probes that came
// through the tunnel.
func MarkSocket(network, address string, c syscall.RawConn) error { return nil }

// DestroyInterface is a no-op: the adapter disappears when meshgate stops.
func DestroyInterface(string) {}
