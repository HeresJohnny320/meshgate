// Package probe measures which WireGuard endpoints are reachable and how
// fast. Every node answers probes on UDP port (WireGuard port + 2) and sends
// probes to every candidate endpoint of every peer.
//
// A successful probe from peer P also tells us P reaches us directly
// (pathsel's "inbound direct"), which keeps both ends of a pair in agreement.
package probe

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/heresjohnny320/meshgate/internal/pathsel"
)

// Offset is added to a WireGuard port to get the probe port.
const Offset = 2

// Interval between probe rounds.
const Interval = 3 * time.Second

var magic = []byte("MGP1")

const (
	typeReq  = 1
	typeResp = 2
)

// Control can tag sockets (Linux SO_MARK, Android VpnService.protect) so
// probes never travel inside the tunnel they are testing.
type Control func(network, address string, c syscall.RawConn) error

// Prober sends probes and answers them.
type Prober struct {
	SelfID  string
	Mesh    netip.Prefix // probes from inside the mesh are ignored
	Control Control

	mu      sync.Mutex
	results map[string]pathsel.Probe // endpoint -> result
	inbound map[string]time.Time     // node ID -> last direct probe
	pending map[uint64]pending
	conn    net.PacketConn
	srv     net.PacketConn
	kick    chan struct{}
	// Boot IDs let us notice that a peer's tunnel was recreated (its
	// WireGuard sessions are gone) within one probe interval and re-handshake
	// immediately instead of waiting for WireGuard timers. A meshgate restart
	// that keeps the kernel interface keeps its boot ID (SetBootID).
	bootID    string
	boots     map[string]string // node ID -> last boot ID seen
	restarted map[string]bool
}

type pending struct {
	endpoint string
	sent     time.Time
}

// New returns a prober.
func New(selfID string, mesh netip.Prefix, ctl Control) *Prober {
	return &Prober{
		SelfID: selfID, Mesh: mesh, Control: ctl,
		results:   map[string]pathsel.Probe{},
		inbound:   map[string]time.Time{},
		pending:   map[uint64]pending{},
		kick:      make(chan struct{}, 1),
		bootID:    randomBootID(),
		boots:     map[string]string{},
		restarted: map[string]bool{},
	}
}

// SetBootID replaces the boot ID (see Prober.bootID).
func (p *Prober) SetBootID(id string) {
	p.mu.Lock()
	p.bootID = id
	p.mu.Unlock()
}

// NewBootID returns a fresh random boot ID.
func NewBootID() string { return randomBootID() }

func randomBootID() string {
	var b [6]byte
	rand.Read(b[:])
	return fmt.Sprintf("%x", b)
}

// TakeRestarted returns peers that restarted since the last call.
func (p *Prober) TakeRestarted() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []string
	for id := range p.restarted {
		out = append(out, id)
	}
	p.restarted = map[string]bool{}
	return out
}

// Kick runs a probe round now (e.g. after the phone switched networks).
func (p *Prober) Kick() {
	select {
	case p.kick <- struct{}{}:
	default:
	}
}

// Serve answers probes on port until ctx ends.
func (p *Prober) Serve(ctx context.Context, port int) error {
	lc := net.ListenConfig{Control: p.Control}
	c, err := lc.ListenPacket(ctx, "udp4", ":"+strconv.Itoa(port))
	if err != nil {
		return err
	}
	p.mu.Lock()
	p.srv = c
	p.mu.Unlock()
	go func() { <-ctx.Done(); c.Close() }()
	buf := make([]byte, 512)
	for {
		n, from, err := c.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			continue
		}
		typ, nonce, sender, target, ok := parse(buf[:n])
		if !ok || typ != typeReq || (target != "" && target != p.SelfID) {
			continue
		}
		// A probe that came through the tunnel (mesh source address) says
		// nothing about direct reachability: drop it without answering, or
		// the sender would wrongly conclude it can reach us directly.
		ua, ok := from.(*net.UDPAddr)
		if !ok {
			continue
		}
		a, ok := netip.AddrFromSlice(ua.IP.To4())
		if !ok || p.Mesh.Contains(a) {
			continue
		}
		if sender != "" {
			p.mu.Lock()
			p.inbound[sender] = time.Now()
			p.mu.Unlock()
		}
		p.mu.Lock()
		boot := p.bootID
		p.mu.Unlock()
		c.WriteTo(encode(typeResp, nonce, p.SelfID, boot), from)
	}
}

// Target is one endpoint to probe.
type Target struct {
	NodeID   string
	Endpoint string // WireGuard "host:port"
}

// Run probes targets() every Interval until ctx ends.
func (p *Prober) Run(ctx context.Context, targets func() []Target) error {
	lc := net.ListenConfig{Control: p.Control}
	c, err := lc.ListenPacket(ctx, "udp4", ":0")
	if err != nil {
		return err
	}
	p.mu.Lock()
	p.conn = c
	p.mu.Unlock()
	go p.readLoop(ctx, c)
	t := time.NewTicker(Interval)
	defer t.Stop()
	for {
		p.Round(c, targets())
		select {
		case <-ctx.Done():
			c.Close()
			return nil
		case <-t.C:
		case <-p.kick:
		}
	}
}

// Round sends one probe to each target.
func (p *Prober) Round(c net.PacketConn, targets []Target) {
	now := time.Now()
	p.mu.Lock()
	for n, pd := range p.pending {
		if now.Sub(pd.sent) > 5*time.Second {
			delete(p.pending, n)
		}
	}
	p.mu.Unlock()
	for _, t := range targets {
		addr, err := ProbeAddr(t.Endpoint)
		if err != nil {
			continue
		}
		var nb [8]byte
		rand.Read(nb[:])
		nonce := binary.BigEndian.Uint64(nb[:])
		p.mu.Lock()
		p.pending[nonce] = pending{endpoint: t.Endpoint, sent: time.Now()}
		p.mu.Unlock()
		if _, err := c.WriteTo(encode(typeReq, nonce, p.SelfID, t.NodeID), addr); err != nil && !errors.Is(err, net.ErrClosed) {
			log.Printf("probe %s: %v", t.Endpoint, err)
		}
	}
}

func (p *Prober) readLoop(ctx context.Context, c net.PacketConn) {
	buf := make([]byte, 512)
	for {
		n, _, err := c.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		p.handleResponse(buf[:n], time.Now())
	}
}

// handleResponse records the RTT of a matching probe and notices restarts.
func (p *Prober) handleResponse(b []byte, now time.Time) {
	typ, nonce, responder, boot, ok := parse(b)
	if !ok || typ != typeResp {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	pd, ok := p.pending[nonce]
	if !ok {
		return // unsolicited or late: ignore
	}
	delete(p.pending, nonce)
	p.results[pd.endpoint] = pathsel.Probe{LastOK: now, RTT: now.Sub(pd.sent)}
	if responder != "" && boot != "" {
		if old, seen := p.boots[responder]; seen && old != boot {
			p.restarted[responder] = true
		}
		p.boots[responder] = boot
	}
}

// Snapshot returns copies of the current results.
func (p *Prober) Snapshot() (map[string]pathsel.Probe, map[string]time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	r := make(map[string]pathsel.Probe, len(p.results))
	for k, v := range p.results {
		r[k] = v
	}
	in := make(map[string]time.Time, len(p.inbound))
	for k, v := range p.inbound {
		in[k] = v
	}
	return r, in
}

// Forget drops all results (e.g. after the phone changed networks).
func (p *Prober) Forget() {
	p.mu.Lock()
	p.results = map[string]pathsel.Probe{}
	p.mu.Unlock()
}

// ProbeAddr maps a WireGuard endpoint to its probe address.
func ProbeAddr(endpoint string) (*net.UDPAddr, error) {
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		return nil, err
	}
	pn, err := strconv.Atoi(port)
	if err != nil {
		return nil, err
	}
	return net.ResolveUDPAddr("udp4", net.JoinHostPort(host, strconv.Itoa(pn+Offset)))
}

func encode(typ byte, nonce uint64, sender, target string) []byte {
	var b bytes.Buffer
	b.Write(magic)
	b.WriteByte(typ)
	binary.Write(&b, binary.BigEndian, nonce)
	b.WriteByte(byte(len(sender)))
	b.WriteString(sender)
	b.WriteByte(byte(len(target)))
	b.WriteString(target)
	return b.Bytes()
}

func parse(b []byte) (typ byte, nonce uint64, sender, target string, ok bool) {
	if len(b) < 15 || !bytes.Equal(b[:4], magic) {
		return
	}
	typ = b[4]
	nonce = binary.BigEndian.Uint64(b[5:13])
	rest := b[13:]
	ls := int(rest[0])
	if len(rest) < 1+ls+1 {
		return
	}
	sender = string(rest[1 : 1+ls])
	rest = rest[1+ls:]
	lt := int(rest[0])
	if len(rest) < 1+lt {
		return
	}
	target = string(rest[1 : 1+lt])
	return typ, nonce, sender, target, true
}
