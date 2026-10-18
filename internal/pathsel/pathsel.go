// Package pathsel decides how this node reaches every other node: directly,
// or through a relay (a node with a public endpoint, usually a VPS).
//
// WireGuard drops packets whose source IP is not in the AllowedIPs of the
// peer they arrived from, so both ends of a pair must agree on the path. The
// rules below are designed so they do, using only data both sides have:
//
//   - A pair is direct if either side can reach the other's endpoint. The
//     side that can probes continuously; the other side sees those probes
//     ("inbound direct") and goes direct too, letting WireGuard learn the
//     endpoint from the handshake.
//   - Otherwise the pair uses the home relay of its anchor node (the more
//     mobile of the two, ties broken by ID). Every node publishes its home
//     relay in its Status record, so both sides pick the same relay.
//
// The same code runs on Linux nodes and inside the mobile apps.
package pathsel

import (
	"sort"
	"time"

	"github.com/heresjohnny320/meshgate/internal/model"
)

// Tunables.
const (
	ProbeFresh   = 10 * time.Second // a probe success counts this long
	InboundFresh = 12 * time.Second // peer probes keep us direct this long
	switchRatio  = 0.75             // new path must be 25% faster...
	switchMinGap = 8 * time.Millisecond
)

// Probe is the latest result for one endpoint.
type Probe struct {
	LastOK time.Time
	RTT    time.Duration
}

// Path says how to reach one peer.
type Path struct {
	Via      string `json:"via,omitempty"`      // relay node ID; "" = direct
	Endpoint string `json:"endpoint,omitempty"` // "" = learn from handshake
}

// Direct reports whether the path is direct.
func (p Path) Direct() bool { return p.Via == "" }

// Result is the full decision for this node.
type Result struct {
	HomeRelay string          `json:"home_relay,omitempty"`
	Paths     map[string]Path `json:"paths"`
	// Up marks peers that answered probes recently (ours to them, or theirs
	// to us). Relays always get a direct Path, so this is what tells a dead
	// relay or exit node apart.
	Up map[string]bool `json:"-"`
}

// Input is everything the decision depends on.
type Input struct {
	Self     model.Node
	Nodes    []model.Node
	Statuses map[string]model.Status
	// Probes: endpoint "host:port" (WireGuard endpoint) -> result.
	Probes map[string]Probe
	// Inbound: peer node ID -> last time it probed us directly.
	Inbound map[string]time.Time
	Prev    *Result
	Now     time.Time
}

// Decide computes paths for every peer.
func Decide(in Input) Result {
	byID := map[string]model.Node{}
	var relays []model.Node
	for _, n := range in.Nodes {
		byID[n.ID] = n
		if n.ID != in.Self.ID && IsRelay(n) {
			relays = append(relays, n)
		}
	}
	sort.Slice(relays, func(i, j int) bool { return relays[i].ID < relays[j].ID })

	res := Result{Paths: map[string]Path{}, Up: map[string]bool{}}
	if !IsRelay(in.Self) {
		res.HomeRelay = pickHomeRelay(in, relays)
	}

	for _, p := range in.Nodes {
		if p.ID == in.Self.ID {
			continue
		}
		res.Paths[p.ID] = decideOne(in, byID, relays, res.HomeRelay, p)
		up := in.Now.Sub(in.Inbound[p.ID]) < InboundFresh
		for _, ep := range p.Endpoints {
			if pr, ok := in.Probes[ep]; ok && in.Now.Sub(pr.LastOK) <= ProbeFresh {
				up = true
			}
		}
		res.Up[p.ID] = up
	}
	return res
}

// IsRelay reports whether n can act as a relay.
func IsRelay(n model.Node) bool {
	return n.Relay && n.Kind == model.NodeServer && len(n.Endpoints) > 0
}

func decideOne(in Input, byID map[string]model.Node, relays []model.Node, homeRelay string, p model.Node) Path {
	var prev *Path
	if in.Prev != nil {
		if pp, ok := in.Prev.Paths[p.ID]; ok {
			prev = &pp
		}
	}
	ep := bestEndpoint(in, p, prev)

	switch {
	case IsRelay(p):
		// Relays are always reached directly at their public endpoint.
		if ep == "" {
			ep = p.Endpoints[0]
		}
		return Path{Endpoint: ep}
	case p.Kind == model.NodeStatic:
		// Stock WireGuard app: only ever talks to its pinned relay.
		if p.ViaRelay == in.Self.ID {
			return Path{}
		}
		if _, ok := byID[p.ViaRelay]; ok {
			return Path{Via: p.ViaRelay}
		}
		return Path{}
	case IsRelay(in.Self):
		// We are a relay: everyone who is not pinned elsewhere talks to us
		// directly, and we learn roaming endpoints from handshakes.
		return Path{Endpoint: ep}
	case ep != "":
		return Path{Endpoint: ep}
	case in.Now.Sub(in.Inbound[p.ID]) < InboundFresh:
		return Path{} // peer reaches us directly; endpoint comes from handshake
	case len(relays) == 0:
		// No relays configured: best effort direct.
		if len(p.Endpoints) > 0 {
			return Path{Endpoint: p.Endpoints[0]}
		}
		return Path{}
	}

	relay := homeRelay
	if anchor := Anchor(in.Self, p); anchor.ID != in.Self.ID {
		if st, ok := in.Statuses[anchor.ID]; ok && st.HomeRelay != "" {
			relay = st.HomeRelay
		}
	}
	if r, ok := byID[relay]; !ok || !IsRelay(r) {
		relay = homeRelay
	}
	return Path{Via: relay}
}

// Anchor returns the node of the pair whose home relay the pair uses: the
// more mobile node (client before server), then the lower ID.
func Anchor(a, b model.Node) model.Node {
	ra, rb := mobility(a), mobility(b)
	if ra != rb {
		if ra > rb {
			return a
		}
		return b
	}
	if a.ID < b.ID {
		return a
	}
	return b
}

func mobility(n model.Node) int {
	if n.Kind == model.NodeClient {
		return 1
	}
	return 0
}

// bestEndpoint returns the fastest freshly-probed endpoint of p, or "".
func bestEndpoint(in Input, p model.Node, prev *Path) string {
	best, bestRTT := "", time.Duration(0)
	for _, ep := range p.Endpoints {
		pr, ok := in.Probes[ep]
		if !ok || in.Now.Sub(pr.LastOK) > ProbeFresh {
			continue
		}
		if best == "" || pr.RTT < bestRTT {
			best, bestRTT = ep, pr.RTT
		}
	}
	// Stick with the previous endpoint unless the new one is clearly better.
	if prev != nil && prev.Direct() && prev.Endpoint != "" && prev.Endpoint != best && best != "" {
		if pr, ok := in.Probes[prev.Endpoint]; ok && in.Now.Sub(pr.LastOK) <= ProbeFresh {
			if !clearlyBetter(bestRTT, pr.RTT) {
				return prev.Endpoint
			}
		}
	}
	return best
}

func pickHomeRelay(in Input, relays []model.Node) string {
	if len(relays) == 0 {
		return ""
	}
	type cand struct {
		id  string
		rtt time.Duration
	}
	var ok []cand
	rttOf := map[string]time.Duration{}
	for _, r := range relays {
		best := time.Duration(-1)
		for _, ep := range r.Endpoints {
			pr, has := in.Probes[ep]
			if !has || in.Now.Sub(pr.LastOK) > ProbeFresh {
				continue
			}
			if best < 0 || pr.RTT < best {
				best = pr.RTT
			}
		}
		if best >= 0 {
			ok = append(ok, cand{r.ID, best})
			rttOf[r.ID] = best
		}
	}
	prev := ""
	if in.Prev != nil {
		prev = in.Prev.HomeRelay
	}
	if len(ok) == 0 {
		// Nothing answers right now; keep what we had rather than flapping.
		for _, r := range relays {
			if r.ID == prev {
				return prev
			}
		}
		return relays[0].ID
	}
	sort.Slice(ok, func(i, j int) bool {
		if ok[i].rtt != ok[j].rtt {
			return ok[i].rtt < ok[j].rtt
		}
		return ok[i].id < ok[j].id
	})
	best := ok[0]
	if prevRTT, alive := rttOf[prev]; alive && prev != best.id && !clearlyBetter(best.rtt, prevRTT) {
		return prev
	}
	return best.id
}

func clearlyBetter(newRTT, oldRTT time.Duration) bool {
	return float64(newRTT) < float64(oldRTT)*switchRatio && oldRTT-newRTT >= switchMinGap
}
