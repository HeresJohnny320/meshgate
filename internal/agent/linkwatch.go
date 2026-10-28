package agent

import (
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/heresjohnny320/meshgate/internal/model"
	"github.com/heresjohnny320/meshgate/internal/pathsel"
	"github.com/heresjohnny320/meshgate/internal/probe"
	"github.com/heresjohnny320/meshgate/internal/wg"
)

// linkDeadAfter: WireGuard renews a session every 2 minutes and drops it
// after 3; a direct link with no handshake for that long carries nothing.
const linkDeadAfter = 3 * time.Minute

// linkWatch leaves a trace in the log (journalctl -u meshgate,
// /var/log/meshgate.log on pfSense) when a link to another server drops,
// comes back or changes path, and when warnings appear or clear. Without it
// a dead tunnel was silent.
type linkWatch struct {
	down    map[string]time.Time // node ID -> when we noticed
	path    map[string]string    // node ID -> "direct" / "via <relay>"
	warn    map[string]bool
	checked time.Time
}

// watchLinks runs at the end of every reconcile (a.mu held).
func (a *Agent) watchLinks(nodes []model.Node, res pathsel.Result, warn []string) {
	lw := &a.links
	now := time.Now()
	if lw.down == nil {
		lw.down, lw.path, lw.warn = map[string]time.Time{}, map[string]string{}, map[string]bool{}
	}

	cur := map[string]bool{}
	for _, w := range warn {
		cur[w] = true
		if !lw.warn[w] {
			log.Printf("warning: %s", w)
		}
	}
	for w := range lw.warn {
		if !cur[w] {
			log.Printf("resolved: %s", w)
		}
	}
	lw.warn = cur

	// Handshakes change slowly; reading them (`wg show` on pfSense) every
	// 15 seconds is plenty.
	if now.Sub(lw.checked) < 15*time.Second {
		return
	}
	lw.checked = now
	names := map[string]string{}
	var self model.Node
	for _, n := range nodes {
		names[n.ID] = n.Name
		if n.ID == a.Cfg.NodeID {
			self = n
		}
	}
	stats := a.wg.Stats()
	for _, n := range nodes {
		if n.ID == a.Cfg.NodeID || n.Kind != model.NodeServer {
			continue // phones come and go; only server links are watched
		}
		p, ok := res.Paths[n.ID]
		if !ok {
			continue
		}
		path := "direct"
		if !p.Direct() {
			path = "via " + names[p.Via]
		}
		if old, seen := lw.path[n.ID]; seen && old != path {
			log.Printf("path to %s: %s -> %s", n.Name, old, path)
		}
		lw.path[n.ID] = path
		if !p.Direct() {
			delete(lw.down, n.ID) // no tunnel of our own to it
			continue
		}
		msg, dead := linkState(stats[n.PublicKey], res.Up[n.ID], now, now.Sub(a.startedAt))
		since, wasDown := lw.down[n.ID]
		switch {
		case dead && !wasDown:
			lw.down[n.ID] = now
			log.Printf("link to %s DOWN: %s", n.Name, msg)
			a.beepFor(self, true)
		case !dead && wasDown:
			delete(lw.down, n.ID)
			log.Printf("link to %s UP again after %s", n.Name, now.Sub(since).Round(time.Second))
			a.beepFor(self, false)
		}
	}
}

// linkState decides whether a direct link is dead and says why. probesOK:
// the peer's meshgate answered path probes recently (outside the tunnel).
func linkState(st wg.PeerStat, probesOK bool, now time.Time, running time.Duration) (string, bool) {
	if running < linkDeadAfter {
		return "", false // give the first handshake time after a start
	}
	hs := st.LastHandshake
	if !hs.IsZero() && now.Sub(hs) <= linkDeadAfter {
		return "", false
	}
	msg := "no WireGuard handshake"
	if hs.IsZero() {
		msg += " since meshgate started"
	} else {
		msg += " since " + hs.Format("15:04:05") + " (" + now.Sub(hs).Round(time.Second).String() + " ago)"
	}
	if st.Endpoint != "" {
		msg += ", endpoint " + st.Endpoint
	}
	if probesOK {
		msg += "; its meshgate still answers probes, so the tunnel itself is broken (interface, keys or port)"
	} else {
		msg += "; it does not answer probes either (offline, or the path to it is blocked)"
	}
	return msg, true
}

// tunnelID names this node's WireGuard interface instance for the probes'
// boot ID. Peers drop their sessions with us when it changes, so it changes
// only when the interface (and its sessions) is new, not when meshgate merely
// restarted and took over the running one.
func (a *Agent) tunnelID(created bool) string {
	path := filepath.Join(a.Cfg.DataDir, "tunnel-id")
	if !created {
		if b, err := os.ReadFile(path); err == nil && len(strings.TrimSpace(string(b))) > 0 {
			return strings.TrimSpace(string(b))
		}
	}
	id := probe.NewBootID()
	os.WriteFile(path, []byte(id+"\n"), 0o600)
	return id
}
