package agent

import (
	"bytes"
	"log"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/heresjohnny320/meshgate/internal/config"
	"github.com/heresjohnny320/meshgate/internal/model"
	"github.com/heresjohnny320/meshgate/internal/pathsel"
	"github.com/heresjohnny320/meshgate/internal/wg"
)

func TestLinkState(t *testing.T) {
	now := time.Now()
	if _, dead := linkState(wg.PeerStat{}, false, now, time.Minute); dead {
		t.Error("reported down right after start")
	}
	if _, dead := linkState(wg.PeerStat{LastHandshake: now.Add(-90 * time.Second)}, true, now, time.Hour); dead {
		t.Error("a 90s old handshake is a live link")
	}
	msg, dead := linkState(wg.PeerStat{LastHandshake: now.Add(-10 * time.Minute), Endpoint: "50.70.64.41:51830"}, true, now, time.Hour)
	if !dead || !strings.Contains(msg, "10m0s ago") || !strings.Contains(msg, "50.70.64.41:51830") || !strings.Contains(msg, "tunnel itself is broken") {
		t.Errorf("dead link: %v %q", dead, msg)
	}
	if msg, _ := linkState(wg.PeerStat{}, false, now, time.Hour); !strings.Contains(msg, "since meshgate started") || !strings.Contains(msg, "does not answer probes") {
		t.Errorf("never handshaked: %q", msg)
	}
}

func TestWatchLinksLogs(t *testing.T) {
	var out bytes.Buffer
	log.SetOutput(&out)
	defer log.SetOutput(os.Stderr)
	nodes := []model.Node{
		{ID: "vps", Name: "vps", Kind: model.NodeServer},
		{ID: "home", Name: "pfsense", Kind: model.NodeServer, PublicKey: "k"},
		{ID: "relay2", Name: "vps2", Kind: model.NodeServer},
		{ID: "phone", Name: "phone", Kind: model.NodeClient},
	}
	// No handshake stats (interface never up here) and running for a while:
	// the direct link to pfsense is down; the phone is never watched.
	a := &Agent{Cfg: config.Node{NodeID: "vps"}, wg: wg.New("mgtest0", [32]byte{}), startedAt: time.Now().Add(-time.Hour)}
	res := pathsel.Result{Paths: map[string]pathsel.Path{"home": {}, "relay2": {}, "phone": {}}, Up: map[string]bool{"home": true}}
	a.watchLinks(nodes, res, []string{"route x advertised twice"})
	got := out.String()
	for _, want := range []string{"link to pfsense DOWN", "tunnel itself is broken", "warning: route x advertised twice"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in\n%s", want, got)
		}
	}
	if strings.Contains(got, "phone") {
		t.Errorf("phones are not watched:\n%s", got)
	}

	// Next pass: pfsense moves to a relay (no own tunnel, no longer "down"),
	// the warning clears. Nothing is logged twice.
	out.Reset()
	a.links.checked = time.Time{}
	res.Paths["home"] = pathsel.Path{Via: "relay2"}
	a.watchLinks(nodes, res, nil)
	got = out.String()
	for _, want := range []string{"path to pfsense: direct -> via vps2", "resolved: route x advertised twice"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in\n%s", want, got)
		}
	}
	if strings.Count(got, "DOWN") != 0 {
		t.Errorf("down logged again:\n%s", got)
	}
}
