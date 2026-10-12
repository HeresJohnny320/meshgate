package tui

import (
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/heresjohnny320/meshgate/internal/model"
	"github.com/heresjohnny320/meshgate/internal/ops"
)

func TestViewsRender(t *testing.T) {
	m := &model_{v: ops.View{
		SelfID:  "a",
		Network: model.Network{CIDR: "100.88.0.0/16"},
		Nodes: []ops.Item[model.Node]{
			{Value: model.Node{ID: "a", Name: "vps", Kind: model.NodeServer, Relay: true, MeshIP: "100.88.0.1", Endpoints: []string{"1.2.3.4:51820"}}},
			{Value: model.Node{ID: "b", Name: "home", Kind: model.NodeServer, MeshIP: "100.88.0.2"}, Local: true},
		},
		Forwards: []ops.Item[model.Forward]{{Value: model.Forward{ID: "f", Name: "minecraft", Proto: "tcp", EdgeNode: "a", ListenPort: 25565, TargetNode: "b", TargetPort: 25565, Enabled: true}}},
		Runtime:  ops.Runtime{Peers: map[string]ops.PeerRuntime{"b": {Path: "direct", LastHandshake: time.Now()}}},
	}}
	for tab := range tabs {
		m.tab = tab
		if out := m.View(); !strings.Contains(out, "MESHGATE") {
			t.Fatalf("tab %d did not render", tab)
		}
	}
	m.tab = 1
	m.forwardForm(&m.v.Forwards[0])
	if !strings.Contains(m.View(), "Apply to") || !strings.Contains(m.View(), "EDIT FORWARD") {
		t.Fatal("form missing scope choice")
	}
	// Navigate and toggle without panicking.
	for _, k := range []string{"tab", "tab", "right", "down", " ", "shift+tab", "esc"} {
		var msg tea.KeyMsg
		switch k {
		case "tab":
			msg = tea.KeyMsg{Type: tea.KeyTab}
		case "shift+tab":
			msg = tea.KeyMsg{Type: tea.KeyShiftTab}
		case "right":
			msg = tea.KeyMsg{Type: tea.KeyRight}
		case "down":
			msg = tea.KeyMsg{Type: tea.KeyDown}
		case "esc":
			msg = tea.KeyMsg{Type: tea.KeyEsc}
		default:
			msg = tea.KeyMsg{Type: tea.KeySpace, Runes: []rune(" ")}
		}
		m.Update(msg)
	}
	if m.form != nil {
		t.Fatal("esc did not close the form")
	}
}
