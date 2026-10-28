package tui

import (
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/heresjohnny320/meshgate/internal/diag"
	"github.com/heresjohnny320/meshgate/internal/events"
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

func TestParityTabs(t *testing.T) {
	m := &model_{theme: "default", v: ops.View{
		SelfID: "a",
		Nodes: []ops.Item[model.Node]{
			{Value: model.Node{ID: "a", Name: "vps", Kind: model.NodeServer, MeshIP: "100.88.0.1"}},
			{Value: model.Node{ID: "b", Name: "home", Kind: model.NodeServer, MeshIP: "100.88.0.2", Routes: []string{"192.168.1.0/24"}}},
		},
		Monitors: []ops.Item[model.Monitor]{{Value: model.Monitor{ID: "m", Name: "survival", Node: "a", IP: "192.168.1.51", Ports: "25566", Proto: "tcp"}}},
		Statuses: map[string]model.Status{"b": {LANs: []model.LAN{{Iface: "igb1", CIDR: "192.168.1.0/24"}, {Iface: "igb1.90", CIDR: "192.168.90.0/24"}, {Iface: "docker0", CIDR: "172.17.0.0/16"}}}},
	}}
	key := func(s string) {
		switch s {
		case "enter":
			m.Update(tea.KeyMsg{Type: tea.KeyEnter})
		case "esc":
			m.Update(tea.KeyMsg{Type: tea.KeyEsc})
		case "ctrl+s":
			m.Update(tea.KeyMsg{Type: tea.KeyCtrlS})
		default:
			m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)})
		}
	}

	// "0" is SETTINGS; CHANGES is past the number keys.
	key("0")
	if m.tab != tabSettings {
		t.Fatalf("0 went to tab %d", m.tab)
	}

	// TRAFFIC (live): the monitor row edits the monitor.
	m.tab, m.sel = tabTraffic, 1
	key("e")
	if m.form == nil || m.form.title != "Edit monitor survival" {
		t.Fatalf("monitor form not opened: %+v", m.form)
	}
	key("esc")
	if got := m.selectedLabel(); got != "monitor survival" {
		t.Fatalf("remove prompt names %q", got)
	}
	m.sel = 0 // the section header: nothing to edit
	key("e")
	if m.form != nil {
		t.Fatal("header row opened a form")
	}

	// TOOLS: a check runs in the background after the form closes.
	m.tab, m.sel = tabTools, 1
	key("enter")
	if m.form == nil {
		t.Fatal("check form not opened")
	}
	key("ctrl+s")
	if m.form != nil || !strings.Contains(m.note, "Running ping") {
		t.Fatalf("check did not start: form=%v note=%q", m.form, m.note)
	}
	m.Update(diagMsg{res: diag.Result{OK: true, Output: "64 bytes from 100.88.0.2"}})
	if !strings.Contains(m.note, "64 bytes") {
		t.Fatalf("result not shown: %q", m.note)
	}
	key("x") // any key closes the note

	// SETTINGS: the admin password is never shown.
	m.tab = tabSettings
	for i, r := range m.settingRows() {
		if r.label == "Web UI admin login" {
			m.sel = i
		}
	}
	key("enter")
	if m.form == nil {
		t.Fatal("admin form not opened")
	}
	key("enter") // to the password field
	for _, r := range "hunter22" {
		key(string(r))
	}
	if out := m.View(); strings.Contains(out, "hunter22") {
		t.Fatal("password shown in clear text")
	}
	key("esc")

	// LOGS: lines still in RAM come first and are marked; Enter shows one.
	m.tab, m.sel = tabLogs, 0
	m.logs = &logsResp{Server: "vps", Node: "a",
		Pending: []events.Entry{{T: 1800000300, Node: "a", Text: "link to home DOWN: no WireGuard handshake"}},
		Entries: []events.Entry{{T: 1800000000, Node: "b", Text: "link to vps UP again after 1m0s"}}}
	if rows := m.logRows(); len(rows) != 2 || !rows[0].ram || rows[1].ram {
		t.Fatalf("log rows: %+v", rows)
	}
	if out := m.View(); !strings.Contains(out, "RAM") || !strings.Contains(out, "waiting in RAM") {
		t.Fatal("RAM lines not marked")
	}
	key("enter")
	if !strings.Contains(m.note, "not delivered yet") || !strings.Contains(m.note, "DOWN") {
		t.Fatalf("note: %q", m.note)
	}
	key("x")
	// Log server unreachable: this node's RAM is what there is.
	m.logs = &logsResp{Error: "log server vps is not reachable", Recent: m.logs.Pending, Pending: m.logs.Pending}
	if rows := m.logRows(); len(rows) != 1 || !rows[0].ram {
		t.Fatalf("offline rows: %+v", rows)
	}
	key("i")
	key("f")
	if !m.logImp || m.logNode != "a" || !strings.Contains(m.logsQuery(), "important=1") || !strings.Contains(m.logsQuery(), "node=a") {
		t.Fatalf("filters: important=%v node=%q q=%s", m.logImp, m.logNode, m.logsQuery())
	}

	// B: one node's full log file, newest first, searchable.
	m.logNode, m.logText = "", ""
	key("b")
	if !m.logFile || !strings.Contains(m.rawQuery(), "node=a") {
		t.Fatalf("file view: %v %s", m.logFile, m.rawQuery())
	}
	m.raw = &rawResp{Node: "a", Source: "journalctl -u meshgate", Lines: []string{
		"Oct 27 18:49:50 systemd[1]: Stopping meshgate.service", "Oct 27 18:49:53 meshgate v0.2.28: node vps", "Oct 27 18:50:01 http: TLS handshake error"}}
	if rows := m.rawRows(); len(rows) != 3 || !strings.Contains(rows[0], "TLS") {
		t.Fatalf("raw rows: %v", rows)
	}
	m.logText = "meshgate"
	if rows := m.rawRows(); len(rows) != 2 {
		t.Fatalf("search: %v", rows)
	}
	key("f") // a file belongs to one node: never "all"
	if m.logNode == "" {
		t.Fatal("file view switched to all nodes")
	}
	key("b")
	if m.logFile {
		t.Fatal("B did not go back to the event log")
	}

	// NODES: detected subnets skip what is shared and container bridges.
	if got := m.detectedSubnets(m.v.Nodes[1].Value); len(got) != 1 || got[0] != "192.168.90.0/24" {
		t.Fatalf("detected %v", got)
	}
}
