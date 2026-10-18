// Package tui is the terminal UI. It talks to the local agent, so it works
// on any node even when the web UI host is offline. Every edit asks whether
// to apply it to all nodes (replicated) or only to this node (local override).
package tui

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	qrcode "github.com/skip2/go-qrcode"

	"github.com/heresjohnny320/meshgate/internal/join"
	"github.com/heresjohnny320/meshgate/internal/localapi"
	"github.com/heresjohnny320/meshgate/internal/model"
	"github.com/heresjohnny320/meshgate/internal/ops"
)

var tabs = []string{"NODES", "FORWARDS", "HTTPS", "RULES", "EXITS", "DEVICES"}

const (
	tabNodes = iota
	tabForwards
	tabHTTPS
	tabRules
	tabExits
	tabDevices
)

type viewMsg struct {
	v   ops.View
	err error
}
type tickMsg struct{}

type model_ struct {
	api     *localapi.Client
	v       ops.View
	err     error
	tab     int
	sel     int
	form    *form
	note    string // modal text (token, config), shown until a key is pressed
	message string // status line under the list
	confirm string // pending "remove?" question
	theme   string
	width   int
	height  int
}

// Run starts the TUI.
func Run(socket string) error {
	t := loadTheme()
	applyTheme(t)
	m := &model_{api: localapi.New(socket), theme: t.name}
	_, err := tea.NewProgram(m, tea.WithAltScreen()).Run()
	return err
}

func (m *model_) Init() tea.Cmd { return tea.Batch(m.load(), tick()) }

func tick() tea.Cmd {
	return tea.Tick(3*time.Second, func(time.Time) tea.Msg { return tickMsg{} })
}

func (m *model_) load() tea.Cmd {
	return func() tea.Msg {
		v, err := m.api.View()
		return viewMsg{v, err}
	}
}

func (m *model_) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		return m, nil
	case viewMsg:
		m.v, m.err = msg.v, msg.err
		if n := m.rows(); m.sel >= n {
			m.sel = max(0, n-1)
		}
		return m, nil
	case tickMsg:
		return m, tea.Batch(m.load(), tick())
	}

	if m.form != nil {
		closed, cmd := m.form.update(msg)
		if closed {
			m.form = nil
			return m, m.load()
		}
		return m, cmd
	}
	km, ok := msg.(tea.KeyMsg)
	if !ok {
		return m, nil
	}
	if m.note != "" {
		m.note = ""
		return m, nil
	}
	key := strings.ToLower(km.String())
	if m.confirm != "" {
		m.confirm = ""
		if key == "y" {
			m.deleteItem()
			return m, m.load()
		}
		m.message = "Nothing removed."
		return m, nil
	}
	m.message = ""
	switch key {
	case "q", "ctrl+c":
		return m, tea.Quit
	case "tab", "right", "l":
		m.tab, m.sel = (m.tab+1)%len(tabs), 0
	case "shift+tab", "left", "h":
		m.tab, m.sel = (m.tab-1+len(tabs))%len(tabs), 0
	case "1", "2", "3", "4", "5", "6":
		m.tab, m.sel = int(key[0]-'1'), 0
	case "up", "k":
		if m.sel > 0 {
			m.sel--
		}
	case "down", "j":
		if m.sel < m.rows()-1 {
			m.sel++
		}
	case "home", "g":
		m.sel = 0
	case "end":
		m.sel = max(0, m.rows()-1)
	case "r":
		return m, m.load()
	case "a", "n":
		m.newItem()
	case "e", "enter":
		m.editItem()
	case "t", " ":
		m.toggleItem()
		return m, m.load()
	case "u":
		if m.tab == tabNodes && m.rows() > 0 {
			n := m.v.Nodes[m.sel].Value
			var out struct{ Message string }
			if err := m.api.Post("update", map[string]string{"node": n.ID}, &out); err != nil {
				m.message = "Error: " + err.Error()
			} else {
				m.message = out.Message
			}
		}
	case "d", "delete", "x":
		if label := m.selectedLabel(); label != "" {
			m.confirm = "Remove " + label + "?"
		}
	case "c":
		m.clearLocal()
		return m, m.load()
	case "w":
		m.staticForm()
	case "s":
		m.settingsForm()
	case "y":
		t := nextTheme(m.theme)
		applyTheme(t)
		m.theme = t.name
		saveTheme(t.name)
		m.message = "Theme: " + t.label + " (saved)"
	}
	return m, nil
}

// selectedLabel names the selected item for the remove prompt.
func (m *model_) selectedLabel() string {
	if m.rows() == 0 {
		return ""
	}
	switch m.tab {
	case tabNodes:
		if m.v.Nodes[m.sel].Value.ID == m.v.SelfID {
			m.message = "This is the node you are on; run `meshgate leave` here to remove it."
			return ""
		}
		return "node " + m.v.Nodes[m.sel].Value.Name
	case tabForwards:
		return "forward " + labelOr(m.v.Forwards[m.sel].Value.Name)
	case tabHTTPS:
		return "HTTPS route " + m.v.Routes[m.sel].Value.Hostname
	case tabRules:
		return "rule " + labelOr(m.v.ACLs[m.sel].Value.Name)
	case tabExits:
		return "exit route " + labelOr(m.v.ExitRoutes[m.sel].Value.Name)
	case tabDevices:
		return "token " + m.v.Tokens[m.sel].ID
	}
	return ""
}

func labelOr(name string) string {
	if name == "" {
		return "(unnamed)"
	}
	return name
}

// toggleItem switches the selected forward, route or rule on or off.
func (m *model_) toggleItem() {
	if m.rows() == 0 {
		return
	}
	var kind, id, what string
	var on bool
	switch m.tab {
	case tabForwards:
		f := m.v.Forwards[m.sel].Value
		kind, id, on, what = model.KindForward, f.ID, f.Enabled, "Forward "+labelOr(f.Name)
	case tabHTTPS:
		r := m.v.Routes[m.sel].Value
		kind, id, on, what = model.KindRoute, r.ID, r.Enabled, "Route "+r.Hostname
	case tabRules:
		a := m.v.ACLs[m.sel].Value
		kind, id, on, what = model.KindACL, a.ID, a.Enabled, "Rule "+labelOr(a.Name)
	case tabExits:
		r := m.v.ExitRoutes[m.sel].Value
		kind, id, on, what = model.KindExitRoute, r.ID, r.Enabled, "Exit route "+labelOr(r.Name)
	default:
		return
	}
	if err := m.api.Post("toggle", map[string]any{"kind": kind, "id": id, "enabled": !on}, nil); err != nil {
		m.message = "Error: " + err.Error()
		return
	}
	if on {
		m.message = what + " disabled."
		if kind == model.KindForward {
			m.message += " Its public port is now blocked."
		}
	} else {
		m.message = what + " enabled."
	}
}

func (m *model_) rows() int {
	switch m.tab {
	case tabNodes:
		return len(m.v.Nodes)
	case tabForwards:
		return len(m.v.Forwards)
	case tabHTTPS:
		return len(m.v.Routes)
	case tabRules:
		return len(m.v.ACLs)
	case tabExits:
		return len(m.v.ExitRoutes)
	case tabDevices:
		return len(m.v.Tokens)
	}
	return 0
}

func (m *model_) name(id string) string {
	for _, n := range m.v.Nodes {
		if n.Value.ID == id {
			return n.Value.Name
		}
	}
	return id
}

func (m *model_) serverOptions() []option {
	var o []option
	for _, n := range m.v.Nodes {
		if n.Value.Kind == model.NodeServer {
			o = append(o, option{n.Value.Name, n.Value.ID})
		}
	}
	return o
}

func (m *model_) relayOptions() []option {
	var o []option
	for _, n := range m.v.Nodes {
		if n.Value.Relay && len(n.Value.Endpoints) > 0 {
			o = append(o, option{n.Value.Name, n.Value.ID})
		}
	}
	return o
}

// exitOptions lists exit nodes a device can send its internet traffic through.
func (m *model_) exitOptions(self string) []option {
	o := []option{{"its own connection", ""}}
	for _, n := range m.v.Nodes {
		if n.Value.Exit && n.Value.ID != self {
			o = append(o, option{"through " + n.Value.Name, n.Value.ID})
		}
	}
	return o
}

func scopeOptions(self string) []option {
	return []option{{"all nodes", "cluster"}, {"only this node (" + self + ")", "local"}}
}

func scopeOf(local bool) string {
	if local {
		return "local"
	}
	return "cluster"
}

func atoi(s string) int { n, _ := strconv.Atoi(strings.TrimSpace(s)); return n }

func lines(s string) []string {
	var out []string
	for _, p := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' }) {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// ---------- actions ----------

func (m *model_) newItem() {
	switch m.tab {
	case tabForwards:
		m.forwardForm(nil)
	case tabHTTPS:
		m.routeForm(nil)
	case tabRules:
		m.aclForm(nil)
	case tabExits:
		m.exitRouteForm(nil)
	case tabDevices:
		m.tokenForm()
	}
}

func (m *model_) editItem() {
	if m.rows() == 0 {
		return
	}
	switch m.tab {
	case tabNodes:
		m.nodeForm(m.v.Nodes[m.sel])
	case tabForwards:
		it := m.v.Forwards[m.sel]
		m.forwardForm(&it)
	case tabHTTPS:
		it := m.v.Routes[m.sel]
		m.routeForm(&it)
	case tabRules:
		it := m.v.ACLs[m.sel]
		m.aclForm(&it)
	case tabExits:
		it := m.v.ExitRoutes[m.sel]
		m.exitRouteForm(&it)
	}
}

func (m *model_) deleteItem() {
	if m.rows() == 0 {
		return
	}
	var kind, id string
	switch m.tab {
	case tabNodes:
		kind, id = model.KindNode, m.v.Nodes[m.sel].Value.ID
	case tabForwards:
		kind, id = model.KindForward, m.v.Forwards[m.sel].Value.ID
	case tabHTTPS:
		kind, id = model.KindRoute, m.v.Routes[m.sel].Value.ID
	case tabRules:
		kind, id = model.KindACL, m.v.ACLs[m.sel].Value.ID
	case tabExits:
		kind, id = model.KindExitRoute, m.v.ExitRoutes[m.sel].Value.ID
	case tabDevices:
		kind, id = model.KindToken, m.v.Tokens[m.sel].ID
	}
	if err := m.api.Post("delete", map[string]string{"kind": kind, "id": id, "scope": "cluster"}, nil); err != nil {
		m.message = "Error: " + err.Error()
	} else {
		m.message = "Removed."
	}
}

func (m *model_) clearLocal() {
	var kind, id string
	switch {
	case m.tab == tabNodes && m.rows() > 0:
		kind, id = model.KindNode, m.v.Nodes[m.sel].Value.ID
	case m.tab == tabForwards && m.rows() > 0:
		kind, id = model.KindForward, m.v.Forwards[m.sel].Value.ID
	case m.tab == tabHTTPS && m.rows() > 0:
		kind, id = model.KindRoute, m.v.Routes[m.sel].Value.ID
	case m.tab == tabRules && m.rows() > 0:
		kind, id = model.KindACL, m.v.ACLs[m.sel].Value.ID
	case m.tab == tabExits && m.rows() > 0:
		kind, id = model.KindExitRoute, m.v.ExitRoutes[m.sel].Value.ID
	default:
		return
	}
	if err := m.api.Post("clear-local", map[string]string{"kind": kind, "id": id}, nil); err != nil {
		m.message = "Error: " + err.Error()
	} else {
		m.message = "Local override removed; the all-nodes value applies again."
	}
}

func (m *model_) forwardForm(it *ops.Item[model.Forward]) {
	f := model.Forward{Proto: model.ProtoTCP, Enabled: true}
	title := "New port forward"
	local := false
	if it != nil {
		f, local, title = it.Value, it.Local, "Edit forward "+it.Value.Name
	}
	servers := m.serverOptions()
	end := ""
	if f.ListenEnd > 0 {
		end = strconv.Itoa(f.ListenEnd)
	}
	m.form = newForm(title, func(v map[string]string) error {
		nf := model.Forward{
			ID: f.ID, Name: v["name"], Proto: model.Proto(v["proto"]), EdgeNode: v["edge"],
			ListenPort: atoi(v["listen"]), ListenEnd: atoi(v["end"]), TargetNode: v["target"],
			TargetIP: v["target_ip"], TargetPort: atoi(v["target_port"]),
			PreserveClientIP: v["preserve"] == "true", Enabled: v["enabled"] == "true",
		}
		return m.api.Post("forward", map[string]any{"forward": nf, "scope": v["scope"]}, nil)
	}).
		text("name", "Name", f.Name, "minecraft").
		choice("proto", "Protocol", []option{{"tcp", "tcp"}, {"udp", "udp"}, {"tcp+udp", "both"}}, string(f.Proto)).
		choice("edge", "Edge node (public)", servers, f.EdgeNode).
		text("listen", "Public port", itoa0(f.ListenPort), "25565").
		text("end", "…to port (range, optional)", end, "").
		choice("target", "Target node", servers, f.TargetNode).
		text("target_port", "Target port", itoa0(f.TargetPort), "25565").
		text("target_ip", "Target LAN IP (optional)", f.TargetIP, "empty = target node itself").
		toggle("preserve", "Show players' real IPs", f.PreserveClientIP).
		toggle("enabled", "Enabled", f.Enabled).
		choice("scope", "Apply to", scopeOptions(m.name(m.v.SelfID)), scopeOf(local)).init()
}

func (m *model_) routeForm(it *ops.Item[model.HTTPRoute]) {
	r := model.HTTPRoute{ForceHTTPS: true, Enabled: true}
	title := "New HTTPS route"
	local := false
	if it != nil {
		r, local, title = it.Value, it.Local, "Edit route "+it.Value.Hostname
	}
	servers := m.serverOptions()
	m.form = newForm(title, func(v map[string]string) error {
		nr := model.HTTPRoute{
			ID: r.ID, Hostname: v["host"], EdgeNode: v["edge"], TargetNode: v["target"],
			TargetIP: v["target_ip"], TargetPort: atoi(v["port"]), TargetTLS: v["tls"] == "true",
			ForceHTTPS: v["force"] == "true", Enabled: v["enabled"] == "true",
		}
		return m.api.Post("route", map[string]any{"route": nr, "scope": v["scope"]}, nil)
	}).
		text("host", "Hostname", r.Hostname, "app.example.com").
		choice("edge", "Edge node (public)", servers, r.EdgeNode).
		choice("target", "Target node", servers, r.TargetNode).
		text("target_ip", "Target LAN IP (optional)", r.TargetIP, "").
		text("port", "Target port", itoa0(r.TargetPort), "8080").
		toggle("tls", "Backend uses HTTPS", r.TargetTLS).
		toggle("force", "Redirect HTTP to HTTPS", r.ForceHTTPS).
		toggle("enabled", "Enabled", r.Enabled).
		choice("scope", "Apply to", scopeOptions(m.name(m.v.SelfID)), scopeOf(local)).init()
}

func (m *model_) nodeForm(it ops.Item[model.Node]) {
	n := it.Value
	f := newForm("Edit node "+n.Name, func(v map[string]string) error {
		patch := map[string]any{"name": v["name"]}
		if n.Kind == model.NodeStatic {
			patch["via_relay"] = v["via"]
		} else if n.Kind == model.NodeClient {
			patch["exit_via"] = v["exit_via"]
			patch["exit_only"] = v["exit_only"] == "true"
			var allowed []string
			for _, name := range lines(v["exits_allowed"]) {
				if name == "*" || name == "any" {
					allowed = []string{"*"}
					break
				}
				for _, it := range m.v.Nodes {
					if strings.EqualFold(it.Value.Name, name) {
						allowed = append(allowed, it.Value.ID)
					}
				}
			}
			patch["exits_allowed"] = allowed
		} else if n.Kind == model.NodeServer {
			patch["endpoints"] = lines(v["endpoints"])
			patch["routes"] = lines(v["routes"])
			patch["relay"] = v["relay"] == "true"
			patch["exit"] = v["exit"] == "true"
			tp, _ := strconv.Atoi(strings.TrimSpace(v["test_port"]))
			patch["test_port"] = tp
			patch["app_admin"] = v["app_admin"] == "true"
			var le []model.LANExit
			for _, src := range lines(v["lan_exit_src"]) {
				le = append(le, model.LANExit{Src: src, Via: v["lan_exit_via"]})
			}
			patch["lan_exits"] = le
			patch["exit_only"] = v["exit_only"] == "true"
			patch["lan_policy"] = v["policy"]
		}
		return m.api.Post("node", map[string]any{"id": n.ID, "patch": patch, "scope": v["scope"]}, nil)
	}).text("name", "Name", n.Name, "")
	switch n.Kind {
	case model.NodeServer:
		f.text("endpoints", "Endpoints (host:port, comma)", strings.Join(n.Endpoints, ", "), "1.2.3.4:51820, 192.168.1.10:51820").
			text("routes", "Shared subnets (comma)", strings.Join(n.Routes, ", "), "192.168.1.0/24").
			toggle("relay", "Relay (public endpoint)", n.Relay).
			toggle("exit", "Exit node (devices may use it for internet)", n.Exit).
			text("test_port", "Test service port (empty = off)", itoa0(n.TestPort), "8099").
			toggle("app_admin", "Phone app may manage through this node", !n.AppAdminOff).
			text("lan_exit_src", "LAN devices via exit (IPs/subnets, comma)", lanExitSrcs(n), "192.168.1.205, 192.168.20.0/24").
			choice("lan_exit_via", "...through exit node", exitChoices(m.exitOptions(n.ID)[1:]), lanExitVia(n)).
			toggle("exit_only", "...exit only (block if no exit reachable)", n.ExitOnly).
			choice("policy", "LAN policy", []option{{"open: any mesh device", model.PolicyOpen}, {"restricted: rules only", model.PolicyRestricted}, {"firewall: pfSense rules decide", model.PolicyFirewall}}, policyOf(n))
	case model.NodeStatic:
		f.choice("via", "Connects through relay", m.relayOptions(), n.ViaRelay)
	case model.NodeClient:
		f.text("exits_allowed", "May use exits (names, comma; * = any)", m.exitNames(n.ExitsAllowed), "vps, vps2").
			choice("exit_via", "Default internet away from home", m.exitOptions(n.ID), n.ExitVia).
			toggle("exit_only", "Exit only (block if no exit reachable)", n.ExitOnly)
	}
	m.form = f.choice("scope", "Apply to", scopeOptions(m.name(m.v.SelfID)), scopeOf(it.Local)).init()
}

func policyOf(n model.Node) string {
	if n.Restricted() || n.FirewallManaged() {
		return n.LANPolicy
	}
	return model.PolicyOpen
}

// aclForm edits an access rule. Devices are entered by name, comma
// separated; empty means any device.
// exitRouteForm edits an exit route (a LAN device sent through an exit).
func (m *model_) exitRouteForm(it *ops.Item[model.ExitRoute]) {
	r := model.ExitRoute{Enabled: true}
	title, local := "New exit route", false
	if it != nil {
		r, local, title = it.Value, it.Local, "Edit exit route "+it.Value.Name
	}
	routers := []option{{"automatic (from the IP)", ""}}
	for _, n := range m.v.Nodes {
		if n.Value.Kind == model.NodeServer && len(n.Value.Routes) > 0 {
			routers = append(routers, option{n.Value.Name, n.Value.ID})
		}
	}
	m.form = newForm(title, func(v map[string]string) error {
		nr := model.ExitRoute{ID: r.ID, Name: v["name"], Src: v["src"], Router: v["router"], Via: v["via"],
			ExitOnly: v["exit_only"] == "true", Enabled: v["enabled"] == "true"}
		return m.api.Post("exitroute", map[string]any{"exit_route": nr, "scope": v["scope"]}, nil)
	}).
		text("name", "Name", r.Name, "gaming-vm").
		text("src", "Device IP or subnet", r.Src, "192.168.200.11").
		choice("via", "Exit node", exitChoices(m.exitOptions("")[1:]), r.Via).
		choice("router", "Router", routers, r.Router).
		toggle("exit_only", "Exit only (no internet if no exit reachable)", r.ExitOnly).
		toggle("enabled", "Enabled", r.Enabled).
		choice("scope", "Apply to", scopeOptions(m.name(m.v.SelfID)), scopeOf(local)).init()
}

func (m *model_) aclForm(it *ops.Item[model.ACL]) {
	a := model.ACL{Proto: "tcp", Enabled: true, To: model.ToSelf}
	title := "New access rule"
	local := false
	if it != nil {
		a, local, title = it.Value, it.Local, "Edit rule "+it.Value.Name
	}
	var from []string
	for _, id := range a.From {
		from = append(from, m.name(id))
	}
	hint := "self, 192.168.20.15 or 192.168.20.0/24"
	if a.Node != "" {
		if lans := m.lans(a.Node); lans != "" {
			hint = "self or " + lans
		}
	}
	m.form = newForm(title, func(v map[string]string) error {
		na := model.ACL{ID: a.ID, Name: v["name"], Node: v["node"], To: v["to"], Proto: v["proto"],
			Ports: v["ports"], Enabled: v["enabled"] == "true"}
		for _, name := range lines(v["from"]) {
			id, ok := m.idByName(name)
			if !ok {
				return fmt.Errorf("no device named %q", name)
			}
			na.From = append(na.From, id)
		}
		return m.api.Post("acl", map[string]any{"acl": na, "scope": v["scope"]}, nil)
	}).
		text("name", "Name", a.Name, "laptop to NAS").
		choice("node", "Enforced on", m.serverOptions(), a.Node).
		text("from", "From devices (empty = any)", strings.Join(from, ", "), "laptop, phone").
		text("to", "To", a.To, hint).
		choice("proto", "Protocol", []option{{"tcp", "tcp"}, {"udp", "udp"}, {"tcp+udp", "both"}, {"icmp", "icmp"}, {"any", "any"}}, a.Proto).
		text("ports", "Ports (empty = all)", a.Ports, "443 or 80,443 or 8000-8100").
		toggle("enabled", "Enabled", a.Enabled).
		choice("scope", "Apply to", scopeOptions(m.name(m.v.SelfID)), scopeOf(local)).init()
}

func (m *model_) idByName(name string) (string, bool) {
	for _, n := range m.v.Nodes {
		if strings.EqualFold(n.Value.Name, name) {
			return n.Value.ID, true
		}
	}
	return "", false
}

// lans lists a node's local networks ("192.168.20.0/24 (igb1.20)").
func (m *model_) lans(nodeID string) string {
	var out []string
	for _, l := range m.v.Statuses[nodeID].LANs {
		out = append(out, l.CIDR+" ("+l.Iface+")")
	}
	return strings.Join(out, ", ")
}

func (m *model_) tokenForm() {
	m.form = newForm("Create join token", func(v map[string]string) error {
		var out struct{ Token string }
		ttl := atoi(v["ttl"])
		if err := m.api.Post("token", map[string]any{"kind": v["kind"], "uses": atoi(v["uses"]), "ttl_hours": ttl, "note": v["note"]}, &out); err != nil {
			return err
		}
		if v["kind"] == "server" {
			linux, pfsense, windows := join.InstallCommands(out.Token)
			m.note = "Linux server (shell):\n  " + linux + "\n\npfSense (Diagnostics > Command Prompt > Execute Shell Command):\n  " + pfsense +
				"\n\nWindows (PowerShell as Administrator):\n  " + windows + "\n"
			return nil
		}
		q, _ := qrcode.New(out.Token, qrcode.Low)
		linux, _, windows := join.InstallCommands(out.Token)
		m.note = "Phone: scan with the meshgate app.\nLinux laptop:  " + linux + " --kind client\nWindows PC (PowerShell as Administrator):  " + windows + " --kind client\n\n" + q.ToSmallString(false)
		return nil
	}).
		choice("kind", "Device type", []option{{"phone / laptop", "client"}, {"server", "server"}}, "client").
		text("uses", "Uses (-1 = unlimited)", "1", "").
		text("ttl", "Valid for hours (0 = forever)", "24", "").
		text("note", "Note", "", "e.g. Alex's phone").init()
}

func (m *model_) staticForm() {
	m.form = newForm("Device using the official WireGuard app", func(v map[string]string) error {
		var out ops.StaticDevice
		if err := m.api.Post("static-device", map[string]string{"name": v["name"], "relay": v["relay"]}, &out); err != nil {
			return err
		}
		q, _ := qrcode.New(out.Config, qrcode.Low)
		m.note = "Scan with the WireGuard app (private key shown only once):\n\n" + q.ToSmallString(false) + "\n" + out.Config
		return nil
	}).
		text("name", "Name", "", "laptop").
		choice("relay", "Relay", m.relayOptions(), "").init()
}

func (m *model_) settingsForm() {
	m.form = newForm("Network settings", func(v map[string]string) error {
		return m.api.Post("network", map[string]string{"acme_email": v["email"]}, nil)
	}).text("email", "Let's Encrypt email", m.v.Network.ACMEEmail, "you@example.com").init()
}

func itoa0(n int) string {
	if n == 0 {
		return ""
	}
	return strconv.Itoa(n)
}

func lanExitSrcs(n model.Node) string {
	var s []string
	for _, e := range n.LANExits {
		s = append(s, e.Src)
	}
	return strings.Join(s, ", ")
}

func lanExitVia(n model.Node) string {
	if len(n.LANExits) > 0 {
		return n.LANExits[0].Via
	}
	return ""
}

func exitChoices(o []option) []option {
	if len(o) == 0 {
		return []option{{"(no exit node yet)", ""}}
	}
	return o
}

func (m *model_) exitNames(ids []string) string {
	var s []string
	for _, id := range ids {
		if id == "*" {
			return "*"
		}
		s = append(s, m.name(id))
	}
	return strings.Join(s, ", ")
}
