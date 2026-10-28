package tui

import (
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"

	"github.com/heresjohnny320/meshgate/internal/model"
)

// Layout follows iptable-UI: a boxed header with live status, one bordered
// card per item, key badges at the bottom. Narrow or short terminals fall
// back to one-line rows.
const (
	maxContentWidth = 120
	minBoxedWidth   = 50
	cardHeight      = 5 // three lines plus the border
)

var panelBorder = lipgloss.RoundedBorder()

func (m *model_) contentWidth() int {
	if m.width < 1 {
		return 100
	}
	return min(m.width, maxContentWidth)
}

func (m *model_) heightLimit() int {
	if m.height < 1 {
		return 40
	}
	return m.height
}

func (m *model_) View() string {
	width := m.contentWidth()
	var view string
	switch {
	case m.form != nil:
		view = m.form.view(width)
	case m.note != "":
		view = lipgloss.JoinVertical(lipgloss.Left,
			panel(width, accentBorder, m.note),
			flow(width, helpKey("ANY KEY", "back")))
	default:
		view = m.listView(width)
	}
	return fitScreen(view, m.width, m.height)
}

// ---------- header ----------

func (m *model_) header(width int) string {
	inner := innerWidth(width)
	brand := flow(inner, brandStyle.Render("MESHGATE"), sectionStyle.Render("MESH MANAGER"))
	self := m.self()
	items := []string{labelStyle.Render("MESH ") + addressStyle.Render(m.v.Network.CIDR)}
	if self.ID != "" {
		items = append(items, labelStyle.Render("NODE ")+selectedStyle.Render(self.Name)+mutedStyle.Render(" ")+addressStyle.Render(self.MeshIP))
	}
	if r := m.v.Runtime.HomeRelay; r != "" {
		items = append(items, labelStyle.Render("RELAY ")+publicStyle.Render(m.name(r)))
	}
	if m.v.Runtime.Userspace {
		items = append(items, labelStyle.Render("WIREGUARD ")+warnStyle.Render("USERSPACE"))
	}
	web := "OFF"
	for _, n := range m.v.Nodes {
		if n.Value.WebUI {
			web = n.Value.Name
		}
	}
	items = append(items, labelStyle.Render("WEB UI ")+onOff(web != "OFF", strings.ToUpper(web), "NONE"))
	if self.Kind == model.NodeServer && len(self.Routes) > 0 {
		items = append(items, labelStyle.Render("LAN ")+policyText(self))
	}
	var tabLine []string
	for i, t := range tabs {
		label := fmt.Sprintf("%d %s", (i+1)%10, t)
		if i >= 10 {
			label = t // past the number keys: TAB reaches it
		}
		if i == m.tab {
			tabLine = append(tabLine, keyStyle.Render(" "+label+" "))
		} else {
			tabLine = append(tabLine, mutedStyle.Render(" "+label+" "))
		}
	}
	return panel(width, accentBorder, brand, flow(inner, items...), flow(inner, tabLine...))
}

// ---------- list ----------

func (m *model_) listView(width int) string {
	header := m.header(width)
	if m.err != nil {
		return lipgloss.JoinVertical(lipgloss.Left, header,
			messageStyle.Width(max(1, width-2)).Render(m.err.Error()),
			flow(width, helpKey("R", "retry"), helpKey("Q", "quit")))
	}
	var warn []string
	for i, w := range m.v.Runtime.Warnings {
		if i == 3 {
			warn = append(warn, line(width, warnStyle.Render(fmt.Sprintf("  … %d more warnings", len(m.v.Runtime.Warnings)-3))))
			break
		}
		warn = append(warn, line(width, warnStyle.Render("! "+w)))
	}
	footer := m.footer(width)
	title := line(width, sectionStyle.Render(tabs[m.tab]+" ")+mutedStyle.Render(m.tabHint()))
	available := m.heightLimit() - lipgloss.Height(header) - lipgloss.Height(footer) - len(warn) - 1

	n := m.rows()
	var body []string
	switch {
	case n == 0:
		body = []string{panel(width, quietBorder, mutedStyle.Render(m.emptyText()))}
	case m.tab == tabTraffic && !m.history:
		rows := m.liveRows()
		start, end := window(m.sel, n, max(1, available))
		for i := start; i < end; i++ {
			body = append(body, line(width, m.liveLine(rows[i], i == m.sel)))
		}
	case m.tab == tabTraffic:
		rows := m.histRows()
		start, end := window(m.sel, n, max(1, available))
		for i := start; i < end; i++ {
			body = append(body, line(width, m.trafficLine(rows[i], i == m.sel, width)))
		}
	case m.tab == tabTools:
		rows := m.toolRows()
		start, end := window(m.sel, n, max(1, available))
		for i := start; i < end; i++ {
			body = append(body, line(width, m.toolLine(rows[i], i == m.sel)))
		}
	case m.tab == tabLogs:
		rows := m.logRows()
		start, end := window(m.sel, n, max(1, available))
		for i := start; i < end; i++ {
			body = append(body, line(width, m.logLine(rows[i], i == m.sel, width)))
		}
	case m.tab == tabSettings:
		rows := m.settingRows()
		start, end := window(m.sel, n, max(1, available))
		for i := start; i < end; i++ {
			body = append(body, line(width, m.settingLine(rows[i], i == m.sel)))
		}
	case m.tab == tabChanges:
		start, end := window(m.sel, n, max(1, available))
		for i := start; i < end; i++ {
			body = append(body, line(width, changeLine(changeLines[i], i == m.sel)))
		}
	case width >= minBoxedWidth && available >= cardHeight*min(n, 2):
		capacity := max(1, available/cardHeight)
		start, end := window(m.sel, n, capacity)
		for i := start; i < end; i++ {
			body = append(body, m.card(i, width))
		}
	default:
		capacity := max(1, available)
		start, end := window(m.sel, n, capacity)
		for i := start; i < end; i++ {
			body = append(body, m.row(i, width))
		}
	}
	parts := append([]string{header}, warn...)
	parts = append(parts, title)
	parts = append(parts, body...)
	parts = append(parts, footer)
	return lipgloss.JoinVertical(lipgloss.Left, parts...)
}

// window returns the visible slice that keeps sel on screen.
func window(sel, n, capacity int) (int, int) {
	if n <= capacity {
		return 0, n
	}
	start := min(max(0, sel-capacity/2), n-capacity)
	return start, start + capacity
}

func (m *model_) tabHint() string {
	switch m.tab {
	case tabNodes:
		return "devices in the mesh and how this node reaches them"
	case tabForwards:
		return "public ports on an edge node, sent through the mesh"
	case tabHTTPS:
		return "websites with automatic certificates"
	case tabRules:
		return "what mesh devices may reach on restricted nodes"
	case tabExits:
		return "LAN devices whose internet goes out through an exit node"
	case tabChanges:
		return "what changed in each version (+ added, - removed, ~ changed or fixed)"
	case tabTraffic:
		if !m.history {
			return "live speeds and totals since each server started   M: history"
		}
		where := ""
		if m.hist != nil {
			where = ", stored on " + m.hist.Server
		}
		if m.histErr != "" {
			where = " (" + m.histErr + ")"
		}
		return "traffic history, last " + m.histRange + where + "   V: change period   M: live"
	case tabTools:
		return "connectivity checks from this node"
	case tabLogs:
		return m.logsHint()
	case tabSettings:
		return "mesh-wide settings and the web UI's certificates"
	case tabDevices:
		return "join tokens for new servers, phones and PCs"
	}
	return ""
}

func (m *model_) emptyText() string {
	switch m.tab {
	case tabForwards:
		return "No forwards yet. Press A to add one (e.g. Minecraft: TCP 25565 on your VPS -> your home server)."
	case tabHTTPS:
		return "No HTTPS routes yet. Press A to publish a website."
	case tabRules:
		return "No access rules. They only matter on nodes whose LAN policy is RESTRICTED (edit the node on tab 1)."
	case tabExits:
		return "No exit routes. Press A to send a LAN device (e.g. 192.168.200.11) out through an exit node."
	case tabLogs:
		if !m.logAll {
			return "Nothing important in this period. Press I to see every line, V for a longer period."
		}
		return "No log lines in this period."
	case tabDevices:
		return "No tokens. Press A to create one, or W for a device using the official WireGuard app."
	}
	return "Nothing here yet."
}

func (m *model_) footer(width int) string {
	type key struct{ k, d string }
	keys := []key{{"UP/DOWN", "select"}, {"TAB", "section"}}
	switch m.tab {
	case tabNodes:
		keys = append(keys, key{"E", "edit"}, key{"U", "update"}, key{"CTRL+U", "update all"}, key{"D", "remove"}, key{"C", "use all-nodes value"})
	case tabTraffic:
		if m.history {
			keys = append(keys, key{"V", "period (6h/1d/1w/1m/1y)"}, key{"O", "save CSV"}, key{"M", "live"})
		} else {
			keys = append(keys, key{"A", "add monitor"}, key{"E", "edit"}, key{"D", "remove"}, key{"M", "history"})
		}
	case tabTools:
		keys = append(keys, key{"ENTER", "run"})
	case tabLogs:
		keys = append(keys, key{"ENTER", "full line"}, key{"I", "important/all"}, key{"F", "node"}, key{"V", "period"}, key{"/", "search"})
	case tabSettings:
		keys = append(keys, key{"ENTER", "change / show"})
	case tabForwards, tabHTTPS, tabRules, tabExits:
		keys = append(keys, key{"A", "add"}, key{"E", "edit"}, key{"T", "on/off"}, key{"D", "remove"}, key{"C", "use all-nodes value"})
	case tabDevices:
		keys = append(keys, key{"A", "new token"}, key{"W", "WireGuard app"}, key{"D", "revoke"})
	}
	if m.tab == tabHTTPS {
		keys = append(keys, key{"S", "settings"})
	}
	keys = append(keys, key{"Y", "theme"}, key{"Q", "quit"})
	items := make([]string, len(keys))
	for i, k := range keys {
		items[i] = helpKey(k.k, k.d)
	}
	out := []string{flow(width, items...)}
	switch {
	case m.confirm != "":
		out = append(out, messageStyle.Width(max(1, width-2)).Render(focusedStyle.Render(m.confirm)+mutedStyle.Render("  Y yes  any other key no")))
	case m.message != "":
		out = append(out, messageStyle.Width(max(1, width-2)).Render(m.message))
	}
	return lipgloss.JoinVertical(lipgloss.Left, out...)
}

// ---------- cards ----------

func (m *model_) card(i, width int) string {
	inner := innerWidth(width)
	sel := i == m.sel
	marker, border := "  ", lipgloss.TerminalColor(quietBorder)
	if sel {
		marker, border = selectedStyle.Render("> "), selectedBorder
	}
	var l1, l2, l3 string
	switch m.tab {
	case tabNodes:
		it := m.v.Nodes[i]
		n := it.Value
		l1 = marker + m.nodeState(n) + "  " + nameStyle(sel).Render(n.Name) + "  " + mutedStyle.Render(m.roles(n)) + localTag(it.Local)
		if v := m.v.Statuses[n.ID].Version; v != "" {
			l1 += "  " + mutedStyle.Render(v)
		}
		if m.outdated(n) {
			l1 += " " + warnStyle.Render("UPDATE AVAILABLE")
		}
		p := m.v.Runtime.Peers[n.ID]
		path, hs := "this node", ""
		if n.ID != m.v.SelfID {
			path, hs = m.pathText(p.Path), handshakeText(p.LastHandshake)
		}
		l2 = labelStyle.Render("MESH IP ") + addressStyle.Render(n.MeshIP) + labelStyle.Render("   PATH ") + valueStyle.Render(path)
		if hs != "" {
			l2 += labelStyle.Render("   HANDSHAKE ") + valueStyle.Render(hs)
		}
		if p.RxBytes+p.TxBytes > 0 {
			l2 += labelStyle.Render("   RX/TX ") + valueStyle.Render(humanBytes(float64(p.RxBytes))+" / "+humanBytes(float64(p.TxBytes)))
		}
		ep := p.Endpoint
		if ep == "" && len(n.Endpoints) > 0 {
			ep = strings.Join(n.Endpoints, " ")
		}
		l3 = labelStyle.Render("ENDPOINT ") + addressStyle.Render(dash(ep))
		if len(n.Routes) > 0 {
			l3 += labelStyle.Render("   SUBNETS ") + portStyle.Render(strings.Join(n.Routes, " ")) + " " + policyText(n)
		}
	case tabForwards:
		it := m.v.Forwards[i]
		f := it.Value
		l1 = marker + onOff(f.Enabled, "ENABLED", "DISABLED") + "  " + mutedStyle.Render("#"+short(f.ID)) + "  " + nameStyle(sel).Render(labelOr(f.Name)) + localTag(it.Local)
		pub := fmt.Sprintf(":%d", f.ListenPort)
		if f.ListenEnd > f.ListenPort {
			pub += fmt.Sprintf("-%d", f.ListenEnd)
		}
		target := m.addrOf(f.TargetNode, f.TargetIP)
		l2 = labelStyle.Render("PUBLIC ") + publicStyle.Render(m.name(f.EdgeNode)) + publicStyle.Render(pub) +
			mutedStyle.Render("   ->   TARGET ") + selectedStyle.Render(m.name(f.TargetNode)) + " " + addressStyle.Render(target) + ":" + portStyle.Render(fmt.Sprint(f.TargetPort))
		l3 = labelStyle.Render("PROTOCOL ") + protocolStyle.Render(strings.ToUpper(string(f.Proto))) +
			labelStyle.Render("   CLIENT IP ") + mutedStyle.Render(map[bool]string{true: "real", false: "masked"}[f.PreserveClientIP])
		if !f.Enabled {
			l3 += "   " + disabledStyle.Render("public port blocked")
		}
	case tabHTTPS:
		it := m.v.Routes[i]
		r := it.Value
		l1 = marker + onOff(r.Enabled, "ENABLED", "DISABLED") + "  " + nameStyle(sel).Render(r.Hostname) + localTag(it.Local)
		scheme := "http"
		if r.TargetTLS {
			scheme = "https"
		}
		l2 = labelStyle.Render("EDGE ") + publicStyle.Render(m.name(r.EdgeNode)) + mutedStyle.Render("   ->   TARGET ") +
			selectedStyle.Render(m.name(r.TargetNode)) + " " + mutedStyle.Render(scheme+"://") + addressStyle.Render(m.addrOf(r.TargetNode, r.TargetIP)) + ":" + portStyle.Render(fmt.Sprint(r.TargetPort))
		mode := "HTTPS only (HTTP redirects)"
		if !r.ForceHTTPS {
			mode = "HTTP and HTTPS"
		}
		l3 = labelStyle.Render("MODE ") + protocolStyle.Render(mode)
		if !r.Enabled {
			l3 += "   " + disabledStyle.Render("visitors get 403")
		}
	case tabRules:
		it := m.v.ACLs[i]
		a := it.Value
		l1 = marker + onOff(a.Enabled, "ENABLED", "DISABLED") + "  " + nameStyle(sel).Render(labelOr(a.Name)) + localTag(it.Local)
		from := "any device"
		if len(a.From) > 0 {
			var names []string
			for _, id := range a.From {
				names = append(names, m.name(id))
			}
			from = strings.Join(names, ", ")
		}
		l2 = labelStyle.Render("FROM ") + selectedStyle.Render(from) + mutedStyle.Render("   ->   TO ") + addressStyle.Render(m.aclTarget(a)) + labelStyle.Render("   ON ") + publicStyle.Render(m.name(a.Node))
		allow := strings.ToUpper(protoLabel(a.Proto))
		if a.Ports != "" {
			allow += " " + a.Ports
		}
		l3 = labelStyle.Render("ALLOW ") + protocolStyle.Render(allow)
		for _, n := range m.v.Nodes {
			if n.Value.ID == a.Node && !n.Value.Restricted() {
				l3 += "   " + warnStyle.Render("node's LAN policy is OPEN: rule has no effect yet")
			}
		}
	case tabExits:
		it := m.v.ExitRoutes[i]
		r := it.Value
		l1 = marker + onOff(r.Enabled, "ENABLED", "DISABLED") + "  " + nameStyle(sel).Render(labelOr(r.Name)) + localTag(it.Local)
		l2 = labelStyle.Render("DEVICE ") + addressStyle.Render(r.Src) + labelStyle.Render("   BEHIND ") + selectedStyle.Render(m.name(r.Router)) +
			mutedStyle.Render("   ->   EXIT ") + publicStyle.Render(m.name(r.Via))
		if r.ExitOnly {
			l3 = labelStyle.Render("EXIT ONLY ") + warnStyle.Render("no internet if no exit node is reachable")
		} else {
			l3 = labelStyle.Render("FALLBACK ") + mutedStyle.Render("normal connection if no exit node is reachable")
		}
	case tabDevices:
		t := m.v.Tokens[i]
		uses := fmt.Sprint(t.UsesLeft)
		if t.UsesLeft < 0 {
			uses = "unlimited"
		}
		exp := "never"
		if t.ExpiresAt > 0 {
			exp = time.Unix(t.ExpiresAt, 0).Format("2006-01-02 15:04")
		}
		l1 = marker + onOff(uses != "0", "ACTIVE", "USED UP") + "  " + mutedStyle.Render("#"+t.ID) + "  " + nameStyle(sel).Render(strings.ToUpper(string(t.Kind))+" TOKEN")
		l2 = labelStyle.Render("USES LEFT ") + portStyle.Render(uses) + labelStyle.Render("   EXPIRES ") + valueStyle.Render(exp)
		l3 = labelStyle.Render("NOTE ") + valueStyle.Render(dash(t.Note))
	}
	return panel(width, border, line(inner, l1), line(inner, l2), line(inner, l3))
}

// row is the one-line fallback for narrow or short terminals.
func (m *model_) row(i, width int) string {
	marker := "  "
	if i == m.sel {
		marker = selectedStyle.Render("> ")
	}
	var text string
	switch m.tab {
	case tabNodes:
		n := m.v.Nodes[i].Value
		text = m.nodeState(n) + " " + selectedStyle.Render(n.Name) + " " + addressStyle.Render(n.MeshIP) + " " + mutedStyle.Render(m.pathText(m.v.Runtime.Peers[n.ID].Path))
	case tabForwards:
		f := m.v.Forwards[i].Value
		text = onOff(f.Enabled, "ON ", "OFF") + " " + publicStyle.Render(fmt.Sprintf(":%d", f.ListenPort)) + mutedStyle.Render("->") +
			addressStyle.Render(m.name(f.TargetNode)) + ":" + portStyle.Render(fmt.Sprint(f.TargetPort)) + " " + protocolStyle.Render(strings.ToUpper(string(f.Proto))) + " " + labelOr(f.Name)
	case tabHTTPS:
		r := m.v.Routes[i].Value
		text = onOff(r.Enabled, "ON ", "OFF") + " " + selectedStyle.Render(r.Hostname) + mutedStyle.Render(" -> ") + addressStyle.Render(m.name(r.TargetNode)) + ":" + portStyle.Render(fmt.Sprint(r.TargetPort))
	case tabRules:
		a := m.v.ACLs[i].Value
		text = onOff(a.Enabled, "ON ", "OFF") + " " + labelOr(a.Name) + mutedStyle.Render(" -> ") + addressStyle.Render(m.aclTarget(a)) + " " + protocolStyle.Render(protoLabel(a.Proto)+" "+a.Ports)
	case tabExits:
		r := m.v.ExitRoutes[i].Value
		text = onOff(r.Enabled, "ON ", "OFF") + " " + labelOr(r.Name) + mutedStyle.Render(" ") + addressStyle.Render(r.Src) + mutedStyle.Render(" -> ") + publicStyle.Render(m.name(r.Via))
	case tabDevices:
		t := m.v.Tokens[i]
		text = mutedStyle.Render("#"+t.ID) + " " + string(t.Kind) + " " + t.Note
	}
	return line(width, marker+text)
}

func (m *model_) nodeState(n model.Node) string {
	if n.ID == m.v.SelfID {
		return enabledStyle.Render("THIS NODE")
	}
	p, ok := m.v.Runtime.Peers[n.ID]
	if !ok || p.LastHandshake.Year() < 2000 {
		if n.Kind == model.NodeStatic {
			return mutedStyle.Render("VIA RELAY")
		}
		return disabledStyle.Render("NO HANDSHAKE")
	}
	if time.Since(p.LastHandshake) > 3*time.Minute {
		return warnStyle.Render("IDLE")
	}
	return enabledStyle.Render("ONLINE")
}

func (m *model_) pathText(path string) string {
	if strings.HasPrefix(path, "via ") {
		return "via " + m.name(strings.TrimPrefix(path, "via "))
	}
	return dash(path)
}

func (m *model_) self() model.Node {
	for _, n := range m.v.Nodes {
		if n.Value.ID == m.v.SelfID {
			return n.Value
		}
	}
	return model.Node{}
}

func (m *model_) addrOf(nodeID, ip string) string {
	if ip != "" {
		return ip
	}
	for _, n := range m.v.Nodes {
		if n.Value.ID == nodeID {
			return n.Value.MeshIP
		}
	}
	return "?"
}

func (m *model_) aclTarget(a model.ACL) string {
	if a.To == model.ToSelf {
		return "this node"
	}
	for _, l := range m.v.Statuses[a.Node].LANs {
		if l.CIDR == a.To {
			return a.To + " (" + l.Iface + ")"
		}
	}
	return a.To
}

func (m *model_) roles(n model.Node) string {
	r := []string{string(n.Kind)}
	if n.Relay {
		r = append(r, "relay")
	}
	if n.Exit {
		r = append(r, "exit node")
	}
	if n.WebUI {
		r = append(r, "web ui")
	}
	// Permissions: the exit nodes this device may use.
	var may []string
	for _, a := range n.ExitsAllowed {
		if a == "*" {
			may = []string{"any exit"}
			break
		}
		may = append(may, m.name(a))
	}
	if len(may) > 0 {
		r = append(r, "may use "+strings.Join(may, "/"))
	} else if n.ExitVia != "" {
		r = append(r, "exit via "+m.name(n.ExitVia))
	}
	return "[" + strings.Join(r, ", ") + "]"
}

func nameStyle(selected bool) lipgloss.Style {
	if selected {
		return selectedStyle
	}
	return labelStyle
}

func localTag(local bool) string {
	if local {
		return "  " + warnStyle.Render("LOCAL ONLY")
	}
	return ""
}

func handshakeText(t time.Time) string {
	if t.Year() < 2000 {
		return "never"
	}
	return time.Since(t).Round(time.Second).String() + " ago"
}

func short(id string) string {
	if len(id) > 6 {
		return id[:6]
	}
	return id
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// policyText is a node's LAN policy as a badge.
func policyText(n model.Node) string {
	switch {
	case n.FirewallManaged():
		return warnStyle.Render("PFSENSE RULES")
	case n.Restricted():
		return onOff(false, "", "RESTRICTED")
	}
	return onOff(true, "OPEN", "")
}

func onOff(on bool, onText, offText string) string {
	if on {
		return enabledStyle.Render(onText)
	}
	return disabledStyle.Render(offText)
}

func helpKey(key, description string) string {
	return keyStyle.Render(" "+key+" ") + " " + mutedStyle.Render(description)
}

// ---------- layout helpers (as in iptable-UI) ----------

// panel draws a rounded box exactly width columns wide.
func panel(width int, color lipgloss.TerminalColor, lines ...string) string {
	content := lipgloss.JoinVertical(lipgloss.Left, lines...)
	if width < 8 {
		return wrap(width, content)
	}
	return lipgloss.NewStyle().Border(panelBorder).BorderForeground(color).Padding(0, 1).Width(width - 2).Render(wrap(innerWidth(width), content))
}

func innerWidth(width int) int {
	if width < 8 {
		return max(1, width)
	}
	return width - 4
}

// line cuts styled text to one line of at most width columns.
func line(width int, text string) string {
	return ansi.Truncate(strings.ReplaceAll(text, "\n", " "), max(0, width), "…")
}

// wrap breaks text to fit width and pads every line.
func wrap(width int, text string) string {
	width = max(1, width)
	ls := strings.Split(ansi.Wrap(text, width, ""), "\n")
	for i, t := range ls {
		ls[i] = line(width, strings.TrimRight(t, " "))
	}
	return lipgloss.NewStyle().Width(width).Render(strings.Join(ls, "\n"))
}

// flow lays items out left to right, wrapping like words.
func flow(width int, items ...string) string {
	var out []string
	cur := ""
	for _, it := range items {
		it = line(width, it)
		switch {
		case cur == "":
			cur = it
		case lipgloss.Width(cur)+2+lipgloss.Width(it) <= width:
			cur += "  " + it
		default:
			out = append(out, cur)
			cur = it
		}
	}
	if cur != "" {
		out = append(out, cur)
	}
	return strings.Join(out, "\n")
}

// fitScreen keeps the view inside the terminal, top first.
func fitScreen(view string, width, height int) string {
	ls := strings.Split(view, "\n")
	if width > 0 {
		for i, l := range ls {
			ls[i] = ansi.Truncate(l, width, "")
		}
	}
	if height > 0 && len(ls) > height {
		ls = ls[:height]
	}
	return strings.Join(ls, "\n")
}

// protoLabel shows an access rule's protocol ("both" is tcp+udp).
func protoLabel(p string) string {
	if p == "both" {
		return "tcp+udp"
	}
	return p
}

// changeLine colours one changelog line: + green, - red, ~ yellow.
func changeLine(l string, sel bool) string {
	marker := "  "
	if sel {
		marker = selectedStyle.Render("> ")
	}
	switch {
	case strings.HasPrefix(l, "## "):
		return marker + sectionStyle.Render(strings.TrimPrefix(l, "## "))
	case strings.HasPrefix(l, "+ "):
		return marker + enabledStyle.Render("+ ") + l[2:]
	case strings.HasPrefix(l, "- "):
		return marker + errStyle.Render("- ") + l[2:]
	case strings.HasPrefix(l, "~ "):
		return marker + warnStyle.Render("~ ") + l[2:]
	}
	return marker + mutedStyle.Render(l)
}

// trafficLine: name, a sparkline of the period (bytes in+out), the total
// transferred and the peak speed.
func (m *model_) trafficLine(r histRow, sel bool, width int) string {
	marker := "  "
	if sel {
		marker = selectedStyle.Render("> ")
	}
	cols := min(48, max(8, width-62))
	vals := make([]float64, cols)
	var total, peak float64
	if h := m.hist; h != nil {
		from, to := float64(h.From), float64(h.To)
		for _, k := range r.keys {
			for _, b := range h.Series[k] {
				total += b[1] + b[2]
				peak = math.Max(peak, math.Max(b[3], b[4]))
				if to > from {
					c := min(cols-1, max(0, int((b[0]-from)/(to-from)*float64(cols))))
					vals[c] += b[1] + b[2]
				}
			}
		}
	}
	label := r.label
	if len(label) > 26 {
		label = label[:25] + "…"
	}
	return marker + fmt.Sprintf("%-27s", label) + " " + addressStyle.Render(spark(vals)) +
		fmt.Sprintf("  %9s  peak %s", humanBytes(total), humanBits(peak))
}

func spark(vals []float64) string {
	const bars = "▁▂▃▄▅▆▇█"
	top := 0.0
	for _, v := range vals {
		top = math.Max(top, v)
	}
	var b strings.Builder
	for _, v := range vals {
		if top == 0 || v == 0 {
			b.WriteString(" ")
			continue
		}
		i := int(v / top * 7.999)
		b.WriteString(string([]rune(bars)[i]))
	}
	return b.String()
}

func humanBytes(n float64) string {
	u := []string{"B", "KB", "MB", "GB", "TB"}
	i := 0
	for n >= 1024 && i < len(u)-1 {
		n /= 1024
		i++
	}
	return fmt.Sprintf("%.1f %s", n, u[i])
}

func humanBits(bytesPerSec float64) string {
	b := bytesPerSec * 8
	u := []string{"bps", "kbps", "Mbps", "Gbps"}
	i := 0
	for b >= 1000 && i < len(u)-1 {
		b /= 1000
		i++
	}
	return fmt.Sprintf("%.1f %s", b, u[i])
}
