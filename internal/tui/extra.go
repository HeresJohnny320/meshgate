package tui

import (
	"encoding/csv"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/heresjohnny320/meshgate/internal/diag"
	"github.com/heresjohnny320/meshgate/internal/model"
	"github.com/heresjohnny320/meshgate/internal/ops"
	"github.com/heresjohnny320/meshgate/internal/traffic"
	"github.com/heresjohnny320/meshgate/internal/update"
)

// The TUI's share of what the web UI has on its Traffic, Tools and Settings
// tabs: live traffic and monitors, checks, history and admin settings.

// ---------- TRAFFIC: live ----------

// liveRow is one line of the live view. Header rows start a section;
// monitor rows can be edited and removed.
type liveRow struct {
	header  string
	label   string
	detail  string
	rate    traffic.Rate
	monitor string // monitor ID
	text    string // free-form line (recent HTTPS requests)
}

// liveRows sums every server's report like the web UI's Traffic tab.
func (m *model_) liveRows() []liveRow {
	fwd, routes, mons := map[string]traffic.Rate{}, map[string]traffic.Route{}, map[string]traffic.Rate{}
	rules := map[string]uint64{}
	var recent []traffic.Request
	type link struct {
		by, peer string
		r        traffic.Rate
	}
	links := map[string]link{}
	add := func(t *traffic.Rate, r traffic.Rate) {
		t.In, t.Out, t.InRate, t.OutRate = t.In+r.In, t.Out+r.Out, t.InRate+r.InRate, t.OutRate+r.OutRate
	}
	for _, t := range m.traffic {
		for id, r := range t.Forwards {
			v := fwd[id]
			add(&v, r)
			fwd[id] = v
		}
		for id, r := range t.Monitors {
			v := mons[id]
			add(&v, r)
			mons[id] = v
		}
		for id, r := range t.Routes {
			v := routes[id]
			add(&v.Rate, r.Rate)
			v.Requests += r.Requests
			v.Errors += r.Errors
			routes[id] = v
		}
		for id, n := range t.ACLs {
			rules[id] += n
		}
		// A link between two servers is measured at both ends: keep one.
		for peer, r := range t.Peers {
			k := strings.Join(sortedPair(t.Node, peer), "|")
			if l, ok := links[k]; !ok || r.In+r.Out > l.r.In+l.r.Out {
				links[k] = link{t.Node, peer, r}
			}
		}
		recent = append(recent, t.Recent...)
	}

	var rows []liveRow
	rows = append(rows, liveRow{header: "MONITORS  (A add, E edit, D remove; they only count, never route)"})
	for _, it := range m.v.Monitors {
		mo := it.Value
		rows = append(rows, liveRow{label: labelOr(mo.Name), detail: monitorMatch(mo) + " on " + m.name(mo.Node), rate: mons[mo.ID], monitor: mo.ID})
	}
	if len(m.v.Monitors) == 0 {
		rows = append(rows, liveRow{text: mutedStyle.Render("    none yet: press A to measure an IP and/or port (e.g. a proxy's backend)")})
	}
	// By target IP: forwards and HTTPS routes to the same machine add up.
	byIP, uses := map[string]traffic.Rate{}, map[string][]string{}
	var ips []string
	addIP := func(ip, use string, r traffic.Rate) {
		if _, ok := byIP[ip]; !ok {
			ips = append(ips, ip)
		}
		v := byIP[ip]
		add(&v, r)
		byIP[ip] = v
		uses[ip] = append(uses[ip], use)
	}
	for _, it := range m.v.Forwards {
		f := it.Value
		addIP(m.addrOf(f.TargetNode, f.TargetIP), fmt.Sprintf("%s (%s %d)", labelOr(f.Name), f.Proto, f.ListenPort), fwd[f.ID])
	}
	for _, it := range m.v.Routes {
		addIP(m.addrOf(it.Value.TargetNode, it.Value.TargetIP), it.Value.Hostname, routes[it.Value.ID].Rate)
	}
	if len(ips) > 0 {
		sort.Slice(ips, func(i, j int) bool {
			a, b := byIP[ips[i]], byIP[ips[j]]
			return a.InRate+a.OutRate > b.InRate+b.OutRate || (a.InRate+a.OutRate == b.InRate+b.OutRate && ips[i] < ips[j])
		})
		rows = append(rows, liveRow{header: "BY TARGET IP  (port forwards and HTTPS routes)"})
		for _, ip := range ips {
			rows = append(rows, liveRow{label: ip, detail: strings.Join(uses[ip], ", "), rate: byIP[ip]})
		}
	}
	if len(m.v.Forwards) > 0 {
		rows = append(rows, liveRow{header: "PORT FORWARDS"})
		for _, it := range m.v.Forwards {
			f := it.Value
			rows = append(rows, liveRow{label: labelOr(f.Name), detail: fmt.Sprintf("%s :%d -> %s:%d", f.Proto, f.ListenPort, m.addrOf(f.TargetNode, f.TargetIP), f.TargetPort), rate: fwd[f.ID]})
		}
	}
	if len(m.v.Routes) > 0 {
		rows = append(rows, liveRow{header: "HTTPS ROUTES"})
		for _, it := range m.v.Routes {
			r := routes[it.Value.ID]
			rows = append(rows, liveRow{label: it.Value.Hostname, detail: fmt.Sprintf("%d requests, %d errors", r.Requests, r.Errors), rate: r.Rate})
		}
	}
	if len(links) > 0 {
		rows = append(rows, liveRow{header: "DEVICES  (WireGuard traffic per link)"})
		keys := make([]string, 0, len(links))
		for k := range links {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool {
			a, b := links[keys[i]].r, links[keys[j]].r
			return a.InRate+a.OutRate > b.InRate+b.OutRate || (a.InRate+a.OutRate == b.InRate+b.OutRate && keys[i] < keys[j])
		})
		for _, k := range keys {
			l := links[k]
			// Received/sent from the device's point of view.
			r := traffic.Rate{In: l.r.Out, Out: l.r.In, InRate: l.r.OutRate, OutRate: l.r.InRate}
			rows = append(rows, liveRow{label: m.name(l.peer), detail: m.name(l.peer) + " <-> " + m.name(l.by), rate: r})
		}
	}
	if len(m.v.ACLs) > 0 {
		rows = append(rows, liveRow{header: "ACCESS RULES  (connections allowed)"})
		for _, it := range m.v.ACLs {
			rows = append(rows, liveRow{text: fmt.Sprintf("    %-27s %s", trunc(labelOr(it.Value.Name), 27), valueStyle.Render(strconv.FormatUint(rules[it.Value.ID], 10)))})
		}
	}
	if len(recent) > 0 {
		sort.Slice(recent, func(i, j int) bool { return recent[i].Time > recent[j].Time })
		rows = append(rows, liveRow{header: "RECENT HTTPS REQUESTS"})
		for _, q := range recent[:min(len(recent), 30)] {
			rows = append(rows, liveRow{text: fmt.Sprintf("    %s  %-15s %3d  %s %s%s  %s %dms", time.Unix(q.Time, 0).Format("15:04:05"),
				q.Client, q.Status, q.Method, q.Host, q.Path, humanBytes(float64(q.Bytes)), q.Ms)})
		}
	}
	return rows
}

func sortedPair(a, b string) []string {
	if a > b {
		return []string{b, a}
	}
	return []string{a, b}
}

func trunc(s string, n int) string {
	if len(s) > n {
		return s[:n-1] + "…"
	}
	return s
}

// liveLine renders one live row: name, what it is, speeds and total.
func (m *model_) liveLine(r liveRow, sel bool) string {
	marker := "  "
	if sel {
		marker = selectedStyle.Render("> ")
	}
	switch {
	case r.header != "":
		return marker + sectionStyle.Render(r.header)
	case r.text != "":
		return marker + r.text
	}
	return marker + fmt.Sprintf("%-22s", trunc(r.label, 22)) + " " + mutedStyle.Render(fmt.Sprintf("%-34s", trunc(r.detail, 34))) +
		labelStyle.Render(" IN ") + valueStyle.Render(fmt.Sprintf("%-10s", humanBits(r.rate.InRate))) +
		labelStyle.Render(" OUT ") + valueStyle.Render(fmt.Sprintf("%-10s", humanBits(r.rate.OutRate))) +
		labelStyle.Render(" TOTAL ") + addressStyle.Render(humanBytes(float64(r.rate.In+r.rate.Out)))
}

// monitorMatch: "tcp 192.168.1.51:25566", "any 10.0.0.0/24", "udp port 19132".
func monitorMatch(mo model.Monitor) string {
	proto := mo.Proto
	if proto == "both" {
		proto = "tcp+udp"
	}
	if mo.IP == "" {
		return proto + " port " + mo.Ports
	}
	if mo.Ports != "" {
		return proto + " " + mo.IP + ":" + mo.Ports
	}
	return proto + " " + mo.IP
}

func (m *model_) selectedMonitor() (ops.Item[model.Monitor], bool) {
	if m.tab != tabTraffic || m.history {
		return ops.Item[model.Monitor]{}, false
	}
	rows := m.liveRows()
	if m.sel >= len(rows) || rows[m.sel].monitor == "" {
		return ops.Item[model.Monitor]{}, false
	}
	for _, it := range m.v.Monitors {
		if it.Value.ID == rows[m.sel].monitor {
			return it, true
		}
	}
	return ops.Item[model.Monitor]{}, false
}

func (m *model_) monitorForm(it *ops.Item[model.Monitor]) {
	mo := model.Monitor{Proto: "tcp", Node: m.v.SelfID}
	title := "New monitor"
	if it != nil {
		mo, title = it.Value, "Edit monitor "+it.Value.Name
	}
	m.form = newForm(title, func(v map[string]string) error {
		nm := model.Monitor{ID: mo.ID, Name: v["name"], Node: v["node"], IP: v["ip"], Ports: v["ports"], Proto: v["proto"]}
		return m.api.Post("monitor", map[string]any{"monitor": nm, "scope": "cluster"}, nil)
	}).
		text("name", "Name", mo.Name, "survival server").
		choice("node", "Measured on", m.serverOptions(), mo.Node).
		text("ip", "IP or subnet (empty = any)", mo.IP, "192.168.1.51").
		text("ports", "Ports (empty = all)", mo.Ports, "25565 or 25565-25570").
		choice("proto", "Protocol", []option{{"tcp", "tcp"}, {"udp", "udp"}, {"tcp+udp", "both"}, {"any (IP only)", "any"}}, mo.Proto).init()
}

// ---------- TRAFFIC: history export ----------

// exportHistory writes the shown period of every series to a CSV file in
// the current directory (the web UI's Download, for terminals).
func (m *model_) exportHistory() {
	h := m.hist
	if h == nil {
		m.message = "No history loaded yet."
		return
	}
	name := fmt.Sprintf("meshgate-traffic-%s-%s.csv", m.histRange, time.Now().Format("2006-01-02-1504"))
	path, _ := filepath.Abs(name)
	f, err := os.Create(path)
	if err != nil {
		m.message = "Error: " + err.Error()
		return
	}
	defer f.Close()
	cols := []string{"kind", "name", "hostname", "proto", "port", "target_ip", "target_port", "target_node", "node", "peer"}
	w := csv.NewWriter(f)
	w.Write(append(append([]string{"time", "unix", "series"}, cols...), "bytes_in", "bytes_out", "peak_in_bps", "peak_out_bps"))
	keys := make([]string, 0, len(h.Series))
	for k := range h.Series {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		var label []string
		for _, c := range cols {
			label = append(label, h.Labels[k][c])
		}
		for _, b := range h.Series[k] {
			t := time.Unix(int64(b[0]), 0)
			row := append([]string{t.Format("2006-01-02 15:04"), strconv.FormatInt(int64(b[0]), 10), k}, label...)
			w.Write(append(row, fmt.Sprint(int64(b[1])), fmt.Sprint(int64(b[2])), fmt.Sprint(int64(b[3]*8)), fmt.Sprint(int64(b[4]*8))))
		}
	}
	w.Flush()
	if err := w.Error(); err != nil {
		m.message = "Error: " + err.Error()
		return
	}
	m.message = "Saved " + path
}

// ---------- NODES ----------

// outdated reports whether a node can update to the latest release (phones
// update in their app; static devices run no meshgate).
func (m *model_) outdated(n model.Node) bool {
	st := m.v.Statuses[n.ID]
	return m.v.Runtime.Latest != "" && update.Newer(st.Version, m.v.Runtime.Latest) &&
		n.Kind != model.NodeStatic && st.OS != "android" && st.OS != "ios"
}

// updateAll updates every node behind the latest release, this one last
// (it restarts).
func (m *model_) updateAll() {
	var ids []string
	for _, it := range m.v.Nodes {
		if m.outdated(it.Value) && it.Value.ID != m.v.SelfID {
			ids = append(ids, it.Value.ID)
		}
	}
	for _, it := range m.v.Nodes {
		if m.outdated(it.Value) && it.Value.ID == m.v.SelfID {
			ids = append(ids, it.Value.ID)
		}
	}
	if len(ids) == 0 {
		m.message = "Every node runs the latest release."
		return
	}
	var msgs []string
	for _, id := range ids {
		var out struct{ Message string }
		if err := m.api.Post("update", map[string]string{"node": id}, &out); err != nil {
			msgs = append(msgs, m.name(id)+": "+err.Error())
		} else {
			msgs = append(msgs, out.Message)
		}
	}
	m.message = strings.Join(msgs, "  ")
}

// detectedSubnets lists the LAN/VLAN subnets a node reports that it does
// not share yet (container bridges skipped), like the web UI's Detect.
func (m *model_) detectedSubnets(n model.Node) []string {
	have := map[string]bool{}
	for _, r := range n.Routes {
		have[r] = true
	}
	var out []string
	for _, l := range m.v.Statuses[n.ID].LANs {
		if bridgeIface.MatchString(l.Iface) || have[l.CIDR] {
			continue
		}
		have[l.CIDR] = true
		out = append(out, l.CIDR)
	}
	return out
}

var bridgeIface = regexp.MustCompile(`^(docker|br-|veth|virbr|cni|flannel|cali|lxc)`)

// ---------- TOOLS ----------

type toolRow struct {
	header string
	label  string
	check  diag.Check
}

// toolRows: a custom check, then quick picks like the web UI's (devices,
// public addresses, both ends of each forward, HTTPS sites).
func (m *model_) toolRows() []toolRow {
	rows := []toolRow{
		{header: "RUN A CHECK  (from " + m.self().Name + "; ENTER to run)"},
		{label: "Custom check: type any target", check: diag.Check{Kind: "ping"}},
		{label: "My public IP (what websites see)", check: diag.Check{Kind: "myip"}},
	}
	group := func(title string, picks []toolRow) {
		if len(picks) > 0 {
			rows = append(rows, toolRow{header: title})
			rows = append(rows, picks...)
		}
	}
	byID := map[string]model.Node{}
	var mesh, public []toolRow
	for _, it := range m.v.Nodes {
		n := it.Value
		byID[n.ID] = n
		if n.MeshIP != "" {
			mesh = append(mesh, toolRow{label: n.Name + " — " + n.MeshIP, check: diag.Check{Kind: "ping", Target: n.MeshIP}})
		}
		if pub := publicHost(n); n.Kind == model.NodeServer && pub != "" {
			public = append(public, toolRow{label: n.Name + " public — " + pub, check: diag.Check{Kind: "ping", Target: pub}})
		}
	}
	l4 := func(p model.Proto) string {
		if p == model.ProtoUDP {
			return "udp"
		}
		return "tcp"
	}
	var outside, target, sites []toolRow
	for _, it := range m.v.Forwards {
		f := it.Value
		if pub := publicHost(byID[f.EdgeNode]); pub != "" {
			outside = append(outside, toolRow{label: fmt.Sprintf("%s — %s:%d/%s", labelOr(f.Name), pub, f.ListenPort, f.Proto),
				check: diag.Check{Kind: l4(f.Proto), Target: pub, Port: f.ListenPort}})
		}
		if ip := m.addrOf(f.TargetNode, f.TargetIP); ip != "" {
			target = append(target, toolRow{label: fmt.Sprintf("%s target — %s:%d", labelOr(f.Name), ip, f.TargetPort),
				check: diag.Check{Kind: l4(f.Proto), Target: ip, Port: f.TargetPort}})
		}
	}
	for _, it := range m.v.Routes {
		sites = append(sites, toolRow{label: it.Value.Hostname, check: diag.Check{Kind: "http", Target: "https://" + it.Value.Hostname + "/"}})
	}
	group("MESH DEVICES", mesh)
	group("PUBLIC ADDRESSES", public)
	group("PORT FORWARDS (FROM OUTSIDE)", outside)
	group("PORT FORWARDS (TARGET)", target)
	group("HTTPS SITES", sites)
	var test []string
	for _, it := range m.v.Nodes {
		if n := it.Value; n.TestPort > 0 {
			test = append(test, fmt.Sprintf("%s -> %s:%d", n.Name, n.MeshIP, n.TestPort))
		}
	}
	rows = append(rows, toolRow{header: "TEST SERVICE  (Nodes > edit > test service port)"})
	if len(test) > 0 {
		rows = append(rows, toolRow{label: "on now: " + strings.Join(test, ", ")})
	} else {
		rows = append(rows, toolRow{label: "off on every node"})
	}
	return rows
}

// publicHost is a server's first endpoint host that is not a private,
// CGNAT or mesh address.
func publicHost(n model.Node) string {
	for _, e := range n.Endpoints {
		host, _, err := net.SplitHostPort(e)
		if err != nil {
			continue
		}
		if ip, err := netip.ParseAddr(host); err == nil && (ip.IsPrivate() || netip.MustParsePrefix("100.64.0.0/10").Contains(ip)) {
			continue
		}
		return host
	}
	return ""
}

func (m *model_) toolLine(r toolRow, sel bool) string {
	marker := "  "
	if sel {
		marker = selectedStyle.Render("> ")
	}
	if r.header != "" {
		return marker + sectionStyle.Render(r.header)
	}
	if r.check.Kind == "" {
		return marker + mutedStyle.Render("    "+r.label)
	}
	return marker + "    " + valueStyle.Render(r.label) + mutedStyle.Render("  ("+r.check.Kind+")")
}

var diagKinds = []option{{"ping", "ping"}, {"my public IP", "myip"}, {"traceroute", "trace"},
	{"TCP port open?", "tcp"}, {"UDP answer (test service)", "udp"}, {"HTTP / HTTPS page", "http"}}

func (m *model_) diagForm(c diag.Check) {
	if c.Kind == "" {
		return // a header or info line
	}
	port := ""
	if c.Port > 0 {
		port = strconv.Itoa(c.Port)
	}
	m.form = newForm("Run a check from "+m.self().Name, func(v map[string]string) error {
		m.diagReq = &diag.Check{Kind: v["kind"], Target: v["target"], Port: atoi(v["port"])}
		return nil
	}).
		choice("kind", "Check", diagKinds, c.Kind).
		text("target", "Target (not for my public IP)", c.Target, "100.88.x.y, 192.168.1.20, example.com or https://…").
		text("port", "Port (tcp/udp)", port, "8099").init()
}

func (m *model_) runDiag(c diag.Check) tea.Cmd {
	return func() tea.Msg {
		var r diag.Result
		err := m.api.Post("diag", c, &r)
		return diagMsg{res: r, err: err}
	}
}

func diagText(r diag.Result, err error) string {
	if err != nil {
		return errStyle.Render("Check failed: " + err.Error())
	}
	if r.OK {
		return focusedStyle.Render("OK") + "\n\n" + r.Output
	}
	return errStyle.Render("FAILED") + "\n\n" + r.Output
}

// ---------- SETTINGS ----------

type settingRow struct {
	label, value string
	open         func()
}

func (m *model_) settingRows() []settingRow {
	netw := m.v.Network
	logServer := "automatic (first VPS relay)"
	if netw.LogServer != "" {
		logServer = m.name(netw.LogServer)
	}
	rows := []settingRow{
		{"Let's Encrypt email", dash(netw.ACMEEmail), m.settingsForm},
		{"Log server (history and logs)", fmt.Sprintf("%s, kept %d days", logServer, netw.HistoryDays()), m.historyForm},
		{"Web UI admin login", "change the username or password", m.adminForm},
	}
	for _, it := range m.v.Nodes {
		n := it.Value
		fp := n.WebFP
		if n.ID == m.v.SelfID {
			fp = m.v.Runtime.WebCertFP
		}
		if n.WebUI && n.WebTLS && fp != "" {
			name, fp := n.Name, fp
			rows = append(rows, settingRow{"Web UI certificate: " + name, fp, func() {
				m.note = "Web UI certificate of " + name + " (SHA-256). Compare it with what the browser shows before accepting:\n\n  " + fp
			}})
		}
	}
	if ca := m.v.Runtime.WebCAFP; ca != "" {
		rows = append(rows, settingRow{"Web UI CA (this server)", ca, func() {
			m.note = "Install this server's CA once per device and the browser stops warning.\nFingerprint (SHA-256):\n\n  " + ca +
				"\n\nRun `meshgate webui ca` on this server for the file and install steps per system."
		}})
	}
	rows = append(rows, settingRow{"Theme (this terminal)", m.theme, func() {
		t := nextTheme(m.theme)
		applyTheme(t)
		m.theme = t.name
		saveTheme(t.name)
	}})
	return rows
}

func (m *model_) settingLine(r settingRow, sel bool) string {
	marker := "  "
	if sel {
		marker = selectedStyle.Render("> ")
	}
	return marker + labelStyle.Render(fmt.Sprintf("%-32s", trunc(r.label, 32))) + " " + valueStyle.Render(r.value)
}

func (m *model_) historyForm() {
	servers := append([]option{{"automatic (first VPS relay)", ""}}, m.serverOptions()...)
	days := ""
	if m.v.Network.LogDays > 0 {
		days = strconv.Itoa(m.v.Network.LogDays)
	}
	m.form = newForm("Log server (traffic history and logs)", func(v map[string]string) error {
		return m.api.Post("history-settings", map[string]any{"log_server": v["server"], "log_days": atoi(v["days"])}, nil)
	}).
		choice("server", "Log server", servers, m.v.Network.LogServer).
		text("days", "Keep for (days)", days, "365").init()
}

func (m *model_) adminForm() {
	m.form = newForm("Web UI admin login", func(v map[string]string) error {
		return m.api.Post("admin", map[string]string{"username": v["user"], "password": v["pass"]}, nil)
	}).
		text("user", "Username", "", "admin").
		password("pass", "New password (8+ characters)").init()
}
