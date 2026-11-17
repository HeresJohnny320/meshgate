package tui

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/heresjohnny320/meshgate/internal/events"
	"github.com/heresjohnny320/meshgate/internal/model"
)

// LOGS tab: the mesh's event log (web UI: Logs), with this node's lines
// that are still in RAM marked.

// logsResp is the ops "events" answer.
type logsResp struct {
	Server  string         `json:"server"`
	Error   string         `json:"error"`
	Entries []events.Entry `json:"entries"`
	Node    string         `json:"node"`
	Pending []events.Entry `json:"pending"`
	Recent  []events.Entry `json:"recent"`
	Dropped int            `json:"dropped"`
}

var logSpans = []struct {
	label string
	secs  int64
}{{"last hour", 3600}, {"last day", 86400}, {"last week", 604800}, {"everything kept", 0}}

// logsQuery is the query the web UI sends too (same order).
func (m *model_) logsQuery() string {
	since := ""
	if s := logSpans[m.logSpan].secs; s > 0 {
		since = strconv.FormatInt(time.Now().Unix()-s, 10)
	}
	imp := "0"
	if m.logImp {
		imp = "1"
	}
	return "events?since=" + since + "&node=" + url.QueryEscape(m.logNode) + "&q=" + url.QueryEscape(m.logText) + "&important=" + imp + "&limit=500"
}

type logRow struct {
	e   events.Entry
	ram bool
}

func (m *model_) logRows() []logRow {
	r := m.logs
	if r == nil {
		return nil
	}
	ram := map[events.Entry]bool{}
	for _, e := range r.Pending {
		ram[e] = true
	}
	var rows []logRow
	if r.Error != "" {
		for _, e := range r.Recent {
			rows = append(rows, logRow{e, ram[e]})
		}
		return rows
	}
	for _, e := range r.Pending {
		rows = append(rows, logRow{e, true})
	}
	for _, e := range r.Entries {
		rows = append(rows, logRow{e, false})
	}
	return rows
}

func (m *model_) logLine(r logRow, sel bool, width int) string {
	marker := "  "
	if sel {
		marker = selectedStyle.Render("> ")
	}
	t := time.Unix(r.e.T, 0)
	when := t.Format("15:04:05")
	if time.Since(t) > 20*time.Hour {
		when = t.Format("Jan 02 15:04")
	}
	tag := "    "
	if r.ram {
		tag = warnStyle.Render("RAM ")
	}
	text := r.e.Text
	style := valueStyle
	if events.Important.MatchString(text) {
		style = focusedStyle
	}
	if strings.Contains(text, " DOWN") {
		style = errStyle
	}
	room := max(10, width-40)
	return marker + mutedStyle.Render(fmt.Sprintf("%-12s ", when)) + tag + selectedStyle.Render(fmt.Sprintf("%-14s ", trunc(m.name(r.e.Node), 14))) +
		style.Render(trunc(text, room))
}

// logsHint says where the lines come from and what is filtered.
func (m *model_) logsHint() string {
	filter := logSpans[m.logSpan].label
	if m.logImp {
		filter += ", important only"
	}
	if m.logNode != "" {
		filter += ", node " + m.name(m.logNode)
	}
	if m.logText != "" {
		filter += `, "` + m.logText + `"`
	}
	switch {
	case m.logs == nil:
		return filter
	case m.logs.Error != "":
		return m.logs.Error + "; showing this node's RAM (" + filter + ")"
	}
	held := ""
	if n := len(m.logs.Pending); n > 0 {
		held = fmt.Sprintf("; %d line(s) waiting in RAM here", n)
	}
	return "stored on " + m.logs.Server + held + " (" + filter + ")"
}

// cycleLogNode steps the node filter through all servers.
func (m *model_) cycleLogNode() {
	ids := []string{""}
	if m.logFile {
		ids = nil // a file belongs to one node
	}
	for _, it := range m.v.Nodes {
		if it.Value.Kind == model.NodeServer {
			ids = append(ids, it.Value.ID)
		}
	}
	for i, id := range ids {
		if id == m.logNode {
			m.logNode = ids[(i+1)%len(ids)]
			return
		}
	}
	m.logNode = ""
	if m.logFile && len(ids) > 0 {
		m.logNode = ids[0]
	}
}

func (m *model_) logSearchForm() {
	m.form = newForm("Search the log", func(v map[string]string) error {
		m.logText, m.sel = v["q"], 0
		return nil
	}).text("q", "Text (empty = everything)", m.logText, "DOWN, pfsense, TLS…").init()
}

// ---------- full log file of one node ----------

// rawResp is the ops "rawlog" answer: one server's own log, oldest first.
type rawResp struct {
	Node   string   `json:"node"`
	Source string   `json:"source"`
	Lines  []string `json:"lines"`
	Error  string   `json:"error"`
}

// fileNode is the node whose log file is shown ("" = this one).
func (m *model_) fileNode() string {
	if m.logNode == "" {
		return m.v.SelfID
	}
	return m.logNode
}

func (m *model_) rawQuery() string {
	return "rawlog?node=" + url.QueryEscape(m.fileNode()) + "&n=1000"
}

// rawRows: newest first, filtered by the search text.
func (m *model_) rawRows() []string {
	if m.raw == nil {
		return nil
	}
	var out []string
	for i := len(m.raw.Lines) - 1; i >= 0; i-- {
		if l := m.raw.Lines[i]; m.logText == "" || strings.Contains(strings.ToLower(l), strings.ToLower(m.logText)) {
			out = append(out, l)
		}
	}
	return out
}

func (m *model_) rawLine(l string, sel bool, width int) string {
	marker := "  "
	if sel {
		marker = selectedStyle.Render("> ")
	}
	style := mutedStyle
	switch {
	case strings.Contains(l, " DOWN") || strings.Contains(l, "panic") || strings.Contains(l, "Main process exited"):
		style = errStyle
	case events.Important.MatchString(l):
		style = focusedStyle
	}
	return marker + style.Render(trunc(l, max(10, width-4)))
}

func (m *model_) rawHint() string {
	name := m.name(m.fileNode())
	switch {
	case m.raw == nil:
		return "full log file of " + name
	case m.raw.Error != "":
		return m.raw.Error
	}
	hint := fmt.Sprintf("full log file of %s (%s), newest first, last %d lines", name, m.raw.Source, len(m.raw.Lines))
	if m.logText != "" {
		hint += `, matching "` + m.logText + `"`
	}
	return hint
}
