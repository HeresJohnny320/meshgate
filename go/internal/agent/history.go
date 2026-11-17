package agent

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/heresjohnny320/meshgate/internal/history"
	"github.com/heresjohnny320/meshgate/internal/model"
	"github.com/heresjohnny320/meshgate/internal/store"
)

// histState: this server's samples for the current 5 minutes (RAM) and the
// 5-minute points not yet delivered to the log server.
type histState struct {
	acc     history.Accumulator
	mu      sync.Mutex
	pending []history.Point
	store   *history.Store // used when this node is the log server
}

// maxPending bounds what is kept while the log server is unreachable
// (about a day of a busy mesh).
const maxPending = 50000

// sampleHistory feeds the current rates (from the traffic meters) into the
// 5-minute accumulator.
func (a *Agent) sampleHistory() {
	t := a.localTraffic()
	for id, r := range t.Forwards {
		a.hist.acc.Sample("f:"+id, r.In, r.Out, r.InRate, r.OutRate)
	}
	for id, r := range t.Routes {
		// HTTPS and plain HTTP separately (the counters hold both together).
		a.hist.acc.Sample("r:"+id, r.In-min(r.In, r.HTTP.In), r.Out-min(r.Out, r.HTTP.Out),
			max(0, r.InRate-r.HTTP.InRate), max(0, r.OutRate-r.HTTP.OutRate))
		a.hist.acc.Sample("h:"+id, r.HTTP.In, r.HTTP.Out, r.HTTP.InRate, r.HTTP.OutRate)
	}
	for id, r := range t.Monitors {
		a.hist.acc.Sample("m:"+id, r.In, r.Out, r.InRate, r.OutRate)
	}
	for id, r := range t.Peers {
		a.hist.acc.Sample("d:"+id+"@"+a.Cfg.NodeID, r.In, r.Out, r.InRate, r.OutRate)
	}
}

// historyLabels describes the series this server measures, so the log
// server can show (and keep) the port, target IP, hostname and nodes of each.
func (a *Agent) historyLabels() map[string]history.Label {
	nodes := map[string]model.Node{}
	for _, n := range store.List[model.Node](a.Store, model.KindNode) {
		nodes[n.ID] = n
	}
	name := func(id string) string {
		if n, ok := nodes[id]; ok && n.Name != "" {
			return n.Name
		}
		return id
	}
	target := func(ip, node string) string {
		if ip != "" {
			return ip
		}
		return nodes[node].MeshIP
	}
	self := a.Cfg.NodeID
	l := map[string]history.Label{}
	for _, f := range store.List[model.Forward](a.Store, model.KindForward) {
		if f.EdgeNode != self {
			continue
		}
		port := strconv.Itoa(f.ListenPort)
		if lo, hi := f.Ports(); hi > lo {
			port = fmt.Sprintf("%d-%d", lo, hi)
		}
		l["f:"+f.ID] = history.Label{"kind": "forward", "name": f.Name, "proto": string(f.Proto), "port": port,
			"target_ip": target(f.TargetIP, f.TargetNode), "target_port": strconv.Itoa(f.TargetPort),
			"target_node": name(f.TargetNode), "node": name(self)}
	}
	for _, r := range store.List[model.HTTPRoute](a.Store, model.KindRoute) {
		if r.EdgeNode != self {
			continue
		}
		for _, k := range [][3]string{{"r:", "https", "443"}, {"h:", "http", "80"}} {
			l[k[0]+r.ID] = history.Label{"kind": k[1], "hostname": strings.ToLower(r.Hostname), "port": k[2],
				"target_ip": target(r.TargetIP, r.TargetNode), "target_port": strconv.Itoa(r.TargetPort),
				"target_node": name(r.TargetNode), "node": name(self)}
		}
	}
	for _, m := range store.List[model.Monitor](a.Store, model.KindMonitor) {
		if m.Node == self {
			l["m:"+m.ID] = history.Label{"kind": "monitor", "name": m.Name, "proto": m.Proto, "port": m.Ports,
				"target_ip": m.IP, "node": name(self)}
		}
	}
	for id, n := range nodes {
		if id != self {
			l["d:"+id+"@"+self] = history.Label{"kind": "link", "node": name(self), "peer": name(id), "peer_ip": n.MeshIP}
		}
	}
	return l
}

// histPost is what servers send the log server every 5 minutes (v0.2.17
// servers sent only the points, as a JSON array).
type histPost struct {
	Points []history.Point          `json:"points"`
	Labels map[string]history.Label `json:"labels,omitempty"`
}

// flushHistory closes the interval that started at start and delivers all
// pending points to the log server (or keeps them for the next try).
func (a *Agent) flushHistory(start time.Time) {
	pts := a.hist.acc.Flush(start.Unix())
	a.hist.mu.Lock()
	a.hist.pending = append(a.hist.pending, pts...)
	if over := len(a.hist.pending) - maxPending; over > 0 {
		a.hist.pending = a.hist.pending[over:]
	}
	send := append([]history.Point(nil), a.hist.pending...)
	a.hist.mu.Unlock()

	netw, _ := store.Get[model.Network](a.Store, model.Key(model.KindNetwork, "main"))
	srv := a.logServer(netw)
	labels := a.historyLabels()
	var err error
	switch {
	case len(send) == 0:
	case srv.ID == a.Cfg.NodeID:
		if err = a.localHistory().Append(send); err == nil {
			err = a.localHistory().SetLabels(labels, true)
		}
	default:
		err = postJSON(a.meshURL(srv, "/v1/history"), histPost{Points: send, Labels: labels})
	}
	if err != nil {
		log.Printf("traffic history: %d points kept for later: %v", len(send), err)
		return
	}
	a.hist.mu.Lock()
	a.hist.pending = a.hist.pending[len(send):]
	a.hist.mu.Unlock()
	if srv.ID == a.Cfg.NodeID {
		a.localHistory().Maintain(time.Now(), netw.HistoryDays())
	} else {
		a.moveHistory(srv)
	}
}

// moveHistory hands the days this server stored while it was the log server
// to the current one, deleting each file once the new server has it.
func (a *Agent) moveHistory(srv model.Node) {
	st := a.localHistory()
	for _, name := range st.Files() {
		data, err := st.Export(name)
		if err != nil {
			continue
		}
		res, err := (&http.Client{Timeout: 60 * time.Second}).Post(
			a.meshURL(srv, "/v1/history/import?name="+name), "application/octet-stream", bytes.NewReader(data))
		if err != nil {
			log.Printf("traffic history: moving %s to log server %s: %v (retrying later)", name, srv.Name, err)
			return
		}
		res.Body.Close()
		if res.StatusCode != http.StatusOK {
			log.Printf("traffic history: moving %s to log server %s: %s (retrying later)", name, srv.Name, res.Status)
			return
		}
		st.Remove(name)
		log.Printf("traffic history: moved %s to the log server %s", name, srv.Name)
	}
}

func (a *Agent) localHistory() *history.Store {
	if a.hist.store == nil {
		a.hist.store = &history.Store{Dir: filepath.Join(a.Cfg.DataDir, "history")}
	}
	return a.hist.store
}

// logServer is the node that stores the history: the chosen one, else the
// first relay by name, else the first server.
func (a *Agent) logServer(netw model.Network) model.Node {
	nodes := store.List[model.Node](a.Store, model.KindNode)
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].Name < nodes[j].Name })
	var first model.Node
	for _, n := range nodes {
		if n.Kind != model.NodeServer {
			continue
		}
		if n.ID == netw.LogServer {
			return n
		}
		if first.ID == "" || (n.Relay && !first.Relay) {
			first = n
		}
	}
	if first.ID == "" {
		first, _ = store.Get[model.Node](a.Store, model.Key(model.KindNode, a.Cfg.NodeID))
	}
	return first
}

func (a *Agent) meshURL(n model.Node, path string) string {
	port := n.MeshPort
	if port == 0 {
		port = model.DefaultMeshPort
	}
	return "http://" + net.JoinHostPort(n.MeshIP, strconv.Itoa(port)) + path
}

func postJSON(url string, v any) error {
	b, _ := json.Marshal(v)
	res, err := (&http.Client{Timeout: 15 * time.Second}).Post(url, "application/json", bytes.NewReader(b))
	if err != nil {
		return err
	}
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("%s", res.Status)
	}
	return nil
}

// histQuery is one request for history: a preset range, or a download's
// from/to (unix seconds) and step.
type histQuery struct {
	rng            string
	from, to, step int64
}

// maxExportPoints bounds a download (a month of 5-minute points, a year of
// hourly ones, per series).
const maxExportPoints = 9000

// exportSteps are the download resolutions, in seconds.
var exportSteps = map[int64]bool{300: true, 900: true, 3600: true, 86400: true}

func parseHistQuery(q url.Values) (histQuery, error) {
	if q.Get("from") == "" {
		rng := q.Get("range")
		r, ok := history.Ranges[rng]
		if !ok {
			rng, r = "1d", history.Ranges["1d"]
		}
		step := int64(r.Step / time.Second)
		to := time.Now().Truncate(r.Step).Add(r.Step).Unix()
		return histQuery{rng: rng, from: to - int64(r.Span/time.Second), to: to, step: step}, nil
	}
	from, err1 := strconv.ParseInt(q.Get("from"), 10, 64)
	to, err2 := strconv.ParseInt(q.Get("to"), 10, 64)
	step, err3 := strconv.ParseInt(q.Get("step"), 10, 64)
	switch {
	case err1 != nil || err2 != nil || err3 != nil || from <= 0 || to <= from:
		return histQuery{}, fmt.Errorf("pick a start and an end after it")
	case !exportSteps[step]:
		return histQuery{}, fmt.Errorf("detail must be 5 minutes, 15 minutes, 1 hour or 1 day")
	case (to-from)/step > maxExportPoints:
		return histQuery{}, fmt.Errorf("too much detail for that period (%d points per series, at most %d): pick a coarser detail or a shorter period",
			(to-from)/step, maxExportPoints)
	}
	return histQuery{rng: "custom", from: from, to: to, step: step}, nil
}

func (h histQuery) values() url.Values {
	if h.rng != "custom" {
		return url.Values{"range": {h.rng}}
	}
	return url.Values{"from": {strconv.FormatInt(h.from, 10)}, "to": {strconv.FormatInt(h.to, 10)}, "step": {strconv.FormatInt(h.step, 10)}}
}

// History answers the UIs: points for a range or a download, from the log
// server.
func (a *Agent) History(q url.Values) (any, error) {
	hq, err := parseHistQuery(q)
	if err != nil {
		return nil, err
	}
	netw, _ := store.Get[model.Network](a.Store, model.Key(model.KindNetwork, "main"))
	srv := a.logServer(netw)
	if srv.ID != a.Cfg.NodeID {
		res, err := (&http.Client{Timeout: 60 * time.Second}).Get(a.meshURL(srv, "/v1/history?"+hq.values().Encode()))
		if err != nil {
			return nil, fmt.Errorf("log server %s is not reachable: %v", srv.Name, err)
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusOK {
			msg, _ := io.ReadAll(io.LimitReader(res.Body, 300))
			return nil, fmt.Errorf("log server %s: %s %s", srv.Name, res.Status, strings.TrimSpace(string(msg)))
		}
		var out histAnswer
		if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
			return nil, err
		}
		if out.Units != "bytes" { // a v0.2.17 log server answers average speeds
			for _, bs := range out.Series {
				for i := range bs {
					bs[i][1] *= float64(out.Step)
					bs[i][2] *= float64(out.Step)
				}
			}
			out.Units = "bytes"
		}
		return out, nil
	}
	return a.queryHistory(hq, srv.Name)
}

// histAnswer is a history query's answer. Buckets are [start, bytes in,
// bytes out, peak in, peak out] (peaks in bytes per second).
type histAnswer struct {
	Range  string                      `json:"range"`
	From   int64                       `json:"from"`
	To     int64                       `json:"to"`
	Step   int64                       `json:"step"`
	Server string                      `json:"server"`
	Units  string                      `json:"units"`
	Series map[string][]history.Bucket `json:"series"`
	Labels map[string]history.Label    `json:"labels"`
}

func (a *Agent) queryHistory(hq histQuery, server string) (histAnswer, error) {
	series, err := a.localHistory().Query(hq.from, hq.to, hq.step)
	if err != nil {
		return histAnswer{}, err
	}
	labels := a.localHistory().Labels()
	for k := range labels {
		if series[k] == nil {
			delete(labels, k)
		}
	}
	return histAnswer{Range: hq.rng, From: hq.from, To: hq.to, Step: hq.step, Server: server, Units: "bytes",
		Series: series, Labels: labels}, nil
}

// serveHistory is the log server's side: servers post points, any server
// may query (mesh port).
func (a *Agent) serveHistory(w http.ResponseWriter, r *http.Request) {
	caller, ok := a.serverCaller(w, r)
	if !ok {
		return
	}
	if r.Method == http.MethodPost {
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 16<<20))
		var post histPost
		if t := bytes.TrimSpace(body); err == nil && len(t) > 0 && t[0] == '[' {
			err = json.Unmarshal(t, &post.Points)
		} else if err == nil {
			err = json.Unmarshal(body, &post)
		}
		if err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		// Each server reports its own device links only.
		own := func(k string) bool { return !strings.HasPrefix(k, "d:") || hasSuffix(k, "@"+caller.ID) }
		for i := range post.Points {
			if !own(post.Points[i].Key) {
				post.Points[i].Key = ""
			}
		}
		for k := range post.Labels {
			if !own(k) {
				delete(post.Labels, k)
			}
		}
		if err := a.localHistory().Append(post.Points); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		a.localHistory().SetLabels(post.Labels, true)
		return
	}
	hq, err := parseHistQuery(r.URL.Query())
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	self, _ := store.Get[model.Node](a.Store, model.Key(model.KindNode, a.Cfg.NodeID))
	out, err := a.queryHistory(hq, self.Name)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}

// serveHistoryImport takes a day file from the previous log server.
func (a *Agent) serveHistoryImport(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.serverCaller(w, r); !ok {
		return
	}
	netw, _ := store.Get[model.Network](a.Store, model.Key(model.KindNetwork, "main"))
	if a.logServer(netw).ID != a.Cfg.NodeID {
		http.Error(w, "not the log server", http.StatusConflict)
		return
	}
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 256<<20))
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if _, err := a.localHistory().Import(r.URL.Query().Get("name"), data); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
	}
}

// serverCaller is the mesh server making the request, or a 403.
func (a *Agent) serverCaller(w http.ResponseWriter, r *http.Request) (model.Node, bool) {
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	for _, n := range store.List[model.Node](a.Store, model.KindNode) {
		if n.MeshIP == ip && n.Kind == model.NodeServer {
			return n, true
		}
	}
	http.Error(w, "only servers", http.StatusForbidden)
	return model.Node{}, false
}

func hasSuffix(s, suf string) bool { return len(s) >= len(suf) && s[len(s)-len(suf):] == suf }
