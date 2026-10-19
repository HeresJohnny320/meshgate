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
		a.hist.acc.Sample("f:"+id, r.InRate, r.OutRate)
	}
	for id, r := range t.Routes {
		a.hist.acc.Sample("r:"+id, r.InRate, r.OutRate)
	}
	for id, r := range t.Peers {
		a.hist.acc.Sample("d:"+id+"@"+a.Cfg.NodeID, r.InRate, r.OutRate)
	}
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
	var err error
	switch {
	case len(send) == 0:
	case srv.ID == a.Cfg.NodeID:
		err = a.localHistory().Append(send)
	default:
		err = postJSON(a.meshURL(srv, "/v1/history"), send)
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
		var out map[string]any
		return out, json.NewDecoder(res.Body).Decode(&out)
	}
	return a.queryHistory(hq, srv.Name)
}

func (a *Agent) queryHistory(hq histQuery, server string) (map[string]any, error) {
	series, err := a.localHistory().Query(hq.from, hq.to, hq.step)
	if err != nil {
		return nil, err
	}
	return map[string]any{"range": hq.rng, "from": hq.from, "to": hq.to, "step": hq.step,
		"server": server, "series": series}, nil
}

// serveHistory is the log server's side: servers post points, any server
// may query (mesh port).
func (a *Agent) serveHistory(w http.ResponseWriter, r *http.Request) {
	caller, ok := a.serverCaller(w, r)
	if !ok {
		return
	}
	if r.Method == http.MethodPost {
		var pts []history.Point
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<20)).Decode(&pts); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		// Each server reports its own measurements only.
		for i := range pts {
			if len(pts[i].Key) > 2 && pts[i].Key[0] == 'd' && !hasSuffix(pts[i].Key, "@"+caller.ID) {
				pts[i].Key = ""
			}
		}
		if err := a.localHistory().Append(pts); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
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
