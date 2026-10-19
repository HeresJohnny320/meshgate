package agent

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"path/filepath"
	"sort"
	"strconv"
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

// History answers the UIs: points for a range, from the log server.
func (a *Agent) History(rng string) (any, error) {
	r, ok := history.Ranges[rng]
	if !ok {
		rng, r = "1d", history.Ranges["1d"]
	}
	netw, _ := store.Get[model.Network](a.Store, model.Key(model.KindNetwork, "main"))
	srv := a.logServer(netw)
	if srv.ID != a.Cfg.NodeID {
		res, err := (&http.Client{Timeout: 20 * time.Second}).Get(a.meshURL(srv, "/v1/history?range="+rng))
		if err != nil {
			return nil, fmt.Errorf("log server %s is not reachable: %v", srv.Name, err)
		}
		defer res.Body.Close()
		var out map[string]any
		if res.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("log server %s: %s", srv.Name, res.Status)
		}
		return out, json.NewDecoder(res.Body).Decode(&out)
	}
	return a.queryHistory(rng, r.Span, r.Step, srv.Name)
}

func (a *Agent) queryHistory(rng string, span, step time.Duration, server string) (map[string]any, error) {
	to := time.Now().Truncate(step).Add(step).Unix()
	from := to - int64(span/time.Second)
	series, err := a.localHistory().Query(from, to, int64(step/time.Second))
	if err != nil {
		return nil, err
	}
	return map[string]any{"range": rng, "from": from, "to": to, "step": int64(step / time.Second),
		"server": server, "series": series}, nil
}

// serveHistory is the log server's side: servers post points, any server
// may query (mesh port).
func (a *Agent) serveHistory(w http.ResponseWriter, r *http.Request) {
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	caller, ok := model.Node{}, false
	for _, n := range store.List[model.Node](a.Store, model.KindNode) {
		if n.MeshIP == ip && n.Kind == model.NodeServer {
			caller, ok = n, true
		}
	}
	if !ok {
		http.Error(w, "only servers", http.StatusForbidden)
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
	rng := r.URL.Query().Get("range")
	rr, ok := history.Ranges[rng]
	if !ok {
		rng, rr = "1d", history.Ranges["1d"]
	}
	self, _ := store.Get[model.Node](a.Store, model.Key(model.KindNode, a.Cfg.NodeID))
	out, err := a.queryHistory(rng, rr.Span, rr.Step, self.Name)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}

func hasSuffix(s, suf string) bool { return len(s) >= len(suf) && s[len(s)-len(suf):] == suf }
