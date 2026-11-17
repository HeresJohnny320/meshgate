package agent

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/heresjohnny320/meshgate/internal/fw"
	"github.com/heresjohnny320/meshgate/internal/history"
	"github.com/heresjohnny320/meshgate/internal/model"
	"github.com/heresjohnny320/meshgate/internal/store"
	"github.com/heresjohnny320/meshgate/internal/traffic"
)

// trafficInterval is how often counters are read; speeds are averaged over it.
const trafficInterval = 5 * time.Second

// meters turns raw counters (which restart from zero when the firewall table
// is reloaded or a WireGuard peer is re-added) into totals and speeds.
type meters struct {
	mu sync.Mutex
	m  map[string]*meter
	at time.Time
}

type meter struct {
	last, total uint64
	rate        float64
}

// observe records raw counter values read now.
func (ms *meters) observe(raw map[string]uint64) {
	ms.mu.Lock()
	defer ms.mu.Unlock()
	now := time.Now()
	dt := now.Sub(ms.at).Seconds()
	if ms.m == nil {
		ms.m = map[string]*meter{}
	}
	for name, v := range raw {
		m := ms.m[name]
		if m == nil {
			ms.m[name] = &meter{last: v, total: v}
			continue
		}
		d := v - m.last
		if v < m.last { // counter restarted
			d = v
		}
		m.total += d
		m.last = v
		if dt > 0.5 {
			m.rate = float64(d) / dt
		}
	}
	if dt > 0.5 || ms.at.IsZero() {
		ms.at = now
	}
}

func (ms *meters) get(name string) (uint64, float64) {
	ms.mu.Lock()
	defer ms.mu.Unlock()
	if m := ms.m[name]; m != nil {
		return m.total, m.rate
	}
	return 0, 0
}

func (ms *meters) rate(in, out string) traffic.Rate {
	ti, ri := ms.get(in)
	to, ro := ms.get(out)
	return traffic.Rate{In: ti, Out: to, InRate: ri, OutRate: ro}
}

// readTraffic samples every counter this node has.
func (a *Agent) readTraffic() {
	raw := map[string]uint64{}
	for name, v := range fw.ReadCounters() {
		if strings.HasPrefix(name, "a_") {
			raw[name] = v[0] // access rules: packets of new connections
		} else {
			raw[name] = v[1] // forwards: bytes
		}
	}
	byKey := map[string]string{}
	for _, n := range store.List[model.Node](a.Store, model.KindNode) {
		byKey[n.PublicKey] = n.ID
	}
	for key, st := range a.wg.Stats() {
		if id := byKey[key]; id != "" {
			raw["p_"+id+"_in"], raw["p_"+id+"_out"] = uint64(st.RxBytes), uint64(st.TxBytes)
		}
	}
	hosts, _ := a.proxy.Stats()
	for h, s := range hosts {
		raw["r_"+h+"_req"], raw["r_"+h+"_err"], raw["r_"+h+"_in"], raw["r_"+h+"_out"] = s.Requests, s.Errors, s.In, s.Out
		raw["r_"+h+"_hin"], raw["r_"+h+"_hout"] = s.HTTPIn, s.HTTPOut
	}
	a.meters.observe(raw)
}

// localTraffic is this node's report.
func (a *Agent) localTraffic() traffic.Node {
	t := traffic.Node{Node: a.Cfg.NodeID, Forwards: map[string]traffic.Rate{}, Routes: map[string]traffic.Route{},
		ACLs: map[string]uint64{}, Peers: map[string]traffic.Rate{}, Monitors: map[string]traffic.Rate{}}
	ms := &a.meters
	for _, f := range store.List[model.Forward](a.Store, model.KindForward) {
		if f.EdgeNode == a.Cfg.NodeID {
			t.Forwards[f.ID] = ms.rate(fw.CounterName("f", f.ID, "in"), fw.CounterName("f", f.ID, "out"))
		}
	}
	for _, r := range store.List[model.HTTPRoute](a.Store, model.KindRoute) {
		if r.EdgeNode != a.Cfg.NodeID {
			continue
		}
		h := strings.ToLower(r.Hostname)
		rt := traffic.Route{Rate: ms.rate("r_"+h+"_in", "r_"+h+"_out"), HTTP: ms.rate("r_"+h+"_hin", "r_"+h+"_hout")}
		rt.Requests, rt.ReqRate = ms.get("r_" + h + "_req")
		rt.Errors, _ = ms.get("r_" + h + "_err")
		t.Routes[r.ID] = rt
	}
	for _, acl := range store.List[model.ACL](a.Store, model.KindACL) {
		if acl.Node == a.Cfg.NodeID {
			t.ACLs[acl.ID], _ = ms.get(fw.CounterName("a", acl.ID, ""))
		}
	}
	for _, m := range store.List[model.Monitor](a.Store, model.KindMonitor) {
		if m.Node == a.Cfg.NodeID {
			t.Monitors[m.ID] = ms.rate(fw.CounterName("m", m.ID, "in"), fw.CounterName("m", m.ID, "out"))
		}
	}
	for _, n := range store.List[model.Node](a.Store, model.KindNode) {
		if n.ID != a.Cfg.NodeID {
			if r := ms.rate("p_"+n.ID+"_in", "p_"+n.ID+"_out"); r.In+r.Out > 0 {
				t.Peers[n.ID] = r
			}
		}
	}
	_, t.Recent = a.proxy.Stats()
	return t
}

// Traffic gathers every server's report: this one directly, the others over
// the mesh (servers that do not answer in time are left out).
func (a *Agent) Traffic() []traffic.Node {
	out := []traffic.Node{a.localTraffic()}
	var mu sync.Mutex
	var wg sync.WaitGroup
	client := &http.Client{Timeout: 3 * time.Second}
	for _, n := range store.List[model.Node](a.Store, model.KindNode) {
		if n.ID == a.Cfg.NodeID || n.Kind != model.NodeServer || n.MeshIP == "" {
			continue
		}
		port := n.MeshPort
		if port == 0 {
			port = model.DefaultMeshPort
		}
		wg.Add(1)
		go func(url string) {
			defer wg.Done()
			res, err := client.Get(url)
			if err != nil {
				return
			}
			defer res.Body.Close()
			var t traffic.Node
			if res.StatusCode == 200 && json.NewDecoder(res.Body).Decode(&t) == nil {
				mu.Lock()
				out = append(out, t)
				mu.Unlock()
			}
		}("http://" + net.JoinHostPort(n.MeshIP, strconv.Itoa(port)) + "/v1/traffic")
	}
	wg.Wait()
	return out
}

// serveTraffic answers other servers' Traffic calls (mesh port, servers only).
func (a *Agent) serveTraffic(w http.ResponseWriter, r *http.Request) {
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	for _, n := range store.List[model.Node](a.Store, model.KindNode) {
		if n.MeshIP == ip && n.Kind == model.NodeServer {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(a.localTraffic())
			return
		}
	}
	http.Error(w, "unknown node", http.StatusForbidden)
}

func (a *Agent) trafficLoop(ctx context.Context) {
	t := time.NewTicker(trafficInterval)
	defer t.Stop()
	interval := time.Now().Truncate(history.Interval)
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			a.readTraffic()
			if cur := now.Truncate(history.Interval); cur.After(interval) {
				go a.flushHistory(interval) // the 5 minutes that just ended
				interval = cur
			}
			a.sampleHistory()
		}
	}
}
