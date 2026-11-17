package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"time"

	"github.com/heresjohnny320/meshgate/internal/events"
	"github.com/heresjohnny320/meshgate/internal/model"
	"github.com/heresjohnny320/meshgate/internal/store"
)

// The event log: every node copies its log lines into RAM (a.events) and
// hands them to the log server every 10 seconds, the way traffic history
// travels. Undelivered lines stay in RAM, and this node's UIs show them, so
// a node cut off from the mesh keeps its story until it is back.

const (
	eventsInterval = 10 * time.Second
	eventsBatch    = 500
	eventsKeep     = 2000 // undelivered lines held in RAM (about 300 KB)
	eventsRecent   = 500  // last lines kept for this node's own view
)

type eventState struct {
	buf      *events.Buffer
	store    *events.Store // used when this node is the log server
	failing  bool          // the log server could not be reached last time
	pruned   time.Time
	lastBeep time.Time
}

// captureLog copies package log's output into the RAM buffer.
func (a *Agent) captureLog() {
	a.ev.buf = events.NewBuffer(a.Cfg.NodeID, eventsKeep, eventsRecent)
	a.ev.store = &events.Store{Dir: filepath.Join(a.Cfg.DataDir, "events")}
	log.SetOutput(io.MultiWriter(os.Stderr, a.ev.buf))
}

func (a *Agent) localEvents() *events.Store { return a.ev.store }

func (a *Agent) eventsLoop(ctx context.Context) {
	t := time.NewTicker(eventsInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			a.flushEvents() // the last lines, e.g. "stopping"
			return
		case <-t.C:
			a.flushEvents()
		}
	}
}

// flushEvents delivers what is held in RAM, batch by batch.
func (a *Agent) flushEvents() {
	netw, _ := store.Get[model.Network](a.Store, model.Key(model.KindNetwork, "main"))
	srv := a.logServer(netw)
	if srv.ID == a.Cfg.NodeID && time.Since(a.ev.pruned) > time.Hour {
		a.localEvents().Maintain(time.Now(), netw.HistoryDays())
		a.ev.pruned = time.Now()
	}
	for i := 0; i < 10; i++ {
		batch := a.ev.buf.Take(eventsBatch)
		if len(batch) == 0 {
			return
		}
		var err error
		if srv.ID == a.Cfg.NodeID {
			err = a.localEvents().Append(batch)
		} else {
			err = postJSON(a.meshURL(srv, "/v1/events"), batch)
		}
		if err != nil {
			if !a.ev.failing {
				a.ev.failing = true
				log.Printf("event log: log server %s not reachable (%v); keeping lines in RAM until it is", srv.Name, err)
			}
			return
		}
		a.ev.buf.Ack(batch)
		if a.ev.failing {
			a.ev.failing = false
			log.Printf("event log: log server %s reachable again; delivered the lines held in RAM", srv.Name)
		}
	}
}

// serveEvents is the log server's side (mesh port): servers post their
// lines, any server may search.
func (a *Agent) serveEvents(w http.ResponseWriter, r *http.Request) {
	caller, ok := a.serverCaller(w, r)
	if !ok {
		return
	}
	if r.Method == http.MethodPost {
		var es []events.Entry
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<20)).Decode(&es); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		for i := range es {
			es[i].Node = caller.ID // a node speaks for itself only
		}
		if err := a.localEvents().Append(es); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}
	found, err := a.localEvents().Query(parseEventQuery(r.URL.Query()))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(found)
}

func parseEventQuery(q url.Values) events.Query {
	num := func(k string) int64 { n, _ := strconv.ParseInt(q.Get(k), 10, 64); return n }
	eq := events.Query{Since: num("since"), Until: num("until"), Node: q.Get("node"), Text: q.Get("q"),
		Important: q.Get("important") == "1", Limit: int(num("limit"))}
	if eq.Limit <= 0 || eq.Limit > 5000 {
		eq.Limit = 500
	}
	return eq
}

// eventsAnswer is what the UIs get: the log server's lines, and this
// node's RAM (Pending: not delivered yet; Recent: shown when the log
// server cannot be reached).
type eventsAnswer struct {
	Server  string         `json:"server"`
	Error   string         `json:"error,omitempty"`
	Entries []events.Entry `json:"entries"`
	Node    string         `json:"node"`
	Pending []events.Entry `json:"pending"`
	Recent  []events.Entry `json:"recent"`
	Dropped int            `json:"dropped,omitempty"`
}

// Events answers the UIs (ops "events").
func (a *Agent) Events(q url.Values) (any, error) {
	eq := parseEventQuery(q)
	netw, _ := store.Get[model.Network](a.Store, model.Key(model.KindNetwork, "main"))
	srv := a.logServer(netw)
	out := eventsAnswer{Server: srv.Name, Node: a.Cfg.NodeID, Entries: []events.Entry{}}
	if srv.ID == a.Cfg.NodeID {
		found, err := a.localEvents().Query(eq)
		if err != nil {
			out.Error = err.Error()
		}
		out.Entries = append(out.Entries, found...)
	} else {
		v := q
		v.Set("limit", strconv.Itoa(eq.Limit))
		res, err := (&http.Client{Timeout: 5 * time.Second}).Get(a.meshURL(srv, "/v1/events?"+v.Encode()))
		switch {
		case err != nil:
			out.Error = fmt.Sprintf("log server %s is not reachable: %v", srv.Name, err)
		case res.StatusCode != http.StatusOK:
			out.Error = fmt.Sprintf("log server %s: %s", srv.Name, res.Status)
			res.Body.Close()
		default:
			json.NewDecoder(res.Body).Decode(&out.Entries)
			res.Body.Close()
		}
	}
	st := a.ev.buf.Snapshot()
	out.Dropped = st.Dropped
	pick := func(es []events.Entry) []events.Entry {
		var got []events.Entry
		for _, e := range es {
			if eq.Matches(e) {
				got = append(got, e)
			}
		}
		sort.SliceStable(got, func(i, j int) bool { return got[i].T > got[j].T })
		return got
	}
	out.Pending = pick(st.Pending)
	if out.Error != "" {
		out.Recent = pick(st.Recent)
	}
	return out, nil
}

// beepFor plays the link tune unless this node is set quiet, at most once
// a minute (several links dropping together beep once).
func (a *Agent) beepFor(self model.Node, down bool) {
	if self.BeepOff || time.Since(a.ev.lastBeep) < time.Minute {
		return
	}
	a.ev.lastBeep = time.Now()
	go beep(down)
}
