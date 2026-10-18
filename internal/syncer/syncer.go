// Package syncer replicates the store between nodes over the mesh.
//
// Every server node serves a small HTTP API on its mesh IP. Nodes push their
// changes to all servers immediately and pull from every server periodically
// (anti-entropy), so config converges even if pushes were lost or the web UI
// node is down. Received changes are pushed onwards (gossip).
//
// The API only listens on the mesh IP, so every request has already been
// authenticated by WireGuard; the source IP identifies the calling node.
package syncer

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/heresjohnny320/meshgate/internal/join"
	"github.com/heresjohnny320/meshgate/internal/model"
	"github.com/heresjohnny320/meshgate/internal/store"
)

// PullInterval is the anti-entropy period.
const PullInterval = 5 * time.Second

type batch struct {
	Entries []store.Entry `json:"entries"`
	Seq     uint64        `json:"seq"`
}

// Syncer runs both sides of replication for one node.
type Syncer struct {
	Store    *store.Store
	SelfID   string
	MeshPort int

	mu      sync.Mutex
	pulled  map[string]uint64 // peer -> their seq we have seen
	pushed  map[string]uint64 // peer -> our seq they have
	lastOK  map[string]time.Time
	client  *http.Client
	trigger chan struct{}
}

// New creates a syncer.
func New(s *store.Store, selfID string, meshPort int) *Syncer {
	return &Syncer{
		Store: s, SelfID: selfID, MeshPort: meshPort,
		pulled: map[string]uint64{}, pushed: map[string]uint64{}, lastOK: map[string]time.Time{},
		client:  &http.Client{Timeout: 8 * time.Second},
		trigger: make(chan struct{}, 1),
	}
}

func (s *Syncer) self() (model.Node, bool) {
	return store.Get[model.Node](s.Store, model.Key(model.KindNode, s.SelfID))
}

// nodeByIP finds the node that owns a mesh IP.
func (s *Syncer) nodeByIP(ip string) (model.Node, bool) {
	for _, n := range store.List[model.Node](s.Store, model.KindNode) {
		if n.MeshIP == ip {
			return n, true
		}
	}
	return model.Node{}, false
}

// Handler serves the mesh API.
func (s *Syncer) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/ping", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, s.SelfID)
	})
	mux.HandleFunc("GET /v1/sync", func(w http.ResponseWriter, r *http.Request) {
		caller, ok := s.caller(r)
		if !ok {
			http.Error(w, "unknown node", http.StatusForbidden)
			return
		}
		since, _ := strconv.ParseUint(r.URL.Query().Get("since"), 10, 64)
		entries, seq := s.Store.Since(since)
		writeJSON(w, batch{Entries: join.FilterFor(caller, entries), Seq: seq})
	})
	mux.HandleFunc("POST /v1/sync", func(w http.ResponseWriter, r *http.Request) {
		caller, ok := s.caller(r)
		if !ok {
			http.Error(w, "unknown node", http.StatusForbidden)
			return
		}
		var b batch
		if err := json.NewDecoder(io.LimitReader(r.Body, 32<<20)).Decode(&b); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		accepted := Authorize(caller, b.Entries)
		if _, err := s.Store.Merge(accepted); err != nil {
			log.Printf("sync: merge from %s: %v", caller.Name, err)
		}
		writeJSON(w, map[string]int{"accepted": len(accepted)})
	})
	return mux
}

// Authorize drops entries the caller may not write. Servers may write
// anything; clients may only publish their own status.
func Authorize(caller model.Node, in []store.Entry) []store.Entry {
	if caller.Writer() {
		return in
	}
	own := model.Key(model.KindStatus, caller.ID)
	var out []store.Entry
	for _, e := range in {
		if e.Key == own && e.Origin == caller.ID {
			out = append(out, e)
		}
	}
	return out
}

func (s *Syncer) caller(r *http.Request) (model.Node, bool) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return model.Node{}, false
	}
	return s.nodeByIP(host)
}

// Kick schedules an immediate push.
func (s *Syncer) Kick() {
	select {
	case s.trigger <- struct{}{}:
	default:
	}
}

// Run pushes on change and pulls periodically until ctx ends.
func (s *Syncer) Run(ctx context.Context) {
	changes := s.Store.Subscribe()
	t := time.NewTicker(PullInterval)
	defer t.Stop()
	s.round(ctx, true)
	for {
		select {
		case <-ctx.Done():
			return
		case <-changes:
			s.round(ctx, false)
		case <-s.trigger:
			s.round(ctx, false)
		case <-t.C:
			s.round(ctx, true)
		}
	}
}

func (s *Syncer) round(ctx context.Context, pull bool) {
	self, ok := s.self()
	if !ok {
		return
	}
	var wg sync.WaitGroup
	for _, n := range store.List[model.Node](s.Store, model.KindNode) {
		if n.ID == s.SelfID || !n.Writer() || n.MeshIP == "" {
			continue
		}
		wg.Add(1)
		go func(n model.Node) {
			defer wg.Done()
			s.push(ctx, self, n)
			if pull {
				s.pull(ctx, n)
			}
		}(n)
	}
	wg.Wait()
}

func (s *Syncer) url(n model.Node, path string) string {
	port := n.MeshPort
	if port == 0 {
		port = s.MeshPort // older records: everyone used the default
	}
	return "http://" + net.JoinHostPort(n.MeshIP, strconv.Itoa(port)) + path
}

func (s *Syncer) push(ctx context.Context, self model.Node, peer model.Node) {
	s.mu.Lock()
	from := s.pushed[peer.ID]
	s.mu.Unlock()
	entries, seq := s.Store.Since(from)
	if !self.Writer() {
		entries = Authorize(self, entries)
	}
	if len(entries) == 0 {
		s.setPushed(peer.ID, seq)
		return
	}
	body, _ := json.Marshal(batch{Entries: entries})
	req, _ := http.NewRequestWithContext(ctx, "POST", s.url(peer, "/v1/sync"), bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	res, err := s.client.Do(req)
	if err != nil {
		return
	}
	io.Copy(io.Discard, res.Body)
	res.Body.Close()
	if res.StatusCode == 200 {
		s.setPushed(peer.ID, seq)
	}
}

func (s *Syncer) setPushed(id string, seq uint64) {
	s.mu.Lock()
	if seq > s.pushed[id] {
		s.pushed[id] = seq
	}
	s.mu.Unlock()
}

func (s *Syncer) pull(ctx context.Context, peer model.Node) {
	s.mu.Lock()
	since := s.pulled[peer.ID]
	s.mu.Unlock()
	req, _ := http.NewRequestWithContext(ctx, "GET", s.url(peer, "/v1/sync?since="+strconv.FormatUint(since, 10)), nil)
	res, err := s.client.Do(req)
	if err != nil {
		return
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return
	}
	var b batch
	if err := json.NewDecoder(res.Body).Decode(&b); err != nil {
		return
	}
	if _, err := s.Store.Merge(b.Entries); err != nil {
		log.Printf("sync: merge from %s: %v", peer.Name, err)
		return
	}
	s.mu.Lock()
	if b.Seq < since {
		// Peer state was reset (reinstalled); start over.
		b.Seq = 0
	}
	s.pulled[peer.ID] = b.Seq
	s.lastOK[peer.ID] = time.Now()
	s.mu.Unlock()
}

// LastContact reports when each server was last pulled successfully.
func (s *Syncer) LastContact() map[string]time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]time.Time{}
	for k, v := range s.lastOK {
		out[k] = v
	}
	return out
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}
