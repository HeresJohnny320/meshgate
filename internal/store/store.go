// Package store is meshgate's replicated configuration store.
//
// Every node keeps a full copy on disk, so the mesh keeps running when the
// web UI (or any other node) is offline. Records are last-write-wins
// registers versioned by a hybrid logical clock; ties break on origin node ID,
// so every node converges to the same state no matter the order in which it
// hears about changes.
//
// Records have one of two scopes:
//
//   - Cluster records replicate to every node.
//   - Local records never leave this node and override the cluster record
//     with the same key ("only apply this change here").
package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Scope selects where a write applies.
type Scope string

const (
	Cluster Scope = "cluster"
	Local   Scope = "local"
)

// Entry is one versioned record.
type Entry struct {
	Key     string          `json:"key"`
	Value   json.RawMessage `json:"value,omitempty"`
	Deleted bool            `json:"deleted,omitempty"`
	Version uint64          `json:"version"`
	Origin  string          `json:"origin"`
	// Seq is this store's local arrival order. It is used for incremental
	// sync ("give me everything you received after seq N") and is reassigned
	// by every receiving store.
	Seq uint64 `json:"seq"`
}

// newer reports whether a should replace b.
func newer(a, b *Entry) bool {
	if a.Version != b.Version {
		return a.Version > b.Version
	}
	return a.Origin > b.Origin
}

type disk struct {
	NodeID  string   `json:"node_id"`
	Clock   uint64   `json:"clock"`
	Seq     uint64   `json:"seq"`
	Cluster []*Entry `json:"cluster"`
	Local   []*Entry `json:"local"`
}

// Store is safe for concurrent use.
type Store struct {
	mu      sync.RWMutex
	path    string
	nodeID  string
	clock   uint64
	seq     uint64
	cluster map[string]*Entry
	local   map[string]*Entry
	subs    []chan struct{}
	now     func() time.Time
}

// Open loads (or creates) the store at path. An empty path keeps it in memory.
func Open(path, nodeID string) (*Store, error) {
	s := &Store{
		path:    path,
		nodeID:  nodeID,
		cluster: map[string]*Entry{},
		local:   map[string]*Entry{},
		now:     time.Now,
	}
	if path == "" {
		return s, nil
	}
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	var d disk
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, fmt.Errorf("store %s: %w", path, err)
	}
	s.clock, s.seq = d.Clock, d.Seq
	for _, e := range d.Cluster {
		s.cluster[e.Key] = e
	}
	for _, e := range d.Local {
		s.local[e.Key] = e
	}
	return s, nil
}

// NodeID returns the ID this store writes as.
func (s *Store) NodeID() string { return s.nodeID }

// SetNodeID is used once, when a fresh node learns its ID during join.
func (s *Store) SetNodeID(id string) {
	s.mu.Lock()
	s.nodeID = id
	s.mu.Unlock()
}

// tick advances the hybrid logical clock. Caller holds mu.
func (s *Store) tick() uint64 {
	phys := uint64(s.now().UnixMilli()) << 16
	if phys > s.clock {
		s.clock = phys
	} else {
		s.clock++
	}
	return s.clock
}

// Put writes v (JSON-encoded) under key.
func (s *Store) Put(key string, v any, scope Scope) (Entry, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return Entry{}, err
	}
	return s.write(key, raw, false, scope)
}

// Delete removes key. A local delete hides a cluster record on this node only.
func (s *Store) Delete(key string, scope Scope) (Entry, error) {
	return s.write(key, nil, true, scope)
}

// ClearLocal drops a local override so the cluster value applies again.
func (s *Store) ClearLocal(key string) error {
	s.mu.Lock()
	_, ok := s.local[key]
	delete(s.local, key)
	err := s.saveLocked()
	s.mu.Unlock()
	if ok {
		s.notify()
	}
	return err
}

func (s *Store) write(key string, raw json.RawMessage, del bool, scope Scope) (Entry, error) {
	if key == "" || !strings.Contains(key, "/") {
		return Entry{}, fmt.Errorf("invalid key %q", key)
	}
	s.mu.Lock()
	s.seq++
	e := &Entry{Key: key, Value: raw, Deleted: del, Version: s.tick(), Origin: s.nodeID, Seq: s.seq}
	if scope == Local {
		s.local[key] = e
	} else {
		s.cluster[key] = e
	}
	err := s.saveLocked()
	out := *e
	s.mu.Unlock()
	s.notify()
	return out, err
}

// Merge applies remote cluster entries and returns the ones that changed
// this store (to be gossiped onwards).
func (s *Store) Merge(in []Entry) ([]Entry, error) {
	s.mu.Lock()
	var changed []Entry
	for i := range in {
		e := in[i]
		if e.Version > s.clock {
			s.clock = e.Version // HLC receive rule
		}
		cur, ok := s.cluster[e.Key]
		if ok && !newer(&e, cur) {
			continue
		}
		s.seq++
		e.Seq = s.seq
		s.cluster[e.Key] = &e
		changed = append(changed, e)
	}
	var err error
	if len(changed) > 0 {
		err = s.saveLocked()
	}
	s.mu.Unlock()
	if len(changed) > 0 {
		s.notify()
	}
	return changed, err
}

// Since returns cluster entries received after seq, in arrival order, and
// the highest seq in the store.
func (s *Store) Since(seq uint64) ([]Entry, uint64) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []Entry
	for _, e := range s.cluster {
		if e.Seq > seq {
			out = append(out, *e)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Seq < out[j].Seq })
	return out, s.seq
}

// Seq returns the highest local sequence number.
func (s *Store) Seq() uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.seq
}

// Raw returns the effective value of key (local override first).
func (s *Store) Raw(key string) (json.RawMessage, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e := s.effective(key)
	if e == nil || e.Deleted {
		return nil, false
	}
	return e.Value, true
}

// IsLocal reports whether key currently has a local override.
func (s *Store) IsLocal(key string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.local[key]
	return ok
}

func (s *Store) effective(key string) *Entry {
	if e, ok := s.local[key]; ok {
		return e
	}
	return s.cluster[key]
}

// Keys returns the live effective keys with the given kind prefix.
func (s *Store) Keys(kind string) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	prefix := kind + "/"
	seen := map[string]bool{}
	var out []string
	for _, m := range []map[string]*Entry{s.local, s.cluster} {
		for k := range m {
			if !strings.HasPrefix(k, prefix) || seen[k] {
				continue
			}
			seen[k] = true
			if e := s.effective(k); e != nil && !e.Deleted {
				out = append(out, k)
			}
		}
	}
	sort.Strings(out)
	return out
}

// Subscribe returns a channel that receives a value after any change.
// Notifications coalesce; consumers should re-read state.
func (s *Store) Subscribe() <-chan struct{} {
	ch := make(chan struct{}, 1)
	s.mu.Lock()
	s.subs = append(s.subs, ch)
	s.mu.Unlock()
	return ch
}

func (s *Store) notify() {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, ch := range s.subs {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

func (s *Store) saveLocked() error {
	if s.path == "" {
		return nil
	}
	d := disk{NodeID: s.nodeID, Clock: s.clock, Seq: s.seq}
	for _, e := range s.cluster {
		d.Cluster = append(d.Cluster, e)
	}
	for _, e := range s.local {
		d.Local = append(d.Local, e)
	}
	sort.Slice(d.Cluster, func(i, j int) bool { return d.Cluster[i].Seq < d.Cluster[j].Seq })
	sort.Slice(d.Local, func(i, j int) bool { return d.Local[i].Seq < d.Local[j].Seq })
	b, err := json.MarshalIndent(d, "", " ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// Get decodes the effective value of key into T.
func Get[T any](s *Store, key string) (T, bool) {
	var v T
	raw, ok := s.Raw(key)
	if !ok {
		return v, false
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		return v, false
	}
	return v, true
}

// List decodes every live record of a kind.
func List[T any](s *Store, kind string) []T {
	var out []T
	for _, k := range s.Keys(kind) {
		if v, ok := Get[T](s, k); ok {
			out = append(out, v)
		}
	}
	return out
}
