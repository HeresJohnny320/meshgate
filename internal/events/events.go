// Package events gathers meshgate's log lines from every node in one place.
// Each node copies its log into a Buffer: the newest lines not yet
// delivered stay in RAM (viewable on that node) until the mesh's log server
// has them, so a node cut off from the mesh loses nothing short of a
// restart. The log server appends them to one JSON-lines file per day and
// deletes days beyond the traffic history's retention.
package events

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// Entry is one log line of one node.
type Entry struct {
	T    int64  `json:"t"` // unix seconds
	Node string `json:"node"`
	Text string `json:"text"`
	seq  uint64 // order in this node's Buffer (identical lines stay distinct)
}

// Important matches the lines worth seeing first: links going down or up,
// path changes, restarts, warnings and errors.
var Important = regexp.MustCompile(`(?i)\b(DOWN|UP again|path to|restarted|recreated|updated|warning|resolved|error|failed|panic)\b`)

// Buffer is an io.Writer for package log that keeps the lines in RAM.
type Buffer struct {
	Node    string
	Max     int // undelivered lines kept (oldest dropped beyond)
	Recent  int // lines kept for viewing on this node, delivered or not
	now     func() time.Time
	mu      sync.Mutex
	pending []Entry
	recent  []Entry
	dropped int
	partial []byte
	seq     uint64
}

// NewBuffer keeps up to max undelivered lines and the last recent lines.
func NewBuffer(node string, max, recent int) *Buffer {
	return &Buffer{Node: node, Max: max, Recent: recent, now: time.Now}
}

// logPrefix is what package log puts in front (date and time); the entry
// has its own timestamp.
var logPrefix = regexp.MustCompile(`^\d{4}/\d\d/\d\d \d\d:\d\d:\d\d(\.\d+)? `)

// Write takes whole lines; a partial line waits for its end.
func (b *Buffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.partial = append(b.partial, p...)
	for {
		i := bytes.IndexByte(b.partial, '\n')
		if i < 0 {
			break
		}
		line := logPrefix.ReplaceAllString(strings.TrimRight(string(b.partial[:i]), "\r"), "")
		b.partial = b.partial[i+1:]
		if line == "" {
			continue
		}
		b.seq++
		e := Entry{T: b.now().Unix(), Node: b.Node, Text: line, seq: b.seq}
		b.pending = append(b.pending, e)
		if over := len(b.pending) - b.Max; over > 0 {
			b.pending = b.pending[over:]
			b.dropped += over
		}
		b.recent = append(b.recent, e)
		if over := len(b.recent) - b.Recent; over > 0 {
			b.recent = b.recent[over:]
		}
	}
	return len(p), nil
}

// Take returns up to n of the oldest undelivered lines (a copy).
func (b *Buffer) Take(n int) []Entry {
	b.mu.Lock()
	defer b.mu.Unlock()
	n = min(n, len(b.pending))
	return append([]Entry(nil), b.pending[:n]...)
}

// Ack drops what Take returned once the log server has it. Lines dropped
// for space meanwhile are fine: everything up to the last sent line goes.
func (b *Buffer) Ack(sent []Entry) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(sent) == 0 {
		return
	}
	last := sent[len(sent)-1].seq
	i := 0
	for i < len(b.pending) && b.pending[i].seq <= last {
		i++
	}
	b.pending = b.pending[i:]
}

// State is what this node holds in RAM, for its own UIs.
type State struct {
	Pending []Entry `json:"pending"` // not yet on the log server
	Recent  []Entry `json:"recent"`  // the last lines, delivered or not
	Dropped int     `json:"dropped"` // lost to the size limit while undelivered
}

// Snapshot copies the RAM state.
func (b *Buffer) Snapshot() State {
	b.mu.Lock()
	defer b.mu.Unlock()
	return State{Pending: append([]Entry(nil), b.pending...), Recent: append([]Entry(nil), b.recent...), Dropped: b.dropped}
}

// Store is the log server's files: events-YYYY-MM-DD.jsonl (UTC days).
type Store struct {
	Dir string
	mu  sync.Mutex
}

var dayFile = regexp.MustCompile(`^events-(\d{4}-\d\d-\d\d)\.jsonl$`)

func day(t int64) string { return time.Unix(t, 0).UTC().Format("2006-01-02") }

// Append adds entries to their days' files.
func (s *Store) Append(es []Entry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return err
	}
	byDay := map[string][]Entry{}
	for _, e := range es {
		byDay[day(e.T)] = append(byDay[day(e.T)], e)
	}
	for d, list := range byDay {
		f, err := os.OpenFile(filepath.Join(s.Dir, "events-"+d+".jsonl"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		w := bufio.NewWriter(f)
		enc := json.NewEncoder(w)
		for _, e := range list {
			enc.Encode(e)
		}
		err = w.Flush()
		f.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

// Query is a search of the stored lines.
type Query struct {
	Since, Until int64  // unix seconds; 0 = open
	Node         string // node ID; "" = all
	Text         string // case-insensitive substring
	Important    bool
	Limit        int
}

// Matches reports whether e fits q (also used for the RAM lines).
func (q Query) Matches(e Entry) bool {
	return (q.Since == 0 || e.T >= q.Since) && (q.Until == 0 || e.T <= q.Until) &&
		(q.Node == "" || e.Node == q.Node) &&
		(q.Text == "" || strings.Contains(strings.ToLower(e.Text), strings.ToLower(q.Text))) &&
		(!q.Important || Important.MatchString(e.Text))
}

// Query returns matching lines, newest first.
func (s *Store) Query(q Query) ([]Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if q.Limit <= 0 {
		q.Limit = 500
	}
	names, _ := os.ReadDir(s.Dir)
	var days []string
	for _, n := range names {
		m := dayFile.FindStringSubmatch(n.Name())
		if m == nil {
			continue
		}
		if (q.Since > 0 && m[1] < day(q.Since)) || (q.Until > 0 && m[1] > day(q.Until)) {
			continue
		}
		days = append(days, n.Name())
	}
	sort.Sort(sort.Reverse(sort.StringSlice(days)))
	var out []Entry
	for _, name := range days {
		data, err := os.ReadFile(filepath.Join(s.Dir, name))
		if err != nil {
			continue
		}
		var dayEntries []Entry
		for _, l := range bytes.Split(data, []byte{'\n'}) {
			var e Entry
			if len(l) > 0 && json.Unmarshal(l, &e) == nil && q.Matches(e) {
				dayEntries = append(dayEntries, e)
			}
		}
		// Lines can arrive late (held in RAM), so order within the day.
		sort.SliceStable(dayEntries, func(i, j int) bool { return dayEntries[i].T > dayEntries[j].T })
		out = append(out, dayEntries...)
		if len(out) >= q.Limit {
			return out[:q.Limit], nil
		}
	}
	return out, nil
}

// Maintain deletes days older than keepDays.
func (s *Store) Maintain(now time.Time, keepDays int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cut := now.AddDate(0, 0, -keepDays).UTC().Format("2006-01-02")
	names, _ := os.ReadDir(s.Dir)
	for _, n := range names {
		if m := dayFile.FindStringSubmatch(n.Name()); m != nil && m[1] < cut {
			os.Remove(filepath.Join(s.Dir, n.Name()))
		}
	}
}
