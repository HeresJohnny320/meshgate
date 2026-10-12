package store

import (
	"math/rand"
	"path/filepath"
	"testing"
	"time"
)

func fixedClock(s *Store, t time.Time) { s.now = func() time.Time { return t } }

func TestLastWriteWinsConverges(t *testing.T) {
	a, _ := Open("", "a")
	b, _ := Open("", "b")
	c, _ := Open("", "c")
	ts := time.Unix(1000, 0)
	for _, s := range []*Store{a, b, c} {
		fixedClock(s, ts) // identical clocks force tie-breaks on origin
	}
	a.Put("forward/x", "from-a", Cluster)
	b.Put("forward/x", "from-b", Cluster)
	c.Put("forward/y", "from-c", Cluster)
	c.Delete("forward/x", Cluster)

	all := [][]Entry{}
	for _, s := range []*Store{a, b, c} {
		e, _ := s.Since(0)
		all = append(all, e)
	}
	// Deliver every batch to every store in a random order.
	r := rand.New(rand.NewSource(1))
	for _, s := range []*Store{a, b, c} {
		order := r.Perm(len(all))
		for _, i := range order {
			s.Merge(all[i])
		}
	}
	for _, s := range []*Store{a, b, c} {
		// a and b tie on forward/x (b wins on origin); c's delete came after
		// its own put of y, so it carries a higher version and wins overall.
		if _, ok := s.Raw("forward/x"); ok {
			t.Fatalf("%s: forward/x should be deleted", s.nodeID)
		}
		if v, ok := Get[string](s, "forward/y"); !ok || v != "from-c" {
			t.Fatalf("%s: forward/y = %q %v", s.nodeID, v, ok)
		}
	}
}

func TestNewerWriteWins(t *testing.T) {
	a, _ := Open("", "a")
	b, _ := Open("", "b")
	fixedClock(a, time.Unix(1000, 0))
	fixedClock(b, time.Unix(2000, 0))
	a.Put("node/1", "old", Cluster)
	b.Put("node/1", "new", Cluster)
	ea, _ := a.Since(0)
	eb, _ := b.Since(0)
	a.Merge(eb)
	b.Merge(ea)
	for _, s := range []*Store{a, b} {
		if v, _ := Get[string](s, "node/1"); v != "new" {
			t.Fatalf("%s got %q", s.nodeID, v)
		}
	}
	// a's clock jumped forward when it merged b's write, so a's next write
	// wins even though a's wall clock is behind.
	a.Put("node/1", "newest", Cluster)
	ea, _ = a.Since(0)
	b.Merge(ea)
	if v, _ := Get[string](b, "node/1"); v != "newest" {
		t.Fatalf("hlc: got %q", v)
	}
}

func TestLocalOverrideNotReplicated(t *testing.T) {
	a, _ := Open("", "a")
	a.Put("forward/f", "cluster", Cluster)
	a.Put("forward/f", "local", Local)
	if v, _ := Get[string](a, "forward/f"); v != "local" {
		t.Fatalf("override: %q", v)
	}
	es, _ := a.Since(0)
	for _, e := range es {
		if string(e.Value) == `"local"` {
			t.Fatal("local entry leaked into sync")
		}
	}
	a.ClearLocal("forward/f")
	if v, _ := Get[string](a, "forward/f"); v != "cluster" {
		t.Fatalf("after clear: %q", v)
	}
}

func TestIncrementalSyncSeesLateOldEntries(t *testing.T) {
	// b received an entry with an old version after a already pulled from b.
	// Seq-based sync must still deliver it.
	a, _ := Open("", "a")
	b, _ := Open("", "b")
	c, _ := Open("", "c")
	fixedClock(c, time.Unix(10, 0))
	fixedClock(b, time.Unix(500, 0))
	b.Put("node/b", "b", Cluster)
	eb, cursor := b.Since(0)
	a.Merge(eb)
	c.Put("node/c", "c", Cluster) // older clock
	ec, _ := c.Since(0)
	b.Merge(ec)
	more, _ := b.Since(cursor)
	a.Merge(more)
	if _, ok := a.Raw("node/c"); !ok {
		t.Fatal("late entry lost")
	}
}

func TestPersistence(t *testing.T) {
	p := filepath.Join(t.TempDir(), "state.json")
	a, _ := Open(p, "a")
	a.Put("node/1", "x", Cluster)
	a.Put("forward/2", "y", Local)
	b, err := Open(p, "a")
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := Get[string](b, "node/1"); v != "x" {
		t.Fatal("cluster not persisted")
	}
	if !b.IsLocal("forward/2") {
		t.Fatal("local not persisted")
	}
	if b.Seq() != a.Seq() {
		t.Fatal("seq not persisted")
	}
}
