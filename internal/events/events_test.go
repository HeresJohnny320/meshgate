package events

import (
	"fmt"
	"log"
	"testing"
	"time"
)

func TestBufferKeepsUndeliveredLines(t *testing.T) {
	b := NewBuffer("pfsense", 3, 4)
	clock := time.Unix(1_800_000_000, 0)
	b.now = func() time.Time { return clock }
	l := log.New(b, "", log.LstdFlags)
	l.Print("link to vps DOWN: no WireGuard handshake")
	b.Write([]byte("half a li"))
	if got := b.Snapshot(); len(got.Pending) != 1 || got.Pending[0].Text != "link to vps DOWN: no WireGuard handshake" || got.Pending[0].T != clock.Unix() {
		t.Fatalf("log prefix not stripped or partial line kept: %+v", got)
	}
	b.Write([]byte("ne\n"))
	for i := 0; i < 3; i++ {
		l.Printf("same line")
	}
	st := b.Snapshot()
	if len(st.Pending) != 3 || st.Dropped != 2 || st.Pending[0].Text != "same line" {
		t.Fatalf("limit: %+v", st)
	}
	if len(st.Recent) != 4 || st.Recent[0].Text != "half a line" {
		t.Fatalf("recent: %+v", st.Recent)
	}

	// Deliver two of the identical lines while another arrives: exactly
	// the undelivered ones stay.
	sent := b.Take(2)
	l.Print("link to vps UP again after 35m0s")
	b.Ack(sent)
	st = b.Snapshot()
	if len(st.Pending) != 2 || st.Pending[0].Text != "same line" || st.Pending[1].Text != "link to vps UP again after 35m0s" {
		t.Fatalf("after ack: %+v", st.Pending)
	}
}

func TestStoreQuery(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	day1 := time.Date(2026, 10, 27, 23, 16, 0, 0, time.UTC).Unix()
	day2 := day1 + 3600 // next UTC day
	err := s.Append([]Entry{
		{T: day1, Node: "pf", Text: "link to vps DOWN: no WireGuard handshake"},
		{T: day1 + 10, Node: "vps", Text: "http: TLS handshake error from 1.2.3.4"},
		{T: day2, Node: "pf", Text: "link to vps UP again after 35m0s"},
	})
	if err != nil {
		t.Fatal(err)
	}
	// A line held in RAM arrives late, for an earlier time.
	s.Append([]Entry{{T: day1 + 5, Node: "pf", Text: "warning: wireguard interface: gone"}})

	all, _ := s.Query(Query{})
	var got []string
	for _, e := range all {
		got = append(got, fmt.Sprint(e.T-day1, " ", e.Node))
	}
	if fmt.Sprint(got) != "[3600 pf 10 vps 5 pf 0 pf]" {
		t.Fatalf("order: %v", got)
	}
	imp, _ := s.Query(Query{Important: true, Node: "pf"})
	if len(imp) != 3 {
		t.Fatalf("important pf: %+v", imp)
	}
	txt, _ := s.Query(Query{Text: "tls", Limit: 5})
	if len(txt) != 1 || txt[0].Node != "vps" {
		t.Fatalf("text: %+v", txt)
	}
	if lim, _ := s.Query(Query{Limit: 2}); len(lim) != 2 {
		t.Fatalf("limit: %d", len(lim))
	}
	if since, _ := s.Query(Query{Since: day2}); len(since) != 1 {
		t.Fatalf("since: %+v", since)
	}

	s.Maintain(time.Unix(day2, 0).AddDate(0, 0, 1), 1)
	if left, _ := s.Query(Query{}); len(left) != 1 || left[0].T != day2 {
		t.Fatalf("maintain kept %+v", left)
	}
}
