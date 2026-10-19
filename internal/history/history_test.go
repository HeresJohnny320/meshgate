package history

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAccumulator(t *testing.T) {
	var a Accumulator
	for _, r := range [][2]float64{{100, 10}, {300, 30}, {200, 20}} {
		a.Sample("f:mc", r[0], r[1])
	}
	a.Sample("f:idle", 0, 0)
	ps := a.Flush(1000)
	if len(ps) != 1 || ps[0].AvgIn != 200 || ps[0].PeakIn != 300 || ps[0].AvgOut != 20 || ps[0].PeakOut != 30 {
		t.Fatalf("points %+v", ps)
	}
	if len(a.Flush(1300)) != 0 {
		t.Fatal("not reset")
	}
}

func TestStoreAppendQueryCompressRetention(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	day0 := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	var ps []Point
	for i := 0; i < 3*288; i++ { // three days of 5-minute points
		ps = append(ps, Point{T: day0.Add(time.Duration(i) * Interval).Unix(), Key: "f:mc", AvgIn: 1000, AvgOut: 100, PeakIn: 5000, PeakOut: 500})
	}
	if err := s.Append(ps); err != nil {
		t.Fatal(err)
	}
	// Day 3 is "today": days 1 and 2 get compressed, nothing is old enough to go.
	if err := s.Maintain(day0.AddDate(0, 0, 2).Add(time.Hour), 365); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"2026-10-01.bin.gz", "2026-10-02.bin.gz", "2026-10-03.bin"} {
		if _, err := os.Stat(filepath.Join(s.Dir, f)); err != nil {
			t.Errorf("missing %s", f)
		}
	}
	got, err := s.Query(day0.Unix(), day0.AddDate(0, 0, 3).Unix(), int64(24*time.Hour/time.Second))
	if err != nil {
		t.Fatal(err)
	}
	bs := got["f:mc"]
	if len(bs) != 3 || bs[0][1] != 1000 || bs[2][3] != 5000 {
		t.Fatalf("daily buckets %v", bs)
	}
	// Only half a day of data: the day's average halves (the rest was idle).
	half := &Store{Dir: t.TempDir()}
	half.Append(ps[:144])
	got, _ = half.Query(day0.Unix(), day0.AddDate(0, 0, 1).Unix(), int64(24*time.Hour/time.Second))
	if b := got["f:mc"]; len(b) != 1 || b[0][1] != 500 {
		t.Fatalf("idle time not counted: %v", b)
	}
	// Retention: keep 1 day, so the first two days go.
	s.Maintain(day0.AddDate(0, 0, 2).Add(time.Hour), 1)
	if _, err := os.Stat(filepath.Join(s.Dir, "2026-10-01.bin.gz")); err == nil {
		t.Error("old day kept past retention")
	}
}

func TestYearSize(t *testing.T) {
	// 20 series, one day of 5-minute points, compressed: the year estimate.
	s := &Store{Dir: t.TempDir()}
	day0 := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	var ps []Point
	for i := 0; i < 288; i++ {
		for k := 0; k < 20; k++ {
			v := float32((i*37+k*101)%5000) + 1
			ps = append(ps, Point{T: day0.Add(time.Duration(i) * Interval).Unix(), Key: "f:" + string(rune('a'+k)) + "1b2c3d4e5f6",
				AvgIn: v, AvgOut: v / 3, PeakIn: v * 2, PeakOut: v})
		}
	}
	s.Append(ps)
	s.Maintain(day0.AddDate(0, 0, 1), 365)
	fi, err := os.Stat(filepath.Join(s.Dir, "2026-10-01.bin.gz"))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("20 series: %d KB/day compressed, ~%.1f MB/year", fi.Size()/1024, float64(fi.Size())*365/1e6)
}

func TestMoveToNewLogServer(t *testing.T) {
	day0 := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	mk := func(day int, key string) []Point {
		var ps []Point
		for i := 0; i < 288; i++ {
			ps = append(ps, Point{T: day0.AddDate(0, 0, day).Add(time.Duration(i) * Interval).Unix(), Key: key, AvgIn: 100, PeakIn: 100})
		}
		return ps
	}
	now := day0.AddDate(0, 0, 1).Add(time.Hour)
	// The old log server has day 0 (compressed) and part of day 1.
	old := &Store{Dir: t.TempDir()}
	old.Append(append(mk(0, "f:a"), mk(1, "f:a")[:12]...))
	old.Maintain(now, 365)
	// The new one already has day 0 compressed (another series) and the rest of day 1.
	nw := &Store{Dir: t.TempDir()}
	nw.Append(append(mk(0, "f:b"), mk(1, "f:a")[12:]...))
	nw.Maintain(now, 365)

	for _, name := range old.Files() {
		data, err := old.Export(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := nw.Import(name, data); err != nil {
			t.Fatal(name, err)
		}
		old.Remove(name)
	}
	if len(old.Files()) != 0 {
		t.Fatal("old server kept files")
	}
	check := func(when string) {
		got, _ := nw.Query(day0.Unix(), day0.AddDate(0, 0, 2).Unix(), int64(24*time.Hour/time.Second))
		a, b := got["f:a"], got["f:b"]
		if len(a) != 2 || a[0][1] != 100 || a[1][1] != 100 || len(b) != 1 || b[0][1] != 100 {
			t.Fatalf("%s: merged history %v / %v", when, a, b)
		}
	}
	check("before maintain")
	nw.Maintain(now, 365) // folds the imported day 0 into its .gz
	check("after maintain")
	if _, err := nw.Import("../x.bin", nil); err == nil {
		t.Fatal("bad name accepted")
	}
}
