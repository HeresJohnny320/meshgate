package history

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAccumulatorExactBytes(t *testing.T) {
	var a Accumulator
	a.Sample("f:mc", 5000, 900, 0, 0) // baseline: what was counted before is not this interval's
	a.Sample("f:mc", 5100, 910, 20, 2)
	a.Sample("f:mc", 5400, 940, 60, 6)
	a.Sample("f:idle", 7, 7, 0, 0)
	a.Sample("f:idle", 7, 7, 0, 0)
	ps := a.Flush(1000)
	if len(ps) != 1 || ps[0].In != 400 || ps[0].Out != 40 || ps[0].PeakIn != 60 || ps[0].PeakOut != 6 {
		t.Fatalf("points %+v", ps)
	}
	// The next interval continues from the last reading; a reset counter
	// (firewall reloaded) counts from zero.
	a.Sample("f:mc", 5500, 950, 10, 1)
	a.Sample("f:mc", 30, 3, 10, 1)
	ps = a.Flush(1300)
	if len(ps) != 1 || ps[0].In != 130 || ps[0].Out != 13 {
		t.Fatalf("next interval %+v", ps)
	}
}

func TestPointJSONFromOldServers(t *testing.T) {
	var ps []Point
	json.Unmarshal([]byte(`[{"t":1,"k":"f:a","ai":10,"ao":2,"pi":50,"po":9},{"t":2,"k":"f:b","bi":7,"bo":3}]`), &ps)
	sec := uint64(Interval.Seconds())
	if ps[0].In != 10*sec || ps[0].Out != 2*sec || ps[0].PeakIn != 50 || ps[1].In != 7 || ps[1].Out != 3 {
		t.Fatalf("%+v", ps)
	}
}

func TestStoreAppendQueryCompressRetention(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	day0 := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	var ps []Point
	for i := 0; i < 3*288; i++ { // three days of 5-minute points
		ps = append(ps, Point{T: day0.Add(time.Duration(i) * Interval).Unix(), Key: "f:mc", In: 1000, Out: 100, PeakIn: 5000, PeakOut: 500})
	}
	if err := s.Append(ps); err != nil {
		t.Fatal(err)
	}
	// Day 3 is "today": days 1 and 2 get compressed, nothing is old enough to go.
	if err := s.Maintain(day0.AddDate(0, 0, 2).Add(time.Hour), 365); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"2026-10-01.dat.gz", "2026-10-02.dat.gz", "2026-10-03.dat"} {
		if _, err := os.Stat(filepath.Join(s.Dir, f)); err != nil {
			t.Errorf("missing %s", f)
		}
	}
	got, err := s.Query(day0.Unix(), day0.AddDate(0, 0, 3).Unix(), int64(24*time.Hour/time.Second))
	if err != nil {
		t.Fatal(err)
	}
	bs := got["f:mc"]
	perDay := float64(24*time.Hour/Interval) * 1000
	if len(bs) != 3 || bs[0][1] != perDay || bs[0][2] != perDay/10 || bs[2][3] != 5000 {
		t.Fatalf("daily buckets %v", bs)
	}
	// Retention: keep 1 day, so the first two days go.
	s.Maintain(day0.AddDate(0, 0, 2).Add(time.Hour), 1)
	if _, err := os.Stat(filepath.Join(s.Dir, "2026-10-01.dat.gz")); err == nil {
		t.Error("old day kept past retention")
	}
}

func TestReadsOldFiles(t *testing.T) {
	// A v0.2.17 day file: average and peak speeds.
	s := &Store{Dir: t.TempDir()}
	day0 := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	f, _ := os.Create(filepath.Join(s.Dir, "2026-10-01.bin"))
	w := bufio.NewWriter(f)
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], uint32(day0.Unix()))
	w.Write(b[:])
	w.Write([]byte{4})
	w.WriteString("f:mc")
	for _, v := range []float32{10, 1, 80, 8} {
		binary.LittleEndian.PutUint32(b[:], math.Float32bits(v))
		w.Write(b[:])
	}
	w.Flush()
	f.Close()
	s.Append([]Point{{T: day0.Add(Interval).Unix(), Key: "f:mc", In: 5, Out: 5}})
	s.Maintain(day0.AddDate(0, 0, 1), 365)
	got, _ := s.Query(day0.Unix(), day0.AddDate(0, 0, 1).Unix(), 86400)
	if b := got["f:mc"]; len(b) != 1 || b[0][1] != 10*Interval.Seconds()+5 || b[0][3] != 80 {
		t.Fatalf("old + new day: %v", got)
	}
}

func TestLabels(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	s.SetLabels(map[string]Label{"f:a": {"kind": "forward", "name": "mc", "port": "25565"}}, true)
	s.SetLabels(map[string]Label{"f:a": {"kind": "forward", "name": "minecraft", "port": "25565"}}, true)
	s.SetLabels(map[string]Label{"f:a": {"kind": "forward", "name": "imported"}, "f:b": {"name": "b"}}, false)
	fresh := &Store{Dir: s.Dir}
	l := fresh.Labels()
	if l["f:a"]["name"] != "minecraft" || l["f:b"]["name"] != "b" {
		t.Fatalf("labels %v", l)
	}
}

func TestMoveToNewLogServer(t *testing.T) {
	day0 := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	mk := func(day int, key string) []Point {
		var ps []Point
		for i := 0; i < 288; i++ {
			ps = append(ps, Point{T: day0.AddDate(0, 0, day).Add(time.Duration(i) * Interval).Unix(), Key: key, In: 100, PeakIn: 100})
		}
		return ps
	}
	now := day0.AddDate(0, 0, 1).Add(time.Hour)
	// The old log server has day 0 (compressed) and part of day 1.
	old := &Store{Dir: t.TempDir()}
	old.Append(append(mk(0, "f:a"), mk(1, "f:a")[:12]...))
	old.SetLabels(map[string]Label{"f:a": {"name": "a"}}, true)
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
		if len(a) != 2 || a[0][1] != 28800 || a[1][1] != 28800 || len(b) != 1 || b[0][1] != 28800 {
			t.Fatalf("%s: merged history %v / %v", when, a, b)
		}
	}
	check("before maintain")
	nw.Maintain(now, 365) // folds the imported day 0 into its .gz
	check("after maintain")
	if nw.Labels()["f:a"]["name"] != "a" {
		t.Fatal("labels not moved")
	}
	if _, err := nw.Import("../x.dat", nil); err == nil {
		t.Fatal("bad name accepted")
	}
}

func TestYearSize(t *testing.T) {
	// 20 series, one day of 5-minute points, compressed: the year estimate.
	s := &Store{Dir: t.TempDir()}
	day0 := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	var ps []Point
	for i := 0; i < 288; i++ {
		for k := 0; k < 20; k++ {
			v := uint64((i*37+k*101)%5000+1) * 300
			ps = append(ps, Point{T: day0.Add(time.Duration(i) * Interval).Unix(), Key: "f:" + string(rune('a'+k)) + "1b2c3d4e5f6",
				In: v * 1000, Out: v * 333, PeakIn: float32(v * 7), PeakOut: float32(v * 3)})
		}
	}
	s.Append(ps)
	s.Maintain(day0.AddDate(0, 0, 1), 365)
	fi, err := os.Stat(filepath.Join(s.Dir, "2026-10-01.dat.gz"))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("20 series: %d KB/day compressed, ~%.1f MB/year", fi.Size()/1024, float64(fi.Size())*365/1e6)
}
