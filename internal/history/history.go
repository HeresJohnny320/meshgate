// Package history keeps traffic history: every server averages its 5-second
// traffic samples in RAM and hands 5-minute points (average and peak, in and
// out) to the mesh's log server, which appends them to one file per day.
// Past days are gzip-compressed and days beyond the retention are deleted,
// so a year of a typical mesh stays around 10-20 MB.
package history

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// Interval is the resolution of stored points (MESHGATE_HISTORY_INTERVAL
// shortens it for tests, e.g. "20s").
var Interval = 5 * time.Minute

func init() {
	if d, err := time.ParseDuration(os.Getenv("MESHGATE_HISTORY_INTERVAL")); err == nil && d >= time.Second {
		Interval = d
	}
}

// Point is one series over one interval. Rates are bytes per second; In is
// toward the target / received by the measuring node.
type Point struct {
	T       int64   `json:"t"` // start of the interval (unix seconds)
	Key     string  `json:"k"` // e.g. "f:<forward id>", "r:<route id>", "d:<peer>@<server>"
	AvgIn   float32 `json:"ai"`
	AvgOut  float32 `json:"ao"`
	PeakIn  float32 `json:"pi"`
	PeakOut float32 `json:"po"`
}

// Accumulator turns frequent rate samples into Points.
type Accumulator struct {
	mu sync.Mutex
	m  map[string]*acc
}

type acc struct {
	n               float64
	sumIn, sumOut   float64
	peakIn, peakOut float64
}

// Sample records the current rates of a series.
func (a *Accumulator) Sample(key string, in, out float64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.m == nil {
		a.m = map[string]*acc{}
	}
	s := a.m[key]
	if s == nil {
		s = &acc{}
		a.m[key] = s
	}
	s.n++
	s.sumIn += in
	s.sumOut += out
	s.peakIn = math.Max(s.peakIn, in)
	s.peakOut = math.Max(s.peakOut, out)
}

// Flush returns the points of the interval starting at t and starts over.
// Series that saw no traffic at all are left out.
func (a *Accumulator) Flush(t int64) []Point {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []Point
	for k, s := range a.m {
		if s.peakIn == 0 && s.peakOut == 0 {
			continue
		}
		out = append(out, Point{T: t, Key: k, AvgIn: float32(s.sumIn / s.n), AvgOut: float32(s.sumOut / s.n),
			PeakIn: float32(s.peakIn), PeakOut: float32(s.peakOut)})
	}
	a.m = nil
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

// Store is the log server's on-disk history: Dir/YYYY-MM-DD.bin for today,
// Dir/YYYY-MM-DD.bin.gz for past days.
type Store struct {
	Dir string
	mu  sync.Mutex
}

func day(t int64) string { return time.Unix(t, 0).UTC().Format("2006-01-02") }

// Append adds points to their days' files.
func (s *Store) Append(points []Point) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return err
	}
	byDay := map[string][]Point{}
	for _, p := range points {
		if len(p.Key) == 0 || len(p.Key) > 255 {
			continue
		}
		byDay[day(p.T)] = append(byDay[day(p.T)], p)
	}
	for d, ps := range byDay {
		f, err := os.OpenFile(filepath.Join(s.Dir, d+".bin"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		w := bufio.NewWriter(f)
		for _, p := range ps {
			encode(w, p)
		}
		err = w.Flush()
		f.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

// Record: uint32 T, uint8 key length, key, 4 x float32.
func encode(w io.Writer, p Point) {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], uint32(p.T))
	w.Write(b[:])
	w.Write([]byte{byte(len(p.Key))})
	io.WriteString(w, p.Key)
	for _, v := range []float32{p.AvgIn, p.AvgOut, p.PeakIn, p.PeakOut} {
		binary.LittleEndian.PutUint32(b[:], math.Float32bits(v))
		w.Write(b[:])
	}
}

func decode(r *bufio.Reader) (Point, error) {
	var p Point
	var b [4]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return p, err
	}
	p.T = int64(binary.LittleEndian.Uint32(b[:]))
	n, err := r.ReadByte()
	if err != nil {
		return p, err
	}
	key := make([]byte, n)
	if _, err := io.ReadFull(r, key); err != nil {
		return p, err
	}
	p.Key = string(key)
	var v [4]float32
	for i := range v {
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return p, err
		}
		v[i] = math.Float32frombits(binary.LittleEndian.Uint32(b[:]))
	}
	p.AvgIn, p.AvgOut, p.PeakIn, p.PeakOut = v[0], v[1], v[2], v[3]
	return p, nil
}

// Maintain compresses past days and deletes days older than keepDays.
func (s *Store) Maintain(now time.Time, keepDays int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	today := now.UTC().Format("2006-01-02")
	oldest := now.UTC().AddDate(0, 0, -keepDays).Format("2006-01-02")
	entries, err := os.ReadDir(s.Dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	for _, e := range entries {
		name := e.Name()
		d := strings.TrimSuffix(strings.TrimSuffix(name, ".gz"), ".bin")
		path := filepath.Join(s.Dir, name)
		switch {
		case len(d) != 10:
		case d < oldest:
			os.Remove(path)
		case strings.HasSuffix(name, ".bin") && d < today:
			if err := gzipFile(path); err != nil {
				return err
			}
		}
	}
	return nil
}

// gzipFile compresses a day into its .gz, after what the .gz already holds
// (points imported from a previous log server): gzip members concatenate.
func gzipFile(path string) error {
	in, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	old, err := os.ReadFile(path + ".gz")
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	tmp := path + ".gz.tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	f.Write(old)
	zw, _ := gzip.NewWriterLevel(f, gzip.BestCompression)
	zw.Write(in)
	if err := zw.Close(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path+".gz"); err != nil {
		return err
	}
	return os.Remove(path)
}

var fileName = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}\.bin(\.gz)?$`)

// Files lists the stored day files (oldest first).
func (s *Store) Files() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	entries, _ := os.ReadDir(s.Dir)
	var out []string
	for _, e := range entries {
		if fileName.MatchString(e.Name()) {
			out = append(out, e.Name())
		}
	}
	return out
}

// Export returns a day file's contents, for moving it to a new log server.
func (s *Store) Export(name string) ([]byte, error) {
	if !fileName.MatchString(name) {
		return nil, errors.New("bad file name")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return os.ReadFile(filepath.Join(s.Dir, name))
}

// Remove deletes a day file once it has been moved.
func (s *Store) Remove(name string) error {
	if !fileName.MatchString(name) {
		return errors.New("bad file name")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return os.Remove(filepath.Join(s.Dir, name))
}

// Import adds the points of a day file from another log server to this
// store (merged with what is already here for that day).
func (s *Store) Import(name string, data []byte) (int, error) {
	if !fileName.MatchString(name) {
		return 0, errors.New("bad file name")
	}
	var r io.Reader = bytes.NewReader(data)
	if strings.HasSuffix(name, ".gz") {
		zr, err := gzip.NewReader(r)
		if err != nil {
			return 0, err
		}
		defer zr.Close()
		r = zr
	}
	br := bufio.NewReader(r)
	var pts []Point
	for {
		p, err := decode(br)
		if err != nil {
			break
		}
		pts = append(pts, p)
	}
	return len(pts), s.Append(pts)
}

// Bucket is a series over one step of a query: averages are averaged,
// peaks are the highest peak.
type Bucket [5]float64 // start, avg in, avg out, peak in, peak out

// Query returns the series between from and to, grouped into steps.
func (s *Store) Query(from, to, step int64) (map[string][]Bucket, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	type agg struct {
		n                        float64
		sumIn, sumOut, pIn, pOut float64
	}
	sums := map[string]map[int64]*agg{}
	for d := time.Unix(from, 0).UTC().Truncate(24 * time.Hour); d.Unix() <= to; d = d.AddDate(0, 0, 1) {
		name := d.Format("2006-01-02")
		for _, src := range dayReaders(filepath.Join(s.Dir, name)) {
			for {
				p, err := decode(src.r)
				if err != nil {
					break
				}
				if p.T < from || p.T >= to {
					continue
				}
				b := from + (p.T-from)/step*step
				m := sums[p.Key]
				if m == nil {
					m = map[int64]*agg{}
					sums[p.Key] = m
				}
				a := m[b]
				if a == nil {
					a = &agg{}
					m[b] = a
				}
				a.n++
				a.sumIn += float64(p.AvgIn)
				a.sumOut += float64(p.AvgOut)
				a.pIn = math.Max(a.pIn, float64(p.PeakIn))
				a.pOut = math.Max(a.pOut, float64(p.PeakOut))
			}
			src.close()
		}
	}
	out := map[string][]Bucket{}
	for k, m := range sums {
		var bs []Bucket
		for t, a := range m {
			// Missing 5-minute points inside a step had no traffic.
			per := float64(step) / Interval.Seconds()
			bs = append(bs, Bucket{float64(t), a.sumIn / per, a.sumOut / per, a.pIn, a.pOut})
		}
		sort.Slice(bs, func(i, j int) bool { return bs[i][0] < bs[j][0] })
		out[k] = bs
	}
	return out, nil
}

type dayReader struct {
	r     *bufio.Reader
	close func()
}

// dayReaders opens a day's compressed part and its uncompressed part (a past
// day has both while imported points wait for the next Maintain).
func dayReaders(base string) []dayReader {
	var out []dayReader
	if f, err := os.Open(base + ".bin.gz"); err == nil {
		if zr, err := gzip.NewReader(f); err == nil {
			out = append(out, dayReader{bufio.NewReader(zr), func() { zr.Close(); f.Close() }})
		} else {
			f.Close()
		}
	}
	if f, err := os.Open(base + ".bin"); err == nil {
		out = append(out, dayReader{bufio.NewReader(f), func() { f.Close() }})
	}
	return out
}

// Ranges are the periods the UIs offer, with their step.
var Ranges = map[string]struct{ Span, Step time.Duration }{
	"6h": {6 * time.Hour, 5 * time.Minute},
	"1d": {24 * time.Hour, 15 * time.Minute},
	"1w": {7 * 24 * time.Hour, 2 * time.Hour},
	"1m": {30 * 24 * time.Hour, 8 * time.Hour},
	"1y": {365 * 24 * time.Hour, 24 * time.Hour},
}
