// Package history keeps traffic history: every server counts the exact bytes
// of each series (forward, HTTPS/HTTP site, device link) and its peak speed in
// RAM and hands one point per 5 minutes to the mesh's log server, which
// appends them to one file per day. Past days are gzip-compressed and days
// beyond the retention are deleted, so a year of a typical mesh stays around
// 10-30 MB. Labels (name, port, target IP, hostname, node) are kept next to
// the days, so a series stays readable after its forward is deleted.
package history

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"encoding/json"
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

// Point is one series over one interval. In is toward the target / received
// by the measuring node, Out the other way.
type Point struct {
	T       int64   `json:"t"` // start of the interval (unix seconds)
	Key     string  `json:"k"` // e.g. "f:<forward id>", "r:<route id>", "h:<route id>", "d:<peer>@<server>"
	In      uint64  `json:"bi"`
	Out     uint64  `json:"bo"`
	PeakIn  float32 `json:"pi"` // bytes per second
	PeakOut float32 `json:"po"`
}

// UnmarshalJSON also takes points from v0.2.17 servers, which sent average
// speeds ("ai"/"ao") instead of bytes.
func (p *Point) UnmarshalJSON(b []byte) error {
	type plain Point
	var v struct {
		plain
		AvgIn  float64 `json:"ai"`
		AvgOut float64 `json:"ao"`
	}
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	*p = Point(v.plain)
	if p.In == 0 && p.Out == 0 && (v.AvgIn > 0 || v.AvgOut > 0) {
		p.In, p.Out = uint64(v.AvgIn*Interval.Seconds()), uint64(v.AvgOut*Interval.Seconds())
	}
	return nil
}

// Accumulator turns counter readings into Points: exact bytes from the
// counters' growth, peaks from the sampled speeds.
type Accumulator struct {
	mu   sync.Mutex
	m    map[string]*acc
	last map[string][2]uint64 // counter readings at the previous sample
}

type acc struct {
	in, out         uint64
	peakIn, peakOut float64
}

// Sample records a series' counters (bytes since some start) and current
// speeds (bytes per second).
func (a *Accumulator) Sample(key string, totalIn, totalOut uint64, rateIn, rateOut float64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.m == nil {
		a.m = map[string]*acc{}
	}
	if a.last == nil {
		a.last = map[string][2]uint64{}
	}
	s := a.m[key]
	if s == nil {
		s = &acc{}
		a.m[key] = s
	}
	if prev, ok := a.last[key]; ok { // the first reading is only the baseline
		s.in += grown(prev[0], totalIn)
		s.out += grown(prev[1], totalOut)
	}
	a.last[key] = [2]uint64{totalIn, totalOut}
	s.peakIn = math.Max(s.peakIn, rateIn)
	s.peakOut = math.Max(s.peakOut, rateOut)
}

// grown is what a counter added; a counter that went down was reset (e.g.
// the firewall reloaded) and counts from zero.
func grown(prev, now uint64) uint64 {
	if now >= prev {
		return now - prev
	}
	return now
}

// Flush returns the points of the interval starting at t and starts over.
// Series that saw no traffic at all are left out.
func (a *Accumulator) Flush(t int64) []Point {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []Point
	for k, s := range a.m {
		if s.in == 0 && s.out == 0 && s.peakIn == 0 && s.peakOut == 0 {
			continue
		}
		out = append(out, Point{T: t, Key: k, In: s.in, Out: s.out, PeakIn: float32(s.peakIn), PeakOut: float32(s.peakOut)})
	}
	a.m = nil
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

// Label describes a series: "kind" (forward, https, http, link) and e.g.
// "name", "proto", "port", "target_ip", "target_port", "target_node",
// "hostname", "node", "peer".
type Label map[string]string

// Store is the log server's on-disk history: Dir/YYYY-MM-DD.dat for today,
// Dir/YYYY-MM-DD.dat.gz for past days (.bin are v0.2.17 files: average speeds
// instead of bytes), and Dir/labels.json.
type Store struct {
	Dir    string
	mu     sync.Mutex
	labels map[string]Label // cache of labels.json
}

const labelsFile = "labels.json"

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
		f, err := os.OpenFile(filepath.Join(s.Dir, d+".dat"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
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

// Record: uint32 T, uint8 key length, key, uvarint bytes in, uvarint bytes
// out, float32 peak in, float32 peak out.
func encode(w io.Writer, p Point) {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], uint32(p.T))
	w.Write(b[:])
	w.Write([]byte{byte(len(p.Key))})
	io.WriteString(w, p.Key)
	var v [binary.MaxVarintLen64]byte
	w.Write(v[:binary.PutUvarint(v[:], p.In)])
	w.Write(v[:binary.PutUvarint(v[:], p.Out)])
	for _, f := range []float32{p.PeakIn, p.PeakOut} {
		binary.LittleEndian.PutUint32(b[:], math.Float32bits(f))
		w.Write(b[:])
	}
}

func decodeHead(r *bufio.Reader) (Point, error) {
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
	return p, nil
}

func readFloats(r *bufio.Reader, v []float32) error {
	var b [4]byte
	for i := range v {
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return err
		}
		v[i] = math.Float32frombits(binary.LittleEndian.Uint32(b[:]))
	}
	return nil
}

func decode(r *bufio.Reader) (Point, error) {
	p, err := decodeHead(r)
	if err != nil {
		return p, err
	}
	if p.In, err = binary.ReadUvarint(r); err != nil {
		return p, err
	}
	if p.Out, err = binary.ReadUvarint(r); err != nil {
		return p, err
	}
	var v [2]float32
	err = readFloats(r, v[:])
	p.PeakIn, p.PeakOut = v[0], v[1]
	return p, err
}

// decodeV1 reads a v0.2.17 record (average and peak speeds) as bytes.
func decodeV1(r *bufio.Reader) (Point, error) {
	p, err := decodeHead(r)
	if err != nil {
		return p, err
	}
	var v [4]float32
	err = readFloats(r, v[:])
	p.In, p.Out = uint64(float64(v[0])*Interval.Seconds()), uint64(float64(v[1])*Interval.Seconds())
	p.PeakIn, p.PeakOut = v[2], v[3]
	return p, err
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
		if !dayFile.MatchString(name) {
			continue
		}
		d := name[:10]
		path := filepath.Join(s.Dir, name)
		switch {
		case d < oldest:
			os.Remove(path)
		case !strings.HasSuffix(name, ".gz") && d < today:
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

var dayFile = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}\.(bin|dat)(\.gz)?$`)

func validName(name string) bool { return name == labelsFile || dayFile.MatchString(name) }

// Files lists the stored files (labels first, then days oldest first).
func (s *Store) Files() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	entries, _ := os.ReadDir(s.Dir)
	var out []string
	for _, e := range entries {
		if e.Name() == labelsFile {
			out = append([]string{labelsFile}, out...)
		} else if dayFile.MatchString(e.Name()) {
			out = append(out, e.Name())
		}
	}
	return out
}

// Export returns a file's contents, for moving it to a new log server.
func (s *Store) Export(name string) ([]byte, error) {
	if !validName(name) {
		return nil, errors.New("bad file name")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return os.ReadFile(filepath.Join(s.Dir, name))
}

// Remove deletes a file once it has been moved.
func (s *Store) Remove(name string) error {
	if !validName(name) {
		return errors.New("bad file name")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if name == labelsFile {
		s.labels = nil
	}
	return os.Remove(filepath.Join(s.Dir, name))
}

// Import adds a file from another log server to this store (merged with what
// is already here).
func (s *Store) Import(name string, data []byte) (int, error) {
	if !validName(name) {
		return 0, errors.New("bad file name")
	}
	if name == labelsFile {
		var l map[string]Label
		if err := json.Unmarshal(data, &l); err != nil {
			return 0, err
		}
		return len(l), s.SetLabels(l, false)
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
	dec := decode
	if strings.Contains(name, ".bin") {
		dec = decodeV1
	}
	br := bufio.NewReader(r)
	var pts []Point
	for {
		p, err := dec(br)
		if err != nil {
			break
		}
		pts = append(pts, p)
	}
	return len(pts), s.Append(pts)
}

// Labels returns every series' description.
func (s *Store) Labels() map[string]Label {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.loadLabels()
	out := make(map[string]Label, len(s.labels))
	for k, v := range s.labels {
		out[k] = v
	}
	return out
}

func (s *Store) loadLabels() {
	if s.labels != nil {
		return
	}
	s.labels = map[string]Label{}
	if b, err := os.ReadFile(filepath.Join(s.Dir, labelsFile)); err == nil {
		json.Unmarshal(b, &s.labels)
	}
}

// SetLabels records series descriptions. With replace, a changed description
// (a renamed forward) wins; otherwise only unknown series are added (an
// import must not overwrite newer labels).
func (s *Store) SetLabels(l map[string]Label, replace bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.loadLabels()
	changed := false
	for k, v := range l {
		if len(k) == 0 || len(k) > 255 || len(v) == 0 || len(v) > 16 {
			continue
		}
		old, ok := s.labels[k]
		if ok && (!replace || sameLabel(old, v)) {
			continue
		}
		s.labels[k], changed = v, true
	}
	if !changed {
		return nil
	}
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return err
	}
	b, _ := json.Marshal(s.labels)
	tmp := filepath.Join(s.Dir, labelsFile+".tmp")
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(s.Dir, labelsFile))
}

func sameLabel(a, b Label) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// Bucket is a series over one step of a query: bytes in and out added up,
// the highest peaks (bytes per second).
type Bucket [5]float64 // start, bytes in, bytes out, peak in, peak out

// Query returns the series between from and to, grouped into steps.
func (s *Store) Query(from, to, step int64) (map[string][]Bucket, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sums := map[string]map[int64]*Bucket{}
	for d := time.Unix(from, 0).UTC().Truncate(24 * time.Hour); d.Unix() <= to; d = d.AddDate(0, 0, 1) {
		for _, src := range dayReaders(filepath.Join(s.Dir, d.Format("2006-01-02"))) {
			for {
				p, err := src.dec(src.r)
				if err != nil {
					break
				}
				if p.T < from || p.T >= to {
					continue
				}
				start := from + (p.T-from)/step*step
				m := sums[p.Key]
				if m == nil {
					m = map[int64]*Bucket{}
					sums[p.Key] = m
				}
				b := m[start]
				if b == nil {
					b = &Bucket{float64(start)}
					m[start] = b
				}
				b[1] += float64(p.In)
				b[2] += float64(p.Out)
				b[3] = math.Max(b[3], float64(p.PeakIn))
				b[4] = math.Max(b[4], float64(p.PeakOut))
			}
			src.close()
		}
	}
	out := map[string][]Bucket{}
	for k, m := range sums {
		bs := make([]Bucket, 0, len(m))
		for _, b := range m {
			bs = append(bs, *b)
		}
		sort.Slice(bs, func(i, j int) bool { return bs[i][0] < bs[j][0] })
		out[k] = bs
	}
	return out, nil
}

type dayReader struct {
	r     *bufio.Reader
	dec   func(*bufio.Reader) (Point, error)
	close func()
}

// dayReaders opens every file of a day: compressed and uncompressed (a past
// day has both while imported points wait for the next Maintain), in the
// current format and v0.2.17's.
func dayReaders(base string) []dayReader {
	var out []dayReader
	for _, ext := range []string{".dat", ".bin"} {
		dec := decode
		if ext == ".bin" {
			dec = decodeV1
		}
		if f, err := os.Open(base + ext + ".gz"); err == nil {
			if zr, err := gzip.NewReader(f); err == nil {
				out = append(out, dayReader{bufio.NewReader(zr), dec, func() { zr.Close(); f.Close() }})
			} else {
				f.Close()
			}
		}
		if f, err := os.Open(base + ext); err == nil {
			out = append(out, dayReader{bufio.NewReader(f), dec, func() { f.Close() }})
		}
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
