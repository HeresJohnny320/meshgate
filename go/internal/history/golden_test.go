package history

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestWriteGolden writes a day file and its points so the Rust build can
// prove it reads and writes the same bytes. Run with
// MESHGATE_GOLDEN=../rust/testdata (from go/) to refresh.
func TestWriteGolden(t *testing.T) {
	dir := os.Getenv("MESHGATE_GOLDEN")
	if dir == "" {
		t.Skip("MESHGATE_GOLDEN not set")
	}
	pts := []Point{
		{T: 1640995200, Key: "f:abc", In: 123456789012, Out: 42, PeakIn: 1234.5, PeakOut: 0.25},
		{T: 1640995500, Key: "d:node1@node2", In: 0, Out: 1, PeakIn: 0, PeakOut: 3e9},
		{T: 1640995800, Key: "r:x", In: 1 << 63, Out: 127, PeakIn: 1, PeakOut: 2},
	}
	s := &Store{Dir: filepath.Join(dir, "history")}
	os.RemoveAll(s.Dir)
	if err := s.Append(pts); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(pts)
	os.WriteFile(filepath.Join(dir, "history", "points.json"), b, 0o644)
}
