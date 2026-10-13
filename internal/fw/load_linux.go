package fw

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
)

// Render returns the rules to load on this OS.
func Render(p Plan) string { return RenderNFT(p) }

// Load applies rendered rules.
func Load(rendered string) error {
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(rendered)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Remove deletes meshgate's rules.
func Remove() error {
	return Load("table inet meshgate\ndelete table inet meshgate\n")
}

// DetectWAN is only needed for pf.
func DetectWAN() string { return "" }

// IsPfSense is always false on Linux.
func IsPfSense() bool { return false }

// ReadCounters returns meshgate's nft counters (name -> packets, bytes).
// They restart from zero whenever the table is reloaded.
func ReadCounters() map[string][2]uint64 {
	out, err := exec.Command("nft", "-j", "list", "counters", "table", "inet", "meshgate").Output()
	if err != nil {
		return nil
	}
	var doc struct {
		Nftables []struct {
			Counter *struct {
				Name    string `json:"name"`
				Packets uint64 `json:"packets"`
				Bytes   uint64 `json:"bytes"`
			} `json:"counter"`
		} `json:"nftables"`
	}
	if json.Unmarshal(out, &doc) != nil {
		return nil
	}
	m := map[string][2]uint64{}
	for _, e := range doc.Nftables {
		if e.Counter != nil {
			m[e.Counter.Name] = [2]uint64{e.Counter.Packets, e.Counter.Bytes}
		}
	}
	return m
}
