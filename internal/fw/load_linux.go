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
	RemoveIptables()
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

// SyncIptables makes the MESHGATE chain hold exactly rules (Plan.
// IptablesRules) and keeps it at the top of iptables' FORWARD chain. ufw and
// Docker set FORWARD's policy to DROP, and a drop in any table wins over
// meshgate's own nftables accept; the chain lets this node's meshgate
// traffic through and nothing else. Rebuilt only when rules change (and
// re-checked every minute with the firewall).
func SyncIptables(rules [][]string) error {
	if _, err := exec.LookPath("iptables"); err != nil {
		return nil // no iptables: nothing can block us there
	}
	ipt := func(args ...string) error {
		out, err := exec.Command("iptables", append([]string{"-w", "5"}, args...)...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("iptables %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
		}
		return nil
	}
	ipt("-N", "MESHGATE") // fails harmlessly when it exists
	if err := ipt("-F", "MESHGATE"); err != nil {
		return err
	}
	for _, r := range rules {
		if err := ipt(append([]string{"-A", "MESHGATE"}, r...)...); err != nil {
			return err
		}
	}
	if ipt("-C", "FORWARD", "-j", "MESHGATE") != nil {
		return ipt("-I", "FORWARD", "1", "-j", "MESHGATE")
	}
	return nil
}

// RemoveIptables deletes the MESHGATE chain.
func RemoveIptables() {
	if _, err := exec.LookPath("iptables"); err != nil {
		return
	}
	for exec.Command("iptables", "-w", "5", "-D", "FORWARD", "-j", "MESHGATE").Run() == nil {
	}
	exec.Command("iptables", "-w", "5", "-F", "MESHGATE").Run()
	exec.Command("iptables", "-w", "5", "-X", "MESHGATE").Run()
}
