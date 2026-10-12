package fw

import (
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
