package fw

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

const pfSep = "#--meshgate-anchor--\n"

// IsPfSense reports whether we run on pfSense.
func IsPfSense() bool {
	b, _ := os.ReadFile("/etc/platform")
	return strings.Contains(strings.ToLower(string(b)), "pfsense")
}

// Render returns the rules to load on this OS.
func Render(p Plan) string {
	n, r, f := RenderPF(p)
	return n + pfSep + r + pfSep + f
}

// Load applies rendered rules into meshgate's pf anchors.
func Load(rendered string) error {
	parts := strings.SplitN(rendered, pfSep, 3)
	if len(parts) != 3 {
		return errors.New("pf: bad rendered rules")
	}
	n, r, f := parts[0], parts[1], parts[2]
	if err := checkPF(); err != nil {
		return err
	}
	if PFRdrAnchor == PFNatAnchor {
		// One anchor may hold both (pf evaluates nat and rdr rules in it
		// from the matching nat-anchor/rdr-anchor); nat must come first.
		return firstErr(pfctl(n+r, "-a", PFNatAnchor, "-f", "-"), pfctl(f, "-a", PFFilterAnchor, "-f", "-"))
	}
	return firstErr(
		pfctl(n, "-a", PFNatAnchor, "-f", "-"),
		pfctl(r, "-a", PFRdrAnchor, "-f", "-"),
		pfctl(f, "-a", PFFilterAnchor, "-f", "-"),
	)
}

func firstErr(errs ...error) error {
	for _, e := range errs {
		if e != nil {
			return e
		}
	}
	return nil
}

// Remove flushes meshgate's anchors.
func Remove() error {
	return errors.Join(
		pfctl("", "-a", PFNatAnchor, "-F", "all"),
		pfctl("", "-a", PFRdrAnchor, "-F", "all"),
		pfctl("", "-a", PFFilterAnchor, "-F", "all"),
	)
}

func pfctl(stdin string, args ...string) error {
	cmd := exec.Command("pfctl", args...)
	cmd.Stdin = strings.NewReader(stdin)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("pfctl %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// checkPF makes sure pf is on and the main ruleset evaluates our anchors;
// otherwise rules would load fine and silently never apply.
func checkPF() error {
	info, _ := exec.Command("pfctl", "-s", "info").CombinedOutput()
	if !strings.Contains(string(info), "Status: Enabled") {
		return errors.New("pf is disabled; enable it with `pfctl -e` (always on with pfSense)")
	}
	rules, _ := exec.Command("pfctl", "-s", "rules").CombinedOutput()
	nat, _ := exec.Command("pfctl", "-s", "nat").CombinedOutput()
	var missing []string
	for _, a := range []struct{ kind, name string }{{"nat-anchor", PFNatAnchor}, {"rdr-anchor", PFRdrAnchor}} {
		line := fmt.Sprintf(`%s "%s/*"`, a.kind, parent(a.name))
		if !strings.Contains(string(nat), line) {
			missing = append(missing, line)
		}
	}
	filterParent := parent(PFFilterAnchor)
	if !strings.Contains(string(rules), `"`+filterParent+`/*"`) {
		missing = append(missing, fmt.Sprintf(`anchor "%s/*"`, filterParent))
	}
	if len(missing) > 0 {
		return fmt.Errorf("pf main ruleset does not reference meshgate's anchors; add to /etc/pf.conf: %s", strings.Join(missing, "; "))
	}
	return nil
}

func parent(anchor string) string {
	p, _, _ := strings.Cut(anchor, "/")
	return p
}

// DetectWAN returns the interface of the IPv4 default route.
func DetectWAN() string {
	out, err := exec.Command("route", "-n", "get", "-inet", "default").CombinedOutput()
	if err != nil {
		return ""
	}
	for _, l := range strings.Split(string(out), "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(l), ":"); ok && k == "interface" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
