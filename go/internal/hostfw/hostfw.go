// Package hostfw keeps the host's own firewall (ufw or firewalld) open for
// what a Linux server needs from outside: meshgate's ports, 80/443 on an
// HTTPS edge and every port forward it is the edge of. Rules are added when
// a forward or route appears and deleted again when it goes away.
//
// meshgate only ever deletes rules it added itself (listed in a state file);
// a rule the admin already had is left alone.
package hostfw

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/heresjohnny320/meshgate/internal/fw"
)

// Backends.
const (
	UFW       = "ufw"
	Firewalld = "firewalld"
)

// Rule is one opening in the host firewall.
type Rule struct {
	Proto string // tcp or udp
	Lo    int    // public port (range Lo..Hi)
	Hi    int
	// To is a port forward's target after DNAT and ToLo..ToHi its ports.
	// ufw then needs a "route" rule (the traffic is forwarded, not for
	// this host); "" means the port is served by this host.
	To         string
	ToLo, ToHi int
	Note       string
}

// Wanted lists the rules a node's firewall plan needs.
func Wanted(p fw.Plan) []Rule {
	var out []Rule
	for _, h := range p.HostOpen {
		out = append(out, Rule{Proto: h.Proto, Lo: h.Port, Hi: h.Port, Note: h.Note})
	}
	for _, d := range p.DNAT {
		toLo, toHi := d.DstPort, d.DstPort
		if d.DstPort == 0 { // ranges keep their ports
			toLo, toHi = d.Lo, d.Hi
		}
		for _, proto := range d.Protos {
			out = append(out, Rule{Proto: proto, Lo: d.Lo, Hi: d.Hi, To: d.Dst, ToLo: toLo, ToHi: toHi, Note: "forward " + d.Name})
		}
	}
	return out
}

// entry is a rule as one backend spells it.
type entry struct {
	Key  string   `json:"key"`  // identity, e.g. "80/tcp"
	Args []string `json:"args"` // the backend's rule spec, without the verb
	Note string   `json:"note"`
	// Theirs: the rule already existed when meshgate wanted it, so it is
	// the admin's and never deleted.
	Theirs bool `json:"theirs,omitempty"`
}

func ports(lo, hi int, sep string) string {
	if hi > lo {
		return fmt.Sprintf("%d%s%d", lo, sep, hi)
	}
	return fmt.Sprint(lo)
}

// sanitize keeps a comment safe as one command-line argument for ufw.
func sanitize(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < ' ' || r == '\'' || r == '"' || r == '\\' {
			return ' '
		}
		return r
	}, s)
	if len(s) > 60 {
		s = s[:60]
	}
	return "meshgate: " + s
}

// spell turns rules into one backend's entries, without duplicates.
func spell(backend string, rules []Rule) []entry {
	seen := map[string]bool{}
	var out []entry
	for _, r := range rules {
		var e entry
		switch backend {
		case UFW:
			if r.To != "" {
				e.Args = []string{"route", "allow", "proto", r.Proto, "to", r.To, "port", ports(r.ToLo, r.ToHi, ":")}
			} else {
				e.Args = []string{"allow", "proto", r.Proto, "to", "any", "port", ports(r.Lo, r.Hi, ":")}
			}
			e.Key = strings.Join(e.Args, " ")
		case Firewalld:
			// firewalld accepts DNATed traffic itself; the forward's public
			// port is opened too so older versions and `firewall-cmd
			// --list-ports` show it.
			e.Key = ports(r.Lo, r.Hi, "-") + "/" + r.Proto
			e.Args = []string{e.Key}
		default:
			continue
		}
		e.Note = sanitize(r.Note)
		if !seen[e.Key] {
			seen[e.Key] = true
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

// state is what meshgate added, kept so it can be removed again.
type state struct {
	Backend string  `json:"backend"`
	Rules   []entry `json:"rules"`
}

func load(path string) state {
	var st state
	if b, err := os.ReadFile(path); err == nil {
		json.Unmarshal(b, &st)
	}
	return st
}

func save(path string, st state) error {
	if len(st.Rules) == 0 {
		err := os.Remove(path)
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	b, _ := json.MarshalIndent(st, "", "  ")
	return os.WriteFile(path, b, 0o600)
}

// runner applies entries with one backend. add reports existed=true when
// the rule was already there (the admin's own).
type runner interface {
	add(e entry) (existed bool, err error)
	del(e entry) error
}

// reconcile brings the host firewall from st to want and returns the new
// state. Rules of a backend that is no longer in use are removed with that
// backend (old) when it is still installed.
func reconcile(st state, backend string, want []entry, cur, old runner) (state, []error) {
	var errs []error
	if st.Backend != "" && st.Backend != backend {
		for _, e := range st.Rules {
			if !e.Theirs && old != nil {
				if err := old.del(e); err != nil {
					errs = append(errs, err)
				}
			}
		}
		st = state{}
	}
	wanted := map[string]bool{}
	for _, e := range want {
		wanted[e.Key] = true
	}
	next := state{Backend: backend}
	have := map[string]bool{}
	for _, e := range st.Rules {
		if wanted[e.Key] {
			next.Rules = append(next.Rules, e)
			have[e.Key] = true
			continue
		}
		if !e.Theirs {
			if err := cur.del(e); err != nil {
				errs = append(errs, err)
				next.Rules = append(next.Rules, e) // try again next time
			}
		}
	}
	for _, e := range want {
		if have[e.Key] {
			continue
		}
		existed, err := cur.add(e)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		e.Theirs = existed
		next.Rules = append(next.Rules, e)
	}
	sort.Slice(next.Rules, func(i, j int) bool { return next.Rules[i].Key < next.Rules[j].Key })
	if len(next.Rules) == 0 {
		next.Backend = ""
	}
	return next, errs
}

func joinErrs(errs []error) error {
	if len(errs) == 0 {
		return nil
	}
	var s []string
	for _, e := range errs {
		s = append(s, e.Error())
	}
	return fmt.Errorf("%s", strings.Join(s, "; "))
}
