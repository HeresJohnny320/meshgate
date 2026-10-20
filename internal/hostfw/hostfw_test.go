package hostfw

import (
	"reflect"
	"testing"

	"github.com/heresjohnny320/meshgate/internal/fw"
)

func TestWantedAndSpell(t *testing.T) {
	p := fw.Plan{
		HostOpen: []fw.HostPort{{"udp", 51820, "wireguard"}, {"tcp", 443, "https routes"}},
		DNAT: []fw.DNAT{
			{Name: "minecraft", Protos: []string{"tcp"}, Lo: 25565, Hi: 25565, Dst: "192.168.1.50", DstPort: 25566},
			{Name: "valheim", Protos: []string{"udp"}, Lo: 2456, Hi: 2458, Dst: "100.88.0.5"},
		},
	}
	rules := Wanted(p)

	var ufw []string
	for _, e := range spell(UFW, rules) {
		ufw = append(ufw, e.Key)
	}
	wantUFW := []string{
		"allow proto tcp to any port 443",
		"allow proto udp to any port 51820",
		"route allow proto tcp to 192.168.1.50 port 25566",
		"route allow proto udp to 100.88.0.5 port 2456:2458",
	}
	if !reflect.DeepEqual(ufw, wantUFW) {
		t.Errorf("ufw = %q, want %q", ufw, wantUFW)
	}

	var fwd []string
	for _, e := range spell(Firewalld, rules) {
		fwd = append(fwd, e.Key)
	}
	wantFwd := []string{"2456-2458/udp", "25565/tcp", "443/tcp", "51820/udp"}
	if !reflect.DeepEqual(fwd, wantFwd) {
		t.Errorf("firewalld = %q, want %q", fwd, wantFwd)
	}
}

func TestSanitizeComment(t *testing.T) {
	if got := sanitize(`it's "x"\`); got != "meshgate: it s  x  " {
		t.Errorf("sanitize = %q", got)
	}
}

// fake records calls; keys in existing are the admin's own rules.
type fake struct {
	existing    map[string]bool
	added, gone []string
}

func (f *fake) add(e entry) (bool, error) {
	if f.existing[e.Key] {
		return true, nil
	}
	f.added = append(f.added, e.Key)
	return false, nil
}

func (f *fake) del(e entry) error {
	f.gone = append(f.gone, e.Key)
	return nil
}

func keys(es []entry) []string {
	var k []string
	for _, e := range es {
		k = append(k, e.Key)
	}
	return k
}

func TestReconcile(t *testing.T) {
	mc := Rule{Proto: "tcp", Lo: 25565, Hi: 25565, To: "192.168.1.50", ToLo: 25565, ToHi: 25565, Note: "forward mc"}
	web := Rule{Proto: "tcp", Lo: 443, Hi: 443, Note: "https routes"}

	// First sync: 443 is already the admin's own rule, the forward is new.
	f := &fake{existing: map[string]bool{"allow proto tcp to any port 443": true}}
	st, errs := reconcile(state{}, UFW, spell(UFW, []Rule{mc, web}), f, nil)
	if len(errs) > 0 || !reflect.DeepEqual(f.added, []string{"route allow proto tcp to 192.168.1.50 port 25565"}) {
		t.Fatalf("added %q, errs %v", f.added, errs)
	}

	// Forward and route deleted: only meshgate's own rule goes.
	f = &fake{}
	st, _ = reconcile(st, UFW, nil, f, f)
	if !reflect.DeepEqual(f.gone, []string{"route allow proto tcp to 192.168.1.50 port 25565"}) {
		t.Errorf("deleted %q, want only the forward", f.gone)
	}
	if len(st.Rules) != 0 || st.Backend != "" {
		t.Errorf("state after removal = %+v", st)
	}

	// Switching from ufw to firewalld removes the ufw rules first.
	old, cur := &fake{}, &fake{}
	st, _ = reconcile(state{}, UFW, spell(UFW, []Rule{web}), old, nil)
	st, _ = reconcile(st, Firewalld, spell(Firewalld, []Rule{web}), cur, old)
	if !reflect.DeepEqual(old.gone, []string{"allow proto tcp to any port 443"}) || !reflect.DeepEqual(cur.added, []string{"443/tcp"}) {
		t.Errorf("switch: ufw deleted %q, firewalld added %q", old.gone, cur.added)
	}
	if st.Backend != Firewalld || !reflect.DeepEqual(keys(st.Rules), []string{"443/tcp"}) {
		t.Errorf("state after switch = %+v", st)
	}

	// Unchanged: nothing is run again.
	f = &fake{}
	reconcile(st, Firewalld, spell(Firewalld, []Rule{web}), f, f)
	if len(f.added)+len(f.gone) != 0 {
		t.Errorf("unchanged sync ran %q / %q", f.added, f.gone)
	}
}
