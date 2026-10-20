package hostfw

import (
	"fmt"
	"os/exec"
	"strings"
)

// Detect returns the active host firewall: ufw, firewalld or "" (none).
func Detect() string {
	if _, err := exec.LookPath("firewall-cmd"); err == nil {
		if exec.Command("firewall-cmd", "--state").Run() == nil {
			return Firewalld
		}
	}
	if _, err := exec.LookPath("ufw"); err == nil {
		if out, err := exec.Command("ufw", "status").Output(); err == nil && strings.Contains(string(out), "Status: active") {
			return UFW
		}
	}
	return ""
}

func runnerFor(backend string) runner {
	switch backend {
	case UFW:
		if _, err := exec.LookPath("ufw"); err == nil {
			return ufwRunner{}
		}
	case Firewalld:
		if _, err := exec.LookPath("firewall-cmd"); err == nil {
			return firewalldRunner{}
		}
	}
	return nil
}

// Sync makes the active host firewall hold exactly rules (plus whatever the
// admin added), using the state file at statePath. off removes everything
// meshgate added. It returns the backend in use.
func Sync(statePath string, rules []Rule, off bool) (string, error) {
	st := load(statePath)
	backend := ""
	if !off {
		backend = Detect()
	}
	var want []entry
	cur := runnerFor(backend)
	if cur == nil {
		backend, cur = "", nopRunner{}
	} else {
		want = spell(backend, rules)
	}
	next, errs := reconcile(st, backend, want, cur, runnerFor(st.Backend))
	if err := save(statePath, next); err != nil {
		errs = append(errs, err)
	}
	return backend, joinErrs(errs)
}

// RemoveAll deletes every rule meshgate added (meshgate leave).
func RemoveAll(statePath string) {
	Sync(statePath, nil, true)
}

type nopRunner struct{}

func (nopRunner) add(entry) (bool, error) { return false, nil }
func (nopRunner) del(entry) error         { return nil }

type ufwRunner struct{}

func (ufwRunner) add(e entry) (bool, error) {
	args := append(append([]string(nil), e.Args...), "comment", e.Note)
	out, err := exec.Command("ufw", args...).CombinedOutput()
	if err != nil {
		return false, fmt.Errorf("ufw %s: %v: %s", e.Key, err, strings.TrimSpace(string(out)))
	}
	// "Skipping adding existing rule" for every address family = the
	// admin's own rule.
	return !strings.Contains(string(out), "Rule added"), nil
}

func (ufwRunner) del(e entry) error {
	// "allow ..." -> "delete allow ...", "route allow ..." -> "route delete allow ...".
	var args []string
	if len(e.Args) > 0 && e.Args[0] == "route" {
		args = append([]string{"route", "delete"}, e.Args[1:]...)
	} else {
		args = append([]string{"delete"}, e.Args...)
	}
	args = append(args, "comment", e.Note)
	out, err := exec.Command("ufw", args...).CombinedOutput()
	if err != nil && !strings.Contains(string(out), "non-existent") {
		return fmt.Errorf("ufw delete %s: %v: %s", e.Key, err, strings.TrimSpace(string(out)))
	}
	return nil
}

type firewalldRunner struct{}

func (firewalldRunner) add(e entry) (bool, error) {
	port := e.Args[0]
	if exec.Command("firewall-cmd", "-q", "--permanent", "--query-port="+port).Run() == nil {
		return true, nil
	}
	for _, perm := range [][]string{{"--permanent"}, nil} {
		args := append(append([]string{"-q"}, perm...), "--add-port="+port)
		if out, err := exec.Command("firewall-cmd", args...).CombinedOutput(); err != nil {
			return false, fmt.Errorf("firewall-cmd --add-port=%s: %v: %s", port, err, strings.TrimSpace(string(out)))
		}
	}
	return false, nil
}

func (firewalldRunner) del(e entry) error {
	port := e.Args[0]
	var errs []string
	for _, perm := range [][]string{{"--permanent"}, nil} {
		args := append(append([]string{"-q"}, perm...), "--remove-port="+port)
		if out, err := exec.Command("firewall-cmd", args...).CombinedOutput(); err != nil && !strings.Contains(string(out), "NOT_ENABLED") {
			errs = append(errs, strings.TrimSpace(string(out)))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("firewall-cmd --remove-port=%s: %s", port, strings.Join(errs, "; "))
	}
	return nil
}
