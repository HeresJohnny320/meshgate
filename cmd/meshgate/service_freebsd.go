package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

const rcScript = "/usr/local/etc/rc.d/meshgate.sh"

// restartService restarts meshgate if it runs; a stopped one stays stopped.
func restartService() error {
	if exec.Command(rcScript, "onestatus").Run() != nil {
		return nil
	}
	return exec.Command(rcScript, "onerestart").Run()
}

func stopService() {
	exec.Command(rcScript, "stop").Run()
	os.Remove(rcScript)
}

// setService starts or stops meshgate and makes that survive reboots
// (meshgate_enable in /etc/rc.conf.local; the rc script defaults to YES).
func setService(on bool) error {
	if on {
		exec.Command("sysrc", "-f", "/etc/rc.conf.local", "-x", "meshgate_enable").Run()
		return runQuiet(rcScript, "onestart")
	}
	runQuiet(rcScript, "onestop")
	return runQuiet("sysrc", "-f", "/etc/rc.conf.local", "meshgate_enable=NO")
}

func runQuiet(name string, args ...string) error {
	if out, err := exec.Command(name, args...).CombinedOutput(); err != nil {
		return fmt.Errorf("%s %v: %v: %s", name, args, err, strings.TrimSpace(string(out)))
	}
	return nil
}

const startHint = rcScript + " start"

func runService(f func(context.Context) error) error { return runInForeground(f) }

func cmdService(string, []string) error {
	return fmt.Errorf("on FreeBSD/pfSense the installer sets up %s", rcScript)
}
