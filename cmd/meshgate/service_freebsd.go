package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
)

const rcScript = "/usr/local/etc/rc.d/meshgate.sh"

func restartService() error { return exec.Command(rcScript, "restart").Run() }

func stopService() {
	exec.Command(rcScript, "stop").Run()
	os.Remove(rcScript)
}

const startHint = rcScript + " start"

func runService(f func(context.Context) error) error { return runInForeground(f) }

func cmdService(string, []string) error {
	return fmt.Errorf("on FreeBSD/pfSense the installer sets up %s", rcScript)
}
