package main

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// restartService restarts meshgate if it runs; a stopped one stays stopped.
func restartService() error { return exec.Command("systemctl", "try-restart", "meshgate").Run() }
func stopService()          { exec.Command("systemctl", "disable", "--now", "meshgate").Run() }

// setService starts or stops meshgate and makes that survive reboots.
func setService(on bool) error {
	verb := "disable"
	if on {
		verb = "enable"
	}
	if out, err := exec.Command("systemctl", verb, "--now", "meshgate").CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl %s: %v: %s", verb, err, strings.TrimSpace(string(out)))
	}
	return nil
}

const startHint = "sudo systemctl enable --now meshgate"

func runService(f func(context.Context) error) error { return runInForeground(f) }

func cmdService(string, []string) error {
	return fmt.Errorf("on Linux the installer sets up systemd: systemctl enable --now meshgate")
}
