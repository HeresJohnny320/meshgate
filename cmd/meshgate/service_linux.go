package main

import (
	"context"
	"fmt"
	"os/exec"
)

func restartService() error { return exec.Command("systemctl", "restart", "meshgate").Run() }
func stopService()          { exec.Command("systemctl", "disable", "--now", "meshgate").Run() }

const startHint = "sudo systemctl enable --now meshgate"

func runService(f func(context.Context) error) error { return runInForeground(f) }

func cmdService(string, []string) error {
	return fmt.Errorf("on Linux the installer sets up systemd: systemctl enable --now meshgate")
}
