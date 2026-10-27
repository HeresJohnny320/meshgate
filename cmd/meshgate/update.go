package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/heresjohnny320/meshgate/internal/agent"
	"github.com/heresjohnny320/meshgate/internal/update"
)

// cmdUpdate installs the latest release on this machine (checksum-verified)
// and restarts meshgate. --check only reports.
func cmdUpdate(args []string) error {
	fs := newFlags("update")
	check := fs.Bool("check", false, "only report whether an update is available")
	fs.Parse(args)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	tag, err := update.Latest(ctx)
	if err != nil {
		return fmt.Errorf("checking for updates: %w", err)
	}
	fmt.Printf("installed %s, latest release %s\n", agent.Version, tag)
	if !update.Newer(agent.Version, tag) {
		fmt.Println("meshgate is up to date.")
		return nil
	}
	if *check {
		fmt.Println("An update is available: run `meshgate update` to install it.")
		return nil
	}
	exe, err := os.Executable()
	if err == nil {
		exe, err = filepath.EvalSymlinks(exe)
	}
	if err != nil {
		return err
	}
	if runtime.GOOS != "windows" {
		if os.Geteuid() != 0 {
			return fmt.Errorf("updating replaces the binary and restarts the service: run it as root (sudo meshgate update)")
		}
		if exe != "/usr/local/bin/meshgate" {
			fmt.Printf("note: updating %s, but the service runs /usr/local/bin/meshgate\n", exe)
		}
	}
	fmt.Printf("Downloading %s and verifying its checksum...\n", update.Asset())
	if err := update.Install(ctx, tag, exe); err != nil {
		return err
	}
	fmt.Printf("Installed %s. Restarting meshgate...\n", tag)
	if err := restartService(); err != nil {
		return fmt.Errorf("installed, but restarting meshgate failed (%v): restart it yourself", err)
	}
	fmt.Println("Done.")
	return nil
}
