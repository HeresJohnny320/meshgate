package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const serviceName = "meshgate"

const startHint = "meshgate service install"

// runService runs the agent under the Service Control Manager when started
// as a service, otherwise in the foreground.
func runService(f func(context.Context) error) error {
	isSvc, err := svc.IsWindowsService()
	if err != nil || !isSvc {
		return runInForeground(f)
	}
	return svc.Run(serviceName, &handler{run: f})
}

type handler struct{ run func(context.Context) error }

func (h *handler) Execute(_ []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- h.run(ctx) }()
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case err := <-done:
			cancel()
			if err != nil {
				return true, 1
			}
			return false, 0
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				cancel()
				select {
				case <-done:
				case <-time.After(10 * time.Second):
				}
				return false, 0
			}
		}
	}
}

func cmdService(cfgPath string, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: meshgate service install|uninstall")
	}
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("service manager (run as Administrator): %w", err)
	}
	defer m.Disconnect()
	switch args[0] {
	case "install":
		exe, err := os.Executable()
		if err != nil {
			return err
		}
		exe, _ = filepath.Abs(exe)
		s, err := m.CreateService(serviceName, exe, mgr.Config{
			DisplayName: "meshgate",
			Description: "meshgate WireGuard mesh node",
			StartType:   mgr.StartAutomatic,
		}, "-config", cfgPath, "agent")
		if err != nil {
			return err
		}
		defer s.Close()
		s.SetRecoveryActions([]mgr.RecoveryAction{
			{Type: mgr.ServiceRestart, Delay: 3 * time.Second},
			{Type: mgr.ServiceRestart, Delay: 10 * time.Second},
			{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
		}, 3600)
		if err := s.Start(); err != nil {
			return err
		}
		fmt.Println("meshgate service installed and started.")
		return nil
	case "uninstall":
		stopService()
		fmt.Println("meshgate service removed.")
		return nil
	}
	return fmt.Errorf("usage: meshgate service install|uninstall")
}

func restartService() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		return err
	}
	defer s.Close()
	if st, err := s.Query(); err == nil && st.State == svc.Stopped {
		return nil // stopped stays stopped
	}
	s.Control(svc.Stop)
	for i := 0; i < 50; i++ {
		if st, err := s.Query(); err == nil && st.State == svc.Stopped {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	return s.Start()
}

// setService starts or stops meshgate and makes that survive reboots
// (automatic vs manual start).
func setService(on bool) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("service manager (run as Administrator): %w", err)
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("meshgate service not installed (meshgate service install): %w", err)
	}
	defer s.Close()
	c, err := s.Config()
	if err != nil {
		return err
	}
	c.StartType = mgr.StartManual
	if on {
		c.StartType = mgr.StartAutomatic
	}
	if err := s.UpdateConfig(c); err != nil {
		return err
	}
	if on {
		if st, err := s.Query(); err == nil && st.State == svc.Running {
			return nil
		}
		return s.Start()
	}
	s.Control(svc.Stop)
	return nil
}

func stopService() {
	m, err := mgr.Connect()
	if err != nil {
		return
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		return
	}
	defer s.Close()
	s.Control(svc.Stop)
	s.Delete()
}
