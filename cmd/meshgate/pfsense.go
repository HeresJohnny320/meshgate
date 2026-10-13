package main

import (
	"errors"
	"fmt"
	"time"

	"github.com/heresjohnny320/meshgate/internal/agent"
	"github.com/heresjohnny320/meshgate/internal/config"
	"github.com/heresjohnny320/meshgate/internal/fw"
	"github.com/heresjohnny320/meshgate/internal/localapi"
	"github.com/heresjohnny320/meshgate/internal/model"
	"github.com/heresjohnny320/meshgate/internal/pfsense"
	"github.com/heresjohnny320/meshgate/internal/webui"
)

// cmdPfSense adds meshgate to the pfSense GUI (VPN > meshgate, and the
// MESHGATE interface whose Firewall > Rules tab decides what mesh devices may
// reach), or removes it again.
func cmdPfSense(cfgPath string, args []string) error {
	if len(args) != 1 || (args[0] != "install" && args[0] != "remove") {
		return errors.New("usage: meshgate pfsense install | remove")
	}
	if !fw.IsPfSense() {
		return errors.New("this is not pfSense")
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	api := localapi.New(cfg.Socket)

	if args[0] == "remove" {
		if _, err := pfsense.Configure("remove"); err != nil {
			return err
		}
		pfsense.RemoveFiles()
		// Without the MESHGATE rules, fall back to meshgate's own lockdown.
		if err := setPolicy(api, model.PolicyFirewall, model.PolicyRestricted); err != nil {
			fmt.Println("warning: could not reset the LAN policy:", err)
		}
		fmt.Println("Removed VPN > meshgate and the MESHGATE interface and rules.")
		return nil
	}

	if cfg.Kind != "" && cfg.Kind != model.NodeServer {
		return errors.New("only server nodes can be managed from pfSense")
	}
	if cfg.Iface != pfsense.Iface {
		fmt.Printf("Renaming the mesh interface %s -> %s and restarting meshgate...\n", cfg.Iface, pfsense.Iface)
		cfg.Iface = pfsense.Iface
		if err := config.Save(cfgPath, cfg); err != nil {
			return err
		}
		if err := restartService(); err != nil {
			return fmt.Errorf("restart meshgate: %w", err)
		}
	}
	if err := waitAgent(api); err != nil {
		return err
	}
	if err := pfsense.WriteFiles(webui.Static(), cfg.Socket, agent.Version); err != nil {
		return err
	}
	opt, err := pfsense.Configure("install")
	if err != nil {
		return err
	}
	if err := setPolicy(api, "", model.PolicyFirewall); err != nil {
		return fmt.Errorf("set LAN policy: %w", err)
	}
	fmt.Printf(`Added to the pfSense GUI:
  VPN > meshgate                  the meshgate dashboard (your pfSense login)
  Firewall > Rules > MESHGATE     what mesh devices may reach (interface %s, %s)
The MESHGATE tab starts with one rule that allows everything. Replace it with
rules for the hosts and ports you want, e.g. pass TCP to 192.168.1.20 port 443.
`, pfsense.Iface, opt)
	return nil
}

// setPolicy sets this node's LAN policy to want, only if it is currently
// from (any policy when from is empty).
func setPolicy(api *localapi.Client, from, want string) error {
	v, err := api.View()
	if err != nil {
		return err
	}
	for _, n := range v.Nodes {
		if n.Value.ID != v.SelfID {
			continue
		}
		if (from != "" && n.Value.LANPolicy != from) || n.Value.LANPolicy == want {
			return nil
		}
		return api.Post("node", map[string]any{"id": v.SelfID, "patch": map[string]string{"lan_policy": want}, "scope": "cluster"}, nil)
	}
	return errors.New("this node is not in the mesh view")
}

func waitAgent(api *localapi.Client) error {
	var err error
	for i := 0; i < 30; i++ {
		if _, err = api.View(); err == nil {
			return nil
		}
		time.Sleep(time.Second)
	}
	return fmt.Errorf("meshgate agent did not come back: %w", err)
}
