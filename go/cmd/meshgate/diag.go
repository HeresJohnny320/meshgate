package main

import (
	"errors"
	"fmt"
	"strconv"

	"github.com/heresjohnny320/meshgate/internal/config"
	"github.com/heresjohnny320/meshgate/internal/diag"
	"github.com/heresjohnny320/meshgate/internal/localapi"
)

const diagUsage = `usage: meshgate diag ping <host>
       meshgate diag trace <host>
       meshgate diag tcp <host> <port>
       meshgate diag udp <host> <port>     (answers only from a meshgate test service)
       meshgate diag http <url>
       meshgate diag myip                  (public IP websites see from this node)`

// cmdDiag runs a check from this node through the agent, the same code the
// web UI's Tools tab uses.
func cmdDiag(cfgPath string, args []string) error {
	if len(args) == 1 && args[0] == "myip" {
		args = append(args, "")
	}
	if len(args) < 2 {
		return errors.New(diagUsage)
	}
	c := diag.Check{Kind: args[0], Target: args[1]}
	switch c.Kind {
	case "ping", "trace", "http", "myip":
	case "tcp", "udp":
		if len(args) < 3 {
			return errors.New(diagUsage)
		}
		c.Port, _ = strconv.Atoi(args[2])
	default:
		return errors.New(diagUsage)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	var r diag.Result
	if err := localapi.New(cfg.Socket).Post("diag", c, &r); err != nil {
		return err
	}
	fmt.Println(r.Output)
	if !r.OK {
		return errors.New("check failed")
	}
	return nil
}
