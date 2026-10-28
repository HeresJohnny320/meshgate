package agent

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/heresjohnny320/meshgate/internal/model"
	"github.com/heresjohnny320/meshgate/internal/store"
	"github.com/heresjohnny320/meshgate/internal/update"
)

var (
	latestMu sync.Mutex
	latest   string
	updating sync.Mutex // one self-update at a time
)

// latestLoop keeps the newest release tag for the dashboard.
func (a *Agent) latestLoop(ctx context.Context) {
	for {
		if tag, err := update.Latest(ctx); err == nil {
			latestMu.Lock()
			latest = tag
			latestMu.Unlock()
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(30 * time.Minute):
		}
	}
}

func latestRelease() string {
	latestMu.Lock()
	defer latestMu.Unlock()
	return latest
}

// Update makes node (this one or another over the mesh) update itself.
func (a *Agent) Update(node string) (string, error) {
	if node == "" || node == a.Cfg.NodeID {
		return a.startSelfUpdate()
	}
	n, ok := store.Get[model.Node](a.Store, model.Key(model.KindNode, node))
	if !ok || n.MeshIP == "" {
		return "", fmt.Errorf("unknown node")
	}
	if n.Kind == model.NodeClient && n.APIHash != "" {
		return "", fmt.Errorf("%s is a phone: update it in the meshgate app", n.Name)
	}
	if n.Kind == model.NodeStatic {
		return "", fmt.Errorf("%s uses the official WireGuard app", n.Name)
	}
	port := n.MeshPort
	if port == 0 {
		port = model.DefaultMeshPort
	}
	c := &http.Client{Timeout: 10 * time.Second}
	res, err := c.Post("http://"+net.JoinHostPort(n.MeshIP, strconv.Itoa(port))+"/v1/update", "application/json", nil)
	if err != nil {
		return "", fmt.Errorf("%s did not answer: %v", n.Name, err)
	}
	res.Body.Close()
	switch res.StatusCode {
	case http.StatusAccepted:
		return n.Name + " is updating; it restarts by itself when done", nil
	case http.StatusNotFound:
		return "", fmt.Errorf("%s runs a meshgate too old for remote updates: run `meshgate update` on it once", n.Name)
	default:
		return "", fmt.Errorf("%s refused: %s", n.Name, res.Status)
	}
}

// serveUpdate lets servers ask this node to update (mesh port).
func (a *Agent) serveUpdate(w http.ResponseWriter, r *http.Request) {
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	for _, n := range store.List[model.Node](a.Store, model.KindNode) {
		if n.MeshIP == ip && n.Kind == model.NodeServer {
			if _, err := a.startSelfUpdate(); err != nil {
				http.Error(w, err.Error(), http.StatusConflict)
				return
			}
			w.WriteHeader(http.StatusAccepted)
			return
		}
	}
	http.Error(w, "only servers may update nodes", http.StatusForbidden)
}

// startSelfUpdate installs the latest release in the background and exits;
// the service manager starts the new version.
func (a *Agent) startSelfUpdate() (string, error) {
	if !updating.TryLock() {
		return "", fmt.Errorf("an update is already running")
	}
	go func() {
		defer updating.Unlock()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		tag, err := update.Latest(ctx)
		if err != nil {
			log.Printf("update: %v", err)
			return
		}
		if !update.Newer(Version, tag) {
			log.Printf("update: %s is current (latest %s)", Version, tag)
			return
		}
		exe, err := os.Executable()
		if err == nil {
			exe, err = filepath.EvalSymlinks(exe)
		}
		if err == nil {
			err = update.Install(ctx, tag, exe)
		}
		if err != nil {
			log.Printf("update to %s failed: %v", tag, err)
			return
		}
		log.Printf("updated %s -> %s; restarting", Version, tag)
		a.flushEvents()         // the log server should know why we vanish
		time.Sleep(time.Second) // let the API answer go out
		os.Exit(3)              // systemd / daemon -r / Windows recovery start the new binary
	}()
	return "updating to the latest release; meshgate restarts by itself when done", nil
}
