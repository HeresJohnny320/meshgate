package agent

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/heresjohnny320/meshgate/internal/model"
	"github.com/heresjohnny320/meshgate/internal/store"
)

// The full log of a node: everything meshgate and its service manager wrote
// there (the systemd journal, /var/log/meshgate.log on pfSense), including
// crashes and stop/start messages that never pass through the event log.

// rawLogFile is where FreeBSD/pfSense's rc script (daemon -o) writes.
const rawLogFile = "/var/log/meshgate.log"

type rawLogAnswer struct {
	Node   string   `json:"node"`
	Source string   `json:"source"`
	Lines  []string `json:"lines"` // oldest first
	Error  string   `json:"error,omitempty"`
}

// readRawLog returns the last n lines of this node's own log.
func readRawLog(n int) ([]string, string, error) {
	switch runtime.GOOS {
	case "linux":
		out, err := exec.Command("journalctl", "-u", "meshgate", "-n", strconv.Itoa(n), "--no-pager", "-o", "short-iso").Output()
		if err != nil {
			return nil, "", fmt.Errorf("journalctl: %v (is meshgate running under systemd?)", err)
		}
		return splitLines(out), "journalctl -u meshgate", nil
	case "freebsd":
		f, err := os.Open(rawLogFile)
		if err != nil {
			return nil, "", err
		}
		defer f.Close()
		// The tail is enough: n lines are far less than the last 2 MB.
		if st, err := f.Stat(); err == nil && st.Size() > 2<<20 {
			f.Seek(st.Size()-2<<20, io.SeekStart)
		}
		data, err := io.ReadAll(f)
		if err != nil {
			return nil, "", err
		}
		lines := splitLines(data)
		if len(lines) > n {
			lines = lines[len(lines)-n:]
		}
		return lines, rawLogFile, nil
	}
	return nil, "", errors.New("no log file on " + runtime.GOOS + "; see the event log")
}

func splitLines(b []byte) []string {
	var out []string
	for _, l := range bytes.Split(bytes.TrimRight(b, "\n"), []byte{'\n'}) {
		if len(l) > 0 {
			out = append(out, string(l))
		}
	}
	return out
}

func rawLogLines(q string) int {
	n, _ := strconv.Atoi(q)
	if n <= 0 || n > 5000 {
		n = 1000
	}
	return n
}

// serveRawLog lets other servers read this node's log (mesh port).
func (a *Agent) serveRawLog(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.serverCaller(w, r); !ok {
		return
	}
	lines, src, err := readRawLog(rawLogLines(r.URL.Query().Get("n")))
	ans := rawLogAnswer{Node: a.Cfg.NodeID, Source: src, Lines: lines}
	if err != nil {
		ans.Error = err.Error()
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ans)
}

// RawLog answers the UIs (ops "rawlog"): this node's log, or another
// server's over the mesh.
func (a *Agent) RawLog(node string, n int) (any, error) {
	n = rawLogLines(strconv.Itoa(n))
	if node == "" || node == a.Cfg.NodeID {
		lines, src, err := readRawLog(n)
		ans := rawLogAnswer{Node: a.Cfg.NodeID, Source: src, Lines: lines}
		if err != nil {
			ans.Error = err.Error()
		}
		return ans, nil
	}
	target, ok := store.Get[model.Node](a.Store, model.Key(model.KindNode, node))
	if !ok || target.Kind != model.NodeServer {
		return nil, errors.New("pick a server node")
	}
	ans := rawLogAnswer{Node: node}
	res, err := (&http.Client{Timeout: 10 * time.Second}).Get(a.meshURL(target, "/v1/rawlog?n="+strconv.Itoa(n)))
	if err != nil {
		ans.Error = fmt.Sprintf("%s is not reachable over the mesh (%v); open its own dashboard or run `meshgate tui` there", target.Name, err)
		return ans, nil
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(res.Body, 300))
		ans.Error = fmt.Sprintf("%s: %s %s", target.Name, res.Status, strings.TrimSpace(string(msg)))
		if res.StatusCode == http.StatusNotFound {
			ans.Error = target.Name + " runs an older meshgate without this view; update it"
		}
		return ans, nil
	}
	if err := json.NewDecoder(res.Body).Decode(&ans); err != nil {
		return nil, err
	}
	return ans, nil
}
