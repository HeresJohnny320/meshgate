package meshcore

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/heresjohnny320/meshgate/internal/changelog"
	"github.com/heresjohnny320/meshgate/internal/model"
	"github.com/heresjohnny320/meshgate/internal/store"
	"github.com/heresjohnny320/meshgate/internal/update"
)

// adminState is the app's dashboard session. The token is kept in memory
// only; every server accepts it (see webui.AppAPI), so requests move to
// another server when the current one is down.
type adminState struct {
	mu     sync.Mutex
	token  string
	user   string
	expiry int64
	last   string // node ID of the server that answered last
}

type adminReply struct {
	Status int    `json:"status"`
	Body   string `json:"body"`
	Server string `json:"server,omitempty"` // name of the node that answered
}

var adminClient = &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{
	DialContext:       (&net.Dialer{Timeout: 4 * time.Second}).DialContext,
	DisableKeepAlives: true,
}}

// Admin carries one request of the app's built-in dashboard. path is what
// the dashboard asks for ("/auth/login", "/api/view", ...); the answer is
// adminReply as JSON. It blocks, so call it off the UI thread.
func (e *Engine) Admin(method, path, body string) string {
	r := e.admin1(method, path, body)
	b, _ := json.Marshal(r)
	return string(b)
}

func (e *Engine) admin1(method, path, body string) adminReply {
	a := &e.admin
	switch path {
	case "/auth/me":
		a.mu.Lock()
		ok := a.token != "" && time.Now().Unix() < a.expiry
		user := a.user
		a.mu.Unlock()
		b, _ := json.Marshal(map[string]any{"ok": ok, "user": user})
		return adminReply{Status: 200, Body: string(b)}
	case "/auth/logout":
		a.mu.Lock()
		a.token, a.user = "", ""
		a.mu.Unlock()
		return adminReply{Status: 200, Body: `{"ok":true}`}
	case "/auth/login":
		r := e.adminSend("POST", "/admin/login", body, "")
		if r.Status == 200 {
			var lr struct {
				Token   string `json:"token"`
				User    string `json:"user"`
				Expires int64  `json:"expires"`
			}
			json.Unmarshal([]byte(r.Body), &lr)
			a.mu.Lock()
			a.token, a.user, a.expiry = lr.Token, lr.User, lr.Expires
			a.mu.Unlock()
			r.Body = `{"ok":true}`
		}
		return r
	}
	rest, ok := strings.CutPrefix(path, "/api/")
	if !ok {
		return adminReply{Status: 404, Body: `{"error":"not found"}`}
	}
	a.mu.Lock()
	tok := a.token
	a.mu.Unlock()
	if tok == "" {
		return adminReply{Status: 401, Body: `{"error":"login required"}`}
	}
	r := e.adminSend(method, "/admin/api/"+rest, body, tok)
	if r.Status == 401 {
		a.mu.Lock()
		a.token = ""
		a.mu.Unlock()
	}
	return r
}

// adminSend tries the servers that answer app management, the last good one
// first, until one replies.
func (e *Engine) adminSend(method, path, body, token string) adminReply {
	servers := e.adminServers()
	if len(servers) == 0 {
		return adminReply{Status: 503, Body: `{"error":"no server in this mesh accepts app management"}`}
	}
	var errs []string
	for _, n := range servers {
		port := n.MeshPort
		if port == 0 {
			port = model.DefaultMeshPort
		}
		url := "http://" + net.JoinHostPort(n.MeshIP, strconv.Itoa(port)) + path
		req, _ := http.NewRequest(method, url, bytes.NewReader([]byte(body)))
		req.Header.Set("Content-Type", "application/json")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		res, err := adminClient.Do(req)
		if err != nil {
			errs = append(errs, n.Name+": unreachable")
			continue
		}
		b, _ := io.ReadAll(io.LimitReader(res.Body, 4<<20))
		res.Body.Close()
		if res.StatusCode == http.StatusNotFound && strings.HasPrefix(path, "/admin/login") {
			errs = append(errs, n.Name+": app management off or meshgate too old")
			continue
		}
		e.admin.mu.Lock()
		e.admin.last = n.ID
		e.admin.mu.Unlock()
		return adminReply{Status: res.StatusCode, Body: string(b), Server: n.Name}
	}
	msg, _ := json.Marshal(map[string]string{"error": fmt.Sprintf("no server answered (%s). Is the tunnel on?", strings.Join(errs, ", "))})
	return adminReply{Status: 503, Body: string(msg)}
}

func (e *Engine) adminServers() []model.Node {
	e.mu.Lock()
	s := e.store
	e.mu.Unlock()
	if s == nil {
		return nil
	}
	e.admin.mu.Lock()
	last := e.admin.last
	e.admin.mu.Unlock()
	var out []model.Node
	for _, n := range store.List[model.Node](s, model.KindNode) {
		if n.Kind == model.NodeServer && n.MeshIP != "" && !n.AppAdminOff {
			out = append(out, n)
		}
	}
	// Last good server first; then those hosting a web UI (likely the
	// "main" one); then by name for a stable order.
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if (a.ID == last) != (b.ID == last) {
			return a.ID == last
		}
		if a.WebUI != b.WebUI {
			return a.WebUI
		}
		return a.Name < b.Name
	})
	return out
}

// UpdateAvailable returns the newest release tag if it is newer than the
// app's version (e.g. "0.2.8" or "v0.2.8"), otherwise "".
func (e *Engine) UpdateAvailable(appVersion string) string {
	tag, err := update.Latest(context.Background())
	if err != nil || !update.Newer(appVersion, tag) {
		return ""
	}
	return tag
}

// DownloadAPK saves release tag's APK to path after checking it against
// the release's SHA256SUMS; the app then asks Android to install it.
func (e *Engine) DownloadAPK(tag, path string) error {
	b, err := update.Fetch(context.Background(), tag, "meshgate-android.apk")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

// Changelog returns the changelog of this app's version (CHANGELOG.md).
func (e *Engine) Changelog() string { return changelog.Text }
