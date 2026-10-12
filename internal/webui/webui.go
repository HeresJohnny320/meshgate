// Package webui serves the browser dashboard. It is a thin, authenticated
// wrapper around the same ops API the TUI uses, so any server node can host
// it and the mesh does not depend on it being up.
package webui

import (
	"crypto/rand"
	"embed"
	"encoding/base64"
	"encoding/json"
	"io"
	"io/fs"
	"net/http"
	"strings"
	"sync"
	"time"

	qrcode "github.com/skip2/go-qrcode"

	"github.com/heresjohnny320/meshgate/internal/ops"
)

//go:embed static
var static embed.FS

const (
	cookieName = "meshgate_session"
	sessionTTL = 12 * time.Hour
)

// UI is the web UI handler.
type UI struct {
	ops *ops.Service
	api http.Handler

	mu       sync.Mutex
	sessions map[string]session
	fails    map[string][]time.Time
}

type session struct {
	user    string
	expires time.Time
}

// New builds the handler.
func New(o *ops.Service) http.Handler {
	u := &UI{ops: o, api: o.Handler("/api/"), sessions: map[string]session{}, fails: map[string][]time.Time{}}
	mux := http.NewServeMux()
	sub, _ := fs.Sub(static, "static")
	mux.Handle("GET /", http.FileServer(http.FS(sub)))
	mux.HandleFunc("POST /auth/login", u.login)
	mux.HandleFunc("POST /auth/logout", u.logout)
	mux.HandleFunc("GET /auth/me", u.me)
	mux.Handle("POST /api/qr", u.auth(http.HandlerFunc(qr)))
	mux.Handle("GET /api/", u.auth(u.api))
	mux.Handle("POST /api/", u.auth(u.api))
	return secure(mux)
}

func secure(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'")
		h.ServeHTTP(w, r)
	})
}

func (u *UI) auth(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := u.user(r); !ok {
			http.Error(w, `{"error":"login required"}`, http.StatusUnauthorized)
			return
		}
		// CSRF: browsers cannot add custom headers to cross-site form posts.
		if r.Method != http.MethodGet && r.Header.Get("X-Meshgate") != "1" {
			http.Error(w, `{"error":"missing csrf header"}`, http.StatusForbidden)
			return
		}
		h.ServeHTTP(w, r)
	})
}

func (u *UI) user(r *http.Request) (string, bool) {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return "", false
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	s, ok := u.sessions[c.Value]
	if !ok || time.Now().After(s.expires) {
		delete(u.sessions, c.Value)
		return "", false
	}
	return s.user, true
}

func (u *UI) login(w http.ResponseWriter, r *http.Request) {
	var b struct{ Username, Password string }
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&b); err != nil {
		http.Error(w, `{"error":"bad request"}`, http.StatusBadRequest)
		return
	}
	ip := r.RemoteAddr
	if i := strings.LastIndex(ip, ":"); i > 0 {
		ip = ip[:i]
	}
	u.mu.Lock()
	var recent []time.Time
	for _, t := range u.fails[ip] {
		if time.Since(t) < 10*time.Minute {
			recent = append(recent, t)
		}
	}
	u.fails[ip] = recent
	u.mu.Unlock()
	if len(recent) >= 5 {
		http.Error(w, `{"error":"too many attempts, wait 10 minutes"}`, http.StatusTooManyRequests)
		return
	}
	if !u.ops.CheckAdmin(b.Username, b.Password) {
		u.mu.Lock()
		u.fails[ip] = append(u.fails[ip], time.Now())
		u.mu.Unlock()
		http.Error(w, `{"error":"wrong username or password"}`, http.StatusUnauthorized)
		return
	}
	id := make([]byte, 32)
	rand.Read(id)
	tok := base64.RawURLEncoding.EncodeToString(id)
	u.mu.Lock()
	u.sessions[tok] = session{user: b.Username, expires: time.Now().Add(sessionTTL)}
	u.mu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: tok, Path: "/", HttpOnly: true,
		SameSite: http.SameSiteStrictMode, Secure: r.TLS != nil, MaxAge: int(sessionTTL.Seconds()),
	})
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"ok":true}`))
}

func (u *UI) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(cookieName); err == nil {
		u.mu.Lock()
		delete(u.sessions, c.Value)
		u.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", MaxAge: -1})
	w.Write([]byte(`{"ok":true}`))
}

func (u *UI) me(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	user, ok := u.user(r)
	json.NewEncoder(w).Encode(map[string]any{"user": user, "ok": ok})
}

func qr(w http.ResponseWriter, r *http.Request) {
	var b struct{ Text string }
	if err := json.NewDecoder(io.LimitReader(r.Body, 8192)).Decode(&b); err != nil || b.Text == "" {
		http.Error(w, `{"error":"bad request"}`, http.StatusBadRequest)
		return
	}
	png, err := qrcode.Encode(b.Text, qrcode.Medium, 320)
	if err != nil {
		http.Error(w, `{"error":"qr failed"}`, http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"png": "data:image/png;base64," + base64.StdEncoding.EncodeToString(png)})
}
