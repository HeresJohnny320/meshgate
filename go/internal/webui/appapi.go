package webui

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/heresjohnny320/meshgate/internal/ops"
)

// TokenTTL is how long an app login lasts.
const TokenTTL = 12 * time.Hour

// AppAPI serves the dashboard API to the phone app on a server's mesh port
// (mesh devices only), under /admin/. Any server can answer: a login yields
// a token signed with a key derived from the admin's stored password hash,
// which every server has, so the app moves to another server when one goes
// down without logging in again. Changing the password invalidates every
// token. off reports whether this node opted out (Node.AppAdminOff).
func AppAPI(o *ops.Service, off func() bool) http.Handler {
	a := &appAPI{ops: o, api: o.Handler("/admin/api/")}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /admin/login", a.login)
	mux.Handle("POST /admin/api/qr", a.auth(http.HandlerFunc(QR)))
	mux.Handle("/admin/api/", a.auth(a.api))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if off() {
			http.Error(w, `{"error":"app management is turned off on this node"}`, http.StatusNotFound)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		mux.ServeHTTP(w, r)
	})
}

type appAPI struct {
	ops *ops.Service
	api http.Handler
	lim limiter
}

func (a *appAPI) login(w http.ResponseWriter, r *http.Request) {
	var b struct{ Username, Password string }
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&b); err != nil {
		http.Error(w, `{"error":"bad request"}`, http.StatusBadRequest)
		return
	}
	if !a.lim.check(w, r, func() bool { return a.ops.CheckAdmin(b.Username, b.Password) }) {
		return
	}
	hash, _ := a.ops.AdminHash(b.Username)
	exp := time.Now().Add(TokenTTL).Unix()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"ok": true, "user": b.Username, "token": signToken(hash, b.Username, exp), "expires": exp})
}

func (a *appAPI) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !a.validToken(tok) {
			http.Error(w, `{"error":"login required"}`, http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Token: base64url(user) "." expiry "." hex(HMAC-SHA256(key, user "." expiry))
// with key = SHA-256("meshgate app token" + password hash).
func signToken(hash, user string, exp int64) string {
	u := base64.RawURLEncoding.EncodeToString([]byte(user))
	e := strconv.FormatInt(exp, 10)
	return u + "." + e + "." + hex.EncodeToString(tokenMAC(hash, u+"."+e))
}

func tokenMAC(hash, msg string) []byte {
	key := sha256.Sum256([]byte("meshgate app token" + hash))
	m := hmac.New(sha256.New, key[:])
	m.Write([]byte(msg))
	return m.Sum(nil)
}

func (a *appAPI) validToken(tok string) bool {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return false
	}
	user, err := base64.RawURLEncoding.DecodeString(parts[0])
	exp, err2 := strconv.ParseInt(parts[1], 10, 64)
	mac, err3 := hex.DecodeString(parts[2])
	if err != nil || err2 != nil || err3 != nil || time.Now().Unix() > exp {
		return false
	}
	hash, ok := a.ops.AdminHash(string(user))
	return ok && hmac.Equal(mac, tokenMAC(hash, parts[0]+"."+parts[1]))
}
