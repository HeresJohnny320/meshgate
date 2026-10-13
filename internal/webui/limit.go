package webui

import (
	"net/http"
	"strings"
	"sync"
	"time"
)

// limiter locks out an address after 5 wrong passwords in 10 minutes.
type limiter struct {
	mu    sync.Mutex
	fails map[string][]time.Time
}

// check runs ok (the password check) unless the caller is locked out, and
// writes the error response itself when it returns false.
func (l *limiter) check(w http.ResponseWriter, r *http.Request, ok func() bool) bool {
	ip := r.RemoteAddr
	if i := strings.LastIndex(ip, ":"); i > 0 {
		ip = ip[:i]
	}
	l.mu.Lock()
	if l.fails == nil {
		l.fails = map[string][]time.Time{}
	}
	var recent []time.Time
	for _, t := range l.fails[ip] {
		if time.Since(t) < 10*time.Minute {
			recent = append(recent, t)
		}
	}
	l.fails[ip] = recent
	l.mu.Unlock()
	if len(recent) >= 5 {
		http.Error(w, `{"error":"too many attempts, wait 10 minutes"}`, http.StatusTooManyRequests)
		return false
	}
	if !ok() {
		l.mu.Lock()
		l.fails[ip] = append(l.fails[ip], time.Now())
		l.mu.Unlock()
		http.Error(w, `{"error":"wrong username or password"}`, http.StatusUnauthorized)
		return false
	}
	return true
}
