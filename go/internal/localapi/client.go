// Package localapi is the client for the agent's unix socket, used by the
// CLI and TUI.
package localapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/heresjohnny320/meshgate/internal/ops"
)

// Client talks to a local agent.
type Client struct{ hc *http.Client }

// New returns a client for the socket path.
func New(socket string) *Client {
	return &Client{hc: &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socket)
		}},
	}}
}

// View fetches the full view.
func (c *Client) View() (ops.View, error) {
	var v ops.View
	err := c.do("GET", "view", nil, &v)
	return v, err
}

// Get reads an operation's result, e.g. "history?range=1d".
func (c *Client) Get(op string, out any) error { return c.do("GET", op, nil, out) }

// Post calls an operation; out may be nil.
func (c *Client) Post(op string, body, out any) error {
	return c.do("POST", op, body, out)
}

func (c *Client) do(method, op string, body, out any) error {
	var rd *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	req, _ := http.NewRequest(method, "http://meshgate/v1/"+op, rd)
	req.Header.Set("Content-Type", "application/json")
	res, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("cannot reach the meshgate agent (is it running? try `sudo systemctl status meshgate`): %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		var e struct{ Error string }
		json.NewDecoder(res.Body).Decode(&e)
		if e.Error == "" {
			e.Error = res.Status
		}
		return fmt.Errorf("%s", e.Error)
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(res.Body).Decode(out)
}
