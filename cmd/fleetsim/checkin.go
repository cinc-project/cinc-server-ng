package main

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/cinc-project/cinc-server-ng/internal/auth"
)

// signer holds the single admin actor used to sign every request. A nil signer
// means unsigned (for a --no-auth server).
type signer struct {
	user string
	key  *rsa.PrivateKey
}

// client talks to one organization's API, optionally signing each request.
type client struct {
	http *http.Client
	base string // e.g. http://host/organizations/acme
	sign *signer
}

// newClient builds a client. When user and keyPEMPath are both set, requests are
// signed; otherwise they are sent unsigned.
func newClient(base, user, keyPEMPath string, timeout time.Duration) (*client, error) {
	c := &client{
		http: &http.Client{
			Timeout:   timeout,
			Transport: &http.Transport{MaxIdleConns: 256, MaxIdleConnsPerHost: 256},
		},
		base: base,
	}
	if user != "" && keyPEMPath != "" {
		pem, err := os.ReadFile(keyPEMPath)
		if err != nil {
			return nil, err
		}
		key, err := auth.ParsePrivateKey(pem)
		if err != nil {
			return nil, err
		}
		c.sign = &signer{user: user, key: key}
	}
	return c, nil
}

// do builds, signs, and sends a request to base+path, returning the response
// body and status code. The request honors ctx, so a cancelled run aborts any
// in-flight call promptly instead of waiting out the client timeout.
func (c *client) do(ctx context.Context, method, path string, body []byte) ([]byte, int, error) {
	var r io.Reader
	if body != nil {
		r = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, r)
	if err != nil {
		return nil, 0, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("X-Ops-Server-API-Version", "1")
	if c.sign != nil {
		ts := time.Now().UTC().Format(time.RFC3339)
		if err := auth.SignRequest(req, c.sign.user, ts, body, c.sign.key); err != nil {
			return nil, 0, err
		}
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, err
	}
	return out, resp.StatusCode, nil
}

// checkIn performs one simulated chef-client check-in for n: fetch the current
// node, stamp automatic.ohai_time with now, and PUT it back. On success the
// node's cached body is updated so the next cycle round-trips the latest state.
func (c *client) checkIn(ctx context.Context, n *node, now int64) error {
	body, status, err := c.do(ctx, "GET", "/nodes/"+n.name, nil)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("GET node %s: status %d", n.name, status)
	}
	stamped, err := stampOhaiTime(body, now)
	if err != nil {
		return err
	}
	_, status, err = c.do(ctx, "PUT", "/nodes/"+n.name, stamped)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("PUT node %s: status %d", n.name, status)
	}
	n.body = stamped
	return nil
}

// stampOhaiTime returns body with automatic.ohai_time set to ts (Unix seconds),
// creating the automatic map if absent. Every other field is preserved.
func stampOhaiTime(body []byte, ts int64) ([]byte, error) {
	var node map[string]any
	if err := json.Unmarshal(body, &node); err != nil {
		return nil, err
	}
	automatic, ok := node["automatic"].(map[string]any)
	if !ok {
		automatic = map[string]any{}
		node["automatic"] = automatic
	}
	automatic["ohai_time"] = float64(ts)
	return json.Marshal(node)
}
