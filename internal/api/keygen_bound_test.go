package api

import (
	"crypto/rsa"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cinc-project/cinc-server-ng/internal/auth"
	"github.com/cinc-project/cinc-server-ng/internal/store"
)

// countKeygens makes a's key generator count its calls.
func countKeygens(a *API) *atomic.Int32 {
	var n atomic.Int32
	a.generateKey = func() (*rsa.PrivateKey, error) {
		n.Add(1)
		return auth.GenerateKey()
	}
	return &n
}

// Generating a key pair is the expensive part of creating an actor, so a
// create that is going to be refused because the name is taken must answer
// before spending it. The answer itself is unchanged.
func TestCreateActorConflictGeneratesNoKey(t *testing.T) {
	cases := []struct {
		name, path, version, body string
	}{
		{"client at v0", "/organizations/acme/clients", "", `{"name":"web"}`},
		{"client with create_key", "/organizations/acme/clients", "1", `{"name":"web","create_key":true}`},
		{"user at v0", "/users", "", userBody(`{"name":"alice"}`)},
		{"user with create_key", "/users", "1", userBody(`{"name":"alice","create_key":true}`)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, srv := keyRaceAPI(t, store.New())
			n := countKeygens(a)
			if resp, body := doAt(t, tc.version, "POST", srv.URL+tc.path, tc.body); resp.StatusCode != http.StatusCreated {
				t.Fatalf("first create = %d: %s", resp.StatusCode, body)
			}
			if got := n.Load(); got != 1 {
				t.Fatalf("first create generated %d keys, want 1", got)
			}
			resp, body := doAt(t, tc.version, "POST", srv.URL+tc.path, tc.body)
			if resp.StatusCode != http.StatusConflict || strings.TrimSpace(body) != `{"error":["Object already exists"]}` {
				t.Errorf("repeat create = %d %s, want 409 Object already exists", resp.StatusCode, body)
			}
			if got := n.Load(); got != 1 {
				t.Errorf("repeat create generated a key (%d in all), want none", got-1)
			}
		})
	}
}

// The same holds for adding a named key the actor already has.
func TestAddExistingKeyGeneratesNoKey(t *testing.T) {
	a, srv := keyRaceAPI(t, store.New())
	mustStatus(t, "POST", srv.URL+"/organizations/acme/clients", `{"name":"web"}`, http.StatusCreated)
	n := countKeygens(a)
	url := srv.URL + "/organizations/acme/clients/web/keys"
	const body = `{"name":"k1","create_key":true,"expiration_date":"infinity"}`
	mustStatus(t, "POST", url, body, http.StatusCreated)
	if got := n.Load(); got != 1 {
		t.Fatalf("first add generated %d keys, want 1", got)
	}
	resp, got := do(t, "POST", url, body)
	if resp.StatusCode != http.StatusConflict || strings.TrimSpace(got) != `{"error":["Key already exists"]}` {
		t.Errorf("repeat add = %d %s, want 409 Key already exists", resp.StatusCode, got)
	}
	if got := n.Load(); got != 1 {
		t.Errorf("repeat add generated a key (%d in all), want none", got-1)
	}
}

// Key generation saturates a CPU for its duration, and any client creation at
// API v0 (or with create_key) asks for one, so the number running at once is
// bounded server-wide: requests past the bound wait for a slot.
func TestKeygenConcurrencyBounded(t *testing.T) {
	for _, tc := range []struct {
		slots    int
		wantBoth bool
	}{
		{slots: 2, wantBoth: true}, // baseline: two slots, both run at once
		{slots: 1, wantBoth: false},
	} {
		a, srv := keyRaceAPI(t, store.New())
		a.keygenSlots = make(chan struct{}, tc.slots)
		entered := make(chan struct{}, 2)
		release := make(chan struct{})
		a.generateKey = func() (*rsa.PrivateKey, error) {
			entered <- struct{}{}
			<-release
			return auth.GenerateKey()
		}
		var wg sync.WaitGroup
		for _, name := range []string{"a", "b"} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if resp, body := do(t, "POST", srv.URL+"/organizations/acme/clients", `{"name":"`+name+`"}`); resp.StatusCode != http.StatusCreated {
					t.Errorf("create %s = %d: %s", name, resp.StatusCode, body)
				}
			}()
		}
		select {
		case <-entered:
		case <-time.After(5 * time.Second):
			close(release)
			wg.Wait()
			t.Fatalf("slots=%d: no key generation started", tc.slots)
		}
		select {
		case <-entered:
			if !tc.wantBoth {
				t.Errorf("slots=%d: a second key generation started while one was running", tc.slots)
			}
		case <-time.After(200 * time.Millisecond):
			if tc.wantBoth {
				t.Errorf("slots=%d: the second key generation did not start alongside the first", tc.slots)
			}
		}
		close(release)
		wg.Wait()
	}
}
