package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cinc-project/cinc-server-ng/internal/store"
)

// stallingUserGet holds a Get of one global user until released, standing in
// for a group PUT that takes long under the membership lock (a large body of
// names, each looked up).
type stallingUserGet struct {
	store.Backend
	user     string
	once     sync.Once
	entered  chan struct{}
	released chan struct{}
	armed    atomic.Bool
}

func (b *stallingUserGet) Get(org, coll, key string) ([]byte, bool, error) {
	if b.armed.Load() && org == "" && coll == "users" && key == b.user {
		b.once.Do(func() {
			close(b.entered)
			<-b.released
		})
	}
	return b.Backend.Get(org, coll, key)
}

// A group PUT holds the membership lock exclusively while it resolves the
// names in its body. That orders it against revocations in its own org, but
// must not hold up client registration or association in any other org: the
// holder is an admin of one org and the work is sized by its request.
func TestGroupPutDoesNotBlockOtherOrgs(t *testing.T) {
	be := &stallingUserGet{
		Backend: store.NewMemoryBackend(), user: "slow",
		entered: make(chan struct{}), released: make(chan struct{}),
	}
	st := store.NewWithBackend(be)
	for _, name := range []string{"acme", "globex"} {
		org, err := st.CreateOrg(name)
		if err != nil {
			t.Fatal(err)
		}
		if err := SeedOrg(org); err != nil {
			t.Fatal(err)
		}
	}
	h := New(st).Handler()
	serve := func(method, path, body string) (int, string) {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(method, path, strings.NewReader(body)))
		return rec.Code, rec.Body.String()
	}
	must := func(want int, method, path, body string) {
		t.Helper()
		if code, got := serve(method, path, body); code != want {
			t.Fatalf("%s %s = %d, want %d: %s", method, path, code, want, got)
		}
	}
	pub := jsonString(t, testPublicKey(t))
	register := func(org, name string) func() (int, string) {
		return func() (int, string) {
			return serve("POST", "/organizations/"+org+"/clients", `{"name":"`+name+`","public_key":`+pub+`}`)
		}
	}
	must(http.StatusCreated, "POST", "/users", userBody(`{"name":"slow","public_key":`+pub+`}`))
	must(http.StatusCreated, "POST", "/users", userBody(`{"name":"bob","public_key":`+pub+`}`))
	must(http.StatusCreated, "POST", "/organizations/acme/groups", `{"groupname":"mygroup"}`)
	// Baseline: with nothing stalled, both orgs register clients.
	must(http.StatusCreated, "POST", "/organizations/globex/clients", `{"name":"node0","public_key":`+pub+`}`)

	be.armed.Store(true)
	putDone := make(chan int, 1)
	go func() {
		code, _ := serve("PUT", "/organizations/acme/groups/mygroup", `{"actors":{"users":["slow"]}}`)
		putDone <- code
	}()
	<-be.entered
	released := false
	release := func() {
		if !released {
			released = true
			close(be.released)
		}
	}
	defer func() {
		release()
		if code := <-putDone; code != http.StatusOK {
			t.Errorf("PUT mygroup = %d", code)
		}
	}()

	type result struct {
		code int
		body string
	}
	start := func(fn func() (int, string)) chan result {
		ch := make(chan result, 1)
		go func() {
			code, body := fn()
			ch <- result{code, body}
		}()
		return ch
	}
	wait := func(ch chan result, d time.Duration) (result, bool) {
		select {
		case r := <-ch:
			return r, true
		case <-time.After(d):
			return result{}, false
		}
	}

	// The same org still waits: the PUT is ordered against its registrations.
	sameOrg := start(register("acme", "node1"))
	if r, done := wait(sameOrg, 200*time.Millisecond); done {
		t.Fatalf("baseline: a registration in acme ran during acme's group PUT: %d %s", r.code, r.body)
	}

	for _, op := range []struct {
		name string
		fn   func() (int, string)
		want int
	}{
		{"register in globex", register("globex", "node2"), http.StatusCreated},
		{"associate in globex", func() (int, string) {
			return serve("POST", "/organizations/globex/users", `{"username":"bob"}`)
		}, http.StatusCreated},
	} {
		r, done := wait(start(op.fn), 5*time.Second)
		if !done {
			t.Fatalf("%s waited on acme's group PUT", op.name)
		}
		if r.code != op.want {
			t.Errorf("%s = %d, want %d: %s", op.name, r.code, op.want, r.body)
		}
	}

	release()
	if r, done := wait(sameOrg, 5*time.Second); !done || r.code != http.StatusCreated {
		t.Errorf("registration in acme after the PUT = %d (done=%v): %s", r.code, done, r.body)
	}
}

// A name repeated in a group PUT is looked up once, so the time the PUT holds
// the lock follows the names it gives, not the length of its body.
func TestGroupPutLooksUpRepeatedNamesOnce(t *testing.T) {
	st := store.New()
	if _, err := st.CreateOrg("acme"); err != nil {
		t.Fatal(err)
	}
	h := New(st).Handler()
	serve := func(method, path, body string) (int, string) {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(method, path, strings.NewReader(body)))
		return rec.Code, rec.Body.String()
	}
	if code, body := serve("POST", "/organizations/acme/groups", `{"groupname":"mygroup"}`); code != http.StatusCreated {
		t.Fatalf("create = %d: %s", code, body)
	}
	put := func(n int) int64 {
		names := strings.TrimSuffix(strings.Repeat(`"ghost",`, n), ",")
		before := st.Counts().Reads.Load()
		if code, body := serve("PUT", "/organizations/acme/groups/mygroup", `{"actors":{"users":[`+names+`],"clients":[`+names+`]}}`); code != http.StatusOK {
			t.Fatalf("PUT = %d: %s", code, body)
		}
		return st.Counts().Reads.Load() - before
	}
	if one, many := put(1), put(1000); many != one {
		t.Errorf("a PUT naming ghost 1000 times made %d reads, one naming it once %d", many, one)
	}
}
