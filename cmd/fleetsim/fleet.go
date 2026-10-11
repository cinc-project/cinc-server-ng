package main

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"math/rand"
	"net/http"
	"sort"
)

// node is one fleet member: its name and last-known full JSON body.
type node struct {
	name string
	body []byte
}

// selectStuck deterministically chooses ceil(frac*len(names)) node names that
// never check in. Sorting first makes the result independent of input order;
// the caller-seeded rng makes it reproducible.
func selectStuck(names []string, frac float64, rng *rand.Rand) map[string]bool {
	sorted := append([]string(nil), names...)
	sort.Strings(sorted)
	rng.Shuffle(len(sorted), func(i, j int) { sorted[i], sorted[j] = sorted[j], sorted[i] })
	// Clamp before converting: NaN or a negative fraction would otherwise give a
	// negative k and panic on the allocation and slice bound below.
	if !(frac > 0) {
		frac = 0
	}
	k := min(int(math.Ceil(min(frac, 1)*float64(len(sorted)))), len(sorted))
	stuck := make(map[string]bool, k)
	for _, name := range sorted[:k] {
		stuck[name] = true
	}
	return stuck
}

// discover reads the whole fleet from the server: list node names, then fetch
// each node's full body. Nodes are returned sorted by name.
func discover(ctx context.Context, c *client) ([]*node, error) {
	body, status, err := c.do(ctx, "GET", "/nodes", nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("list nodes: status %d", status)
	}
	var list map[string]string
	if err := json.Unmarshal(body, &list); err != nil {
		return nil, err
	}
	names := make([]string, 0, len(list))
	for name := range list {
		names = append(names, name)
	}
	sort.Strings(names)
	nodes := make([]*node, 0, len(names))
	for _, name := range names {
		nb, status, err := c.do(ctx, "GET", "/nodes/"+name, nil)
		if err != nil {
			return nil, err
		}
		if status != http.StatusOK {
			return nil, fmt.Errorf("get node %s: status %d", name, status)
		}
		nodes = append(nodes, &node{name: name, body: nb})
	}
	return nodes, nil
}
