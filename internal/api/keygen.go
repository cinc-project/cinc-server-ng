package api

import (
	"context"
	"crypto/rsa"
	"runtime"
)

// keygenConcurrency is how many key pairs the server generates at once. A
// 2048-bit RSA key keeps a CPU busy for tens to hundreds of milliseconds, and
// any actor able to create a client can ask for one per request (API v0, or
// create_key), so without a bound a burst of such requests takes every CPU
// from the rest of the server. Half the CPUs, and at least one, leaves the
// other half serving requests. erchef bounds the same work with its keygen
// worker pool.
func keygenConcurrency() int {
	return max(1, runtime.GOMAXPROCS(0)/2)
}

// newKey generates a key pair once one of the server's keygen slots is free,
// waiting for one as long as ctx lasts. Request handlers generate keys through
// it, never through generateKey directly, and never while holding a lock: a
// request waiting for a slot must not hold anything up but itself.
func (a *API) newKey(ctx context.Context) (*rsa.PrivateKey, error) {
	select {
	case a.keygenSlots <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	defer func() { <-a.keygenSlots }()
	return a.generateKey()
}
