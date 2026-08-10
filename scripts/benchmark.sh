#!/usr/bin/env bash
#
# benchmark.sh — measure cinc-server-ng HTTP performance and (if available) compare
# against the chef-zero gem.
#
# It builds cinc-server-ng, starts it in both modes (no-auth and real Mixlib auth),
# optionally starts chef-zero (multi-org) for comparison, seeds each with an
# identical node set, and runs cmd/loadtest against each. Results are printed
# and written to a file.
#
# Usage:
#   scripts/benchmark.sh [output-file]
#
# Env overrides:
#   SEED=500 WARM=3000 DUR=3000 CONC=10   # loadtest parameters
#   CHEF_ZERO=1                            # set 0 to skip chef-zero even if present
#
# Requires: go. Optional: chef-zero on PATH for the comparison column.
set -euo pipefail

cd "$(dirname "$0")/.."

OUT="${1:-bench-$(git describe --tags --always 2>/dev/null || echo dev).txt}"
SEED="${SEED:-500}"
WARM="${WARM:-3000}"
DUR="${DUR:-3000}"
CONC="${CONC:-10}"
WANT_CHEF_ZERO="${CHEF_ZERO:-1}"

PORT_CHEF=8901
PORT_NOAUTH=8902
PORT_AUTH=8903

TMP="$(mktemp -d)"
KEY="$TMP/pivotal.pem"
PIDS=()
cleanup() {
  for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null || true; done
  pkill -f "chef-zero --multi-org --host 127.0.0.1 --port $PORT_CHEF" 2>/dev/null || true
  rm -rf "$TMP"
}
trap cleanup EXIT

echo "building cinc-server-ng..."
make build >/dev/null
VERSION="$(./cinc-server-ng --version 2>/dev/null || git describe --tags --always 2>/dev/null || echo dev)"

run() { go run ./cmd/loadtest -seed "$SEED" -warm "$WARM" -dur "$DUR" -conc "$CONC" "$@"; }
wait_up() { for _ in $(seq 1 50); do curl -sf -o /dev/null "$1" && return 0; sleep 0.1; done; return 1; }

{
  echo "### cinc-server-ng benchmark — $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "version: $VERSION"
  echo "host:    $(uname -msr)"
  echo "go:      $(go version | awk '{print $3}')"
  command -v chef-zero >/dev/null 2>&1 && echo "chef-zero: $(chef-zero --version 2>&1 | head -1)"
  echo "params:  seed=$SEED warm=$WARM dur=${DUR}ms conc=$CONC"
  echo

  # cinc-server-ng, no auth (engine-only, comparable to chef-zero's non-verifying auth)
  ./cinc-server-ng --addr "127.0.0.1:$PORT_NOAUTH" --orgs acme --no-auth >"$TMP/noauth.log" 2>&1 &
  PIDS+=($!)
  wait_up "http://127.0.0.1:$PORT_NOAUTH/_status"
  run -base "http://127.0.0.1:$PORT_NOAUTH/organizations/acme" -label "cinc-server-ng $VERSION (no-auth)"
  echo

  # cinc-server-ng, real Mixlib auth
  ./cinc-server-ng --addr "127.0.0.1:$PORT_AUTH" --orgs acme --admin pivotal --key-out "$KEY" >"$TMP/auth.log" 2>&1 &
  PIDS+=($!)
  wait_up "http://127.0.0.1:$PORT_AUTH/_status"
  run -base "http://127.0.0.1:$PORT_AUTH/organizations/acme" -user pivotal -keypem "$KEY" -label "cinc-server-ng $VERSION (auth)"
  echo

  # chef-zero, if available
  if [ "$WANT_CHEF_ZERO" = "1" ] && command -v chef-zero >/dev/null 2>&1; then
    chef-zero --multi-org --host 127.0.0.1 --port "$PORT_CHEF" >"$TMP/chef-zero.log" 2>&1 &
    PIDS+=($!)
    wait_up "http://127.0.0.1:$PORT_CHEF/organizations" || true
    curl -s -X POST -H 'Content-Type: application/json' \
      -d '{"name":"acme","full_name":"Acme"}' -o /dev/null \
      "http://127.0.0.1:$PORT_CHEF/organizations" || true
    run -base "http://127.0.0.1:$PORT_CHEF/organizations/acme" -label "chef-zero (gem)"
  else
    echo "(chef-zero not run)"
  fi
} | tee "$OUT"

echo
echo "results written to $OUT"
