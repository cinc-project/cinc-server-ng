#!/usr/bin/env bash
#
# bench-tls.sh — measure what native TLS (--tls-cert/--tls-key) costs, by
# running cmd/loadtest against the same cinc-server-ng binary over plain HTTP
# and over HTTPS, for cmd/benchreport.
#
# Both runs use the in-memory backend with authentication on (the binary's
# defaults), the same seeded data and the same signing identity, so the only
# difference is the transport. Each transport is measured REPS times in an
# order that rotates every repetition, and every run starts a fresh process.
# loadtest's cold figure is the first request on a fresh connection, so over
# HTTPS it includes the TLS handshake; the warm figures reuse one connection.
#
# Usage:
#   scripts/bench-tls.sh <output-dir>
#
# Writes <output-dir>/run-<rep>-<http|https>.json and <rep>-<http|https>.txt,
# then <output-dir>/report.md from cmd/benchreport.
#
# Env overrides:
#   SEED=500 WARM=1000 DUR=3000 CONC=10 REPS=3   # loadtest parameters
#
# Requires: go, curl, openssl (to make a throwaway self-signed certificate).
set -euo pipefail

cd "$(dirname "$0")/.."

OUT="${1:?usage: scripts/bench-tls.sh <output-dir>}"
SEED="${SEED:-500}"
WARM="${WARM:-1000}"
DUR="${DUR:-3000}"
CONC="${CONC:-10}"
REPS="${REPS:-3}"
PORT=8911
ORG=bench

mkdir -p "$OUT"
TMP="$(mktemp -d)"
PID=""
cleanup() {
  [ -n "$PID" ] && kill "$PID" 2>/dev/null || true
  rm -rf "$TMP"
}
trap cleanup EXIT

if curl -sk -o /dev/null "http://127.0.0.1:$PORT/" || curl -sk -o /dev/null "https://127.0.0.1:$PORT/"; then
  echo "port $PORT is already in use; stop whatever is listening there first" >&2
  exit 1
fi

echo "building cinc-server-ng and loadtest..."
go build -o "$TMP/cinc-server-ng" ./cmd/cinc-server-ng
go build -o "$TMP/loadtest" ./cmd/loadtest

# A P-256 certificate, what an ACME client issues by default.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 1 \
  -subj "/CN=localhost" -addext "subjectAltName=IP:127.0.0.1,DNS:localhost" \
  -keyout "$TMP/server.key" -out "$TMP/server.crt" 2>/dev/null

declare -A LABEL=([http]="cinc-server-ng (HTTP)" [https]="cinc-server-ng (HTTPS)")
TRANSPORTS=(http https)

run_one() { # run_one <rep> <http|https>
  local rep=$1 slug=$2 name="$1-$2"
  local flags=(--addr "127.0.0.1:$PORT" --orgs "$ORG" --key-out "$TMP/pivotal.pem")
  local trust=()
  if [ "$slug" = https ]; then
    flags+=(--tls-cert "$TMP/server.crt" --tls-key "$TMP/server.key")
    trust=(-cacert "$TMP/server.crt")
  fi
  "$TMP/cinc-server-ng" "${flags[@]}" >"$OUT/$name.log" 2>&1 &
  PID=$!
  for _ in $(seq 1 100); do
    curl -sf --cacert "$TMP/server.crt" -o /dev/null "$slug://127.0.0.1:$PORT/_status" && break
    sleep 0.1
  done
  "$TMP/loadtest" -label "${LABEL[$slug]}" -base "$slug://127.0.0.1:$PORT/organizations/$ORG" \
    -user pivotal -keypem "$TMP/pivotal.pem" "${trust[@]}" \
    -seed "$SEED" -warm "$WARM" -dur "$DUR" -conc "$CONC" \
    -json "$OUT/run-$name.json" | tee "$OUT/$name.txt"
  kill "$PID"
  wait "$PID" 2>/dev/null || true
  PID=""
  rm -f "$OUT/$name.log"
}

for rep in $(seq 1 "$REPS"); do
  n=${#TRANSPORTS[@]}
  for i in $(seq 0 $((n - 1))); do
    slug=${TRANSPORTS[$(((i + rep - 1) % n))]}
    echo "== rep $rep: ${LABEL[$slug]}"
    run_one "$rep" "$slug"
  done
done

go run ./cmd/benchreport -runs "$OUT/run-*.json" -o "$OUT/report.md"
echo "report: $OUT/report.md"
