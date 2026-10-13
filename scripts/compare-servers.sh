#!/usr/bin/env bash
#
# compare-servers.sh — run cmd/loadtest against Chef Infra Server, chef-zero and
# cinc-server-ng on one machine, one server at a time, for cmd/benchreport.
#
# Run by .github/workflows/benchmark-vs-chef-server.yml after it has installed
# and provisioned Cinc Server (the FOSS Chef Infra Server build) and chef-zero.
# Only one server is up while it is measured, so none competes with another for
# the machine: Chef Infra Server is stopped while the others run. Each server
# is measured REPS times, in an order that rotates every repetition so no
# server always runs first or last, and every cinc-server-ng and chef-zero run
# starts a fresh process. A memory sample (scripts/memsample.sh) covers each run.
#
# Writes $OUT/run-<rep>-<server>.json, $OUT/mem-<rep>-<server>.json and
# $OUT/<rep>-<server>.txt. Exits non-zero if any run had failed requests, after
# running everything else.
#
# Environment:
#   BIN         directory holding cinc-server-ng and loadtest binaries
#   OUT         results directory (created)
#   ORG         organization every server serves
#   BENCH_USER  user the signed runs authenticate as
#   USER_KEY    that user's private key
#   STATE_DIR   cinc-server-ng --state directory carrying the same user
#   REF_URL     Chef Infra Server org URL; CACERT its certificate
#   SEED CONC WARM REPS  loadtest parameters and repetitions
#   SERVERS     optional subset, e.g. "sqlite memory noauth zero" to try the
#               harness on a machine without Chef Infra Server
#
# The -tls variants serve cinc-server-ng over HTTPS (--tls-cert/--tls-key) with
# a throwaway self-signed P-256 certificate, so it can be compared with Chef
# Infra Server, which is always measured over HTTPS, transport for transport.
set -euo pipefail

: "${BIN:?}" "${OUT:?}" "${ORG:?}" "${BENCH_USER:?}" "${USER_KEY:?}" "${STATE_DIR:?}"
: "${REF_URL:?}" "${CACERT:?}" "${SEED:=500}" "${CONC:=10}" "${WARM:=1000}" "${REPS:=3}"

HERE="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$OUT"
FAILED=0
SETTLE=10 # seconds a freshly started server idles before its idle sample

# Labels, as they appear in the report; the slug names the result files.
declare -A LABEL=(
  [chef]="Chef Infra Server"
  [sqlite]="cinc-server-ng (SQLite)"
  [sqlite-tls]="cinc-server-ng (SQLite, HTTPS)"
  [memory]="cinc-server-ng (in memory)"
  [memory-tls]="cinc-server-ng (in memory, HTTPS)"
  [noauth]="cinc-server-ng (no auth)"
  [zero]="chef-zero"
)
read -r -a SERVERS <<<"${SERVERS:-chef sqlite sqlite-tls memory memory-tls noauth zero}"

# The certificate the -tls variants serve, and loadtest trusts.
TLS_DIR="$(mktemp -d)"
trap 'rm -rf "$TLS_DIR"' EXIT
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 1 \
  -subj "/CN=localhost" -addext "subjectAltName=IP:127.0.0.1,DNS:localhost" \
  -keyout "$TLS_DIR/server.key" -out "$TLS_DIR/server.crt" 2>/dev/null

wait_for() { # wait_for <seconds> <command...>
  local limit=$1; shift
  for _ in $(seq 1 "$limit"); do "$@" >/dev/null 2>&1 && return 0; sleep 1; done
  echo "timed out waiting for: $*" >&2
  return 1
}

# shellcheck disable=SC2329 # called through wait_for
chef_up() { curl -fsSk https://localhost/_status | grep -q '"status":"pong"'; }

# measure <rep> <slug> <root-pid> <sudo-or-empty> <loadtest args...>: sample the
# server's memory while loadtest runs against it.
measure() {
  local rep=$1 slug=$2 pid=$3 asroot=$4; shift 4
  local name="$rep-$slug"
  sleep "$SETTLE"
  $asroot "$HERE/memsample.sh" "$OUT/mem-$name.json" "${LABEL[$slug]}" "$pid" &
  local sampler=$!
  if ! "$BIN/loadtest" -label "${LABEL[$slug]}" -seed "$SEED" -conc "$CONC" -warm "$WARM" \
    -json "$OUT/run-$name.json" "$@" | tee "$OUT/$name.txt"; then
    echo "::warning::$name had failed requests" >&2
    FAILED=1
  fi
  $asroot kill -TERM "$sampler"
  wait "$sampler" || true
}

run_chef() {
  sudo cinc-server-ctl start >/dev/null
  wait_for 600 chef_up
  local root
  root=$(pgrep -f 'runsvdir.*/opt/cinc-project/service' | head -1)
  [ -n "$root" ] || { echo "cannot find Cinc Server's runsvdir" >&2; exit 1; }
  measure "$1" chef "$root" sudo -base "$REF_URL" -user "$BENCH_USER" -keypem "$USER_KEY" -cacert "$CACERT"
  sudo cinc-server-ctl stop >/dev/null
}

# run_cinc <rep> <slug> <port> <server flags...>; a -tls slug serves HTTPS.
run_cinc() {
  local rep=$1 slug=$2 port=$3; shift 3
  local scheme=http tls=() trust=()
  if [[ $slug == *-tls ]]; then
    scheme=https
    tls=(--tls-cert "$TLS_DIR/server.crt" --tls-key "$TLS_DIR/server.key")
    trust=(-cacert "$TLS_DIR/server.crt")
  fi
  "$BIN/cinc-server-ng" --addr "127.0.0.1:$port" --orgs "$ORG" "${tls[@]}" "$@" >"$OUT/$rep-$slug.log" 2>&1 &
  local pid=$!
  wait_for 60 curl -fsS --cacert "$TLS_DIR/server.crt" "$scheme://127.0.0.1:$port/_status"
  local auth=(-user "$BENCH_USER" -keypem "$USER_KEY")
  [ "$slug" = noauth ] && auth=()
  measure "$rep" "$slug" "$pid" "" -base "$scheme://127.0.0.1:$port/organizations/$ORG" "${auth[@]}" "${trust[@]}"
  kill "$pid"; wait "$pid" 2>/dev/null || true
}

run_zero() {
  local rep=$1 port=8892
  chef-zero --multi-org --host 127.0.0.1 --port "$port" >"$OUT/$rep-zero.log" 2>&1 &
  local pid=$!
  wait_for 60 curl -s -o /dev/null "http://127.0.0.1:$port/organizations"
  curl -fsS -X POST -H 'Content-Type: application/json' -o /dev/null \
    -d "{\"name\":\"$ORG\",\"full_name\":\"$ORG\"}" "http://127.0.0.1:$port/organizations"
  measure "$rep" zero "$pid" "" -base "http://127.0.0.1:$port/organizations/$ORG"
  kill "$pid"; wait "$pid" 2>/dev/null || true
}

run_server() { # run_server <rep> <slug>
  case $2 in
    chef) run_chef "$1" ;;
    sqlite) run_cinc "$1" sqlite 8890 --state "$STATE_DIR" --storage sqlite --db "$OUT/$1-sqlite.db" ;;
    sqlite-tls) run_cinc "$1" sqlite-tls 8893 --state "$STATE_DIR" --storage sqlite --db "$OUT/$1-sqlite-tls.db" ;;
    memory) run_cinc "$1" memory 8889 --state "$STATE_DIR" ;;
    memory-tls) run_cinc "$1" memory-tls 8894 --state "$STATE_DIR" ;;
    noauth) run_cinc "$1" noauth 8891 --no-auth ;;
    zero) run_zero "$1" ;;
  esac
}

if [[ " ${SERVERS[*]} " == *" chef "* ]]; then
  sudo cinc-server-ctl stop >/dev/null
fi
for rep in $(seq 1 "$REPS"); do
  n=${#SERVERS[@]}
  for i in $(seq 0 $((n - 1))); do
    slug=${SERVERS[$(((i + rep - 1) % n))]}
    echo "::group::rep $rep: ${LABEL[$slug]}"
    run_server "$rep" "$slug"
    echo "::endgroup::"
  done
done
exit "$FAILED"
