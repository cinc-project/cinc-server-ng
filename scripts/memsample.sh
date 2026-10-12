#!/usr/bin/env bash
#
# memsample.sh — record how much memory a server uses, for cmd/benchreport.
#
# Samples the proportional set size (PSS) of a process and every descendant it
# has at the time of each sample, until stopped with SIGTERM or SIGINT, then
# writes {"label", "idle_kb", "peak_kb"} to the output file: idle is the first
# sample, peak the largest.
#
# PSS rather than RSS because a multi-process server shares pages between its
# processes (PostgreSQL's backends share one buffer pool): RSS counts each
# shared page once per process, PSS divides it between them, so the sum is
# what the server actually occupies.
#
# Linux only (reads /proc/<pid>/smaps_rollup). Sampling processes owned by
# another user, such as a packaged Chef Infra Server's, needs root.
#
# Usage:
#   scripts/memsample.sh <out.json> <label> <root-pid> [interval-seconds]
set -euo pipefail

if [ $# -lt 3 ]; then
  echo "usage: $0 <out.json> <label> <root-pid> [interval-seconds]" >&2
  exit 2
fi
OUT="$1" LABEL="$2" ROOT="$3" INTERVAL="${4:-0.5}"

# pids prints ROOT and all of its descendants.
pids() {
  ps -e -o pid=,ppid= | awk -v root="$ROOT" '
    { kids[$2] = kids[$2] " " $1 }
    END {
      queue[1] = root; head = 1; tail = 1
      while (head <= tail) {
        p = queue[head++]; print p
        n = split(kids[p], c, " ")
        for (i = 1; i <= n; i++) queue[++tail] = c[i]
      }
    }'
}

# sample prints the summed PSS, in KiB, of the tree right now. A process can
# exit between listing and reading, so unreadable entries are skipped.
sample() {
  local total=0 pss
  for pid in $(pids); do
    pss=$(awk '/^Pss:/ { print $2; exit }' "/proc/$pid/smaps_rollup" 2>/dev/null || true)
    total=$((total + ${pss:-0}))
  done
  echo "$total"
}

IDLE=$(sample)
PEAK=$IDLE
finish() {
  printf '{"label":"%s","idle_kb":%d,"peak_kb":%d}\n' "$LABEL" "$IDLE" "$PEAK" >"$OUT"
  exit 0
}
trap finish TERM INT

while kill -0 "$ROOT" 2>/dev/null; do
  now=$(sample)
  [ "$now" -gt "$PEAK" ] && PEAK=$now
  # sleep in the background so the trap runs as soon as a signal arrives.
  sleep "$INTERVAL" &
  wait $! || true
done
finish
