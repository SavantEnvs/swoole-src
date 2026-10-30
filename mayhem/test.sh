#!/usr/bin/env bash
#
# mayhem/test.sh — runs the pure (no network, no PHP) suites of swoole's own gtest binary
# `core-tests`, built by mayhem/build.sh with normal flags. exit 0 = all pass and none went missing.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

# Pure suites only: protocol parsers/framers and in-memory data structures. Network, coroutine,
# process and server suites need sockets, DNS or a PHP runtime and are left out; util.bitmap passes
# alone but fails when combined with the other util tests (shared state), http2.ssl and redis.get
# need a live peer.
SUITES="base64.*:ProtocolFramingTest.*:Http2SettingsTest.*:MimeTypeTest.*:mqtt_protocol.*:RedisProtocolTest.*"
SUITES+=":Socks5ProtocolTest.*:multipart_parser.*:hash.*:string.*:heap.*:HeapTypes/*:util.*:buffer.*"
SUITES+=":lru_cache.*:ringbuffer.*:fixed_pool.*:websocket.*:http2.*:redis.*"
SKIP="util.bitmap:http2.ssl:redis.get"
EXPECTED_MIN=150   # the suite runs 156; fewer means tests vanished (e.g. a binary that exits early)

BIN="$SRC/build/tests/bin/core-tests"
[ -x "$BIN" ] || { echo "missing $BIN — mayhem/build.sh should have built it" >&2; exit 1; }

OUT="$(mktemp)"
timeout 900 "$BIN" --gtest_filter="$SUITES-$SKIP" >"$OUT" 2>&1
cat "$OUT"

passed=$(sed -n 's/^\[  PASSED  \] \([0-9]*\) tests\?\..*/\1/p' "$OUT" | tail -1)
failed=$(sed -n 's/^\[  FAILED  \] \([0-9]*\) tests\?, listed below.*/\1/p' "$OUT" | tail -1)
skipped=$(sed -n 's/^\[  SKIPPED \] \([0-9]*\) tests\?, listed below.*/\1/p' "$OUT" | tail -1)
passed=${passed:-0}; failed=${failed:-0}; skipped=${skipped:-0}

if [ $((passed + failed + skipped)) -lt "$EXPECTED_MIN" ]; then
  echo "only $((passed + failed + skipped)) tests ran, expected at least $EXPECTED_MIN" >&2
  failed=$((failed + 1))
fi
emit_ctrf "gtest" "$passed" "$failed" "$skipped"
