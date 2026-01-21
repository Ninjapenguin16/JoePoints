#!/usr/bin/env bash
# api_fuzz_test.sh
# Usage: ./api_fuzz_test.sh <YOUR_API_KEY> [interactive]
# Example: ./api_fuzz_test.sh 0123...abcdef interactive

set -euo pipefail

BASE="http://localhost:8080"
API_KEY="${1:-0123456789abcdef0123456789abcdef}"
INTERACTIVE=false
if [[ "${2:-}" == "interactive" || "${2:-}" == "step" ]]; then
  INTERACTIVE=true
fi

AUTH_HDR() { printf 'Authorization: Bearer %s' "$1"; }

# Helper: pause if interactive
maybe_pause() {
  if $INTERACTIVE; then
    echo -n "Press any key to run the test (or Ctrl-C to quit)... "
    # read 1 char silently
    read -n1 -s
    echo
  fi
}

# helper to run curl and show labeled output
run() {
  local label="$1"; shift
  echo -e "\n=== $label ==="
  maybe_pause
  curl -i -sS "$@"
  echo -e "\n---end---\n"
}

# quick generator for large JSON (~5MB)
gen_large_json() {
  python - <<'PY'
import json
s = "A"*(5*1024*1024)
obj = {"first": s[:2000], "last": s[:2000], "extra": s}
print(json.dumps(obj))
PY
}

# ---------- BEGIN TESTS ----------
run "GENKEY - valid" -X POST "$BASE/api/genkey" -H "$(AUTH_HDR "$API_KEY")"

run "ADD PERSON - valid" -X POST "$BASE/api/addperson" \
  -H "$(AUTH_HDR "$API_KEY")" -H "Content-Type: application/json" \
  -d '{"first":"John","last":"Doe"}'

run "GET ALL - valid" -X GET "$BASE/api/getall"

run "GENKEY - missing auth" -X POST "$BASE/api/genkey"

run "GENKEY - short key" -X POST "$BASE/api/genkey" -H "$(AUTH_HDR "deadbeef")"

run "ADD PERSON - missing content-type" -X POST "$BASE/api/addperson" -H "$(AUTH_HDR "$API_KEY")" -d '{"first":"Alice","last":"Smith"}'

run "ADD PERSON - malformed JSON" -X POST "$BASE/api/addperson" -H "$(AUTH_HDR "$API_KEY")" -H "Content-Type: application/json" -d '{"first":"Alice", "last": "Smith"'

run "ADD PERSON - SQLi payload" -X POST "$BASE/api/addperson" -H "$(AUTH_HDR "$API_KEY")" -H "Content-Type: application/json" \
  -d $'{"first":"Robert\'); DROP TABLE users;--","last":"Mallory"}'

run "REMOVE PERSON - missing uid" -X POST "$BASE/api/removeperson" -H "$(AUTH_HDR "$API_KEY")" -H "Content-Type: application/json" -d '{}'

run "SET POINTS - negative points" -X POST "$BASE/api/setpoints" -H "$(AUTH_HDR "$API_KEY")" -H "Content-Type: application/json" -d '{"uid":1,"points":-500}'

run "ADD POINTS - points as float" -X POST "$BASE/api/addpoints" -H "$(AUTH_HDR "$API_KEY")" -H "Content-Type: application/json" -d '{"uid":1,"points":12.34}'

run "REMOVE KEY - missing auth" -X POST "$BASE/api/removekey"

run "GET UID - missing params" -X GET "$BASE/api/getuid?first=John"

run "GET POINTS - invalid uid" -X GET "$BASE/api/getpoints?uid=one"

# Concurrency block: if interactive, confirm before blasting
if $INTERACTIVE; then
  echo -e "\nConcurrency test will run (50 requests, 10 parallel)."
  maybe_pause
fi

echo -e "\n=== CONCURRENCY TEST: addpoints x50 (10 parallel) ==="
seq 1 50 | xargs -n1 -P10 -I{} bash -c \
  "curl -sS -X POST '$BASE/api/addpoints' -H \"$(AUTH_HDR "$API_KEY")\" -H 'Content-Type: application/json' -d '{\"uid\":1,\"points\":1}' -w ' (done {})\n'"

echo -e "\n---concurrency end---\n"

# Large body test
LARGE_JSON="$(gen_large_json)"
run "SET POINTS - huge body (timeout test)" -X POST "$BASE/api/setpoints" -H "$(AUTH_HDR "$API_KEY")" -H "Content-Type: application/json" --data-binary "$LARGE_JSON" --max-time 20

# finishing tests
run "GET ALL - extraneous query params" -X GET "$BASE/api/getall?debug=true&foo=bar"

echo -e "\nAll tests complete.\n"
