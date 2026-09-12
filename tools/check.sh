#!/usr/bin/env bash
# Everything that has to be true before this repo is pushed.
#
#   tools/check.sh [path-to-ts-tvl]
#
# 1. docs/model_spec.js still matches the model it claims to describe.
# 2. The page still renders every item that spec contains.
#
# (1) needs a ts-tvl checkout. Give it as an argument, or set TS_TVL, or keep
# one at ../ts-tvl. Without it the check is SKIPPED and says so loudly - the
# anti-drift promise is the whole point of this repo, so a silent skip would be
# worse than no check at all.
set -uo pipefail

cd "$(dirname "$0")/.."
fail=0
say() { printf '%s\n' "$*"; }

TS_TVL="${1:-${TS_TVL:-../ts-tvl}}"
PY="${PYTHON:-python3}"
for candidate in ../.venv/bin/python ../../.venv/bin/python; do
  [ -x "$candidate" ] && PY="$candidate" && break
done

say "== 1/2  docs/model_spec.js vs the model"
if [ -d "$TS_TVL/tvl" ]; then
  if PYTHONPATH="$TS_TVL" "$PY" tools/generate_spec.py \
       --out docs/model_spec.js --check; then
    say "   ok"
  else
    say ""
    say "   The model changed and the page was not regenerated. Run:"
    say "     PYTHONPATH=$TS_TVL $PY tools/generate_spec.py --out docs/model_spec.js"
    fail=1
  fi
else
  say "   SKIPPED - no ts-tvl checkout at '$TS_TVL'."
  say "   Pass one as an argument or set TS_TVL. The page is NOT being checked"
  say "   against the model, so treat anything it shows as unverified."
fi

say ""
say "== 2/2  the page renders the spec"
if [ -d node_modules/jsdom ] || node -e 'require("jsdom")' 2>/dev/null; then
  node tools/render_test.js || fail=1
else
  say "   SKIPPED - jsdom not installed. Run: npm install --no-save jsdom"
fi

say ""
if [ "$fail" -ne 0 ]; then
  say "FAILED"
  exit 1
fi
say "PASSED"
