#!/usr/bin/env bash
# Everything that has to be true before this repo is pushed.
#
#   tools/check.sh [path-to-ts-tvl]
#
# 1. docs/model_spec.js still matches the model it claims to describe.
# 2. The page still renders every item that spec contains.
#
# (1) needs a Python that can import `tvl`. Point at a ts-tvl checkout with the
# argument, $TS_TVL, or a sibling ../ts-tvl; point at an interpreter with
# $PYTHON if the default cannot see ts-tvl's dependencies.
#
# Where a check cannot run it says SKIPPED and why. It never passes quietly:
# an anti-drift gate that silently does nothing is worse than not having one.
set -uo pipefail

cd "$(dirname "$0")/.." || { echo "cannot enter repository root"; exit 1; }
fail=0
say() { printf '%s\n' "$*"; }

TS_TVL="${1:-${TS_TVL:-../ts-tvl}}"

# Find an interpreter that can actually import tvl, rather than guessing at
# virtualenv paths and letting the import blow up later with a traceback that
# does not say what is wrong.
pick_python() {
  local candidates=()
  [ -n "${PYTHON:-}" ] && candidates+=("$PYTHON")
  candidates+=(python3 ../.venv/bin/python ../../.venv/bin/python .venv/bin/python)
  for py in "${candidates[@]}"; do
    # If an explicitly requested interpreter is unusable, say so instead of
    # quietly running a different one than the caller asked for.
    if [ -n "${PYTHON:-}" ] && [ "$py" != "$PYTHON" ] && [ -z "${warned:-}" ]; then
      warned=1
      say "   note: PYTHON='$PYTHON' cannot import ts-tvl; trying others" >&2
    fi
    command -v "$py" >/dev/null 2>&1 || [ -x "$py" ] || continue
    # Probe what the generator actually imports, not just the top-level
    # package: `import tvl` succeeds on an interpreter with none of ts-tvl's
    # dependencies installed, which would pick the wrong one and fail later
    # with a traceback instead of this message.
    if PYTHONPATH="$TS_TVL" "$py" -c \
         'import tvl.targets.model.tropic01_model' >/dev/null 2>&1; then
      printf '%s' "$py"; return 0
    fi
  done
  return 1
}

say "== 1/2  docs/model_spec.js vs the model"
if [ ! -d "$TS_TVL/tvl" ]; then
  say "   SKIPPED - no ts-tvl checkout at '$TS_TVL'."
  say "   Pass one as an argument or set TS_TVL."
  say "   The page is NOT being checked against the model."
elif ! PY="$(pick_python)"; then
  say "   SKIPPED - found ts-tvl at '$TS_TVL' but no interpreter that can"
  say "   import it. ts-tvl needs pydantic 1.x, cryptography, crcmod, pyyaml."
  say "   Create one and point PYTHON at it:"
  say "     python3 -m venv .venv && .venv/bin/pip install -e '$TS_TVL'"
  say "     PYTHON=.venv/bin/python tools/check.sh"
  say "   The page is NOT being checked against the model."
else
  say "   using $PY"
  if PYTHONPATH="$TS_TVL" "$PY" tools/generate_spec.py \
       --out docs/model_spec.js --check; then
    say "   ok"
  else
    say ""
    say "   The model changed and the page was not regenerated. Run:"
    say "     PYTHONPATH=$TS_TVL $PY tools/generate_spec.py --out docs/model_spec.js"
    fail=1
  fi
fi

say ""
say "== 2/2  the page renders the spec"
if node -e 'require("jsdom")' 2>/dev/null; then
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
