#!/usr/bin/env bash
# run.sh -- the gateway-hold walk. Six steps, plus the DENY variants.
#
#   ./bootstrap.sh      once (minutes: it installs a LiteLLM proxy)
#   ./run.sh            the walk (about two minutes; five with the app leg)
#
# Everything it prints is a real request and a real response. Nothing is
# simulated, and a step that cannot run says so instead of pretending.
#
# WHAT IS AND IS NOT LIVE
#   steps 1, 2, 5, 6 and both DENY variants   always live, no account needed
#   steps 3 and 4 (the approval inbox + a human clicking Approve)
#       live ONLY when RFX_DEMO_GATE_TOKEN + RFX_DEMO_EVIDENCE_KEY name a
#       Reeflex tenant's registered gate. Without them the walk RUNS ANYWAY
#       and reports those two steps as NOT RUN. See README.md.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNDIR="${REEFLEX_DEMO_RUNDIR:-/tmp/reeflex-gateway-hold-run}"
VENV="${REEFLEX_DEMO_VENV:-/tmp/reeflex-gateway-hold-venv}"
PY="$VENV/bin/python"
OUT="${REEFLEX_DEMO_TRANSCRIPT:-$HERE/evidence/transcript.txt}"

PORT_CORE="${REEFLEX_DEMO_PORT_CORE:-18701}"
PORT_IMPATIENT="${REEFLEX_DEMO_PORT_IMPATIENT:-18703}"
PORT_PATIENT="${REEFLEX_DEMO_PORT_PATIENT:-18704}"
APPROVER="${REEFLEX_DEMO_APPROVER:-alice.approver@acme.example}"
APP_BASE="${RFX_DEMO_APP_BASE:-https://app.reeflex.io}"
KEEP_UP="${REEFLEX_DEMO_KEEP_UP:-0}"

mkdir -p "$HERE/evidence/shots"
exec > >(tee "$OUT") 2>&1

step()  { printf '\n\n\033[1;36m========== %s\033[0m\n' "$*"; }
sub()   { printf '\n\033[1m-- %s\033[0m\n' "$*"; }
note()  { printf '   %s\n' "$*"; }
skip()  { printf '\n\033[33m   NOT RUN: %s\033[0m\n' "$*"; }

trap 'rc=$?; [ "$KEEP_UP" = "1" ] || "$HERE/stack.sh" down >/dev/null 2>&1; exit $rc' EXIT

# ---------------------------------------------------------------------------
step "STEP 0  what this walk is running against"
# ---------------------------------------------------------------------------
"$HERE/stack.sh" up || exit 1
set -a; . "$RUNDIR/env"; set +a
export REEFLEX_CORE_URL="http://127.0.0.1:$PORT_CORE"
export APPROVER_TOKEN RFX_DEMO_APP_BASE="$APP_BASE"
export REEFLEX_DEMO_PORT_IMPATIENT="$PORT_IMPATIENT"
export REEFLEX_DEMO_PORT_PATIENT="$PORT_PATIENT"
export REEFLEX_DEMO_APPROVER="$APPROVER"
export RFX_DEMO_SHOTS="$HERE/evidence/shots"
BROWSER_PY="${REEFLEX_DEMO_BROWSER_PYTHON:-/root/.venvs/reeflex-app/bin/python}"

sub "the pieces, pinned"
docker image inspect "${REEFLEX_DEMO_CORE_IMAGE:-ghcr.io/reeflex-io/reeflex-core@sha256:58a0a531dfa1aa9bdfaf82baf94c4a1388303520cae755ffbbe1a28d9e64845b}" \
  --format '   reeflex-core   {{.RepoTags}} digest {{index .RepoDigests 0}}'
note "litellm        $($PY -c 'import importlib.metadata as m; print(m.version("litellm"))')"
note "classifier     $($PY -c 'import reeflex_claude,os;print(os.path.dirname(reeflex_claude.__file__))')"
note "core config    REEFLEX_REQUIRE_VERIFIED_APPROVER is NOT SET => the shipped default (true, since 0.2.0)"

sub "the classifier is not the stale PyPI wheel"
# The wheel on PyPI is 0.1.7 (2026-07-06), which predates RFX-144/145/146; with
# it, `echo starting && rm -rf /var/lib/pgsql` is priced reversible/single and
# core ALLOWS it. This walk asserts the vintage rather than hoping.
"$PY" -m pytest "$HERE/../../reeflex-litellm/tests/test_classifier_vintage.py" -q 2>&1 | tail -2

sub "the tenancy binding, validated before any traffic"
REEFLEX_LITELLM_TENANCY_MAP_FILE="$HERE/config/tenancy.json" \
  "$VENV/bin/reeflex-litellm" tenancy || exit 1

if [ -n "${RFX_DEMO_GATE_TOKEN:-}" ]; then
  note "app leg: LIVE against $APP_BASE"
else
  skip "steps 3 and 4 -- no RFX_DEMO_GATE_TOKEN in the environment."
  note "        The walk continues; nothing below is faked to cover for it."
fi

# ---------------------------------------------------------------------------
step "STEP 1  ONE prompt. The model proposes DROP TABLE customers."
# ---------------------------------------------------------------------------
PROMPT_HOLD='Clean up the old customer table on prod. TOOL run_shell {"command": "psql -h prod-db -c \"DROP TABLE customers\""}'
note "prompt: $PROMPT_HOLD"
note ""
note "The model is a local mock, deliberately: the thing being demonstrated is"
note "the GATEWAY, and a real model would make the one variable that matters --"
note "which tool call comes back -- nondeterministic. Point the proxy at any"
note "OpenAI-compatible model and the seat behaves identically."

# ---------------------------------------------------------------------------
step "STEP 2  the gateway returns a HOLD instead of the tool call"
# ---------------------------------------------------------------------------
sub "POST /v1/chat/completions  (gateway on :$PORT_IMPATIENT, reeflex_hold_wait: 2)"
SESS2="demo-step2-$(date +%s)"
RESP2="$RUNDIR/step2.json"
curl -s -m 40 -X POST "http://127.0.0.1:$PORT_IMPATIENT/v1/chat/completions" \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $LITELLM_MASTER_KEY" \
  -H "x-reeflex-session: $SESS2" \
  -d "$($PY "$HERE/lib/mkbody.py" "$PROMPT_HOLD")" > "$RESP2"
"$PY" "$HERE/lib/show.py" refusal "$RESP2"
HOLD2="$($PY "$HERE/lib/show.py" hold-id "$RESP2")"

sub "the command string is not in the response the caller received"
"$PY" "$HERE/lib/show.py" absent "$RESP2" 'DROP TABLE customers'

sub "and core is holding it: GET /v1/holds/$HOLD2"
curl -s -m 10 "http://127.0.0.1:$PORT_CORE/v1/holds/$HOLD2" \
  -H "Authorization: Bearer $GATEWAY_TOKEN" | "$PY" "$HERE/lib/show.py" hold -

# ---------------------------------------------------------------------------
step "STEP 3  the hold in the approval inbox at $APP_BASE"
# ---------------------------------------------------------------------------
if [ -z "${RFX_DEMO_GATE_TOKEN:-}" ]; then
  skip "no gate credential. What WOULD happen is in README.md, and the"
  note "        adapter's ledger line below records that nobody was asked:"
  "$PY" "$HERE/lib/show.py" ledger-last "$RUNDIR/decisions.jsonl"
else
  sub "the adapter's ledger line: was a human actually asked?"
  "$PY" "$HERE/lib/show.py" ledger-last "$RUNDIR/decisions.jsonl"
  note ""
  note "This is the field a report needs. \`hold_announced: sent\` means the"
  note "hold reached an inbox; \`failed\` and \`not_configured\` are holds nobody"
  note "was told about, and reading those as human oversight would be the"
  note "Article 14 overclaim in miniature."
fi

# ---------------------------------------------------------------------------
step "STEP 4+5  a human approves in the UI, and the agent's call is released"
# ---------------------------------------------------------------------------
# ONE request, blocked at the patient gateway, released by a real approval.
# The gateway resubmits the ORIGINAL envelope with the approval attached and
# releases the tool call only if CORE answers allow -- core's eight
# resubmission checks are the authority, not the hold status.
SESS5="demo-step5-$(date +%s)"
RESP5="$RUNDIR/step5.json"
sub "the agent's request, at the gateway that waits (:$PORT_PATIENT, wait 180s)"
( curl -s -m 200 -X POST "http://127.0.0.1:$PORT_PATIENT/v1/chat/completions" \
    -H 'Content-Type: application/json' \
    -H "Authorization: Bearer $LITELLM_MASTER_KEY" \
    -H "x-reeflex-session: $SESS5" \
    -d "$($PY "$HERE/lib/mkbody.py" "$PROMPT_HOLD")" > "$RESP5" ) &
CURL_PID=$!
sleep 7
HOLD5="$($PY "$HERE/lib/show.py" pending-for-session \
          "http://127.0.0.1:$PORT_CORE" "$GATEWAY_TOKEN" "$SESS5")"
note "the caller is still waiting; core is holding $HOLD5"

if [ -z "${RFX_DEMO_GATE_TOKEN:-}" ]; then
  skip "step 4 in the UI -- no tenant. Approving through core's own"
  note "        resolution route instead, with the APPROVER's credential."
  sub "control first: the approver's credential is not a key to submitting actions"
  curl -s -o /dev/null -w '   POST /v1/decide with the approver token -> HTTP %{http_code}  (401 = correct)\n' \
    -m 10 -X POST "http://127.0.0.1:$PORT_CORE/v1/decide" \
    -H "Authorization: Bearer $APPROVER_TOKEN" -H 'Content-Type: application/json' -d '{}'
  sub "control: approving as somebody else, on alice's credential"
  curl -s -m 10 -X POST "http://127.0.0.1:$PORT_CORE/v1/holds/$HOLD5/resolve" \
    -H "Authorization: Bearer $APPROVER_TOKEN" -H 'Content-Type: application/json' \
    -d '{"decision":"approve","principal":{"type":"human","id":"bob.somebody@acme.example"},"reason":"not me"}' \
    | "$PY" "$HERE/lib/show.py" json-line -
  sub "the real approval"
  curl -s -m 10 -X POST "http://127.0.0.1:$PORT_CORE/v1/holds/$HOLD5/resolve" \
    -H "Authorization: Bearer $APPROVER_TOKEN" -H 'Content-Type: application/json' \
    -d "{\"decision\":\"approve\",\"principal\":{\"type\":\"human\",\"id\":\"$APPROVER\"},\"reason\":\"Reviewed the migration plan; customers is superseded by customers_v2.\"}" \
    | "$PY" "$HERE/lib/show.py" resolved -
else
  sub "the relay, watching the app for a human decision"
  nohup "$PY" "$HERE/lib/relay.py" --hold-id "$HOLD5" --timeout 150 \
    > "$RUNDIR/relay.log" 2>&1 &
  RELAY_PID=$!
  sleep 3
  sub "a human, in a real browser, on $APP_BASE/app/holds"
  timeout 150 "$BROWSER_PY" "$HERE/lib/approve_in_ui.py" approve \
    --hold-id "$HOLD5" --shots "$HERE/evidence/shots"
  sub "the relay carrying that decision to core"
  wait "$RELAY_PID" 2>/dev/null
  cat "$RUNDIR/relay.log"
fi

sub "what the blocked caller finally received"
wait "$CURL_PID" 2>/dev/null
"$PY" "$HERE/lib/show.py" released "$RESP5"

sub "5b  MEASURED LIMIT: a retry cannot spend an approval that arrives late"
"$PY" "$HERE/lib/late_approval.py"

# ---------------------------------------------------------------------------
step "STEP 6  the record, and exactly what it may and may not claim"
# ---------------------------------------------------------------------------
sub "the adapter's decision ledger for this walk"
"$PY" "$HERE/lib/show.py" ledger-table "$RUNDIR/decisions.jsonl"
sub "the released call's full ledger line"
"$PY" "$HERE/lib/show.py" ledger-released "$RUNDIR/decisions.jsonl"
sub "what CANNOT be on the evidence wire, proven by running the projection"
"$PY" "$HERE/lib/wire_truth.py" "$RUNDIR/decisions.jsonl"
if [ -n "${RFX_DEMO_GATE_TOKEN:-}" ]; then
  sub "an Attest report over the org this walk wrote to"
  # Playwright lives in a different interpreter from the demo venv on this
  # box; the attest step is a WEB-plane walk, so it runs there.
  "$BROWSER_PY" "$HERE/lib/attest.py" || note "(the attest step reported its own outcome above)"
fi

# ---------------------------------------------------------------------------
step "DENY VARIANT A  a hard deny -- a structured tool result the model reads"
# ---------------------------------------------------------------------------
sub "the same tool, a wider command: rm -rf /var/lib/pgsql"
SESSD="demo-denyA-$(date +%s)"
curl -s -m 30 -X POST "http://127.0.0.1:$PORT_IMPATIENT/v1/chat/completions" \
  -H 'Content-Type: application/json' -H "Authorization: Bearer $LITELLM_MASTER_KEY" \
  -H "x-reeflex-session: $SESSD" \
  -d "$($PY "$HERE/lib/mkbody.py" 'TOOL run_shell {"command": "rm -rf /var/lib/pgsql"}')" \
  > "$RUNDIR/denyA.json"
"$PY" "$HERE/lib/show.py" refusal-full "$RUNDIR/denyA.json"

# ---------------------------------------------------------------------------
step "DENY VARIANT B  unclassifiable -> HOLD, not deny (R0)"
# ---------------------------------------------------------------------------
"$PY" "$HERE/lib/r0.py"

# ---------------------------------------------------------------------------
step "WHAT THE GATE ACTUALLY DISCRIMINATES ON  (and what it does not)"
# ---------------------------------------------------------------------------
"$PY" "$HERE/lib/discrimination.py"

# ---------------------------------------------------------------------------
step "CONTROL  the same three envelopes against api-dev.reeflex.io"
# ---------------------------------------------------------------------------
note "So no verdict above is an artefact of the container this walk started."
"$PY" "$HERE/lib/apidev_control.py" || note "(api-dev unreachable from here -- the control did not run)"

step "done. transcript: $OUT"
note "screenshots: $HERE/evidence/shots/"
note "run dir (ledger, core audit, logs): $RUNDIR"
