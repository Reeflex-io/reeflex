#!/usr/bin/env bash
# stack.sh -- bring the demo's four processes up, or take them down.
#
#   ./stack.sh up      core + mock model + two litellm proxies
#   ./stack.sh down     all of it, including the container
#   ./stack.sh status   what is listening
#
# run.sh calls this; it is a separate file so you can leave the stack running
# and poke at it by hand after the walk.
#
# WHAT RUNS WHERE
#   18701  reeflex-core v0.2.0, in a container of its own (`rfx-demo-core`)
#   18702  the mock model (proxy/mock_model.py from the reeflex-litellm package)
#   18703  litellm proxy, seat with reeflex_hold_wait: 2    ("impatient")
#   18704  litellm proxy, seat with reeflex_hold_wait: 180  ("patient")
#
# NOTHING here touches a shared host. The container is named `rfx-demo-core`
# and is never another agent's; api-dev.reeflex.io is only ever READ, with the
# public eval token, as a control on the verdict.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="${REEFLEX_DEMO_VENV:-/tmp/reeflex-gateway-hold-venv}"
RUNDIR="${REEFLEX_DEMO_RUNDIR:-/tmp/reeflex-gateway-hold-run}"
CORE_NAME="${REEFLEX_DEMO_CORE_NAME:-rfx-demo-core}"
CORE_IMAGE="${REEFLEX_DEMO_CORE_IMAGE:-ghcr.io/reeflex-io/reeflex-core@sha256:58a0a531dfa1aa9bdfaf82baf94c4a1388303520cae755ffbbe1a28d9e64845b}"

PORT_CORE="${REEFLEX_DEMO_PORT_CORE:-18701}"
PORT_MODEL="${REEFLEX_DEMO_PORT_MODEL:-18702}"
PORT_IMPATIENT="${REEFLEX_DEMO_PORT_IMPATIENT:-18703}"
PORT_PATIENT="${REEFLEX_DEMO_PORT_PATIENT:-18704}"

# The approving human. A real deployment reads this from its identity provider;
# the demo names it, because core verifies the CREDENTIAL against the principal
# and both have to agree.
APPROVER="${REEFLEX_DEMO_APPROVER:-alice.approver@acme.example}"

say() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
warn() { printf '\033[33m   %s\033[0m\n' "$*"; }
die() { printf '\n\033[31mFAILED: %s\033[0m\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# secrets: generated per run, mode 600, never echoed
# ---------------------------------------------------------------------------
# Three separate credentials, on purpose, because the demo's point is partly
# that they are separate:
#   GATEWAY_TOKEN   core's REEFLEX_AUTH_TOKEN -- what the GOVERNED party holds
#   APPROVER_TOKEN  bound to the approver in REEFLEX_RESOLVER_TOKENS -- what
#                   the HUMAN holds. Usable on the hold-resolution route ONLY
#                   (monorepo #105); it 401s on /v1/decide, and run.sh proves
#                   that rather than asserting it.
#   MASTER_KEY      the litellm proxy's own master key -- what the AGENT holds
write_env() {
  mkdir -p "$RUNDIR"
  chmod 700 "$RUNDIR"
  if [ -f "$RUNDIR/env" ]; then return; fi
  umask 077
  {
    echo "GATEWAY_TOKEN=$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')"
    echo "APPROVER_TOKEN=$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')"
    echo "LITELLM_MASTER_KEY=sk-$(head -c 18 /dev/urandom | od -An -tx1 | tr -d ' \n')"
  } > "$RUNDIR/env"
  chmod 600 "$RUNDIR/env"
}

wait_http() { # url, seconds, label
  local url="$1" secs="$2" label="$3" i=0
  while [ "$i" -lt "$((secs * 2))" ]; do
    if curl -s -m 2 -o /dev/null "$url"; then return 0; fi
    i=$((i + 1)); sleep 0.5
  done
  die "$label did not come up at $url within ${secs}s (log: $RUNDIR/)"
}

# A PORT THAT ANSWERS IS NOT NECESSARILY THIS RUN'S PROCESS.
#
# This cost a whole recorded run. `up` was called while the PREVIOUS run's two
# proxies were still listening on 18703/18704 (that run had been started with
# REEFLEX_DEMO_KEEP_UP=1). The new litellm processes could not bind and exited
# -- and `wait_http` got its 200 from the OLD processes, which were still
# holding the PREVIOUS tenant's gate credentials. So the walk pushed its holds
# into one org while the browser looked at another, the inbox was empty, and
# every component reported success.
#
# So: take the stack down first, then BIND-TEST every port before starting
# anything. Refusing to start is a much better outcome than a green run
# against somebody else's process.
bind_test() {
  local port="$1" label="$2"
  if "$VENV/bin/python" -c "
import socket, sys
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
try:
    s.bind(('127.0.0.1', int(sys.argv[1])))
except OSError:
    sys.exit(1)
finally:
    s.close()
" "$port"; then return 0; fi
  die "port $port ($label) is in use by a process this script did not start.
   Anything running there will answer every health check and serve the WRONG
   configuration -- that is how a walk pushes evidence into one tenant while
   you read another. Stop it, or set REEFLEX_DEMO_PORT_* to a free block."
}

up() {
  write_env
  # Idempotent restart: whatever this script started before, stop it now.
  down_quiet
  for pair in "$PORT_CORE:core" "$PORT_MODEL:model" \
              "$PORT_IMPATIENT:gateway-impatient" "$PORT_PATIENT:gateway-patient"; do
    bind_test "${pair%%:*}" "${pair##*:}"
  done
  # shellcheck disable=SC1091
  set -a; . "$RUNDIR/env"; set +a
  mkdir -p "$RUNDIR/core-data" "$RUNDIR/logs"
  # The published image runs as uid 10001 (`reeflex`), and RUNDIR is 700 root.
  # Without this the bind mount is unwritable and the failure is worth knowing
  # about because it is NOT a crash: core's audit log degrades with a WARN
  # ("audit failure != deny") and keeps answering, but the HOLD STORE fails
  # CLOSED -- every `require_approval` comes back as
  # `deny reeflex.core/hold_store_unavailable`. So a misconfigured volume
  # silently converts every human-approval action into a refusal. Measured
  # here on 2026-09-08 before this line existed.
  chown -R 10001:10001 "$RUNDIR/core-data" 2>/dev/null \
    || chmod -R 777 "$RUNDIR/core-data"

  say "core: reeflex-core v0.2.0 on :$PORT_CORE (container $CORE_NAME)"
  docker rm -f "$CORE_NAME" >/dev/null 2>&1 || true
  # REEFLEX_REQUIRE_VERIFIED_APPROVER is DELIBERATELY NOT SET: the demo runs at
  # the SHIPPED DEFAULT, which is `true` since 0.2.0. A demo that turned the
  # guard off would be demonstrating a configuration we do not ship.
  #
  # REEFLEX_RESOLVER_TOKENS accepts a JSON STRING as well as a path, which is
  # what makes this one line instead of a directory mount.
  docker run -d --name "$CORE_NAME" \
    -p "127.0.0.1:$PORT_CORE:8080" \
    -e "REEFLEX_AUTH_TOKEN=$GATEWAY_TOKEN" \
    -e "REEFLEX_RESOLVER_TOKENS={\"$APPROVER_TOKEN\":{\"type\":\"human\",\"id\":\"$APPROVER\"}}" \
    -e "REEFLEX_AUDIT_LOG=/data/decisions.jsonl" \
    -e "REEFLEX_HOLDS_PATH=/data/holds.jsonl" \
    -v "$RUNDIR/core-data:/data" \
    "$CORE_IMAGE" >/dev/null
  wait_http "http://127.0.0.1:$PORT_CORE/healthz" 30 "reeflex-core"
  echo "   $(curl -s -m 5 "http://127.0.0.1:$PORT_CORE/healthz" | head -c 120)"

  say "model: the mock, on :$PORT_MODEL"
  nohup "$VENV/bin/python" "$HERE/../../reeflex-litellm/proxy/mock_model.py" \
    --port "$PORT_MODEL" > "$RUNDIR/logs/model.log" 2>&1 &
  echo $! > "$RUNDIR/model.pid"
  wait_http "http://127.0.0.1:$PORT_MODEL/health" 20 "mock model"
  echo "   $(cat "$RUNDIR/logs/model.log" | head -1)"

  # Both proxies share one ledger: it is the ADAPTER'S decision ledger, and
  # step 6 reads the whole walk out of it.
  export REEFLEX_CORE_URL="http://127.0.0.1:$PORT_CORE"
  export REEFLEX_CORE_TOKEN="$GATEWAY_TOKEN"
  export REEFLEX_LITELLM_TENANCY_MAP_FILE="$HERE/config/tenancy.json"
  # ROTATE THE LEDGER PER RUN. In production this file is append-only and
  # rotating it would be wrong; in a demo it is the difference between a table
  # a reader can check against the steps above it and a table with three
  # earlier experiments in it. The old one is moved aside, never deleted.
  if [ -s "$RUNDIR/decisions.jsonl" ]; then
    mv "$RUNDIR/decisions.jsonl" \
       "$RUNDIR/decisions.jsonl.$(date +%Y%m%d-%H%M%S)"
    echo "   previous ledger moved aside (this run starts a clean one)"
  fi
  export REEFLEX_LITELLM_LEDGER_PATH="$RUNDIR/decisions.jsonl"
  export LITELLM_MASTER_KEY

  # THE APP LEG IS OPT-IN, and it is opt-in on the presence of a CREDENTIAL,
  # not on a flag. Steps 3 and 4 of the walk -- the hold in a real approval
  # inbox, and a human clicking Approve -- need a Reeflex tenant with a
  # registered gate. Nobody can be handed one in a repository, so:
  #
  #   * with RFX_DEMO_GATE_TOKEN + RFX_DEMO_EVIDENCE_KEY in the environment,
  #     the gateway pushes its holds and its §4 evidence to the URLs in
  #     config/tenancy.json and the walk runs the app steps live;
  #   * without them, the walk runs every other step and says, in the
  #     transcript, that 3 and 4 were NOT run and why. It does not pretend.
  #
  # The two switches are separate on purpose (see evidence.py): the holds push
  # writes into a queue a person is expected to answer.
  if [ -n "${RFX_DEMO_GATE_TOKEN:-}" ] && [ -n "${RFX_DEMO_EVIDENCE_KEY:-}" ]; then
    export REEFLEX_LITELLM_HOLDS_PUSH=true
    export REEFLEX_LITELLM_EVIDENCE_PUSH=true
    export RFX_DEMO_GATE_TOKEN RFX_DEMO_EVIDENCE_KEY
    echo "   app leg: ENABLED (a gate credential is present in the environment)"
  else
    echo "   app leg: not configured (no RFX_DEMO_GATE_TOKEN) -- steps 3 and 4"
    echo "            will be reported as NOT RUN, not simulated"
  fi

  for arm in impatient:$PORT_IMPATIENT patient:$PORT_PATIENT; do
    name="${arm%%:*}"; port="${arm##*:}"
    say "gateway ($name): litellm on :$port"
    nohup "$VENV/bin/litellm" --config "$HERE/config/litellm-$name.yaml" \
      --host 127.0.0.1 --port "$port" \
      > "$RUNDIR/logs/proxy-$name.log" 2>&1 &
    echo $! > "$RUNDIR/proxy-$name.pid"
  done
  for arm in impatient:$PORT_IMPATIENT patient:$PORT_PATIENT; do
    name="${arm%%:*}"; port="${arm##*:}"
    wait_http "http://127.0.0.1:$port/health/liveliness" 90 "litellm ($name)"
    echo "   litellm ($name) up on :$port"
  done

  say "stack up. run dir: $RUNDIR"
}

down_quiet() {
  for f in "$RUNDIR"/*.pid; do
    [ -f "$f" ] || continue
    pid="$(cat "$f")"
    if kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
      # litellm takes a moment to release its socket; without this wait the
      # bind test races this script's own cleanup.
      for _ in 1 2 3 4 5 6 7 8 9 10 11 12; do
        kill -0 "$pid" 2>/dev/null || break
        sleep 0.5
      done
      kill -9 "$pid" 2>/dev/null || true
    fi
    rm -f "$f"
  done
  docker rm -f "$CORE_NAME" >/dev/null 2>&1 || true
}

down() {
  say "down"
  for f in "$RUNDIR"/*.pid; do
    [ -f "$f" ] || continue
    pid="$(cat "$f")"
    # Kill only the pid we recorded. NEVER a pkill by name: a leading pkill on
    # this box has killed the killer's own shell before.
    if kill -0 "$pid" 2>/dev/null; then kill "$pid" 2>/dev/null || true; fi
    rm -f "$f"
  done
  docker rm -f "$CORE_NAME" >/dev/null 2>&1 || true
  echo "   processes stopped, container $CORE_NAME removed"
  echo "   run dir left in place for inspection: $RUNDIR"
}

status() {
  # BY BIND TEST, NOT BY `ss`. On this box `ss -ltn` returns ZERO ROWS to an
  # unprivileged-in-sandbox caller and exits 0, so every "the port is free"
  # reading it gives is a false negative -- and one of those sent a whole
  # recorded run into the wrong tenant. A failed bind is the only reading here
  # that cannot lie about a port being taken.
  for p in "$PORT_CORE" "$PORT_MODEL" "$PORT_IMPATIENT" "$PORT_PATIENT"; do
    printf '   :%s ' "$p"
    if bind_test "$p" "status" >/dev/null 2>&1; then echo "-"; else echo "in use"; fi
  done
  docker ps --filter "name=$CORE_NAME" --format '   container {{.Names}} {{.Image}} {{.Status}}'
}

case "${1:-}" in
  up) up ;;
  down) down ;;
  status) status ;;
  *) die "usage: $0 up|down|status" ;;
esac
