#!/bin/zsh

set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
HOST="127.0.0.1"
PORT="${MACOS_INSPECTOR_PORT:-8765}"
URL="http://${HOST}:${PORT}/"
OUTPUT_DIR="${MACOS_INSPECTOR_OUTPUT:-${ROOT}/macos-inspector-reports}"
STATE_DIR="${MACOS_INSPECTOR_STATE_DIR:-${ROOT}/tmp}"
LOG_FILE="${STATE_DIR}/dashboard-${PORT}.log"
PID_FILE="${STATE_DIR}/dashboard-${PORT}.pid"
SERVER_PID=""
PID_FILE_CREATED=0

alert_error() {
  print -u2 -- "$1"
  if [ "${MACOS_INSPECTOR_NO_ALERT:-0}" != "1" ] && [ -x /usr/bin/osascript ]; then
    /usr/bin/osascript \
      -e 'on run argv' \
      -e 'display alert "macOS Inspector" message (item 1 of argv) as critical' \
      -e 'end run' \
      "$1" >/dev/null 2>&1 || true
  fi
}

open_dashboard() {
  if [ "${MACOS_INSPECTOR_NO_OPEN:-0}" = "1" ]; then
    print -- "$URL"
  else
    /usr/bin/open "$URL"
  fi
}

open_setup_help() {
  if [ "${MACOS_INSPECTOR_NO_OPEN:-0}" != "1" ]; then
    /usr/bin/open "${ROOT}/docs/START_HERE.html" >/dev/null 2>&1 || true
  fi
}

dashboard_ready() {
  /usr/bin/curl --silent --fail --max-time 1 "${URL}api/health" 2>/dev/null | /usr/bin/grep -Eq '"status"[[:space:]]*:[[:space:]]*"ok"'
}

cleanup() {
  if [ -n "$SERVER_PID" ]; then
    pid="$SERVER_PID"
    SERVER_PID=""
    /bin/kill "$pid" >/dev/null 2>&1 || true
    wait "$pid" >/dev/null 2>&1 || true
  fi
  if [ "$PID_FILE_CREATED" = "1" ]; then
    /bin/rm -f "$PID_FILE"
    PID_FILE_CREATED=0
  fi
}

handle_signal() {
  cleanup
  exit 0
}

trap cleanup EXIT
trap handle_signal INT TERM HUP

case "$PORT" in
  ''|*[!0-9]*) alert_error "The dashboard port must be a number between 1 and 65535."; exit 1 ;;
esac
if [ "$PORT" -lt 1 ] || [ "$PORT" -gt 65535 ]; then
  alert_error "The dashboard port must be a number between 1 and 65535."
  exit 1
fi

if dashboard_ready; then
  open_dashboard
  exit 0
fi

PYTHON=""
if [ -n "${MACOS_INSPECTOR_PYTHON:-}" ]; then
  candidates=("$MACOS_INSPECTOR_PYTHON")
else
  candidates=("${ROOT}/.venv/bin/python3" "${ROOT}/venv/bin/python3" "$(command -v python3 2>/dev/null || true)" /opt/homebrew/bin/python3 /usr/local/bin/python3 /usr/bin/python3)
fi
for candidate in "${candidates[@]}"; do
  if [ -x "$candidate" ] && "$candidate" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)' >/dev/null 2>&1; then
    PYTHON="$candidate"
    break
  fi
done
if [ -z "$PYTHON" ]; then
  open_setup_help
  alert_error "A compatible Python 3.10 or newer was not found. Open docs/START_HERE.html for setup instructions. If MACOS_INSPECTOR_PYTHON is set, it must point to a compatible executable. No software was installed or downloaded."
  exit 1
fi

/bin/mkdir -p "$STATE_DIR" "$OUTPUT_DIR"
/bin/chmod 700 "$STATE_DIR" "$OUTPUT_DIR"
/usr/bin/touch "$LOG_FILE"
/bin/chmod 600 "$LOG_FILE"

/usr/bin/env HOME="${HOME:-/Users/Shared}" \
  PATH="${PATH:-/usr/bin:/bin:/usr/sbin:/sbin}" \
  TMPDIR="${TMPDIR:-/private/tmp}" PYTHONUNBUFFERED=1 \
  PYTHONPATH="${ROOT}/src${PYTHONPATH:+:${PYTHONPATH}}" \
  "$PYTHON" -m macos_inspector --web --no-open-browser \
  --host "$HOST" --port "$PORT" --output "$OUTPUT_DIR" \
  >"$LOG_FILE" 2>&1 &
SERVER_PID=$!
print -- "$SERVER_PID" >"$PID_FILE"
PID_FILE_CREATED=1
/bin/chmod 600 "$PID_FILE"

attempt=0
while [ "$attempt" -lt 80 ]; do
  if dashboard_ready; then
    open_dashboard
    print -- "macOS Inspector is running at ${URL}"
    print -- "Keep this window open. Closing it stops the local dashboard."
    if wait "$SERVER_PID"; then
      server_status=0
    else
      server_status=$?
    fi
    SERVER_PID=""
    /bin/rm -f "$PID_FILE"
    PID_FILE_CREATED=0
    if [ "$server_status" -ne 0 ]; then
      alert_error "The dashboard stopped unexpectedly. Details: ${LOG_FILE}"
    fi
    exit "$server_status"
  fi
  if ! /bin/kill -0 "$SERVER_PID" 2>/dev/null; then
    break
  fi
  /bin/sleep 0.25
  attempt=$((attempt + 1))
done

alert_error "The dashboard could not start. Details: ${LOG_FILE}"
exit 1
