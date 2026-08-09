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
  /bin/rm -f "$PID_FILE"
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

if [ -n "${MACOS_INSPECTOR_PYTHON:-}" ] && [ -x "$MACOS_INSPECTOR_PYTHON" ]; then
  PYTHON="$MACOS_INSPECTOR_PYTHON"
elif [ -x "${ROOT}/.venv/bin/python3" ]; then
  PYTHON="${ROOT}/.venv/bin/python3"
elif [ -x "${ROOT}/venv/bin/python3" ]; then
  PYTHON="${ROOT}/venv/bin/python3"
elif command -v python3 >/dev/null 2>&1; then
  PYTHON="$(command -v python3)"
else
  alert_error "Python 3.10 or newer was not found. Install Python 3, then open macOS Inspector.command again."
  exit 1
fi

if ! "$PYTHON" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)' >/dev/null 2>&1; then
  alert_error "macOS Inspector requires Python 3.10 or newer."
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
