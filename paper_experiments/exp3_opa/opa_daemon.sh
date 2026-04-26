#!/usr/bin/env bash
# Start/stop a local OPA daemon for exp5 REST measurements.
#
#   ./opa_daemon.sh start    # binds 127.0.0.1:8181, writes opa.pid + opa.log
#   ./opa_daemon.sh stop     # kills the daemon
#   ./opa_daemon.sh status   # prints PID and 'opa version'

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
PID_FILE="$HERE/opa.pid"
LOG_FILE="$HERE/opa.log"
ADDR="127.0.0.1:8181"

case "${1:-}" in
    start)
        if [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
            echo "OPA already running (PID $(cat "$PID_FILE"))"
            exit 0
        fi
        echo "Starting OPA on $ADDR..."
        opa run --server --addr "$ADDR" --log-level error >"$LOG_FILE" 2>&1 &
        echo $! > "$PID_FILE"
        sleep 0.5
        if curl -s "http://$ADDR/health" >/dev/null; then
            echo "OPA ready, PID $(cat "$PID_FILE"), log $LOG_FILE"
        else
            echo "OPA failed to start; see $LOG_FILE" >&2
            exit 1
        fi
        ;;
    stop)
        if [ -f "$PID_FILE" ]; then
            PID="$(cat "$PID_FILE")"
            if kill -0 "$PID" 2>/dev/null; then
                kill "$PID" && echo "OPA stopped (PID $PID)"
            fi
            rm -f "$PID_FILE"
        else
            echo "no PID file"
        fi
        ;;
    status)
        if [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
            echo "OPA running (PID $(cat "$PID_FILE")) on $ADDR"
            curl -s "http://$ADDR/health" && echo
        else
            echo "OPA not running"
        fi
        ;;
    *)
        echo "usage: $0 {start|stop|status}" >&2
        exit 2
        ;;
esac
