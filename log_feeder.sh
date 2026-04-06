#!/bin/bash
# =============================================================================
# log_feeder.sh — SSH Log Feeder
# Streams auth.log content to stdout for the Python analyzer to consume.
# Supports --live (real-time tail) and --file (static read) modes.
# Usage:
#   ./log_feeder.sh --live                        # monitor /var/log/auth.log live
#   ./log_feeder.sh --file /path/to/auth.log      # read a static file
#   ./log_feeder.sh --live | python3 analyzer.py  # pipe into analyzer
# =============================================================================

set -euo pipefail

# Default values
MODE=""
LOG_FILE="/var/log/auth.log"

# ----------------------------
# Parse CLI arguments
# ----------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        --live)
            MODE="live"
            shift
            ;;
        --file)
            MODE="file"
            LOG_FILE="$2"
            shift 2
            ;;
        --help|-h)
            echo "Usage: $0 [--live | --file <path>]"
            echo ""
            echo "  --live            Stream /var/log/auth.log in real-time (tail -f)"
            echo "  --file <path>     Read from a specific log file (static)"
            exit 0
            ;;
        *)
            echo "[ERROR] Unknown argument: $1" >&2
            exit 1
            ;;
    esac
done

# ----------------------------
# Validate mode selection
# ----------------------------
if [[ -z "$MODE" ]]; then
    echo "[ERROR] You must specify a mode: --live or --file <path>" >&2
    exit 1
fi

# ----------------------------
# Validate log file existence
# ----------------------------
if [[ ! -f "$LOG_FILE" ]]; then
    echo "[ERROR] Log file not found: $LOG_FILE" >&2
    exit 1
fi

# ----------------------------
# Stream logs based on mode
# ----------------------------
if [[ "$MODE" == "live" ]]; then
    echo "[FEEDER] Starting live monitoring of: $LOG_FILE" >&2
    # tail -F handles log rotation automatically (better than -f)
    exec tail -F "$LOG_FILE"

elif [[ "$MODE" == "file" ]]; then
    echo "[FEEDER] Reading static log file: $LOG_FILE" >&2
    exec cat "$LOG_FILE"
fi
