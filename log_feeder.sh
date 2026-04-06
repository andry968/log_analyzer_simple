#!/bin/bash

set -euo pipefail

MODE=""
LOG_FILE="/var/log/auth.log"

while [[ $# -gt 0 ]]; do
    case "$1" in
        -lv)
            MODE="live"
            shift
            ;;
        -f)
            MODE="file"
            LOG_FILE="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 [-lv | -f <path>]"
            echo ""
            echo "  -lv               Stream /var/log/auth.log in real-time (tail -F)"
            echo "  -f  <path>        Read from a specific log file (static)"
            echo "  -h                Show this help"
            echo ""
            echo "Examples:"
            echo "  ./log_feeder.sh -lv"
            echo "  ./log_feeder.sh -f /var/log/auth.log"
            echo "  ./log_feeder.sh -lv | python3 analyzer.py -t 3 -o report.csv"
            exit 0
            ;;
        *)
            echo "[ERROR] Unknown argument: $1" >&2
            exit 1
            ;;
    esac
done

# Validate mode
if [[ -z "$MODE" ]]; then
    echo "[ERROR] You must specify a mode: -lv or -f <path>" >&2
    echo "        Run with -h for help." >&2
    exit 1
fi

# Validate log file
if [[ ! -f "$LOG_FILE" ]]; then
    echo "[ERROR] Log file not found: $LOG_FILE" >&2
    exit 1
fi

# Stream
if [[ "$MODE" == "live" ]]; then
    echo "[FEEDER] Live monitoring: $LOG_FILE" >&2
    exec tail -F "$LOG_FILE"
elif [[ "$MODE" == "file" ]]; then
    echo "[FEEDER] Reading file: $LOG_FILE" >&2
    exec cat "$LOG_FILE"
fi
