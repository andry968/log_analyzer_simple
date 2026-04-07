#!/bin/bash
# =============================================================================
# log_feeder.sh — SSH Log Feeder with Timezone and Time Range Filtering
# Pure bash, no Python dependency
# =============================================================================

set -uo pipefail

MODE=""
LOG_FILE="/var/log/auth.log"
TIMEZONE=""
TIME_RANGE=""

# -----------------------------------------------------------------------------
# Helper: validate time range format (HH:MM-HH:MM)
validate_time_range() {
    local range="$1"
    if [[ ! "$range" =~ ^([01]?[0-9]|2[0-3]):[0-5][0-9]-([01]?[0-9]|2[0-3]):[0-5][0-9]$ ]]; then
        echo "[ERROR] Invalid time range format: $range" >&2
        echo "        Expected HH:MM-HH:MM (e.g., 19:00-20:00 or 01:00-17:00)" >&2
        exit 1
    fi
}

# -----------------------------------------------------------------------------
# Helper: validate timezone format (UTC, UTC+7, UTC-4, UTC+07:00, etc.)
validate_timezone() {
    local tz="$1"
    if [[ ! "$tz" =~ ^UTC([+-]?[0-9]{1,2}(:[0-5][0-9])?)?$ ]]; then
        echo "[ERROR] Invalid timezone format: $tz" >&2
        echo "        Examples: UTC, UTC+7, UTC-4, UTC+07:00" >&2
        exit 1
    fi
}

# -----------------------------------------------------------------------------
# Parse timezone string -> offset in minutes
# Input:  "UTC+7", "UTC-4", "UTC+07:00", "UTC"
# Output: integer minutes (e.g., 420, -240, 0)
parse_tz_to_minutes() {
    local tz="$1"
    if [[ "$tz" == "UTC" ]]; then
        echo 0
        return
    fi
    # Match UTC+7 or UTC-4 or UTC+07:00
    if [[ "$tz" =~ ^UTC([+-])([0-9]{1,2})(:([0-5][0-9]))?$ ]]; then
        local sign="${BASH_REMATCH[1]}"
        local hours=$(( 10#${BASH_REMATCH[2]} ))
        local mins=$(( 10#${BASH_REMATCH[4]:-0} ))
        local total=$(( hours * 60 + mins ))
        [[ "$sign" == "-" ]] && total=$(( -total ))
        echo "$total"
    else
        echo 0
    fi
}

# -----------------------------------------------------------------------------
# Parse log's own offset string -> offset in minutes
# Input:  "+07:00" or "-05:00"
# Output: integer minutes
parse_log_offset_to_minutes() {
    local offset="$1"
    if [[ "$offset" =~ ^([+-])([0-9]{2}):([0-9]{2})$ ]]; then
        local sign="${BASH_REMATCH[1]}"
        local h=$(( 10#${BASH_REMATCH[2]} ))
        local m=$(( 10#${BASH_REMATCH[3]} ))
        local total=$(( h * 60 + m ))
        [[ "$sign" == "-" ]] && total=$(( -total ))
        echo "$total"
    else
        echo 0
    fi
}

# -----------------------------------------------------------------------------
# Detect timezone offset from the first line of a log file
detect_timezone_from_log() {
    local logfile="$1"
    if [[ ! -f "$logfile" ]]; then
        echo "UTC"
        return
    fi
    local first_line
    first_line=$(head -n1 "$logfile" 2>/dev/null || true)
    if [[ -z "$first_line" ]]; then
        echo "UTC"
        return
    fi
    local offset
    offset=$(echo "$first_line" | grep -oE '[+-][0-9]{2}:[0-9]{2}' | head -1)
    if [[ -z "$offset" ]]; then
        echo "UTC"
        return
    fi
    local sign="${offset:0:1}"
    local hours=$(( 10#${offset:1:2} ))
    if [[ "$sign" == "+" ]]; then
        echo "UTC+$hours"
    else
        echo "UTC-$hours"
    fi
}

# -----------------------------------------------------------------------------
# Convert a log line's timestamp to target timezone, return HH:MM as minutes
# Returns -1 if timestamp can't be parsed
get_line_minutes_in_tz() {
    local line="$1"
    local target_offset_min="$2"

    # Extract ISO 8601 timestamp: 2026-04-01T08:15:22.123456+07:00
    local ts
    ts=$(echo "$line" | grep -oE '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?[+-][0-9]{2}:[0-9]{2}')

    if [[ -z "$ts" ]]; then
        echo "-1"
        return
    fi

    # Extract time part: T08:15:22
    local time_part
    time_part=$(echo "$ts" | grep -oE 'T[0-9]{2}:[0-9]{2}:[0-9]{2}')
    local h=$(( 10#${time_part:1:2} ))
    local m=$(( 10#${time_part:4:2} ))

    # Extract log's own offset: +07:00
    local log_offset_str
    log_offset_str=$(echo "$ts" | grep -oE '[+-][0-9]{2}:[0-9]{2}$')
    local log_offset_min
    log_offset_min=$(parse_log_offset_to_minutes "$log_offset_str")

    # Convert: line_time_in_utc = h:m - log_offset
    # Then convert to target: + target_offset
    local line_min=$(( h * 60 + m ))
    local utc_min=$(( line_min - log_offset_min ))
    local target_min=$(( utc_min + target_offset_min ))

    # Normalize to 0-1439
    target_min=$(( target_min % 1440 ))
    [[ $target_min -lt 0 ]] && target_min=$(( target_min + 1440 ))

    echo "$target_min"
}

# -----------------------------------------------------------------------------
# Check if a time (in minutes) is within range
# Supports wrap-around midnight (e.g., 22:00-02:00)
in_time_range() {
    local current_min="$1"
    local start_min="$2"
    local end_min="$3"

    if [[ $start_min -le $end_min ]]; then
        [[ $current_min -ge $start_min && $current_min -le $end_min ]] && echo 1 || echo 0
    else
        # wrap-around
        [[ $current_min -ge $start_min || $current_min -le $end_min ]] && echo 1 || echo 0
    fi
}

# -----------------------------------------------------------------------------
# Parse time range string "HH:MM-HH:MM" -> start_min and end_min
parse_time_range_to_minutes() {
    local range="$1"
    local start_h start_m end_h end_m

    start_h=$(echo "$range" | grep -oE '^[0-9]+')
    start_m=$(echo "$range" | sed 's/^[0-9]*://; s/-.*//')
    end_h=$(echo "$range" | sed 's/.*-//; s/:.*//')
    end_m=$(echo "$range" | grep -oE '[0-9]+$')

    echo "$(( 10#$start_h * 60 + 10#$start_m )) $(( 10#$end_h * 60 + 10#$end_m ))"
}

# -----------------------------------------------------------------------------
# Main filter: reads stdin line by line, applies timezone + time range filter
run_filter() {
    local tz="$1"
    local range="$2"

    local target_offset_min
    target_offset_min=$(parse_tz_to_minutes "$tz")

    local range_parts
    range_parts=$(parse_time_range_to_minutes "$range")
    local start_min end_min
    start_min=$(echo "$range_parts" | cut -d' ' -f1)
    end_min=$(echo "$range_parts" | cut -d' ' -f2)

    while IFS= read -r line; do
        local line_min
        line_min=$(get_line_minutes_in_tz "$line" "$target_offset_min")

        if [[ "$line_min" == "-1" ]]; then
            continue
        fi

        local ok
        ok=$(in_time_range "$line_min" "$start_min" "$end_min")
        [[ "$ok" == "1" ]] && echo "$line"
    done | display_with_tz "$tz"
}

# -----------------------------------------------------------------------------
# Replace timestamp inline: rewrite the ISO 8601 timestamp in the log line
# to the target timezone. The rest of the line is untouched.
# e.g. 2026-04-01T08:15:22.123456+07:00 -> 2026-04-01T04:15:22.123456+03:00
display_with_tz() {
    local tz="$1"
    local target_offset_min
    target_offset_min=$(parse_tz_to_minutes "$tz")

    # Build offset string with safe method (no printf leading dash)
    local new_offset_str
    if (( target_offset_min >= 0 )); then
        local new_h=$(( target_offset_min / 60 ))
        local new_m=$(( target_offset_min % 60 ))
        new_offset_str="+$(printf "%02d:%02d" "$new_h" "$new_m")"
    else
        local abs=$(( -target_offset_min ))
        local new_h=$(( abs / 60 ))
        local new_m=$(( abs % 60 ))
        new_offset_str="-"$(printf "%02d:%02d" "$new_h" "$new_m")
    fi

    while IFS= read -r line; do
        # Extract original timestamp (supports both ISO and [YYYY-MM-DD HH:MM:SS] format)
        local ts
        ts=$(echo "$line" | grep -oE '\[[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}\]' || true)
        if [[ -z "$ts" ]]; then
            # If no bracket timestamp, try ISO format
            ts=$(echo "$line" | grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?[+-][0-9]{2}:[0-9]{2}' || true)
        fi
        if [[ -z "$ts" ]]; then
            echo "$line"
            continue
        fi

        # Extract date and time from bracket format
        if [[ "$ts" =~ \[([0-9]{4}-[0-9]{2}-[0-9]{2})\ ([0-9]{2}):([0-9]{2}):([0-9]{2})\}\] ]]; then
            local date_part="${BASH_REMATCH[1]}"
            local h=$((10#${BASH_REMATCH[2]}))
            local m=$((10#${BASH_REMATCH[3]}))
            local s=$((10#${BASH_REMATCH[4]}))
            # Assume log's offset is UTC+0 (since no offset in bracket format)
            local log_offset_min=0
        else
            # ISO format parsing (as before)
            date_part=$(echo "$ts" | grep -oE '^[0-9]{4}-[0-9]{2}-[0-9]{2}')
            time_part=$(echo "$ts" | grep -oE 'T[0-9]{2}:[0-9]{2}:[0-9]{2}')
            subsec=$(echo "$ts" | grep -oE '\.[0-9]+' || true)
            log_offset_str=$(echo "$ts" | grep -oE '[+-][0-9]{2}:[0-9]{2}$')
            h=$((10#${time_part:1:2}))
            m=$((10#${time_part:4:2}))
            s=$((10#${time_part:7:2}))
            log_offset_min=$(parse_log_offset_to_minutes "$log_offset_str")
        fi

        # Convert to target timezone
        local total_min=$(( h * 60 + m - log_offset_min + target_offset_min ))
        total_min=$(( total_min % 1440 ))
        (( total_min < 0 )) && total_min=$(( total_min + 1440 ))
        local new_h=$(( total_min / 60 ))
        local new_m=$(( total_min % 60 ))

        # Build new timestamp in original format
        if [[ "$ts" =~ ^\[.*\]$ ]]; then
            local new_ts=$(printf "[%s %02d:%02d:%02d]" "$date_part" "$new_h" "$new_m" "$s")
        else
            local new_ts=$(printf "%sT%02d:%02d:%02d%s%s" "$date_part" "$new_h" "$new_m" "$s" "$subsec" "$new_offset_str")
        fi

        # Replace timestamp
        echo "${line/$ts/$new_ts}"
    done
}

# -----------------------------------------------------------------------------
# Parse arguments
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
        -tz)
            TIMEZONE="$2"
            validate_timezone "$TIMEZONE"
            shift 2
            ;;
        -tr)
            TIME_RANGE="$2"
            validate_time_range "$TIME_RANGE"
            shift 2
            ;;
        -h|--help)
            cat <<EOF
Usage: $0 [-lv | -f <path>] [-tz <timezone>] [-tr <range>]

Modes (required):
  -lv               Stream /var/log/auth.log in real-time (tail -F)
  -f  <path>        Read from a specific log file (static)

Filters (optional):
  -tz <timezone>    Timezone for display/filtering.
                    Examples: UTC, UTC+7, UTC-4, UTC+07:00.
  -tr <range>       Time range to filter, format HH:MM-HH:MM.
                    Examples: 08:00-17:00, 22:00-02:00 (crosses midnight).

Examples:
  $0 -lv
  $0 -f /var/log/auth.log
  $0 -f auth.log -tz UTC+7
  $0 -lv -tz UTC+7 -tr 08:00-17:00
  $0 -f auth.log -tr 22:00-02:00
  $0 -f auth.log -tz UTC+3 -tr 08:00-09:00 | python3 analyzer.py
EOF
            exit 0
            ;;
        *)
            echo "[ERROR] Unknown argument: $1" >&2
            echo "        Run with -h for help." >&2
            exit 1
            ;;
    esac
done

# -----------------------------------------------------------------------------
# Validate
if [[ -z "$MODE" ]]; then
    echo "[ERROR] You must specify a mode: -lv or -f <path>" >&2
    exit 1
fi

if [[ ! -f "$LOG_FILE" ]]; then
    echo "[ERROR] Log file not found: $LOG_FILE" >&2
    exit 1
fi

# -----------------------------------------------------------------------------
# Determine timezone
if [[ -n "$TIME_RANGE" && -z "$TIMEZONE" ]]; then
    TIMEZONE=$(detect_timezone_from_log "$LOG_FILE")
    echo "[FEEDER] Auto-detected timezone: $TIMEZONE" >&2
fi

[[ -n "$TIMEZONE" ]] && echo "[FEEDER] Timezone: $TIMEZONE" >&2
[[ -n "$TIME_RANGE" ]] && echo "[FEEDER] Time range filter: $TIME_RANGE" >&2

# -----------------------------------------------------------------------------
# Run
if [[ "$MODE" == "live" ]]; then
    echo "[FEEDER] Live monitoring: $LOG_FILE" >&2
    if [[ -n "$TIME_RANGE" ]]; then
        tail -F "$LOG_FILE" | run_filter "$TIMEZONE" "$TIME_RANGE"
    elif [[ -n "$TIMEZONE" ]]; then
        tail -F "$LOG_FILE" | display_with_tz "$TIMEZONE"
    else
        exec tail -F "$LOG_FILE"
    fi

elif [[ "$MODE" == "file" ]]; then
    echo "[FEEDER] Reading file: $LOG_FILE" >&2
    if [[ -n "$TIME_RANGE" ]]; then
        cat "$LOG_FILE" | run_filter "$TIMEZONE" "$TIME_RANGE"
    elif [[ -n "$TIMEZONE" ]]; then
        cat "$LOG_FILE" | display_with_tz "$TIMEZONE"
    else
        exec cat "$LOG_FILE"
    fi
fi
