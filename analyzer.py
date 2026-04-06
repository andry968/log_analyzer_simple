#!/usr/bin/env python3
"""
analyzer.py — SSH Auth Log Analyzer
====================================
Reads auth.log entries from stdin (piped from log_feeder.sh or any source),
detects SSH events, counts per-IP attempts, and prints colored alerts.

Usage:
    cat auth.log | python3 analyzer.py [options]
    ./log_feeder.sh --live | python3 analyzer.py --threshold 5
    ./log_feeder.sh --file auth.log | python3 analyzer.py --no-color --threshold 3
"""

import sys
import re
import argparse
from collections import defaultdict
from datetime import datetime


# =============================================================================
# ANSI Color Codes (optional, toggled via --no-color)
# =============================================================================
class Colors:
    RESET   = "\033[0m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    CYAN    = "\033[96m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    MAGENTA = "\033[95m"

# Will be set to False if --no-color is passed
USE_COLOR = True

def colorize(text: str, *codes: str) -> str:
    """Wrap text in ANSI codes if color is enabled."""
    if not USE_COLOR:
        return text
    return "".join(codes) + text + Colors.RESET


# =============================================================================
# Regex Patterns for auth.log parsing
# =============================================================================

# Matches lines like: "Failed password for invalid user admin from 192.168.1.10 port 22 ssh2"
FAILED_PATTERN = re.compile(
    r"Failed password for (?:invalid user )?(\S+) from ([\d.]+) port \d+"
)

# Matches: "Accepted password for user from 192.168.1.10 port 22 ssh2"
# Also handles publickey auth
SUCCESS_PATTERN = re.compile(
    r"Accepted (?:password|publickey) for (\S+) from ([\d.]+) port \d+"
)

# Matches disconnects/invalid users (supplementary context)
INVALID_USER_PATTERN = re.compile(
    r"Invalid user (\S+) from ([\d.]+)"
)


# =============================================================================
# LogEvent — represents a parsed log event
# =============================================================================
class LogEvent:
    def __init__(self, event_type: str, user: str, ip: str, raw_line: str):
        self.event_type = event_type   # "failed", "success", "invalid"
        self.user       = user
        self.ip         = ip
        self.raw_line   = raw_line.strip()
        self.timestamp  = datetime.now().strftime("%H:%M:%S")


# =============================================================================
# LogParser — parses a single log line into a LogEvent
# =============================================================================
class LogParser:
    @staticmethod
    def parse(line: str) -> LogEvent | None:
        """
        Try each pattern against the log line.
        Returns a LogEvent on match, or None if irrelevant.
        """
        m = FAILED_PATTERN.search(line)
        if m:
            return LogEvent("failed", m.group(1), m.group(2), line)

        m = SUCCESS_PATTERN.search(line)
        if m:
            return LogEvent("success", m.group(1), m.group(2), line)

        m = INVALID_USER_PATTERN.search(line)
        if m:
            return LogEvent("invalid", m.group(1), m.group(2), line)

        return None  # Not an SSH event we care about


# =============================================================================
# AlertEngine — tracks counts and fires alerts
# =============================================================================
class AlertEngine:
    def __init__(self, threshold: int):
        self.threshold      = threshold
        self.failed_counts  = defaultdict(int)   # ip -> count of failed attempts
        self.alerted_ips    = set()              # IPs that already triggered brute-force alert
        self.success_count  = 0
        self.failed_total   = 0
        self.invalid_count  = 0

    def process(self, event: LogEvent):
        """Process a parsed event and print the appropriate alert."""

        if event.event_type == "failed":
            self.failed_counts[event.ip] += 1
            self.failed_total += 1
            self._print_failed(event)
            self._check_brute_force(event.ip)

        elif event.event_type == "success":
            self.success_count += 1
            self._print_success(event)

        elif event.event_type == "invalid":
            self.invalid_count += 1
            # Invalid user attempts are subtly noted (not always re-alerted)
            self._print_invalid(event)

    def _check_brute_force(self, ip: str):
        """Fire a brute-force alert if threshold is crossed (once per IP)."""
        count = self.failed_counts[ip]
        if count >= self.threshold and ip not in self.alerted_ips:
            self.alerted_ips.add(ip)
            self._print_brute_force(ip, count)
        elif count > self.threshold and ip in self.alerted_ips:
            # Print escalating count update every 5 additional attempts
            if (count - self.threshold) % 5 == 0:
                print(colorize(
                    f"  [!] BRUTE FORCE ONGOING | {ip} now at {count} failed attempts",
                    Colors.BOLD, Colors.RED
                ))

    # -----------------------------------------------------------------------
    # Print helpers
    # -----------------------------------------------------------------------
    def _print_failed(self, event: LogEvent):
        count = self.failed_counts[event.ip]
        line = (
            f"[{event.timestamp}] "
            f"{colorize('FAILED LOGIN', Colors.YELLOW, Colors.BOLD)} | "
            f"IP: {colorize(event.ip, Colors.CYAN)} | "
            f"User: {colorize(event.user, Colors.MAGENTA)} | "
            f"Attempts from this IP: {colorize(str(count), Colors.YELLOW)}"
        )
        print(line)

    def _print_success(self, event: LogEvent):
        line = (
            f"[{event.timestamp}] "
            f"{colorize('SUCCESS LOGIN', Colors.GREEN, Colors.BOLD)} | "
            f"IP: {colorize(event.ip, Colors.CYAN)} | "
            f"User: {colorize(event.user, Colors.GREEN)}"
        )
        print(line)

    def _print_invalid(self, event: LogEvent):
        line = (
            f"[{event.timestamp}] "
            f"{colorize('INVALID USER', Colors.DIM, Colors.YELLOW)} | "
            f"IP: {colorize(event.ip, Colors.CYAN)} | "
            f"User: {colorize(event.user, Colors.MAGENTA)}"
        )
        print(line)

    def _print_brute_force(self, ip: str, count: int):
        separator = colorize("=" * 60, Colors.RED, Colors.BOLD)
        print()
        print(separator)
        print(colorize(
            f"  *** BRUTE FORCE DETECTED ***",
            Colors.RED, Colors.BOLD
        ))
        print(colorize(
            f"  IP Address : {ip}",
            Colors.RED
        ))
        print(colorize(
            f"  Attempts   : {count} (threshold: {self.threshold})",
            Colors.RED
        ))
        print(colorize(
            f"  Action     : Consider blocking with: iptables -A INPUT -s {ip} -j DROP",
            Colors.YELLOW
        ))
        print(separator)
        print()

    # -----------------------------------------------------------------------
    # Summary Report
    # -----------------------------------------------------------------------
    def print_summary(self, top_n: int = 10):
        """Print a final summary report after all logs are processed."""
        sep = colorize("=" * 60, Colors.CYAN, Colors.BOLD)
        print()
        print(sep)
        print(colorize("  SUMMARY REPORT", Colors.BOLD, Colors.CYAN))
        print(sep)
        print(f"  Total Failed Logins   : {colorize(str(self.failed_total), Colors.YELLOW)}")
        print(f"  Total Successful      : {colorize(str(self.success_count), Colors.GREEN)}")
        print(f"  Invalid User Attempts : {colorize(str(self.invalid_count), Colors.DIM)}")
        print(f"  Unique Attacking IPs  : {colorize(str(len(self.failed_counts)), Colors.RED)}")
        print(f"  Brute Force Alerts    : {colorize(str(len(self.alerted_ips)), Colors.RED, Colors.BOLD)}")
        print()

        if self.failed_counts:
            print(colorize(f"  TOP {top_n} ATTACKING IPs:", Colors.BOLD, Colors.RED))
            sorted_ips = sorted(self.failed_counts.items(), key=lambda x: x[1], reverse=True)
            for rank, (ip, count) in enumerate(sorted_ips[:top_n], 1):
                bar = colorize("█" * min(count, 40), Colors.RED)
                flag = colorize(" *** BRUTE FORCE ***", Colors.RED, Colors.BOLD) if ip in self.alerted_ips else ""
                print(f"  #{rank:>2} {colorize(ip, Colors.CYAN):<20} {count:>5} attempts  {bar}{flag}")

        print(sep)
        print()


# =============================================================================
# Main entry point
# =============================================================================
def parse_args():
    parser = argparse.ArgumentParser(
        description="SSH Auth Log Analyzer — reads from stdin, detects SSH threats.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  cat /var/log/auth.log | python3 analyzer.py
  ./log_feeder.sh --live | python3 analyzer.py --threshold 5
  ./log_feeder.sh --file sample.log | python3 analyzer.py --no-color --threshold 3
        """
    )
    parser.add_argument(
        "--threshold", type=int, default=5,
        help="Number of failed attempts before brute-force alert (default: 5)"
    )
    parser.add_argument(
        "--no-color", action="store_true",
        help="Disable colored output (useful for logging to file)"
    )
    parser.add_argument(
        "--top", type=int, default=10,
        help="Number of top attacking IPs to show in summary (default: 10)"
    )
    return parser.parse_args()


def main():
    global USE_COLOR

    args = parse_args()
    USE_COLOR = not args.no_color

    # Print startup banner
    print(colorize("=" * 60, Colors.CYAN, Colors.BOLD))
    print(colorize("  SSH Auth Log Analyzer", Colors.BOLD, Colors.CYAN))
    print(colorize(f"  Threshold : {args.threshold} failed attempts = brute force", Colors.DIM))
    print(colorize(f"  Reading from stdin...", Colors.DIM))
    print(colorize("=" * 60, Colors.CYAN, Colors.BOLD))
    print()

    parser = LogParser()
    engine = AlertEngine(threshold=args.threshold)

    # Read line by line from stdin (piped from log_feeder.sh or direct cat)
    try:
        for raw_line in sys.stdin:
            event = parser.parse(raw_line)
            if event:
                engine.process(event)

    except KeyboardInterrupt:
        # Graceful exit on Ctrl+C (common in --live mode)
        print(colorize("\n[!] Interrupted by user. Generating summary...", Colors.YELLOW))

    # Always print summary at the end
    engine.print_summary(top_n=args.top)


if __name__ == "__main__":
    main()
