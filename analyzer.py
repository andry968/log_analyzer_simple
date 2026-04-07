#!/usr/bin/env python3

import sys
import re
import csv
import argparse
from collections import defaultdict
from datetime import datetime
from pathlib import Path


# =============================================================================
# ANSI Color Codes
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
    ORANGE  = "\033[33m"

USE_COLOR = True

def colorize(text: str, *codes: str) -> str:
    if not USE_COLOR:
        return text
    return "".join(codes) + text + Colors.RESET


# =============================================================================
# Timestamp Extraction
# =============================================================================
def extract_timestamp(line: str) -> str:
    """
    Extract ISO timestamp from beginning of log line and return as 'YYYY-MM-DD HH:MM:SS'.
    Returns current time if line is empty or has no timestamp.
    """
    line = line.strip()
    if not line:
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    first_token = line.split(maxsplit=1)[0]
    
    if 'T' in first_token:
        dt_part = first_token[:19]
        return dt_part.replace('T', ' ')
    
    if ' ' in first_token and '-' in first_token and ':' in first_token:
        return first_token[:19] if len(first_token) >= 19 else first_token
    
    try:
        dt = datetime.fromisoformat(first_token)
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# =============================================================================
# Regex Patterns
# =============================================================================
FAILED_PATTERN = re.compile(
    r"Failed password for (?:invalid user )?(\S+) from ([\d.]+) port \d+"
)
SUCCESS_PATTERN = re.compile(
    r"Accepted (?:password|publickey) for (\S+) from ([\d.]+) port \d+"
)
INVALID_USER_PATTERN = re.compile(
    r"Invalid user (\S+) from ([\d.]+)"
)

SU_SUCCESS_PATTERN = re.compile(
    r"su\[\d+\]: \(to (\S+)\) (\S+) on "
)

SU_FAILED_PATTERN = re.compile(
    r"su\[\d+\]: FAILED su for (\S+) by (\S+)"
)

SUDO_SUCCESS_PATTERN = re.compile(
    r"sudo:\s+(\S+)\s+:.*USER=(\S+)\s*;.*COMMAND=(.+)"
)

SUDO_FAILED_PATTERN = re.compile(
    r"sudo:.*authentication failure.*user=(\S+)"
)


# =============================================================================
# LogEvent
# =============================================================================
class LogEvent:
    def __init__(self, event_type: str, user: str, ip: str, raw_line: str, extra: str = "", timestamp: str = None):
        self.event_type = event_type
        self.user       = user
        self.ip         = ip       
        self.raw_line   = raw_line.strip()
        self.extra      = extra
        if timestamp is None:
            self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        else:
            self.timestamp = timestamp


# =============================================================================
# LogParser
# =============================================================================
class LogParser:
    @staticmethod
    def parse(line: str) -> "LogEvent | None":
        ts = extract_timestamp(line)

        m = FAILED_PATTERN.search(line)
        if m:
            return LogEvent("ssh_failed", m.group(1), m.group(2), line, timestamp=ts)

        m = SUCCESS_PATTERN.search(line)
        if m:
            return LogEvent("ssh_success", m.group(1), m.group(2), line, timestamp=ts)

        m = INVALID_USER_PATTERN.search(line)
        if m:
            return LogEvent("invalid_user", m.group(1), m.group(2), line, timestamp=ts)

        m = SU_SUCCESS_PATTERN.search(line)
        if m:

            return LogEvent("su_success", m.group(1), m.group(2), line, timestamp=ts)

        m = SU_FAILED_PATTERN.search(line)
        if m:
            return LogEvent("su_failed", m.group(1), m.group(2), line, timestamp=ts)

        m = SUDO_SUCCESS_PATTERN.search(line)
        if m:
            return LogEvent("sudo_success", m.group(2), m.group(1), line, extra=m.group(3).strip(), timestamp=ts)

        m = SUDO_FAILED_PATTERN.search(line)
        if m:
            return LogEvent("sudo_failed", "root", m.group(1), line, timestamp=ts)

        return None


# =============================================================================
# OutputWriter — saves events + summary to .csv or .txt
# =============================================================================
class OutputWriter:
    def __init__(self, filepath: str):
        self.filepath = filepath
        self.is_csv   = filepath.lower().endswith(".csv")
        self.records  = []

    def record(self, event: LogEvent):
        self.records.append({
            "timestamp"  : event.timestamp,
            "event_type" : event.event_type,
            "user"       : event.user,
            "ip_or_from" : event.ip,
            "extra"      : event.extra,
        })

    def write(self, summary_lines: list):
        path = Path(self.filepath)

        if self.is_csv:
            with open(path, "w", newline="") as f:
                fieldnames = ["timestamp", "event_type", "user", "ip_or_from", "extra"]
                w = csv.DictWriter(f, fieldnames=fieldnames, delimiter=";")
                w.writeheader()
                w.writerows(self.records)
            with open(path, "a") as f:
                f.write("\n# SUMMARY\n")
                for line in summary_lines:
                    f.write(f"# {line}\n")
        else:
            with open(path, "w") as f:
                f.write("SSH AUTH LOG ANALYZER — EVENT LOG\n")
                f.write("=" * 60 + "\n\n")
                for r in self.records:
                    f.write(
                        f"[{r['timestamp']}] {r['event_type']:<14} | "
                        f"IP/From: {r['ip_or_from']:<18} | "
                        f"User: {r['user']:<15}"
                    )
                    if r["extra"]:
                        f.write(f" | {r['extra']}")
                    f.write("\n")
                f.write("\n" + "=" * 60 + "\n")
                f.write("SUMMARY\n" + "=" * 60 + "\n")
                for line in summary_lines:
                    f.write(line + "\n")

        print(colorize(f"\n[+] Output saved → {self.filepath}", Colors.GREEN, Colors.BOLD))


# =============================================================================
# AlertEngine
# =============================================================================
class AlertEngine:
    def __init__(self, threshold: int, writer: "OutputWriter | None" = None):
        self.threshold      = threshold
        self.writer         = writer
        self.failed_counts  = defaultdict(int)
        self.alerted_ips    = set()
        self.su_escalations = []

        self.ssh_failed_total  = 0
        self.ssh_success_total = 0
        self.invalid_total     = 0
        self.su_success_total  = 0
        self.su_failed_total   = 0
        self.sudo_total        = 0

    def process(self, event: LogEvent):
        if self.writer:
            self.writer.record(event)

        t = event.event_type

        if t == "ssh_failed":
            self.failed_counts[event.ip] += 1
            self.ssh_failed_total += 1
            self._print_ssh_failed(event)
            self._check_brute_force(event.ip)

        elif t == "ssh_success":
            self.ssh_success_total += 1
            self._print_ssh_success(event)

        elif t == "invalid_user":
            self.invalid_total += 1
            self._print_invalid(event)

        elif t == "su_success":
            self.su_success_total += 1
            self.su_escalations.append((event.ip, event.user))
            self._print_su_success(event)
            if event.user == "root":
                self._print_privesc_alert(event, via="su")

        elif t == "su_failed":
            self.su_failed_total += 1
            self._print_su_failed(event)

        elif t == "sudo_success":
            self.sudo_total += 1
            self.su_escalations.append((event.ip, event.user))
            self._print_sudo_success(event)
            if event.user == "root":
                self._print_privesc_alert(event, via="sudo")

        elif t == "sudo_failed":
            self.su_failed_total += 1
            self._print_sudo_failed(event)

    def _check_brute_force(self, ip: str):
        count = self.failed_counts[ip]
        if count >= self.threshold and ip not in self.alerted_ips:
            self.alerted_ips.add(ip)
            self._print_brute_force(ip, count)
        elif count > self.threshold and ip in self.alerted_ips:
            if (count - self.threshold) % 5 == 0:
                print(colorize(
                    f"  [!] BRUTE FORCE ONGOING | {ip} now at {count} attempts",
                    Colors.BOLD, Colors.RED
                ))

    # --- print helpers ---

    def _print_ssh_failed(self, e):
        count = self.failed_counts[e.ip]
        print(
            f"[{e.timestamp}] "
            f"{colorize('FAILED SSH  ', Colors.YELLOW, Colors.BOLD)} | "
            f"IP: {colorize(e.ip, Colors.CYAN)} | "
            f"User: {colorize(e.user, Colors.MAGENTA)} | "
            f"Attempt #{colorize(str(count), Colors.YELLOW)}"
        )

    def _print_ssh_success(self, e):
        print(
            f"[{e.timestamp}] "
            f"{colorize('SUCCESS SSH ', Colors.GREEN, Colors.BOLD)} | "
            f"IP: {colorize(e.ip, Colors.CYAN)} | "
            f"User: {colorize(e.user, Colors.GREEN)}"
        )

    def _print_invalid(self, e):
        print(
            f"[{e.timestamp}] "
            f"{colorize('INVALID USER', Colors.DIM, Colors.YELLOW)} | "
            f"IP: {colorize(e.ip, Colors.CYAN)} | "
            f"User: {colorize(e.user, Colors.MAGENTA)}"
        )

    def _print_brute_force(self, ip, count):
        sep = colorize("=" * 60, Colors.RED, Colors.BOLD)
        print()
        print(sep)
        print(colorize("  *** BRUTE FORCE DETECTED ***", Colors.RED, Colors.BOLD))
        print(colorize(f"  IP Address : {ip}", Colors.RED))
        print(colorize(f"  Attempts   : {count} (threshold: {self.threshold})", Colors.RED))
        print(colorize(f"  Block with : iptables -A INPUT -s {ip} -j DROP", Colors.YELLOW))
        print(sep)
        print()

    def _print_su_success(self, e):
        print(
            f"[{e.timestamp}] "
            f"{colorize('SU SUCCESS  ', Colors.ORANGE, Colors.BOLD)} | "
            f"User: {colorize(e.ip, Colors.CYAN)} "
            f"→ became {colorize(e.user, Colors.ORANGE)}"
        )

    def _print_su_failed(self, e):
        print(
            f"[{e.timestamp}] "
            f"{colorize('SU FAILED   ', Colors.YELLOW, Colors.BOLD)} | "
            f"User: {colorize(e.ip, Colors.CYAN)} "
            f"tried to become {colorize(e.user, Colors.MAGENTA)}"
        )

    def _print_sudo_success(self, e):
        cmd = e.extra[:50] + "..." if len(e.extra) > 50 else e.extra
        print(
            f"[{e.timestamp}] "
            f"{colorize('SUDO        ', Colors.ORANGE, Colors.BOLD)} | "
            f"User: {colorize(e.ip, Colors.CYAN)} "
            f"→ as {colorize(e.user, Colors.ORANGE)} "
            f"| CMD: {colorize(cmd, Colors.DIM)}"
        )

    def _print_sudo_failed(self, e):
        print(
            f"[{e.timestamp}] "
            f"{colorize('SUDO FAILED ', Colors.YELLOW, Colors.BOLD)} | "
            f"User: {colorize(e.ip, Colors.CYAN)} failed sudo auth"
        )

    def _print_privesc_alert(self, e, via="su"):
        sep = colorize("=" * 60, Colors.ORANGE, Colors.BOLD)
        print()
        print(sep)
        print(colorize(
            f"  *** PRIVILEGE ESCALATION TO ROOT ({via.upper()}) ***",
            Colors.ORANGE, Colors.BOLD
        ))
        print(colorize(f"  From User  : {e.ip}", Colors.ORANGE))
        print(colorize(f"  Target     : root", Colors.ORANGE))
        if via == "sudo" and e.extra:
            cmd = e.extra[:50] + "..." if len(e.extra) > 50 else e.extra
            print(colorize(f"  Command    : {cmd}", Colors.YELLOW))
        print(colorize("  Action     : Verify this is an authorized admin!", Colors.YELLOW))
        print(sep)
        print()

    def print_summary(self, top_n: int = 10) -> list:
        """Print summary, return plain lines for file output."""
        sep = colorize("=" * 60, Colors.CYAN, Colors.BOLD)
        plain = []

        def both(colored_line: str):
            print(colored_line)
            plain.append(re.sub(r"\033\[[0-9;]*m", "", colored_line))

        print()
        print(sep)
        both(colorize("  SUMMARY REPORT", Colors.BOLD, Colors.CYAN))
        print(sep)
        both(f"  SSH Failed Logins     : {colorize(str(self.ssh_failed_total), Colors.YELLOW)}")
        both(f"  SSH Successful        : {colorize(str(self.ssh_success_total), Colors.GREEN)}")
        both(f"  Invalid User Probes   : {colorize(str(self.invalid_total), Colors.DIM)}")
        both(f"  SU Success            : {colorize(str(self.su_success_total), Colors.ORANGE)}")
        both(f"  SU/Sudo Failed        : {colorize(str(self.su_failed_total), Colors.YELLOW)}")
        both(f"  Sudo Commands Run     : {colorize(str(self.sudo_total), Colors.ORANGE)}")
        both(f"  Unique Attacking IPs  : {colorize(str(len(self.failed_counts)), Colors.RED)}")
        both(f"  Brute Force Alerts    : {colorize(str(len(self.alerted_ips)), Colors.RED, Colors.BOLD)}")

        if self.su_escalations:
            print()
            both(colorize("  PRIVILEGE ESCALATIONS DETECTED:", Colors.BOLD, Colors.ORANGE))
            seen = set()
            for from_user, target in self.su_escalations:
                key = f"{from_user}>{target}"
                if key not in seen:
                    seen.add(key)
                    both(f"    {colorize(from_user, Colors.CYAN)} → {colorize(target, Colors.ORANGE)}")

        if self.failed_counts:
            print()
            both(colorize(f"  TOP {top_n} ATTACKING IPs:", Colors.BOLD, Colors.RED))
            sorted_ips = sorted(self.failed_counts.items(), key=lambda x: x[1], reverse=True)
            for rank, (ip, count) in enumerate(sorted_ips[:top_n], 1):
                bar  = colorize("█" * min(count, 40), Colors.RED)
                flag = colorize(" *** BRUTE FORCE ***", Colors.RED, Colors.BOLD) if ip in self.alerted_ips else ""
                both(f"  #{rank:>2} {colorize(ip, Colors.CYAN):<20} {count:>5} attempts  {bar}{flag}")

        print(sep)
        print()
        return plain


# =============================================================================
# CLI
# =============================================================================
def parse_args():
    p = argparse.ArgumentParser(
        description="SSH Auth Log Analyzer v2",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  cat /var/log/auth.log | python3 analyzer.py
  ./log_feeder.sh -f /var/log/auth.log | python3 analyzer.py -t 3
  ./log_feeder.sh -lv | python3 analyzer.py -t 5 -o report.csv
  cat auth.log | python3 analyzer.py --no-color -o output.txt
        """
    )
    p.add_argument("-t", "--threshold", type=int, default=5,
                   help="Failed attempts before brute-force alert (default: 5)")
    p.add_argument("--no-color", action="store_true",
                   help="Disable colored output")
    p.add_argument("--top", type=int, default=10,
                   help="Top N attacking IPs in summary (default: 10)")
    p.add_argument("-o", "--output", type=str, default=None,
                   help="Save output to file: report.csv or report.txt")
    return p.parse_args()


# =============================================================================
# Main
# =============================================================================
def main():
    global USE_COLOR
    args      = parse_args()
    USE_COLOR = not args.no_color

    # validate -o extension
    if args.output and not (args.output.endswith(".csv") or args.output.endswith(".txt")):
        print(colorize("[!] -o only supports .csv or .txt", Colors.YELLOW))
        sys.exit(1)

    writer = OutputWriter(args.output) if args.output else None

    # banner
    print(colorize("=" * 60, Colors.CYAN, Colors.BOLD))
    print(colorize("  SSH Auth Log Analyzer v2", Colors.BOLD, Colors.CYAN))
    print(colorize(f"  Threshold  : {args.threshold} failed = brute force", Colors.DIM))
    print(colorize(f"  Detects    : SSH fail/success, invalid user, su, sudo", Colors.DIM))
    if args.output:
        print(colorize(f"  Saving to  : {args.output}", Colors.DIM))
    print(colorize("  Reading from stdin...", Colors.DIM))
    print(colorize("=" * 60, Colors.CYAN, Colors.BOLD))
    print()

    log_parser = LogParser()
    engine     = AlertEngine(threshold=args.threshold, writer=writer)

    try:
        for raw_line in sys.stdin:
            event = log_parser.parse(raw_line)
            if event:
                engine.process(event)
    except KeyboardInterrupt:
        print(colorize("\n[!] Interrupted. Generating summary...", Colors.YELLOW))

    summary_lines = engine.print_summary(top_n=args.top)

    if writer:
        writer.write(summary_lines)


if __name__ == "__main__":
    main()
