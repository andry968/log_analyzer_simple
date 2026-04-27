#!/usr/bin/env python3

import sys
import re
import csv
import json
import shutil
import argparse
from collections import defaultdict
from datetime import datetime, timezone, timedelta
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
    WHITE   = "\033[37m"

USE_COLOR = True

def colorize(text: str, *codes: str) -> str:
    if not USE_COLOR:
        return text
    return "".join(codes) + text + Colors.RESET


# =============================================================================
# Timestamp Parsing
# =============================================================================
def parse_timestamp_with_tz(raw_line: str):
    line_stripped = raw_line.strip()
    if not line_stripped:
        return None, raw_line

    iso_tz_pattern = re.compile(r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(\.\d+)?([+-]\d{2}:\d{2})\s+(.*)')
    m = iso_tz_pattern.match(line_stripped)
    if m:
        dt_part = m.group(1)
        tz_str  = m.group(3)
        rest    = m.group(4)
        dt = datetime.strptime(dt_part, "%Y-%m-%dT%H:%M:%S")
        sign = 1 if tz_str[0] == '+' else -1
        hh, mm = map(int, tz_str[1:].split(':'))
        tz = timezone(timedelta(hours=sign*hh, minutes=sign*mm))
        dt = dt.replace(tzinfo=tz)
        utc_offset = dt.strftime('%z')
        utc_hours = sign * hh
        if mm == 0:
            utc_str = f"UTC{utc_hours:+d}"
        else:
            utc_str = f"UTC{utc_hours:+d}:{mm:02d}"
        formatted = f"{dt.strftime('%Y-%m-%d %H:%M:%S')} {utc_str}"
        return formatted, rest

    trad_pattern = re.compile(r'^(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(.*)')
    m = trad_pattern.match(line_stripped)
    if m:
        ts_str, host, rest = m.group(1), m.group(2), m.group(3)
        dt = datetime.strptime(ts_str, "%b %d %H:%M:%S")
        formatted = f"{dt.strftime('%Y-%m-%d %H:%M:%S')} (local)"
        remaining = f"{host} {rest}"
        return formatted, remaining

    first_token = line_stripped.split(maxsplit=1)[0]
    try:
        if 'T' in first_token and len(first_token) >= 19:
            dt = datetime.fromisoformat(first_token[:19])
            remaining = line_stripped[len(first_token):].strip()
            return dt.strftime("%Y-%m-%d %H:%M:%S"), remaining
    except:
        pass
    return None, raw_line


# =============================================================================
# Data Classes
# =============================================================================
class LogEvent:
    def __init__(self, event_type, user, ip, extra="", timestamp=None):
        self.event_type = event_type
        self.user = user
        self.ip = ip
        self.extra = extra
        self.timestamp = timestamp or datetime.now().strftime("%Y-%m-%d %H:%M:%S")


class LogLine:
    def __init__(self, raw_line, ts_display, host_proc, message, event=None):
        self.raw_line = raw_line
        self.ts_display = ts_display
        self.host_proc = host_proc
        self.message = message
        self.event = event


# =============================================================================
# Regex Patterns
# =============================================================================
FAILED_PATTERN = re.compile(r"Failed password for (?:invalid user )?(\S+) from ([\d.]+) port \d+")
SUCCESS_PATTERN = re.compile(r"Accepted (?:password|publickey) for (\S+) from ([\d.]+) port \d+")
INVALID_USER_PATTERN = re.compile(r"Invalid user (\S+) from ([\d.]+)")
SU_SUCCESS_PATTERN = re.compile(r"su\[\d+\]: \(to (\S+)\) (\S+) on ")
SU_FAILED_PATTERN = re.compile(r"su\[\d+\]: FAILED su for (\S+) by (\S+)")
SUDO_SUCCESS_PATTERN = re.compile(r"sudo:\s+(\S+)\s+:.*USER=(\S+)\s*;.*COMMAND=(.+)")
SUDO_FAILED_PATTERN = re.compile(r"sudo:.*authentication failure.*user=(\S+)")
DISCONNECT_PATTERN = re.compile(r"Received disconnect from ([\d.]+)")
SESSION_OPEN_PATTERN = re.compile(r"pam_unix\(sshd:session\): session opened for user (\S+)")
SESSION_CLOSE_PATTERN = re.compile(r"pam_unix\(sshd:session\): session closed for user (\S+)")
USERADD_PATTERN = re.compile(r"useradd\[\d+\]: new user: name=(\S+)")


# =============================================================================
# Log Parser
# =============================================================================
class LogParser:
    @staticmethod
    def parse_line(raw_line: str) -> LogLine:
        ts_display, remaining = parse_timestamp_with_tz(raw_line)
        if not ts_display:
            return LogLine(raw_line, "", "", raw_line, None)

        host_proc = ""
        message = remaining
        hp_match = re.match(r'^(\S+)\s+(\S+\[\d+\]):\s+(.*)', remaining)
        if hp_match:
            host_proc = f"{hp_match.group(1)} {hp_match.group(2)}"
            message = hp_match.group(3)
        else:
            parts = remaining.split(' ', 1)
            if len(parts) >= 2:
                host_proc = parts[0]
                message = parts[1]

        full = raw_line
        event = None
        m = FAILED_PATTERN.search(full)
        if m: event = LogEvent("ssh_failed", m.group(1), m.group(2))
        elif (m := SUCCESS_PATTERN.search(full)): event = LogEvent("ssh_success", m.group(1), m.group(2))
        elif (m := INVALID_USER_PATTERN.search(full)): event = LogEvent("invalid_user", m.group(1), m.group(2))
        elif (m := SU_SUCCESS_PATTERN.search(full)): event = LogEvent("su_success", m.group(1), m.group(2))
        elif (m := SU_FAILED_PATTERN.search(full)): event = LogEvent("su_failed", m.group(1), m.group(2))
        elif (m := SUDO_SUCCESS_PATTERN.search(full)): event = LogEvent("sudo_success", m.group(2), m.group(1), extra=m.group(3).strip())
        elif (m := SUDO_FAILED_PATTERN.search(full)): event = LogEvent("sudo_failed", "root", m.group(1))
        elif (m := DISCONNECT_PATTERN.search(full)): event = LogEvent("disconnect", "", m.group(1))
        elif (m := SESSION_OPEN_PATTERN.search(full)): event = LogEvent("session_opened", m.group(1), "")
        elif (m := SESSION_CLOSE_PATTERN.search(full)): event = LogEvent("session_closed", m.group(1), "")
        elif (m := USERADD_PATTERN.search(full)): event = LogEvent("user_add", m.group(1), "")

        return LogLine(raw_line, ts_display, host_proc, message, event)


# =============================================================================
# Table Printer
# =============================================================================
class TablePrinter:
    def __init__(self, col_ts=30, col_host=30, col_msg=None):
        self.col_ts = col_ts
        self.col_host = col_host
        try:
            terminal_width = shutil.get_terminal_size().columns
        except:
            terminal_width = 120
        if col_msg is None:
            self.col_msg = max(40, terminal_width - self.col_ts - self.col_host - 6)
        else:
            self.col_msg = col_msg
        self.total_width = self.col_ts + self.col_host + self.col_msg + 6
        self._header_printed = False

    def print_header(self):
        if self._header_printed:
            return
        hdr = (f"{'TIMESTAMP'.ljust(self.col_ts)} | "
               f"{'HOST/PROCESS'.ljust(self.col_host)} | "
               f"{'MESSAGE'.ljust(self.col_msg)}")
        print(colorize(hdr, Colors.BOLD, Colors.WHITE))
        print(colorize("-" * self.total_width, Colors.WHITE))
        self._header_printed = True

    def print_row(self, log_line: LogLine):
        if not self._header_printed:
            self.print_header()

        ts_disp = f"[{log_line.ts_display}]" if log_line.ts_display else ""
        ts = ts_disp.ljust(self.col_ts)
        hp = log_line.host_proc.ljust(self.col_host)
        msg_full = log_line.message

        color_codes = (Colors.WHITE,)
        if log_line.event:
            color_codes = AlertEngine.LINE_COLORS.get(log_line.event.event_type, (Colors.WHITE,))

        lines = self._wrap_text(msg_full, self.col_msg)
        for i, line in enumerate(lines):
            if i == 0:
                row = f"{ts} | {hp} | {line}"
            else:
                empty_ts = " " * self.col_ts
                empty_hp = " " * self.col_host
                row = f"{empty_ts} | {empty_hp} | {line}"
            print(colorize(row, *color_codes))
        print()

    def _wrap_text(self, text, width):
        if not text:
            return [""]
        if len(text) <= width:
            return [text.ljust(width)]
        wrapped = []
        while len(text) > width:
            split_at = text.rfind(' ', 0, width)
            if split_at == -1:
                wrapped.append(text[:width])
                text = text[width:]
            else:
                wrapped.append(text[:split_at])
                text = text[split_at+1:]
        if text:
            wrapped.append(text)
        return [w.ljust(width) for w in wrapped]


# =============================================================================
# Output Writer
# =============================================================================
class OutputWriter:
    def __init__(self, filepath):
        self.filepath = filepath
        ext = Path(filepath).suffix.lower()
        self.is_csv = ext == ".csv"
        self.is_json = ext == ".json"
        self.records = []

    def record(self, event: LogEvent):
        if not event:
            return
        self.records.append({
            "timestamp": event.timestamp,
            "event_type": event.event_type,
            "user": event.user,
            "ip_or_from": event.ip,
            "extra": event.extra
        })

    def write(self, summary_dict: dict):
        path = Path(self.filepath)
        if self.is_json:
            output = {"events": self.records, "summary": summary_dict}
            with open(path, "w") as f:
                json.dump(output, f, indent=2, ensure_ascii=False)
        elif self.is_csv:
            with open(path, "w", newline="") as f:
                w = csv.DictWriter(f, fieldnames=["timestamp","event_type","user","ip_or_from","extra"], delimiter=";")
                w.writeheader()
                w.writerows(self.records)
            with open(path, "a") as f:
                f.write("\n# SUMMARY\n")
                for k, v in summary_dict.items():
                    f.write(f"# {k}: {v}\n")
        else:  # TXT
            with open(path, "w") as f:
                f.write("SSH AUTH LOG ANALYZER — EVENT LOG\n" + "="*60 + "\n\n")
                for r in self.records:
                    f.write(f"[{r['timestamp']}] {r['event_type']:<14} | "
                            f"IP/From: {r['ip_or_from']:<18} | "
                            f"User: {r['user']:<15}")
                    if r["extra"]:
                        f.write(f" | {r['extra']}")
                    f.write("\n")
                f.write("\n" + "="*60 + "\nSUMMARY\n" + "="*60 + "\n")
                for k, v in summary_dict.items():
                    f.write(f"{k}: {v}\n")
        print(colorize(f"\n[+] Output saved → {self.filepath}", Colors.GREEN, Colors.BOLD))


# =============================================================================
# Alert Engine
# =============================================================================
class AlertEngine:
    LINE_COLORS = {
        "ssh_failed":      (Colors.RED, Colors.BOLD),
        "ssh_success":     (Colors.GREEN, Colors.BOLD),
        "invalid_user":    (Colors.YELLOW, Colors.DIM),
        "su_success":      (Colors.ORANGE, Colors.BOLD),
        "su_failed":       (Colors.YELLOW, Colors.BOLD),
        "sudo_success":    (Colors.ORANGE, Colors.BOLD),
        "sudo_failed":     (Colors.YELLOW, Colors.BOLD),
        "disconnect":      (Colors.RED,),
        "session_opened":  (Colors.CYAN,),
        "session_closed":  (Colors.CYAN, Colors.DIM),
        "user_add":        (Colors.MAGENTA, Colors.BOLD),
    }

    def __init__(self, threshold, writer=None, table=None):
        self.threshold = threshold
        self.writer = writer
        self.table = table
        self.failed_counts = defaultdict(int)
        self.alerted_ips = set()
        self.su_escalations = []
        self.ssh_failed_total = 0
        self.ssh_success_total = 0
        self.invalid_total = 0
        self.su_success_total = 0
        self.su_failed_total = 0
        self.sudo_total = 0
        self.disconnect_total = 0
        self.session_open_total = 0
        self.session_close_total = 0
        self.user_add_total = 0

    def process(self, log_line):
        self.table.print_row(log_line)
        if log_line.event:
            if self.writer:
                self.writer.record(log_line.event)
            self._update_stats(log_line.event)

    def _update_stats(self, event):
        t = event.event_type
        if t == "ssh_failed":
            self.failed_counts[event.ip] += 1
            self.ssh_failed_total += 1
            self._check_brute_force(event.ip)
        elif t == "ssh_success":
            self.ssh_success_total += 1
        elif t == "invalid_user":
            self.invalid_total += 1
        elif t == "su_success":
            self.su_success_total += 1
            self.su_escalations.append((event.ip, event.user))
            if event.user == "root":
                self._print_privesc_alert(event, via="su")
        elif t == "su_failed":
            self.su_failed_total += 1
        elif t == "sudo_success":
            self.sudo_total += 1
            self.su_escalations.append((event.ip, event.user))
            if event.user == "root":
                self._print_privesc_alert(event, via="sudo")
        elif t == "sudo_failed":
            self.su_failed_total += 1
        elif t == "disconnect":
            self.disconnect_total += 1
        elif t == "session_opened":
            self.session_open_total += 1
        elif t == "session_closed":
            self.session_close_total += 1
        elif t == "user_add":
            self.user_add_total += 1
            self._print_user_add_alert(event)

    def _check_brute_force(self, ip):
        count = self.failed_counts[ip]
        if count >= self.threshold and ip not in self.alerted_ips:
            self.alerted_ips.add(ip)
            self._print_brute_force(ip, count)
        elif count > self.threshold and ip in self.alerted_ips:
            if (count - self.threshold) % 5 == 0:
                print(colorize(f"  [!] BRUTE FORCE ONGOING | {ip} now at {count} attempts", Colors.BOLD, Colors.RED))

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

    def _print_privesc_alert(self, e, via="su"):
        sep = colorize("=" * 60, Colors.ORANGE, Colors.BOLD)
        print()
        print(sep)
        print(colorize(f"  *** PRIVILEGE ESCALATION TO ROOT ({via.upper()}) ***", Colors.ORANGE, Colors.BOLD))
        print(colorize(f"  From User  : {e.ip}", Colors.ORANGE))
        print(colorize(f"  Target     : root", Colors.ORANGE))
        if via == "sudo" and e.extra:
            cmd = e.extra[:50] + "..." if len(e.extra) > 50 else e.extra
            print(colorize(f"  Command    : {cmd}", Colors.YELLOW))
        print(colorize("  Action     : Verify this is an authorized admin!", Colors.YELLOW))
        print(sep)
        print()

    def _print_user_add_alert(self, e):
        sep = colorize("=" * 60, Colors.MAGENTA, Colors.BOLD)
        print()
        print(sep)
        print(colorize("  *** NEW USER ACCOUNT CREATED ***", Colors.MAGENTA, Colors.BOLD))
        print(colorize(f"  Username   : {e.user}", Colors.MAGENTA))
        print(colorize("  Action     : Verify if this is an authorized operation!", Colors.YELLOW))
        print(sep)
        print()

    def get_summary_dict(self, top_n=10):
        d = {
            "ssh_failed_total": self.ssh_failed_total,
            "ssh_success_total": self.ssh_success_total,
            "invalid_user_probes": self.invalid_total,
            "disconnects": self.disconnect_total,
            "sessions_opened": self.session_open_total,
            "sessions_closed": self.session_close_total,
            "su_success_total": self.su_success_total,
            "su_failed_total": self.su_failed_total,
            "sudo_commands": self.sudo_total,
            "user_add_events": self.user_add_total,
            "unique_attacking_ips": len(self.failed_counts),
            "brute_force_alerts": len(self.alerted_ips),
        }
        if self.failed_counts:
            sorted_ips = sorted(self.failed_counts.items(), key=lambda x: x[1], reverse=True)[:top_n]
            d["top_attacking_ips"] = [{"ip": ip, "count": c} for ip, c in sorted_ips]
        if self.su_escalations:
            seen = set()
            uniq = []
            for u, tgt in self.su_escalations:
                key = f"{u}>{tgt}"
                if key not in seen:
                    seen.add(key)
                    uniq.append({"from": u, "to": tgt})
            d["privilege_escalations"] = uniq
        return d

    def print_summary(self, top_n=10):
        sep = colorize("=" * 60, Colors.CYAN, Colors.BOLD)
        print()
        print(sep)
        print(colorize("  SUMMARY REPORT", Colors.BOLD, Colors.CYAN))
        print(sep)
        print(f"  SSH Failed Logins     : {colorize(str(self.ssh_failed_total), Colors.YELLOW)}")
        print(f"  SSH Successful        : {colorize(str(self.ssh_success_total), Colors.GREEN)}")
        print(f"  Invalid User Probes   : {colorize(str(self.invalid_total), Colors.DIM)}")
        print(f"  Disconnects           : {colorize(str(self.disconnect_total), Colors.RED)}")
        print(f"  Sessions Opened       : {colorize(str(self.session_open_total), Colors.CYAN)}")
        print(f"  Sessions Closed       : {colorize(str(self.session_close_total), Colors.CYAN)}")
        print(f"  SU Success            : {colorize(str(self.su_success_total), Colors.ORANGE)}")
        print(f"  SU/Sudo Failed        : {colorize(str(self.su_failed_total), Colors.YELLOW)}")
        print(f"  Sudo Commands Run     : {colorize(str(self.sudo_total), Colors.ORANGE)}")
        print(f"  User Add Events       : {colorize(str(self.user_add_total), Colors.MAGENTA)}")
        print(f"  Unique Attacking IPs  : {colorize(str(len(self.failed_counts)), Colors.RED)}")
        print(f"  Brute Force Alerts    : {colorize(str(len(self.alerted_ips)), Colors.RED, Colors.BOLD)}")
        if self.su_escalations:
            print()
            print(colorize("  PRIVILEGE ESCALATIONS DETECTED:", Colors.BOLD, Colors.ORANGE))
            seen = set()
            for u, tgt in self.su_escalations:
                key = f"{u}>{tgt}"
                if key not in seen:
                    seen.add(key)
                    print(f"    {colorize(u, Colors.CYAN)} → {colorize(tgt, Colors.ORANGE)}")
        if self.failed_counts:
            print()
            print(colorize(f"  TOP {top_n} ATTACKING IPs:", Colors.BOLD, Colors.RED))
            sorted_ips = sorted(self.failed_counts.items(), key=lambda x: x[1], reverse=True)
            for rank, (ip, cnt) in enumerate(sorted_ips[:top_n], 1):
                bar = colorize("█" * min(cnt, 40), Colors.RED)
                flag = colorize(" *** BRUTE FORCE ***", Colors.RED, Colors.BOLD) if ip in self.alerted_ips else ""
                print(f"  #{rank:>2} {colorize(ip, Colors.CYAN):<20} {cnt:>5} attempts  {bar}{flag}")
        print(sep)
        print()


# =============================================================================
# CLI
# =============================================================================
def parse_args():
    p = argparse.ArgumentParser(
        description="SSH Auth Log Analyzer - Tabel rapi dengan warna",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="Contoh:\n  cat /var/log/auth.log | python3 analyzer.py\n  cat auth.log | python3 analyzer.py -t 3 -o laporan.json"
    )
    p.add_argument("-t", "--threshold", type=int, default=5, help="Batas failed brute force (default: 5)")
    p.add_argument("--no-color", action="store_true", help="Matikan warna")
    p.add_argument("--top", type=int, default=10, help="Jumlah IP penyerang di ringkasan")
    p.add_argument("-o", "--output", type=str, default=None, help="Simpan ke .csv/.txt/.json")
    return p.parse_args()


# =============================================================================
# Main
# =============================================================================
def main():
    global USE_COLOR
    args = parse_args()
    USE_COLOR = not args.no_color

    if args.output:
        ext = Path(args.output).suffix.lower()
        if ext not in (".csv", ".txt", ".json"):
            print(colorize("[!] Output hanya mendukung .csv, .txt, .json", Colors.YELLOW))
            sys.exit(1)

    table = TablePrinter()
    writer = OutputWriter(args.output) if args.output else None
    engine = AlertEngine(threshold=args.threshold, writer=writer, table=table)

    # Banner
    print(colorize("=" * table.total_width, Colors.CYAN, Colors.BOLD))
    print(colorize("  DR. Auth Log Analyzer", Colors.BOLD, Colors.CYAN))
    print(colorize(f"  Threshold  : {args.threshold} failed → brute force", Colors.DIM))
    print(colorize("  Detects    : SSH fail/success, invalid user, su, sudo, session, disconnect, useradd", Colors.DIM))
    if args.output:
        print(colorize(f"  Saving to  : {args.output}", Colors.DIM))
    print(colorize("  Table mode : all lines, wrapped, separated", Colors.DIM))
    print(colorize("=" * table.total_width, Colors.CYAN, Colors.BOLD))
    print()

    table.print_header()

    try:
        for raw_line in sys.stdin:
            raw_line = raw_line.strip()
            if not raw_line:
                continue
            log_line = LogParser.parse_line(raw_line)
            engine.process(log_line)
    except KeyboardInterrupt:
        print(colorize("\n[!] Interrupted. Generating summary...", Colors.YELLOW))

    engine.print_summary(top_n=args.top)
    if writer:
        writer.write(engine.get_summary_dict(top_n=args.top))


if __name__ == "__main__":
    main()
