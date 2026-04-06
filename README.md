```markdown
# SSH Auth Log Analyzer

![Python](https://img.shields.io/badge/Python-3.x-blue?style=flat-square&logo=python)
![Bash](https://img.shields.io/badge/Bash-5.x-green?style=flat-square&logo=gnubash)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Category](https://img.shields.io/badge/Category-Security-red?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Linux-lightgrey?style=flat-square&logo=linux)

A real‑time SSH authentication log analyzer that detects brute‑force attacks, privilege escalations (su/sudo), and invalid user probes.  
Comes with a lightweight Bash feeder (`log_feeder.sh`) and a feature‑rich Python analyzer (`analyzer.py`).

---

## Preview

```

============================================================
SSH Auth Log Analyzer v2
Threshold  : 5 failed = brute force
Detects    : SSH fail/success, invalid user, su, sudo
Reading from stdin...
============================================================

[2026-04-06 10:15:23] FAILED SSH   | IP: 192.168.1.100 | User: admin | Attempt #1
[2026-04-06 10:15:25] FAILED SSH   | IP: 192.168.1.100 | User: root  | Attempt #2
...
============================================================
*** BRUTE FORCE DETECTED ***
IP Address : 192.168.1.100
Attempts   : 5 (threshold: 5)
Block with : iptables -A INPUT -s 192.168.1.100 -j DROP
============================================================

```

---

## Why?

Manually tailing `/var/log/auth.log` is tedious and error‑prone. This tool automates the detection of:

- Repeated failed logins (brute force)
- Successful logins from suspicious IPs
- Invalid username probing
- `su` / `sudo` usage (both success and failure)
- Privilege escalation to `root`

The feeder/analyzer separation allows you to:
- Read static log files or live streams
- Pipe the output to other tools
- Save structured reports (CSV/TXT) for later analysis

---

## Features

- **Real‑time monitoring** with `tail -F` (via `log_feeder.sh -lv`)
- **Static file analysis** (via `log_feeder.sh -f`)
- **Regex‑based parsing** of SSH, `su`, and `sudo` logs
- **Brute‑force detection** with configurable threshold
- **Privilege escalation alerts** (when a user becomes `root`)
- **Colour‑coded terminal output** (can be disabled)
- **Summary statistics** (top attacking IPs, total failed/success, etc.)
- **Export to CSV or TXT** (`-o` flag)
- **No external dependencies** – pure Python 3 + standard bash

---

## Installation

No installation required. Just clone and run:

```bash
git clone https://github.com/yourusername/ssh-auth-analyzer.git
cd ssh-auth-analyzer
chmod +x log_feeder.sh analyzer.py
```

---

Requirements

· Linux (reads /var/log/auth.log or any compatible log)
· Python 3.6+
· Bash 4+

No extra Python packages needed.

---

Usage

1. Live monitoring (most common)

```bash
./log_feeder.sh -lv | python3 analyzer.py
```

2. Analyze a static log file

```bash
./log_feeder.sh -f /var/log/auth.log | python3 analyzer.py
```

3. Change brute‑force threshold (default 5)

```bash
./log_feeder.sh -lv | python3 analyzer.py -t 3
```

4. Save output to CSV

```bash
./log_feeder.sh -lv | python3 analyzer.py -o report.csv
```

5. Save output to plain text

```bash
./log_feeder.sh -lv | python3 analyzer.py -o report.txt
```

6. Disable coloured output (useful for piping to files)

```bash
./log_feeder.sh -lv | python3 analyzer.py --no-color -o report.txt
```

7. Show top 15 attacking IPs in summary

```bash
./log_feeder.sh -f auth.log | python3 analyzer.py --top 15
```

8. Directly pipe from cat or tail

```bash
cat /var/log/auth.log | python3 analyzer.py
tail -F /var/log/auth.log | python3 analyzer.py -t 5
```

---

log_feeder.sh Options

Flag Description
-lv Live monitor /var/log/auth.log (uses tail -F)
-f <path> Read a static log file (e.g. -f /var/log/auth.log)
-h Show help

---

analyzer.py Options

Flag Description
-t, --threshold Failed attempts before brute‑force alert (default: 5)
--no-color Disable coloured output
--top Show top N attacking IPs in summary (default: 10)
-o, --output Save to file – must end with .csv or .txt

---

Detected Events

Event Type Description Example Output Colour
ssh_failed Failed password for a valid or invalid user Yellow
ssh_success Successful SSH login Green
invalid_user Connection attempt with a non‑existent user Dim Yellow
su_success Successful su to another user Orange
su_failed Failed su attempt Yellow
sudo_success Successful sudo command Orange
sudo_failed Failed sudo authentication Yellow

---

Output Formats

CSV (when using -o report.csv)

Columns are separated by semicolon (;) for direct opening in LibreOffice Calc / Excel:

```
timestamp;event_type;user;ip_or_from;extra
2026-04-06 10:15:23;ssh_failed;admin;192.168.1.100;
2026-04-06 10:15:25;ssh_failed;root;192.168.1.100;
2026-04-06 10:15:30;sudo_success;root;alice;COMMAND=/usr/bin/systemctl restart sshd
```

A summary section is appended at the end (commented with #).

TXT (when using -o report.txt)

Human‑readable report with a detailed event log followed by summary statistics.

Terminal (default)

Colour‑coded, real‑time output with inline brute‑force alerts and privilege escalation warnings.

---

Example Workflow

```bash
# Live monitor with threshold 3, save CSV report
./log_feeder.sh -lv | python3 analyzer.py -t 3 -o incident_$(date +%Y%m%d).csv
```

Press Ctrl+C to stop – the summary and file will still be generated.

---

Use Cases

· Blue Team / SOC – real‑time detection of ongoing SSH brute force
· DFIR – retrospective analysis of /var/log/auth.log after an incident
· System hardening – identify accounts being probed or misused
· Compliance – generate login/sudo reports for auditing

---

Notes

· The feeder script sends log lines to stdout; all informational messages go to stderr (so they don’t interfere with the pipe).
· The analyzer reads from stdin, so you can replace the feeder with any command that outputs auth.log‑style lines.
· For btmp (failed login attempts) or other log formats, adjust the file path accordingly – the regex patterns remain the same.

---

License

MIT License – see LICENSE for details.

---

Author

Your Name – GitHub

Contributions and suggestions are welcome!

```
