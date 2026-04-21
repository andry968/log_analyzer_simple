# Auth Log Analyzer

![Python](https://img.shields.io/badge/Python-3.x-blue?style=flat-square&logo=python)
![Bash](https://img.shields.io/badge/Bash-5.x-green?style=flat-square&logo=gnubash)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Category](https://img.shields.io/badge/Category-Security-red?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Linux-lightgrey?style=flat-square&logo=linux)

A real‑time SSH authentication log analyzer that detects brute‑force attacks, privilege escalations (su/sudo), and invalid user probes.  
Comes with a lightweight Bash feeder (`log_feeder.sh`) and a feature‑rich Python analyzer (`analyzer.py`).

---

## Preview

<img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/7f9e0750-6e37-4da1-b06d-78d5980966bf" />


---

## Latest Update

- April - 07 - 2025 : Added new feature `-tz` and `-tr`, see the details [CHANGELOG.md](./CHANGELOG.md)

---

## Why?

Manually tailing `/var/log/auth.log` is tedious and error‑prone. This tool automates the detection.

The feeder/analyzer separation allows you to read static log files or live streams, Pipe the output to other tools, Save structured reports (CSV/TXT) for later analysis

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
- **No external dependencies** pure Python 3 + standard bash

---

## Installation

Make sure you have '/var/log/auth.log', clone and run:

```bash
sudo apt install -y rsyslog 
git clone https://github.com/andry968/log_analyzer_simple.git
cd log_analyzer_simple
chmod +x log_feeder.sh
```

---

## Requirements

- Linux (reads /var/log/auth.log or any compatible log)
- Python 3.x
- Bash

No extra Python packages needed.

---

## Usage

1. Show help
```bash
./log_feeder.sh -h
 python3 analyzer.py -h
```
   
2. Live monitoring (most common)

```bash
./log_feeder.sh -lv | python3 analyzer.py
```

3. Analyze a static log file

```bash
./log_feeder.sh -f /path/to/log | python3 analyzer.py
```

4. Change brute‑force threshold (default 5)

```bash
./log_feeder.sh -lv | python3 analyzer.py -t 3
```

5. Save output to CSV

```bash
./log_feeder.sh -lv | python3 analyzer.py -o report.csv
```

6. Save output to plain text

```bash
./log_feeder.sh -lv | python3 analyzer.py -o report.txt
```

7. Disable coloured output (useful for piping to files)

```bash
./log_feeder.sh -lv | python3 analyzer.py --no-color -o report.txt
```

8. Show top 15 attacking IPs in summary

```bash
./log_feeder.sh -f /path/to/log | python3 analyzer.py --top 15
```

9. Directly pipe from **cat or tail**

```bash
cat /var/log/auth.log | python3 analyzer.py
tail -F /var/log/auth.log | python3 analyzer.py -t 5
```

---

## Output Formats

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

---

## Use Cases

- **Blue Team / SOC**: real‑time detection of ongoing SSH brute force
- **DFIR**: retrospective analysis of /var/log/auth.log after an incident
- **System hardening**: identify accounts being probed or misused
- **Compliance**: generate login/sudo reports for auditing

---

## Notes

- The feeder script sends log lines to stdout; all informational messages go to stderr (so they don’t interfere with the pipe).
- The analyzer reads from stdin, so you can replace the feeder with any command that outputs auth.log‑style lines.
- For btmp (failed login attempts) or other log formats, adjust the file path accordingly, the regex patterns remain the same.

---

## License

GPL-3.0 License – see [LICENSE](LICENSE) for details.

---

Contributions and suggestions are welcome!
