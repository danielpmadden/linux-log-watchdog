# linux-log-watchdog

`linux-log-watchdog` is a lightweight Python project for parsing Linux logs and surfacing operational/security signals. It's designed to be practical for IT/infrastructure workflows and clean enough for portfolio use.

## What it does

- Scans one or many Linux log files
- Detects configurable patterns (SSH failures, service errors, disk warnings)
- Produces a summary report with:
  - per-pattern counts
  - parsed timestamps
  - matched lines and source file/line number
- Supports:
  - **scan mode** (one-time analysis)
  - **follow mode** (tail new lines for a fixed duration)

## Project structure

```text
linux-log-watchdog/
├── linux_log_watchdog/
│   ├── __init__.py
│   ├── __main__.py
│   ├── cli.py
│   └── watchdog.py
├── sample_logs/
│   ├── auth.log
│   └── syslog.log
├── sample_patterns.json
├── pyproject.toml
└── README.md
```

## Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

Or run directly without install:

```bash
python -m linux_log_watchdog --help
```

## Usage

### 1) One-time scan mode

```bash
python -m linux_log_watchdog \
  --log sample_logs/auth.log \
  --log sample_logs/syslog.log \
  --mode scan
```

### 2) Follow mode (tail new lines)

```bash
python -m linux_log_watchdog \
  --log sample_logs/auth.log \
  --mode follow \
  --duration 20
```

### 3) Use custom pattern config

```bash
python -m linux_log_watchdog \
  --log sample_logs/auth.log \
  --log sample_logs/syslog.log \
  --config sample_patterns.json
```

### 4) Inline pattern override

```bash
python -m linux_log_watchdog \
  --log sample_logs/syslog.log \
  --pattern kernel_issue::"EXT4-fs warning|I/O error"
```

### 5) JSON output for integrations

```bash
python -m linux_log_watchdog \
  --log sample_logs/auth.log \
  --mode scan \
  --json
```

## Example output (scan mode)

```text
Linux Log Watchdog Summary
===========================
Started: 2026-01-10T20:00:00.000000
Ended:   2026-01-10T20:00:00.010000
Files:   sample_logs/auth.log, sample_logs/syslog.log

Pattern Counts:
- failed_ssh_login: 3
- service_error: 5
- disk_warning: 2

Matched Lines:

[failed_ssh_login] (3 match(es))
  - sample_logs/auth.log:1 | 2026-06-12T08:45:10 | Jun 12 08:45:10 ... Failed password ...
```

## Why this is portfolio-friendly

- Reflects realistic operations use cases (auth abuse, service reliability, disk health)
- Keeps dependencies minimal (standard library only)
- Provides both human-readable and JSON-style outputs
- Uses maintainable structure with reusable pattern rules

## Notes

- Timestamps are parsed from syslog-style prefixes like `Jun 12 08:45:10`.
- In follow mode, only **newly appended lines** are analyzed.
- For production, you can schedule scan mode via cron or run follow mode under systemd.
