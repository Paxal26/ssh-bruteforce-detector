# SSH Brute-Force Detector

A command-line tool that parses SSH auth logs, detects brute-force attempts by correlating failed login events per IP, and generates a structured JSON threat report.

## What it does

- Parses raw SSH `auth.log` files
- Extracts source IPs using regex
- Counts failed login attempts per IP
- Flags IPs that exceed a configurable threshold
- Identifies targeted usernames
- Exports a JSON report with full findings

## Usage
```bash
python analyzer.py --file auth.log --threshold 3 --output report.json
```

## Arguments

| Argument | Default | Description |
|---|---|---|
| `--file` | auth.log | Path to the log file |
| `--threshold` | 3 | Failed attempts before an IP gets flagged |
| `--output` | report.json | Output path for the JSON report |

## Sample Output
```json
{
    "generated": "2026-04-01 12:31:00",
    "summary": {
        "total_lines": 15,
        "failed_attempts": 12,
        "unique_ips": 3,
        "flagged_ips": 2,
        "threshold": 3
    },
    "flagged": {
        "192.168.1.105": 5,
        "45.33.32.156": 5
    },
    "targeted_users": ["admin", "root", "test", "deploy"]
}
```

## Security Use Case

Brute-force attacks against SSH are one of the most common threats any organization faces. This tool replicates the core logic behind SIEM correlation rules — parsing raw logs into structured events, correlating them by source IP, and alerting when behavior crosses a suspicious threshold. The threshold is fully tunable to match an environment's baseline activity.

## Requirements

Python 3.x — no external libraries required