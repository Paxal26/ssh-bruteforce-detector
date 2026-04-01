import re
import json
import argparse
from collections import Counter
from datetime import datetime

def read_log(filepath):
    with open(filepath, "r") as f:
        return f.readlines()

def get_failed_lines(lines):
    return [line.strip() for line in lines if "Failed password" in line]

def extract_ip(line):
    match = re.search(r"from (\d+\.\d+\.\d+\.\d+)", line)
    if match:
        return match.group(1)
    return None

def extract_user(line):
    match = re.search(r"for (?:invalid user )?(\w+) from", line)
    if match:
        return match.group(1)
    return "unknown"

def count_ips(failed_lines):
    ips = [extract_ip(line) for line in failed_lines if extract_ip(line)]
    return Counter(ips)

def flag_attackers(ip_counts, threshold):
    return {ip: count for ip, count in ip_counts.items() if count >= threshold}

def build_report(log_lines, failed_lines, ip_counts, flagged, threshold):
    targeted_users = list(set(extract_user(line) for line in failed_lines))
    return {
        "generated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "summary": {
            "total_lines": len(log_lines),
            "failed_attempts": len(failed_lines),
            "unique_ips": len(ip_counts),
            "flagged_ips": len(flagged),
            "threshold": threshold
        },
        "ip_counts": dict(ip_counts),
        "flagged": flagged,
        "targeted_users": targeted_users
    }

def save_report(report, output_path):
    with open(output_path, "w") as f:
        json.dump(report, f, indent=4)
    print(f"\nReport saved to {output_path}")


def main():
    parser = argparse.ArgumentParser(description="SSH brute-force detector")
    parser.add_argument("--file", default="auth.log")
    parser.add_argument("--threshold", type=int, default=3)
    parser.add_argument("--output", default="report.json")
    args = parser.parse_args()

    log_lines = read_log(args.file)
    failed_lines = get_failed_lines(log_lines)
    ip_counts = count_ips(failed_lines)
    flagged = flag_attackers(ip_counts, args.threshold)
    report = build_report(log_lines, failed_lines, ip_counts, flagged, args.threshold)

    print(f"Total lines: {len(log_lines)}")
    print(f"Failed attempts: {len(failed_lines)}\n")

    print("--- IP Attempt Counts ---")
    for ip, count in sorted(ip_counts.items(), key=lambda x: x[1], reverse=True):
        print(f"{ip}: {count} attempts")

    print(f"\n--- Flagged IPs ({args.threshold}+ attempts) ---")
    if flagged:
        for ip, count in flagged.items():
            print(f"[ALERT] {ip} — {count} failed attempts")
    else:
        print("No IPs flagged at this threshold.")

    save_report(report, args.output)


if __name__ == "__main__":
    main()
