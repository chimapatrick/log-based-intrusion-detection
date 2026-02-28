import re
import argparse
from collections import defaultdict
from datetime import datetime

# Example pattern for Linux auth logs (failed SSH login attempts)
FAILED_LOGIN_PATTERN = re.compile(r"Failed password.*from (\d+\.\d+\.\d+\.\d+)")

def parse_failed_logins(log_file):
    failed_attempts = defaultdict(int)

    with open(log_file, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            match = FAILED_LOGIN_PATTERN.search(line)
            if match:
                ip = match.group(1)
                failed_attempts[ip] += 1

    return failed_attempts

def generate_report(failed_attempts, threshold):
    suspicious = {ip: count for ip, count in failed_attempts.items() if count >= threshold}

    with open("alert_report.txt", "w") as f:
        f.write("INTRUSION DETECTION ALERT REPORT\n")
        f.write("=" * 40 + "\n")
        f.write(f"Generated: {datetime.now()}\n")
        f.write(f"Threshold: {threshold} failed attempts\n\n")

        if not suspicious:
            f.write("No suspicious activity detected.\n")
        else:
            f.write("Suspicious IPs detected (possible brute-force attempts):\n\n")
            for ip, count in sorted(suspicious.items(), key=lambda x: x[1], reverse=True):
                f.write(f"IP: {ip}  | Failed Attempts: {count}\n")

    return suspicious

def main():
    parser = argparse.ArgumentParser(description="Log-Based Intrusion Detection (Brute Force Detector)")
    parser.add_argument("--log", required=True, help="Path to authentication log file")
    parser.add_argument("--threshold", type=int, default=5, help="Failed login threshold")
    args = parser.parse_args()

    failed_attempts = parse_failed_logins(args.log)

    print("\n=== Log Analysis Summary ===")
    if not failed_attempts:
        print("No failed logins found.")
    else:
        for ip, count in sorted(failed_attempts.items(), key=lambda x: x[1], reverse=True):
            print(f"{ip} -> {count} failed attempts")

    suspicious = generate_report(failed_attempts, args.threshold)

    if suspicious:
        print("\n⚠ Suspicious activity detected! (possible brute-force attempts)")
        print("✅ Report saved as alert_report.txt\n")
    else:
        print("\n✅ No suspicious activity detected.")
        print("✅ Report saved as alert_report.txt\n")
