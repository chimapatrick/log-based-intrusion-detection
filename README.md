# 📊 Log-Based Intrusion Detection (Brute Force Detection)

## Overview
This project is a lightweight log analysis tool that detects suspicious authentication behaviour such as repeated failed login attempts, which may indicate brute-force attacks.

It demonstrates core SOC and security analyst skills: log parsing, threat detection logic, alerting, and reporting.

## Key Features
- Parses authentication logs (Linux-style / auth.log format)
- Detects repeated failed login attempts per IP address
- Flags potential brute-force activity using a configurable threshold
- Generates a simple alert report (TXT)

## Technologies Used
- Python
- Regex (pattern matching)
- Log analysis / security monitoring concepts

## How to Run
1. Place your log file in the project folder (or use the sample provided)
2. Run:
```bash
python log_detector.py --log sample_auth.log --threshold 5

Output

Console summary

File report: alert_report.txt

Ethical Use

Use for defensive security monitoring and lab practice. Do not misuse.

Author

Chima Patrick
MSc Cyber Security – Robert Gordon University
