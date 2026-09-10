# 🛡️ SOC Log Analyzer

A Python-based Security Operations Center (SOC) log analysis tool that detects repeated failed login attempts, identifies suspicious IP addresses, classifies risk levels, and generates security recommendations.

## 🎯 Project Overview

This project simulates a basic SOC analyst workflow.

The analyzer reads security log data and identifies suspicious authentication activity based on failed login attempts.

## 🚀 Features

- 🔍 Detects failed login attempts
- 🌐 Extracts IP addresses from log entries
- 🔢 Counts failed login attempts per IP
- 🚦 Classifies IPs as LOW, MEDIUM, or HIGH risk
- 💡 Provides security recommendations
- 📄 Generates an automatic security report
- 🧪 Includes automated pytest tests

## ⚙️ Risk Classification

| Failed Attempts | Risk Level |
|---:|---|
| 1–2 | LOW |
| 3–4 | MEDIUM |
| 5+ | HIGH |

## 🛠️ Technologies Used

- Python
- Regular Expressions (Regex)
- Collections / Counter
- Pytest
- Git & GitHub

## 📂 Project Structure

```text
SOC-Log-Analyzer/
│
├── log_analyzer.py
├── test_log_analyzer.py
├── sample.log
├── security_report.txt
└── README.md