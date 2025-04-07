# SOARed

**SOARed** (Security Orchestration, Automation, and Red Team Detection) is a Python-based AI agent designed to detect red team PowerShell attacks in SOC logs and integrate with Shuffle for automated SOAR responses. It identifies suspicious commands, generates alerts, and triggers workflows to notify teams, isolate hosts, or log incidents.

**Current Version:** 1.0  
**Date:** April 07, 2025

---

## Features

- **Red Team Detection:** Identifies PowerShell commands like `DownloadString`, `Invoke-Command`, and AMSI bypasses in SOC logs.
- **Anomaly Detection:** Flags unusual command frequencies against a baseline.
- **Shuffle Integration:** Sends alerts to Shuffle workflows for orchestrated responses.
- **SOAR Payloads:** Outputs actionable JSON payloads for incident response automation.

---

## Prerequisites

- **Python 3.8+**: With `requests` (`pip install requests`).
- **Docker**: For running Shuffle locally or on a server.
- **Shuffle**: An instance of Shuffle SOAR platform (see [Shuffle GitHub](https://github.com/Shuffle/Shuffle)).
- **SOC Logs**: A log file or SIEM connection (sample logs included for testing).

---

## Installation

1. **Clone the Repository:**
```bash
git clone https://github.com/yourusername/SOARed.git
cd SOARed
