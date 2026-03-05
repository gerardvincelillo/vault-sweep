from datetime import datetime
import json
from pathlib import Path

class Report:
    def __init__(self, results):
        self.results = results
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def print_report(self):
        print("\n=== VaultSweep Vulnerability Scan Report ===")
        print(f"Scan Timestamp: {self.timestamp}")
        for key, value in self.results.items():
            print(f"{key}: {value}")
        print("============================================\n")

    def save_report(self, filename):
        with open(filename, "w", encoding="utf-8") as f:
            f.write("=== VaultSweep Vulnerability Scan Report ===\n")
            f.write(f"Scan Timestamp: {self.timestamp}\n\n")
            for key, value in self.results.items():
                f.write(f"{key}: {value}\n")
            f.write("============================================\n")
        print(f"Report saved to {filename}")

    def save_json_report(self, filename: str):
        payload = {"timestamp": self.timestamp, "results": self.results}
        path = Path(filename)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(f"JSON report saved to {path}")
