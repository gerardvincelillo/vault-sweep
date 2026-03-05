from __future__ import annotations

import platform
from typing import Any

from checks import bitlocker, firewall
from report import Report

try:
    import wmi  # type: ignore
except Exception:  # pragma: no cover
    wmi = None


class VaultSweepScanner:
    def __init__(self):
        self.wmi_conn = wmi.WMI() if wmi else None
        self.results: dict[str, Any] = {}
        self.findings: list[dict[str, str]] = []

    def gather_system_info(self):
        self.results["OS"] = platform.platform()
        self.results["Hostname"] = platform.node()
        self.results["Processor"] = platform.processor()
        self.results["Platform"] = platform.system()
        self.results["WMI Available"] = bool(self.wmi_conn)

    def check_firewall(self):
        fw_status = firewall.check_firewall_status()
        self.results["Firewall Status"] = fw_status
        status = fw_status.lower()
        if "disabled" in status:
            self.findings.append(
                {
                    "id": "firewall-disabled",
                    "severity": "high",
                    "description": "Firewall appears disabled.",
                    "recommendation": "Enable Windows Firewall for all profiles.",
                }
            )
        elif "error" in status or "unknown" in status:
            self.findings.append(
                {
                    "id": "firewall-unknown",
                    "severity": "medium",
                    "description": "Could not reliably determine firewall state.",
                    "recommendation": "Run with Administrator privileges and verify firewall policy manually.",
                }
            )

    def check_bitlocker(self):
        bl_status = bitlocker.check_bitlocker_status()
        self.results["BitLocker Status"] = bl_status
        status = bl_status.lower()
        if "not protected" in status:
            self.findings.append(
                {
                    "id": "bitlocker-not-protected",
                    "severity": "medium",
                    "description": "Drive encryption appears disabled.",
                    "recommendation": "Enable BitLocker on system and data volumes.",
                }
            )
        elif "error" in status or "failed" in status:
            self.findings.append(
                {
                    "id": "bitlocker-check-failed",
                    "severity": "low",
                    "description": "BitLocker check could not complete.",
                    "recommendation": "Re-run as Administrator and validate encryption policy.",
                }
            )

    def _risk_summary(self) -> dict[str, Any]:
        severity_weight = {"low": 10, "medium": 25, "high": 45, "critical": 70}
        total = sum(severity_weight.get(f["severity"], 0) for f in self.findings)
        score = max(0, 100 - total)
        return {
            "score": score,
            "finding_count": len(self.findings),
            "status": "at_risk" if score < 70 else "acceptable",
        }

    def run_all_checks(self):
        print("[*] Gathering system information...")
        self.gather_system_info()
        print("[*] Checking firewall status...")
        self.check_firewall()
        print("[*] Checking BitLocker status...")
        self.check_bitlocker()
        self.results["Risk Summary"] = self._risk_summary()
        self.results["Findings"] = self.findings
        return self.results

    def generate_report(self, text_path: str = "vaultsweep_report.txt", json_path: str | None = None):
        report = Report(self.results)
        report.print_report()
        report.save_report(text_path)
        if json_path:
            report.save_json_report(json_path)
