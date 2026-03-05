import json

from report import Report
from scanner import VaultSweepScanner


def test_report_can_write_json(tmp_path) -> None:
    report = Report({"Firewall Status": "Enabled"})
    target = tmp_path / "report.json"
    report.save_json_report(str(target))
    payload = json.loads(target.read_text(encoding="utf-8"))
    assert payload["results"]["Firewall Status"] == "Enabled"


def test_scanner_risk_summary_populates_findings(monkeypatch) -> None:
    monkeypatch.setattr("checks.firewall.check_firewall_status", lambda: "Disabled")
    monkeypatch.setattr("checks.bitlocker.check_bitlocker_status", lambda: "Not Protected")

    scanner = VaultSweepScanner()
    results = scanner.run_all_checks()
    assert results["Risk Summary"]["score"] < 100
    assert results["Risk Summary"]["finding_count"] >= 2
