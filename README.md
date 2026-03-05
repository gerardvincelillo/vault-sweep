# VaultSweep

VaultSweep is a local Windows security baseline scanner focused on quick posture checks and actionable reporting.

## Current Capabilities

- System profile collection (OS, hostname, processor, platform)
- Firewall status check
- BitLocker status check
- Risk summary scoring (`0-100`)
- Structured findings with severity and recommendation
- Report outputs:
  - text report
  - JSON report

## Installation

```bash
git clone https://github.com/gerardvincelillo/vault-sweep.git
cd vault-sweep
python -m pip install -r requirements.txt
```

## Usage

```bash
python main.py
```

With JSON output:

```bash
python main.py --output-text reports/vaultsweep.txt --output-json reports/vaultsweep.json
```

## Notes

- Best run on Windows with Administrator privileges for reliable checks.
- If a check cannot be completed (permissions/environment), VaultSweep records a lower-confidence finding instead of crashing.

## Development

Run tests:

```bash
python -m pytest -q
```

## License

MIT
