import argparse

from scanner import VaultSweepScanner

def print_banner():
    print(
        r"""
__     __          _ _   ____                         
\ \   / /_ _ _   _| | |_/ ___|_      _____  ___ _ __  
 \ \ / / _` | | | | | __\___ \ \ /\ / / _ \/ _ \ '_ \ 
  \ V / (_| | |_| | | |_ ___) \ V  V /  __/  __/ |_) |
   \_/ \__,_|\__,_|_|\__|____/ \_/\_/ \___|\___| .__/ 
                                               |_|    
"""
    )

def main():
    parser = argparse.ArgumentParser(description="VaultSweep - Windows security baseline scanner")
    parser.add_argument("--output-text", default="vaultsweep_report.txt", help="Path for text report output.")
    parser.add_argument("--output-json", default=None, help="Optional path for JSON report output.")
    args = parser.parse_args()

    print_banner()
    scanner = VaultSweepScanner()
    scanner.run_all_checks()
    scanner.generate_report(text_path=args.output_text, json_path=args.output_json)

if __name__ == "__main__":
    main()
