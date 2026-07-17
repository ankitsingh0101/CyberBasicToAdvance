"""
cli.py
Command-line interface for the phishing email detector.
Usage: python cli.py email.txt
       python cli.py email.txt --vt-key YOUR_KEY
       cat email.txt | python cli.py -
"""

import argparse
import sys
import os
import json

# Add current directory to path
sys.path.insert(0, os.path.dirname(__file__))
from detector import analyze_email


# ── Colour output ─────────────────────────────────────────────────────────────

COLORS = {
    "red":    "\033[91m",
    "yellow": "\033[93m",
    "green":  "\033[92m",
    "blue":   "\033[94m",
    "white":  "\033[97m",
    "grey":   "\033[90m",
    "bold":   "\033[1m",
    "reset":  "\033[0m",
}

def c(text, color):
    return f"{COLORS.get(color,'')}{text}{COLORS['reset']}"

def severity_color(sev):
    return {"fail": "red", "warn": "yellow", "pass": "green", "info": "blue"}.get(sev, "white")

def verdict_color(verdict):
    return {"PHISHING": "red", "SUSPICIOUS": "yellow", "LOW RISK": "blue", "CLEAN": "green"}.get(verdict, "white")


# ── Display ───────────────────────────────────────────────────────────────────

def print_banner():
    print(c("\n╔══════════════════════════════════════════════╗", "blue"))
    print(c("║       Phishing Email Detector v1.0           ║", "blue"))
    print(c("╚══════════════════════════════════════════════╝", "blue"))

def print_section(title):
    print(f"\n{c('▶ ' + title, 'bold')}")
    print(c("─" * 50, "grey"))

def print_finding(severity, label, detail=""):
    icons = {"fail": "✗", "warn": "⚠", "pass": "✓", "info": "ℹ"}
    icon = icons.get(severity, "•")
    color = severity_color(severity)
    label_str = c(f"[{label}]", color)
    detail_str = c(f"  {detail}", "grey") if detail else ""
    print(f"  {c(icon, color)} {label_str}{detail_str}")

def display_results(result):
    score = result["score"]
    verdict = result["verdict"]
    meta = result["meta"]

    print_banner()

    # ── Verdict box ──────────────────────────────────────────────────────────
    vc = verdict_color(verdict)
    score_bar = "█" * (score // 5) + "░" * (20 - score // 5)
    print(f"\n  {c('VERDICT', 'bold')}: {c(verdict, vc)}   {c(f'Risk Score: {score}/100', vc)}")
    print(f"  [{c(score_bar, vc)}]")
    print(f"  {c(result['advice'], 'grey')}")
    if result["phishing_summary"] and result["phishing_summary"] != "No phishing language patterns detected.":
        print(f"  {c('Summary:', 'bold')} {result['phishing_summary']}")

    # ── Email metadata ───────────────────────────────────────────────────────
    print_section("Email metadata")
    for key, val in meta.items():
        if val and val != "N/A":
            print(f"  {c(key.title().replace('_',' ')+':', 'grey')} {val[:80]}")

    # ── Score breakdown ──────────────────────────────────────────────────────
    print_section("Score breakdown")
    bars = {
        "Headers": result["header_score"],
        "URLs":    result["url_score"],
        "Language": result["nlp_score"],
    }
    for label, s in bars.items():
        bar = "█" * (s // 5) + "░" * (20 - s // 5)
        col = "red" if s >= 70 else "yellow" if s >= 40 else "green"
        print(f"  {label.ljust(10)} [{c(bar, col)}] {s}/100")

    # ── Header findings ──────────────────────────────────────────────────────
    print_section(f"Header analysis  (score: {result['header_score']}/100)")
    for severity, label, detail in result["header_findings"]:
        print_finding(severity, label, detail)

    # ── URL findings ─────────────────────────────────────────────────────────
    if result["url_results"]:
        print_section(f"URL analysis  (score: {result['url_score']}/100)")
        for url_result in result["url_results"]:
            print(f"\n  {c('URL:', 'bold')} {c(url_result['defanged'], 'grey')}")
            print(f"  {c('Domain:', 'grey')} {url_result['domain']}  |  "
                  f"{c('Risk:', 'grey')} {url_result['score']}/100")
            for severity, message in url_result["findings"]:
                print(f"    {c('•', severity_color(severity))} {message}")
    else:
        print_section("URL analysis")
        print(f"  {c('ℹ', 'blue')} No URLs found in email body")

    # ── NLP findings ─────────────────────────────────────────────────────────
    print_section(f"Language analysis  (score: {result['nlp_score']}/100)")
    if result["nlp_findings"]:
        for severity, label, detail in result["nlp_findings"]:
            print_finding(severity, label, detail)
    else:
        print(f"  {c('✓', 'green')} No suspicious language patterns detected")

    print(c("\n" + "═" * 50 + "\n", "grey"))


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Phishing Email Detector — analyze email files for phishing indicators",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python cli.py email.txt
  python cli.py email.txt --vt-key YOUR_VIRUSTOTAL_API_KEY
  python cli.py email.txt --json
  cat suspicious_email.eml | python cli.py -
  python cli.py samples/phishing_sample.txt
        """
    )
    parser.add_argument("file", help="Path to email file (.txt or .eml), or '-' for stdin")
    parser.add_argument("--vt-key", default="", help="VirusTotal API key (free at virustotal.com)")
    parser.add_argument("--json", action="store_true", help="Output raw JSON results")

    args = parser.parse_args()

    # Read email
    try:
        if args.file == "-":
            raw_email = sys.stdin.read()
        else:
            with open(args.file, "r", encoding="utf-8", errors="ignore") as f:
                raw_email = f.read()
    except FileNotFoundError:
        print(f"Error: File '{args.file}' not found.")
        sys.exit(1)

    if not raw_email.strip():
        print("Error: Email file is empty.")
        sys.exit(1)

    # Analyze
    result = analyze_email(raw_email, vt_api_key=args.vt_key)

    if args.json:
        # Sanitize for JSON output
        output = {
            "score": result["score"],
            "verdict": result["verdict"],
            "advice": result["advice"],
            "header_score": result["header_score"],
            "url_score": result["url_score"],
            "nlp_score": result["nlp_score"],
            "meta": result["meta"],
            "url_count": len(result["url_results"]),
        }
        print(json.dumps(output, indent=2))
    else:
        display_results(result)


if __name__ == "__main__":
    main()
