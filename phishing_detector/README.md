# Phishing Email Detector

Analyzes emails for phishing indicators across three layers:
- **Header analysis** — SPF, DKIM, DMARC, Reply-To mismatch, display name spoofing
- **URL analysis** — brand impersonation, suspicious TLDs, shorteners, raw IPs, VirusTotal
- **Language analysis** — urgency, threats, credential harvesting, reward bait, impersonation

---

## Setup

```bash
pip install flask requests
```

No other dependencies — NLP runs on pure Python regex patterns.

---

## Usage

### CLI
```bash
# Analyze an email file
python cli.py samples/phishing_sample.txt

# With VirusTotal URL scanning (free API key at virustotal.com)
python cli.py email.txt --vt-key YOUR_API_KEY

# JSON output
python cli.py email.txt --json

# Pipe from stdin
cat email.eml | python cli.py -
```

### Web UI
```bash
python app.py
# Open http://localhost:5000
```

---

## Project structure

```
phishing_detector/
├── cli.py              # Command-line interface
├── app.py              # Flask web UI
├── detector.py         # Core pipeline — combines all analyzers
├── header_analyzer.py  # SPF/DKIM/DMARC/spoofing checks
├── url_checker.py      # URL extraction, defanging, VirusTotal
├── nlp_analyzer.py     # Language pattern detection
└── samples/
    ├── phishing_sample.txt
    └── legit_sample.txt
```

---

## How scoring works

| Layer    | Weight | What it checks |
|----------|--------|----------------|
| Headers  | 35%    | SPF/DKIM/DMARC fail, Reply-To mismatch, display name spoofing |
| URLs     | 35%    | Brand impersonation, bad TLD, shorteners, IP URLs, VirusTotal |
| Language | 30%    | Urgency, threats, credential harvesting, reward bait |

**Final score = weighted average of all three**

| Score   | Verdict    |
|---------|------------|
| 70-100  | PHISHING   |
| 40-69   | SUSPICIOUS |
| 15-39   | LOW RISK   |
| 0-14    | CLEAN      |

---

## Getting a VirusTotal API key (free)

1. Go to https://virustotal.com
2. Create a free account
3. Go to your profile → API Key
4. Free tier: 500 requests/day
