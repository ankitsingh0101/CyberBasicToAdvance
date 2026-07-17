# Network Port Scanner

A multithreaded TCP/UDP port scanner built from scratch in Python.
Scans open ports, grabs service banners, classifies risk levels,
and generates a clean interactive HTML report.

---

## Features

- Multithreaded TCP scanning (200+ threads by default)
- UDP scanning support
- Service name detection (80+ known services)
- Banner grabbing to fingerprint what's actually running
- OS guess via TTL heuristics
- Risk classification: HIGH / MEDIUM / LOW per port
- Filterable HTML report with recommendations
- No external dependencies — pure Python stdlib

---

## Setup

```bash
# No pip install needed — uses Python stdlib only
python --version   # Python 3.8+ required
```

---

## Usage

```bash
# Scan top 1024 ports (default)
python scanner.py 192.168.1.1

# Scan specific ports
python scanner.py 192.168.1.1 -p 22,80,443,3306,3389

# Scan a range with more threads
python scanner.py scanme.nmap.org -p 1-2000 --threads 300

# UDP scan
python scanner.py 192.168.1.1 --protocol udp -p 53,67,69,123,161

# Both TCP and UDP
python scanner.py 192.168.1.1 --protocol both -p 1-500

# Verbose mode — print each open port live
python scanner.py localhost -p 1-1024 --verbose

# Custom output filename
python scanner.py 10.0.0.1 --output my_report.html

# Skip HTML report (terminal output only)
python scanner.py 192.168.1.1 --no-report
```

---

## Output

### Terminal
```
=======================================================
   Network Port Scanner
=======================================================

  Target   : scanme.nmap.org (45.33.32.156)
  Protocol : TCP
  Ports    : 1024 ports
  Threads  : 200
  Started  : 2025-06-01 10:32:15
  --------------------------------------------------
  Scanning... 100% (1024/1024 ports) | Open: 4 | 312 ports/sec | ETA: 0s

  Scan complete in 3.27s
  Open ports found: 4

  PORT       PROTO  STATE         SERVICE           RISK
  ----------------------------------------------------------
  22         TCP    open          SSH                ~ MEDIUM
  80         TCP    open          HTTP               ~ MEDIUM
  443        TCP    open          HTTPS              ~ MEDIUM
  9929       TCP    open          Unknown              LOW

  HTML report saved: scan_report.html
```

### HTML Report
Open `scan_report.html` in any browser to see:
- Summary stats (ports scanned, open, risk breakdown)
- Filterable table by risk level
- Banners captured from each service
- Specific recommendations for risky ports

---

## Project Structure

```
port_scanner/
├── scanner.py     # Main scanner — CLI, threading, scan logic
├── report.py      # HTML report generator
└── README.md
```

---

## How It Works

### TCP Scanning
For each port, a TCP `connect()` is attempted. If the 3-way handshake
completes (return code 0), the port is open. This is a "connect scan"
(same as Nmap's -sT), which is reliable but leaves connection logs.

### Banner Grabbing
Once a port is confirmed open, we send a probe (HTTP HEAD or \r\n)
and read up to 1024 bytes. This reveals what software is listening
(e.g. "OpenSSH_8.9", "Apache/2.4.52", "MySQL 8.0.28").

### Multithreading
Uses Python's `ThreadPoolExecutor` — each port gets its own thread.
With 200 threads and 1s timeout, scanning 1024 ports takes ~5 seconds.

### Risk Classification
Ports are classified based on:
- Known attack vectors (23=Telnet, 4444=Metasploit, etc.)
- Exposure sensitivity (3389=RDP, 3306=MySQL)
- General exposure (80=HTTP, 443=HTTPS)

---

## Legal Notice

Only scan systems you own or have explicit written permission to test.
Unauthorized port scanning may be illegal in your jurisdiction.

---

## Next Level Upgrades (Week 2+)

- [ ] Add Nmap-style OS fingerprinting using TCP/IP stack quirks
- [ ] Export results as JSON/CSV in addition to HTML
- [ ] Add CVE lookup for detected service versions
- [ ] Build a GUI with Tkinter or a web UI with Flask
- [ ] Add email/Telegram notification when scan completes
- [ ] Implement SYN scan (requires raw sockets + root)
