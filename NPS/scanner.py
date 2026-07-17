"""
Network Port Scanner
A multithreaded TCP/UDP port scanner with service fingerprinting and HTML report generation.
Usage: python scanner.py <target> [options]
"""

import socket
import threading
import argparse
import time
import struct
import sys
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from report import generate_html_report

# Common services mapped to ports
SERVICE_MAP = {
    20: "FTP Data", 21: "FTP Control", 22: "SSH", 23: "Telnet",
    25: "SMTP", 53: "DNS", 67: "DHCP Server", 68: "DHCP Client",
    69: "TFTP", 80: "HTTP", 110: "POP3", 119: "NNTP",
    123: "NTP", 135: "MS RPC", 137: "NetBIOS NS", 138: "NetBIOS DGM",
    139: "NetBIOS SSN", 143: "IMAP", 161: "SNMP", 162: "SNMP Trap",
    179: "BGP", 194: "IRC", 389: "LDAP", 443: "HTTPS",
    445: "SMB", 465: "SMTPS", 514: "Syslog", 515: "LPD",
    587: "SMTP (Submit)", 631: "IPP", 636: "LDAPS", 993: "IMAPS",
    995: "POP3S", 1080: "SOCKS Proxy", 1194: "OpenVPN",
    1433: "MS SQL", 1521: "Oracle DB", 1723: "PPTP", 2049: "NFS",
    2375: "Docker", 2376: "Docker TLS", 3000: "Dev Server",
    3306: "MySQL", 3389: "RDP", 4444: "Metasploit", 5000: "Flask Dev",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 6443: "Kubernetes",
    7001: "WebLogic", 8080: "HTTP Alt", 8443: "HTTPS Alt",
    8888: "Jupyter", 9000: "PHP-FPM", 9200: "Elasticsearch",
    9300: "Elasticsearch Transport", 27017: "MongoDB",
}

# Risk levels for certain ports
HIGH_RISK_PORTS = {23, 21, 135, 139, 445, 4444, 1433, 3389, 27017, 6379}
MEDIUM_RISK_PORTS = {22, 80, 443, 3306, 5432, 8080, 9200, 2375, 5900}


def get_service_name(port):
    """Return known service name or 'Unknown'."""
    if port in SERVICE_MAP:
        return SERVICE_MAP[port]
    try:
        return socket.getservbyport(port)
    except OSError:
        return "Unknown"


def grab_banner(host, port, timeout=2):
    """Try to grab a service banner from an open port."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            # Send common probe strings
            probes = [b"HEAD / HTTP/1.0\r\n\r\n", b"\r\n", b"HELP\r\n"]
            for probe in probes:
                try:
                    s.send(probe)
                    banner = s.recv(1024).decode("utf-8", errors="ignore").strip()
                    if banner:
                        # Clean up the banner
                        banner = " ".join(banner.split())[:120]
                        return banner
                except Exception:
                    continue
    except Exception:
        pass
    return ""


def get_risk_level(port):
    """Classify port risk level."""
    if port in HIGH_RISK_PORTS:
        return "high"
    elif port in MEDIUM_RISK_PORTS:
        return "medium"
    return "low"


def scan_tcp_port(host, port, timeout=1):
    """Scan a single TCP port. Returns result dict if open, else None."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((host, port))
            if result == 0:
                service = get_service_name(port)
                banner = grab_banner(host, port)
                risk = get_risk_level(port)
                return {
                    "port": port,
                    "protocol": "TCP",
                    "state": "open",
                    "service": service,
                    "banner": banner,
                    "risk": risk,
                }
    except (socket.error, OSError):
        pass
    return None


def scan_udp_port(host, port, timeout=2):
    """Scan a single UDP port (less reliable than TCP)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(b"\x00" * 4, (host, port))
            try:
                data, _ = s.recvfrom(1024)
                return {
                    "port": port,
                    "protocol": "UDP",
                    "state": "open",
                    "service": get_service_name(port),
                    "banner": data.decode("utf-8", errors="ignore")[:80] if data else "",
                    "risk": get_risk_level(port),
                }
            except socket.timeout:
                # Timeout = possibly open (no ICMP unreachable received)
                return {
                    "port": port,
                    "protocol": "UDP",
                    "state": "open|filtered",
                    "service": get_service_name(port),
                    "banner": "",
                    "risk": get_risk_level(port),
                }
    except (socket.error, OSError):
        pass
    return None


def resolve_target(target):
    """Resolve hostname to IP address."""
    try:
        ip = socket.gethostbyname(target)
        return ip
    except socket.gaierror:
        print(f"[ERROR] Cannot resolve host: {target}")
        sys.exit(1)


def get_os_ttl_hint(host):
    """Try to guess OS based on TTL (rough heuristic)."""
    try:
        # We can't do raw ICMP easily without root, so try TCP TTL from banner
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2)
            s.connect((host, 80))
            ttl = s.getsockopt(socket.IPPROTO_IP, socket.IP_TTL)
            if ttl <= 64:
                return "Linux/Unix (TTL ~64)"
            elif ttl <= 128:
                return "Windows (TTL ~128)"
            else:
                return "Cisco/Network device (TTL ~255)"
    except Exception:
        return "Unknown"


def parse_port_range(port_str):
    """Parse port range string like '1-1024' or '80,443,8080'."""
    ports = []
    for part in port_str.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-", 1)
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))
    return sorted(set(ports))


def print_progress(scanned, total, open_count, start_time):
    """Print a live progress line."""
    elapsed = time.time() - start_time
    rate = scanned / elapsed if elapsed > 0 else 0
    pct = (scanned / total) * 100
    eta = (total - scanned) / rate if rate > 0 else 0
    sys.stdout.write(
        f"\r  Scanning... {pct:.0f}% ({scanned}/{total} ports) | "
        f"Open: {open_count} | {rate:.0f} ports/sec | ETA: {eta:.0f}s   "
    )
    sys.stdout.flush()


def run_scan(host, ports, protocol="tcp", threads=200, timeout=1, verbose=False):
    """Run the full multithreaded scan."""
    ip = resolve_target(host)
    print(f"\n  Target   : {host} ({ip})")
    print(f"  Protocol : {protocol.upper()}")
    print(f"  Ports    : {len(ports)} ports")
    print(f"  Threads  : {threads}")
    print(f"  Started  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("  " + "-" * 50)

    open_ports = []
    scanned = 0
    start_time = time.time()
    lock = threading.Lock()

    def scan_port(port):
        nonlocal scanned
        if protocol == "tcp":
            result = scan_tcp_port(ip, port, timeout)
        else:
            result = scan_udp_port(ip, port, timeout)
        with lock:
            scanned += 1
            if result:
                open_ports.append(result)
                if verbose:
                    risk_label = {"high": "[HIGH]", "medium": "[MED]", "low": "[LOW]"}.get(result["risk"], "")
                    print(f"\n  {risk_label} Port {port}/{protocol.upper()} open — {result['service']}")
            if scanned % 50 == 0 or scanned == len(ports):
                print_progress(scanned, len(ports), len(open_ports), start_time)

    with ThreadPoolExecutor(max_workers=threads) as executor:
        executor.map(scan_port, ports)

    elapsed = time.time() - start_time
    print(f"\n\n  Scan complete in {elapsed:.2f}s")
    print(f"  Open ports found: {len(open_ports)}")

    return ip, open_ports, elapsed


def main():
    parser = argparse.ArgumentParser(
        description="Network Port Scanner — multithreaded with HTML report",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scanner.py 192.168.1.1
  python scanner.py scanme.nmap.org -p 1-1000
  python scanner.py 10.0.0.1 -p 80,443,8080,3306 --protocol tcp
  python scanner.py localhost -p 1-65535 --threads 500 --verbose
        """
    )
    parser.add_argument("target", help="Target hostname or IP address")
    parser.add_argument("-p", "--ports", default="1-1024",
                        help="Port range or list (default: 1-1024). E.g. '1-1000' or '80,443,22'")
    parser.add_argument("--protocol", choices=["tcp", "udp", "both"], default="tcp",
                        help="Protocol to scan (default: tcp)")
    parser.add_argument("--threads", type=int, default=200,
                        help="Number of concurrent threads (default: 200)")
    parser.add_argument("--timeout", type=float, default=1.0,
                        help="Connection timeout in seconds (default: 1.0)")
    parser.add_argument("--output", default="scan_report.html",
                        help="Output HTML report filename (default: scan_report.html)")
    parser.add_argument("--verbose", action="store_true",
                        help="Print each open port as it's found")
    parser.add_argument("--no-report", action="store_true",
                        help="Skip HTML report generation")

    args = parser.parse_args()

    print("\n" + "=" * 55)
    print("   Network Port Scanner")
    print("=" * 55)

    ports = parse_port_range(args.ports)
    all_results = []

    if args.protocol in ("tcp", "both"):
        ip, tcp_results, elapsed_tcp = run_scan(
            args.target, ports, "tcp", args.threads, args.timeout, args.verbose
        )
        all_results.extend(tcp_results)

    if args.protocol in ("udp", "both"):
        ip, udp_results, elapsed_udp = run_scan(
            args.target, ports, "udp", args.threads, args.timeout, args.verbose
        )
        all_results.extend(udp_results)

    if args.protocol == "tcp":
        ip = resolve_target(args.target)
        elapsed_tcp = 0  # already set above

    # Sort by port number
    all_results.sort(key=lambda x: x["port"])

    # Print summary table
    if all_results:
        print("\n  PORT       PROTO  STATE         SERVICE           RISK")
        print("  " + "-" * 62)
        for r in all_results:
            risk_color = {"high": "!!", "medium": " ~", "low": "  "}.get(r["risk"], "  ")
            state_str = r["state"].ljust(13)
            print(f"  {str(r['port']).ljust(10)} {r['protocol'].ljust(6)} {state_str} {r['service'].ljust(17)} {risk_color} {r['risk'].upper()}")
    else:
        print("\n  No open ports found in the scanned range.")

    # Generate HTML report
    if not args.no_report:
        os_hint = get_os_ttl_hint(ip if args.protocol == "tcp" else resolve_target(args.target))
        generate_html_report(
            target=args.target,
            ip=ip,
            ports_scanned=len(ports),
            results=all_results,
            os_hint=os_hint,
            output_file=args.output,
        )
        print(f"\n  HTML report saved: {args.output}")

    print("=" * 55 + "\n")


if __name__ == "__main__":
    main()
