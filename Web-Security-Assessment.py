"""
╔══════════════════════════════════════════════════════════════╗
║           IT Security Assessment Tool  v2.0                 ║
║  Network · Ports · Services · SSL · Vulnerabilities · OS    ║
╚══════════════════════════════════════════════════════════════╝

Usage:
  python it_security_assessment.py                     # scan localhost
  python it_security_assessment.py 192.168.1.1         # scan single host
  python it_security_assessment.py 192.168.1.0/24      # scan subnet
  python it_security_assessment.py -f targets.txt      # scan from file
  python it_security_assessment.py 10.0.0.1 --json     # JSON output
  python it_security_assessment.py 10.0.0.1 --csv      # CSV output

Options:
  --json            Save JSON report
  --csv             Save CSV report
  --ports <range>   Port range, e.g. "1-1024" or "22,80,443"
  --timeout <sec>   Socket timeout (default: 1.5)
  --threads <n>     Worker threads (default: 100)
  --no-ssl          Skip SSL/TLS checks
  --no-vuln         Skip vulnerability checks
  --quiet           Minimal output
"""

import sys
import os
import re
import ssl
import csv
import json
import socket
import struct
import platform
import hashlib
import ipaddress
import datetime
import argparse
import threading
import subprocess
import concurrent.futures
import urllib.request
import urllib.error
import urllib.parse
from dataclasses import dataclass, field, asdict
from typing import Optional


# ══════════════════════════════════════════════════════════════
#  ANSI colour helpers
# ══════════════════════════════════════════════════════════════

class C:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RED     = "\033[91m"
    YELLOW  = "\033[93m"
    GREEN   = "\033[92m"
    CYAN    = "\033[96m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    WHITE   = "\033[97m"
    BG_RED  = "\033[41m"
    BG_YELLOW = "\033[43m"

    @staticmethod
    def disable():
        for attr in ['RESET','BOLD','DIM','RED','YELLOW','GREEN',
                     'CYAN','BLUE','MAGENTA','WHITE','BG_RED','BG_YELLOW']:
            setattr(C, attr, "")

USE_COLOR = sys.stdout.isatty()
if not USE_COLOR:
    C.disable()

def severity_color(sev: str) -> str:
    return {"CRITICAL": C.RED + C.BOLD,
            "HIGH":     C.RED,
            "MEDIUM":   C.YELLOW,
            "LOW":      C.CYAN,
            "INFO":     C.BLUE,
            "PASS":     C.GREEN}.get(sev.upper(), "")

def status_icon(status: str) -> str:
    return {"pass":    f"{C.GREEN}[✔]{C.RESET}",
            "warn":    f"{C.YELLOW}[!]{C.RESET}",
            "fail":    f"{C.RED}[✘]{C.RESET}",
            "info":    f"{C.BLUE}[i]{C.RESET}",
            "open":    f"{C.GREEN}[○]{C.RESET}",
            "closed":  f"{C.DIM}[·]{C.RESET}",
            "filtered":f"{C.YELLOW}[?]{C.RESET}"}.get(status, "[?]")


# ══════════════════════════════════════════════════════════════
#  Data structures
# ══════════════════════════════════════════════════════════════

@dataclass
class PortResult:
    port:     int
    protocol: str = "tcp"
    state:    str = "closed"   # open | closed | filtered
    service:  str = ""
    version:  str = ""
    banner:   str = ""

@dataclass
class SSLResult:
    enabled:       bool = False
    protocol:      str  = ""
    cipher:        str  = ""
    bits:          int  = 0
    expiry:        str  = ""
    days_left:     int  = 0
    subject_cn:    str  = ""
    issuer:        str  = ""
    self_signed:   bool = False
    issues:        list = field(default_factory=list)

@dataclass
class Finding:
    title:    str
    severity: str   # CRITICAL | HIGH | MEDIUM | LOW | INFO | PASS
    category: str
    detail:   str
    host:     str = ""
    port:     int = 0
    cve:      str = ""
    remediation: str = ""

@dataclass
class HostReport:
    ip:            str
    hostname:      str       = ""
    os_guess:      str       = ""
    mac_address:   str       = ""
    is_alive:      bool      = False
    response_ms:   float     = 0.0
    open_ports:    list      = field(default_factory=list)   # list[PortResult]
    ssl_results:   dict      = field(default_factory=dict)   # port -> SSLResult
    findings:      list      = field(default_factory=list)   # list[Finding]
    scanned_at:    str       = ""
    score:         int       = 100
    grade:         str       = "A+"

@dataclass
class AssessmentReport:
    started_at:  str
    finished_at: str = ""
    scanner_host:str = ""
    scanner_os:  str = ""
    targets:     list = field(default_factory=list)   # list[HostReport]
    total_score: int  = 0
    summary:     dict = field(default_factory=dict)


# ══════════════════════════════════════════════════════════════
#  Well-known ports & service fingerprints
# ══════════════════════════════════════════════════════════════

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 119, 135, 137, 138, 139,
    143, 161, 389, 443, 445, 465, 587, 636, 993, 995, 1080, 1433,
    1521, 1723, 2049, 2082, 2083, 2086, 2087, 3306, 3389, 4444,
    5432, 5900, 6379, 6660, 6661, 6662, 6663, 8080, 8443, 8888,
    9200, 9300, 11211, 27017, 27018, 28017,
]

SERVICE_MAP = {
    21:    ("FTP",      "File Transfer Protocol — often unencrypted"),
    22:    ("SSH",      "Secure Shell"),
    23:    ("Telnet",   "Unencrypted remote terminal — deprecated"),
    25:    ("SMTP",     "Mail transfer"),
    53:    ("DNS",      "Domain Name System"),
    80:    ("HTTP",     "Unencrypted web"),
    110:   ("POP3",     "Mail retrieval — unencrypted"),
    111:   ("RPC",      "Sun RPC / portmapper"),
    119:   ("NNTP",     "Network News"),
    135:   ("MSRPC",    "Microsoft RPC — potential attack surface"),
    137:   ("NetBIOS",  "NetBIOS Name Service"),
    138:   ("NetBIOS",  "NetBIOS Datagram"),
    139:   ("SMB",      "Server Message Block / NetBIOS session"),
    143:   ("IMAP",     "Mail retrieval — unencrypted"),
    161:   ("SNMP",     "Simple Network Management Protocol"),
    389:   ("LDAP",     "Lightweight Directory Access Protocol"),
    443:   ("HTTPS",    "Encrypted web"),
    445:   ("SMB",      "Server Message Block / Direct TCP"),
    465:   ("SMTPS",    "Encrypted SMTP"),
    587:   ("SMTP",     "Mail submission with STARTTLS"),
    636:   ("LDAPS",    "Encrypted LDAP"),
    993:   ("IMAPS",    "Encrypted IMAP"),
    995:   ("POP3S",    "Encrypted POP3"),
    1080:  ("SOCKS",    "SOCKS proxy"),
    1433:  ("MSSQL",    "Microsoft SQL Server"),
    1521:  ("Oracle",   "Oracle DB"),
    1723:  ("PPTP",     "VPN — weak protocol"),
    2049:  ("NFS",      "Network File System"),
    3306:  ("MySQL",    "MySQL / MariaDB database"),
    3389:  ("RDP",      "Windows Remote Desktop"),
    4444:  ("Metasploit","Known exploit framework port"),
    5432:  ("PostgreSQL","PostgreSQL database"),
    5900:  ("VNC",      "Virtual Network Computing — remote desktop"),
    6379:  ("Redis",    "Redis cache/database — often unauthenticated"),
    8080:  ("HTTP-alt", "Alternate HTTP"),
    8443:  ("HTTPS-alt","Alternate HTTPS"),
    8888:  ("Jupyter",  "Jupyter Notebook / common dev server"),
    9200:  ("Elasticsearch","Elasticsearch REST API"),
    9300:  ("Elasticsearch","Elasticsearch cluster"),
    11211: ("Memcached","Memcached — often unauthenticated"),
    27017: ("MongoDB",  "MongoDB — often unauthenticated"),
}

# Dangerous ports that should never be exposed externally
DANGEROUS_PORTS = {23, 111, 135, 137, 138, 139, 445, 1433, 3306, 3389,
                   4444, 5432, 5900, 6379, 9200, 9300, 11211, 27017}

# Deprecated / insecure services
INSECURE_SERVICES = {21: "Use SFTP/SCP instead", 23: "Use SSH instead",
                     110: "Use POP3S (995)", 143: "Use IMAPS (993)",
                     80: "Redirect to HTTPS", 1723: "Use IKEv2/L2TP/OpenVPN"}


# ══════════════════════════════════════════════════════════════
#  Network utilities
# ══════════════════════════════════════════════════════════════

def resolve_hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""

def ping_host(ip: str, timeout: float = 1.0) -> tuple[bool, float]:
    """Returns (alive, response_ms). Uses TCP SYN to port 80/443 as fallback."""
    import time

    # Try ICMP ping via subprocess
    try:
        param = "-n" if platform.system().lower() == "windows" else "-c"
        t0 = time.monotonic()
        result = subprocess.run(
            ["ping", param, "1", "-W", "1", ip],
            capture_output=True, timeout=3
        )
        ms = (time.monotonic() - t0) * 1000
        if result.returncode == 0:
            return True, round(ms, 2)
    except Exception:
        pass

    # Fallback: TCP connect to port 80 or 443
    for port in [80, 443, 22]:
        try:
            t0 = time.monotonic()
            s = socket.create_connection((ip, port), timeout=timeout)
            ms = (time.monotonic() - t0) * 1000
            s.close()
            return True, round(ms, 2)
        except Exception:
            pass

    return False, 0.0

def get_mac(ip: str) -> str:
    """Try to get MAC from ARP table (local subnet only)."""
    try:
        out = subprocess.check_output(["arp", "-n", ip],
                                      stderr=subprocess.DEVNULL,
                                      timeout=3, text=True)
        match = re.search(r"([0-9a-f]{2}(?::[0-9a-f]{2}){5})", out, re.I)
        return match.group(1) if match else ""
    except Exception:
        return ""

def grab_banner(ip: str, port: int, timeout: float = 2.0) -> str:
    """Try to grab a service banner."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        # Send common probes
        if port == 80 or port == 8080:
            s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
        elif port == 21:
            pass  # FTP sends banner on connect
        elif port == 22:
            pass  # SSH sends banner on connect
        elif port == 25 or port == 587:
            pass  # SMTP sends banner
        banner = s.recv(1024).decode("utf-8", errors="replace").strip()
        s.close()
        return banner[:200].replace("\r\n", " ").replace("\n", " ")
    except Exception:
        return ""

def os_fingerprint(ip: str, open_ports: list) -> str:
    """Heuristic OS guess from open ports and TTL."""
    ports = set(p.port for p in open_ports)
    if 3389 in ports or 135 in ports or 445 in ports:
        return "Windows (likely)"
    if 22 in ports and 111 in ports:
        return "Linux/Unix (likely)"
    if 22 in ports and 80 in ports:
        return "Linux/Unix (likely)"
    if 548 in ports:
        return "macOS (likely)"
    if open_ports:
        return "Unknown"
    return "No open ports detected"


# ══════════════════════════════════════════════════════════════
#  Port scanner
# ══════════════════════════════════════════════════════════════

def scan_port(ip: str, port: int, timeout: float = 1.5) -> PortResult:
    result = PortResult(port=port)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        code = s.connect_ex((ip, port))
        s.close()
        if code == 0:
            result.state = "open"
            svc = SERVICE_MAP.get(port, ("unknown", ""))
            result.service = svc[0]
        else:
            result.state = "closed"
    except socket.timeout:
        result.state = "filtered"
    except Exception:
        result.state = "closed"
    return result

def scan_ports(ip: str, ports: list[int], timeout: float = 1.5,
               threads: int = 100, grab_banners: bool = True) -> list[PortResult]:
    """Concurrent port scanner."""
    open_results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(scan_port, ip, p, timeout): p for p in ports}
        for f in concurrent.futures.as_completed(futures):
            r = f.result()
            if r.state == "open":
                open_results.append(r)

    # Grab banners for open ports (limited concurrency)
    if grab_banners and open_results:
        def enrich(r: PortResult):
            r.banner = grab_banner(ip, r.port, timeout=2.0)
            return r
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
            open_results = list(ex.map(enrich, open_results))

    return sorted(open_results, key=lambda r: r.port)

def parse_ports(spec: str) -> list[int]:
    """Parse '22,80,443' or '1-1024' into a list of ints."""
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            a, b = part.split("-", 1)
            ports.update(range(int(a), int(b) + 1))
        else:
            ports.add(int(part))
    return sorted(ports)


# ══════════════════════════════════════════════════════════════
#  SSL / TLS checker
# ══════════════════════════════════════════════════════════════

def check_ssl_port(ip: str, port: int, hostname: str = "") -> Optional[SSLResult]:
    """Full SSL/TLS analysis on a given port."""
    result = SSLResult()
    sni = hostname or ip

    # Test if SSL is even available
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_OPTIONAL

    try:
        with socket.create_connection((ip, port), timeout=5) as raw:
            with ctx.wrap_socket(raw, server_hostname=sni) as ssock:
                cert    = ssock.getpeercert()
                proto   = ssock.version()
                cipher  = ssock.cipher()
                result.enabled  = True
                result.protocol = proto or ""
                result.cipher   = cipher[0] if cipher else ""
                result.bits     = cipher[2] if cipher else 0
    except ssl.SSLError:
        return None   # Not SSL or cert error — still report
    except (ConnectionRefusedError, socket.timeout, OSError):
        return None

    # Protocol weakness
    weak_protos = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
    if result.protocol in weak_protos:
        result.issues.append(f"Weak protocol: {result.protocol}")

    # Cipher weakness
    for kw in ["RC4", "DES", "NULL", "EXPORT", "anon", "MD5"]:
        if kw.upper() in result.cipher.upper():
            result.issues.append(f"Weak cipher: {result.cipher}")
            break

    if result.bits and result.bits < 128:
        result.issues.append(f"Weak key size: {result.bits} bits")

    # Certificate details
    if cert:
        # Subject CN
        subject = dict(x[0] for x in cert.get("subject", []))
        issuer  = dict(x[0] for x in cert.get("issuer",  []))
        result.subject_cn = subject.get("commonName", "")
        result.issuer     = issuer.get("organizationName",
                            issuer.get("commonName", ""))

        # Self-signed
        if subject == issuer:
            result.self_signed = True
            result.issues.append("Self-signed certificate — not trusted by browsers")

        # Expiry
        not_after_str = cert.get("notAfter", "")
        if not_after_str:
            try:
                not_after = datetime.datetime.strptime(
                    not_after_str, "%b %d %H:%M:%S %Y %Z")
                result.expiry   = not_after.strftime("%Y-%m-%d")
                result.days_left = (not_after - datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)).days
                if result.days_left < 0:
                    result.issues.append("CERTIFICATE EXPIRED")
                elif result.days_left < 14:
                    result.issues.append(f"Critical: expires in {result.days_left} days")
                elif result.days_left < 30:
                    result.issues.append(f"Warning: expires in {result.days_left} days")
            except ValueError:
                pass

    return result


# ══════════════════════════════════════════════════════════════
#  Vulnerability / misconfiguration checks
# ══════════════════════════════════════════════════════════════

def analyze_findings(host: HostReport, skip_ssl: bool = False) -> list[Finding]:
    findings = []
    ip = host.ip
    open_port_nums = {p.port for p in host.open_ports}

    # ── Port-based findings ─────────────────────────────────
    for pr in host.open_ports:
        p = pr.port

        # Dangerous ports exposed
        if p in DANGEROUS_PORTS:
            svc_name = SERVICE_MAP.get(p, ("port " + str(p), ""))[0]
            findings.append(Finding(
                title=f"Potentially dangerous port open: {p}/{svc_name}",
                severity="HIGH",
                category="Network Exposure",
                detail=f"Port {p} ({svc_name}) should not be publicly accessible. "
                       f"Restrict with firewall rules or disable if unused.",
                host=ip, port=p,
                remediation=f"Block port {p} at firewall level unless explicitly required."
            ))

        # Insecure protocols
        if p in INSECURE_SERVICES:
            svc_name = SERVICE_MAP.get(p, ("port " + str(p), ""))[0]
            findings.append(Finding(
                title=f"Insecure service: {svc_name} on port {p}",
                severity="MEDIUM",
                category="Insecure Protocol",
                detail=f"{svc_name} transmits data in plaintext. "
                       f"Credentials and data can be intercepted.",
                host=ip, port=p,
                remediation=INSECURE_SERVICES[p]
            ))

        # Telnet — always critical
        if p == 23:
            findings.append(Finding(
                title="Telnet enabled — critical unencrypted access",
                severity="CRITICAL",
                category="Insecure Protocol",
                detail="Telnet transmits all data including passwords in cleartext. "
                       "Any observer on the network can capture credentials.",
                host=ip, port=23,
                cve="CVE-1999-0619",
                remediation="Disable Telnet immediately. Replace with SSH."
            ))

        # Default database ports
        for db_port, db_name in [(3306,"MySQL"),(5432,"PostgreSQL"),
                                  (27017,"MongoDB"),(6379,"Redis"),
                                  (9200,"Elasticsearch"),(11211,"Memcached")]:
            if p == db_port:
                findings.append(Finding(
                    title=f"{db_name} port exposed on network",
                    severity="CRITICAL",
                    category="Database Exposure",
                    detail=f"{db_name} ({db_port}) is accessible. If unauthenticated "
                           f"or weakly authenticated, this allows data theft.",
                    host=ip, port=db_port,
                    remediation=f"Bind {db_name} to 127.0.0.1. "
                                f"Enable authentication. Use firewall to restrict access."
                ))

        # VNC
        if p == 5900:
            findings.append(Finding(
                title="VNC remote desktop exposed",
                severity="HIGH",
                category="Remote Access",
                detail="VNC provides graphical desktop access. If weakly "
                       "authenticated or unauthenticated, full system access is possible.",
                host=ip, port=5900,
                remediation="Use VPN tunnel for VNC. Enable strong authentication. "
                            "Firewall to specific IPs only."
            ))

        # RDP
        if p == 3389:
            findings.append(Finding(
                title="RDP (Remote Desktop) exposed to network",
                severity="HIGH",
                category="Remote Access",
                detail="Windows RDP is a common brute-force and exploitation target "
                       "(e.g. BlueKeep CVE-2019-0708).",
                host=ip, port=3389,
                cve="CVE-2019-0708",
                remediation="Place RDP behind VPN. Enable NLA. Apply all patches. "
                            "Use firewall to allowlist source IPs."
            ))

        # SNMP
        if p == 161:
            findings.append(Finding(
                title="SNMP port open — potential information disclosure",
                severity="MEDIUM",
                category="Network Management",
                detail="SNMPv1/v2 use community strings ('public'/'private') "
                       "which are trivially guessable and expose detailed system info.",
                host=ip, port=161,
                remediation="Use SNMPv3 with auth+encryption. Change community strings. "
                            "Firewall SNMP to management systems only."
            ))

    # ── SSL findings ─────────────────────────────────────────
    if not skip_ssl:
        for port, ssl_res in host.ssl_results.items():
            for issue in ssl_res.issues:
                sev = "CRITICAL" if "EXPIRED" in issue.upper() or "WEAK" in issue.upper() \
                      else "HIGH" if "Critical" in issue \
                      else "MEDIUM"
                findings.append(Finding(
                    title=f"SSL/TLS issue on port {port}: {issue}",
                    severity=sev,
                    category="SSL/TLS",
                    detail=issue,
                    host=ip, port=port,
                    remediation="Update TLS to 1.2 minimum (prefer 1.3). "
                                "Renew certificate. Use strong ciphers (AES-GCM, ChaCha20)."
                ))

    # ── No SSL on web port ───────────────────────────────────
    if 80 in open_port_nums and 443 not in open_port_nums:
        findings.append(Finding(
            title="HTTP served without HTTPS",
            severity="HIGH",
            category="SSL/TLS",
            detail="Port 80 is open but 443 is not. All web traffic is unencrypted.",
            host=ip, port=80,
            remediation="Deploy TLS certificate (Let's Encrypt is free). "
                        "Redirect all HTTP to HTTPS with 301 redirect."
        ))

    # ── No open ports ────────────────────────────────────────
    if not host.open_ports:
        findings.append(Finding(
            title="No open ports detected",
            severity="INFO",
            category="Network",
            detail="Either the host is firewalled or filtered, or not running services.",
            host=ip
        ))

    # ── Banner grabbing findings ─────────────────────────────
    for pr in host.open_ports:
        if pr.banner:
            # Version disclosure
            for pattern in [r"Apache/[\d.]+", r"nginx/[\d.]+", r"OpenSSH_[\w.]+",
                             r"IIS/[\d.]+", r"PHP/[\d.]+"]:
                if re.search(pattern, pr.banner, re.I):
                    findings.append(Finding(
                        title=f"Software version disclosure on port {pr.port}",
                        severity="LOW",
                        category="Information Disclosure",
                        detail=f"Banner reveals: {pr.banner[:80]}",
                        host=ip, port=pr.port,
                        remediation="Suppress version strings in server configuration."
                    ))
                    break

    # ── Positive findings (no issues) ───────────────────────
    if host.is_alive and not any(f.severity in ("CRITICAL","HIGH")
                                  for f in findings):
        findings.append(Finding(
            title="No critical or high-severity issues detected",
            severity="PASS",
            category="Summary",
            detail="Host passed all high-severity checks in this scan.",
            host=ip
        ))

    return findings


# ══════════════════════════════════════════════════════════════
#  Scoring
# ══════════════════════════════════════════════════════════════

SEV_WEIGHTS = {"CRITICAL": -30, "HIGH": -15, "MEDIUM": -8, "LOW": -3}

def compute_score(findings: list[Finding]) -> tuple[int, str]:
    score = 100
    for f in findings:
        score += SEV_WEIGHTS.get(f.severity, 0)
    score = max(0, min(100, score))
    grade = ("A+" if score >= 95 else "A"  if score >= 90 else
             "B"  if score >= 80 else "C"  if score >= 70 else
             "D"  if score >= 55 else "F")
    return score, grade


# ══════════════════════════════════════════════════════════════
#  System info
# ══════════════════════════════════════════════════════════════

def get_local_info() -> dict:
    return {
        "hostname": socket.gethostname(),
        "os":       f"{platform.system()} {platform.release()}",
        "python":   platform.python_version(),
        "user":     os.environ.get("USER", os.environ.get("USERNAME", "unknown")),
    }

def expand_targets(targets_raw: list[str]) -> list[str]:
    """Expand CIDR ranges, hostnames, and plain IPs into a flat list."""
    ips = []
    for t in targets_raw:
        try:
            net = ipaddress.ip_network(t, strict=False)
            if net.num_addresses == 1:
                ips.append(str(net.network_address))
            else:
                ips.extend(str(h) for h in net.hosts())
        except ValueError:
            # Might be a hostname
            try:
                ip = socket.gethostbyname(t)
                ips.append(ip)
            except Exception:
                ips.append(t)  # add raw and let scan fail gracefully
    return ips


# ══════════════════════════════════════════════════════════════
#  Pretty printer
# ══════════════════════════════════════════════════════════════

def print_banner():
    print(f"""
{C.CYAN}{C.BOLD}╔══════════════════════════════════════════════════════════════╗
║          IT Security Assessment Tool  v2.0                  ║
║  Network · Ports · Services · SSL · Vulnerabilities · OS    ║
╚══════════════════════════════════════════════════════════════╝{C.RESET}""")

def print_section(title: str, char: str = "─"):
    w = 62
    pad = max(0, w - len(title) - 4)
    print(f"\n{C.BOLD}{C.BLUE}── {title} {char * pad}{C.RESET}")

def print_host_header(h: HostReport):
    alive_str = f"{C.GREEN}ALIVE{C.RESET}" if h.is_alive else f"{C.RED}DOWN{C.RESET}"
    print(f"\n{C.BOLD}{'═'*64}{C.RESET}")
    print(f"  {C.BOLD}Host     :{C.RESET} {h.ip}"
          + (f"  ({h.hostname})" if h.hostname else ""))
    print(f"  {C.BOLD}Status   :{C.RESET} {alive_str}"
          + (f"  ({h.response_ms} ms)" if h.response_ms else ""))
    if h.os_guess:
        print(f"  {C.BOLD}OS Guess :{C.RESET} {h.os_guess}")
    if h.mac_address:
        print(f"  {C.BOLD}MAC      :{C.RESET} {h.mac_address}")
    print(f"{C.BOLD}{'═'*64}{C.RESET}")

def print_ports(ports: list[PortResult]):
    if not ports:
        print(f"  {C.DIM}No open ports found in scanned range.{C.RESET}")
        return
    print(f"  {'PORT':<8} {'SERVICE':<14} {'BANNER / INFO'}")
    print(f"  {'─'*7}  {'─'*13}  {'─'*38}")
    for pr in ports:
        svc = f"{C.GREEN}{pr.service:<14}{C.RESET}" if pr.service else f"{'?':<14}"
        banner = f"{C.DIM}{pr.banner[:45]}…{C.RESET}" if len(pr.banner) > 45 \
                 else f"{C.DIM}{pr.banner}{C.RESET}"
        print(f"  {C.GREEN}{pr.port:<8}{C.RESET} {svc} {banner}")

def print_ssl(port: int, ssl_res: SSLResult):
    ok = not ssl_res.issues
    color = C.GREEN if ok else C.YELLOW
    mark  = "✔" if ok else "⚠"
    print(f"  {color}[{mark}]{C.RESET} Port {port}: "
          f"{ssl_res.protocol or '?'} · {ssl_res.cipher or '?'} "
          f"({ssl_res.bits} bit) · expires {ssl_res.expiry or '?'} "
          f"· CN={ssl_res.subject_cn or '?'}")
    for issue in ssl_res.issues:
        print(f"       {C.YELLOW}⚠ {issue}{C.RESET}")

def print_findings(findings: list[Finding], verbose: bool = False):
    order = ["CRITICAL","HIGH","MEDIUM","LOW","INFO","PASS"]
    sorted_f = sorted(findings, key=lambda f: order.index(f.severity)
                      if f.severity in order else 99)
    for f in sorted_f:
        col   = severity_color(f.severity)
        label = f"{col}[{f.severity:^8}]{C.RESET}"
        print(f"  {label}  {C.BOLD}{f.title}{C.RESET}")
        if verbose or f.severity in ("CRITICAL","HIGH"):
            print(f"             {C.DIM}{f.detail}{C.RESET}")
            if f.remediation:
                print(f"             {C.CYAN}→ {f.remediation}{C.RESET}")
            if f.cve:
                print(f"             {C.MAGENTA}CVE: {f.cve}{C.RESET}")

def print_score(score: int, grade: str):
    color = (C.GREEN if grade.startswith("A") else
             C.YELLOW if grade in ("B","C") else C.RED)
    bar_len = 40
    filled  = round(score / 100 * bar_len)
    bar     = f"{color}{'█' * filled}{C.DIM}{'░' * (bar_len - filled)}{C.RESET}"
    print(f"\n  Score : {color}{C.BOLD}{score:>3}/100{C.RESET}  {bar}  "
          f"Grade: {color}{C.BOLD}{grade}{C.RESET}")

def print_summary(report: AssessmentReport):
    print_section("ASSESSMENT SUMMARY")
    total_hosts  = len(report.targets)
    alive_hosts  = sum(1 for h in report.targets if h.is_alive)
    total_open   = sum(len(h.open_ports) for h in report.targets)
    all_findings = [f for h in report.targets for f in h.findings]
    crits = sum(1 for f in all_findings if f.severity == "CRITICAL")
    highs = sum(1 for f in all_findings if f.severity == "HIGH")
    meds  = sum(1 for f in all_findings if f.severity == "MEDIUM")
    lows  = sum(1 for f in all_findings if f.severity == "LOW")

    print(f"\n  Hosts scanned    : {total_hosts}  ({alive_hosts} alive)")
    print(f"  Open ports found : {total_open}")
    print(f"  Findings         : "
          f"{C.RED}{crits} critical{C.RESET}  "
          f"{C.RED}{highs} high{C.RESET}  "
          f"{C.YELLOW}{meds} medium{C.RESET}  "
          f"{C.CYAN}{lows} low{C.RESET}")
    elapsed = ""
    if report.finished_at and report.started_at:
        try:
            t0 = datetime.datetime.fromisoformat(report.started_at)
            t1 = datetime.datetime.fromisoformat(report.finished_at)
            elapsed = f"  ({(t1-t0).seconds}s)"
        except Exception:
            pass
    print(f"\n  Started  : {report.started_at}")
    print(f"  Finished : {report.finished_at}{elapsed}")
    print(f"  Scanner  : {report.scanner_host} / {report.scanner_os}")


# ══════════════════════════════════════════════════════════════
#  Export helpers
# ══════════════════════════════════════════════════════════════

def save_json(report: AssessmentReport, path: str):
    def _serial(obj):
        if hasattr(obj, "__dataclass_fields__"):
            return asdict(obj)
        return str(obj)
    with open(path, "w") as fh:
        json.dump(asdict(report), fh, indent=2, default=str)
    print(f"\n{C.DIM}JSON report → {path}{C.RESET}")

def save_csv(report: AssessmentReport, path: str):
    rows = []
    for h in report.targets:
        for f in h.findings:
            rows.append({
                "host": h.ip,
                "hostname": h.hostname,
                "score": h.score,
                "grade": h.grade,
                "severity": f.severity,
                "category": f.category,
                "title": f.title,
                "detail": f.detail,
                "port": f.port or "",
                "cve": f.cve,
                "remediation": f.remediation,
            })
    with open(path, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()) if rows else [])
        w.writeheader()
        w.writerows(rows)
    print(f"{C.DIM}CSV report  → {path}{C.RESET}")


# ══════════════════════════════════════════════════════════════
#  Core scan orchestration
# ══════════════════════════════════════════════════════════════

def scan_host(ip: str, ports: list[int], timeout: float, threads: int,
              check_ssl: bool, check_vuln: bool, verbose: bool,
              quiet: bool) -> HostReport:
    host = HostReport(
        ip=ip,
        scanned_at=datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None).isoformat(timespec="seconds") + "Z"
    )

    if not quiet:
        print(f"\n  {C.CYAN}Scanning {ip}…{C.RESET}")

    # 1. Ping / alive check
    host.is_alive, host.response_ms = ping_host(ip, timeout)
    if not host.is_alive and not quiet:
        print(f"  {C.DIM}Host appears down — scanning anyway…{C.RESET}")

    # 2. Hostname resolution
    host.hostname = resolve_hostname(ip)

    # 3. MAC (local subnet only)
    host.mac_address = get_mac(ip)

    # 4. Port scan
    if not quiet:
        print(f"  {C.DIM}Scanning {len(ports)} ports with {threads} threads…{C.RESET}")
    host.open_ports = scan_ports(ip, ports, timeout=timeout, threads=threads)

    # 5. OS fingerprint
    host.os_guess = os_fingerprint(ip, host.open_ports)

    # 6. SSL checks on HTTPS-capable open ports
    ssl_ports = {443, 8443, 465, 993, 995, 636}
    if check_ssl:
        for pr in host.open_ports:
            if pr.port in ssl_ports or pr.service in ("HTTPS", "HTTPS-alt", "IMAPS",
                                                        "POP3S", "SMTPS", "LDAPS"):
                ssl_res = check_ssl_port(ip, pr.port, host.hostname)
                if ssl_res:
                    host.ssl_results[pr.port] = ssl_res

    # 7. Vulnerability / misconfiguration analysis
    if check_vuln:
        host.findings = analyze_findings(host, skip_ssl=not check_ssl)

    # 8. Score
    host.score, host.grade = compute_score(host.findings)

    # 9. Print host results
    if not quiet:
        print_host_header(host)

        print_section("Open Ports")
        print_ports(host.open_ports)

        if host.ssl_results:
            print_section("SSL / TLS")
            for port, ssl_res in sorted(host.ssl_results.items()):
                print_ssl(port, ssl_res)

        print_section("Security Findings")
        print_findings(host.findings, verbose=verbose)

        print_score(host.score, host.grade)

    return host


def run_assessment(args) -> AssessmentReport:
    info   = get_local_info()
    report = AssessmentReport(
        started_at  =datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None).isoformat(timespec="seconds") + "Z",
        scanner_host=info["hostname"],
        scanner_os  =info["os"],
    )

    # Determine targets
    targets_raw = []
    if hasattr(args, "file") and args.file:
        with open(args.file) as fh:
            targets_raw = [l.strip() for l in fh if l.strip() and not l.startswith("#")]
    elif args.targets:
        targets_raw = args.targets
    else:
        targets_raw = ["127.0.0.1"]

    ips = expand_targets(targets_raw)

    # Determine port list
    if args.ports:
        ports = parse_ports(args.ports)
    else:
        ports = COMMON_PORTS

    print_banner()
    print(f"\n  Scanner  : {info['hostname']} ({info['os']})")
    print(f"  Targets  : {len(ips)} host(s)")
    print(f"  Ports    : {len(ports)} ports")
    print(f"  Started  : {report.started_at}\n")

    for ip in ips:
        host = scan_host(
            ip, ports,
            timeout  =getattr(args, "timeout",  1.5),
            threads  =getattr(args, "threads",  100),
            check_ssl=not getattr(args, "no_ssl",  False),
            check_vuln=not getattr(args, "no_vuln", False),
            verbose  =getattr(args, "verbose",  False),
            quiet    =getattr(args, "quiet",    False),
        )
        report.targets.append(host)

    report.finished_at = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None).isoformat(timespec="seconds") + "Z"
    print_summary(report)

    # Exports
    ts = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None).strftime("%Y%m%d_%H%M%S")
    if getattr(args, "json", False):
        save_json(report, f"it_security_{ts}.json")
    if getattr(args, "csv", False):
        save_csv(report, f"it_security_{ts}.csv")

    return report


# ══════════════════════════════════════════════════════════════
#  CLI entry point
# ══════════════════════════════════════════════════════════════

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="IT Security Assessment Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    p.add_argument("targets", nargs="*",
                   help="IP addresses, hostnames, or CIDR ranges to scan")
    p.add_argument("-f", "--file",
                   help="File containing one target per line")
    p.add_argument("--ports", default=None,
                   help="Port range: '1-1024' or '22,80,443' (default: common ports)")
    p.add_argument("--timeout", type=float, default=1.5,
                   help="Socket timeout in seconds (default: 1.5)")
    p.add_argument("--threads", type=int, default=100,
                   help="Concurrent threads (default: 100)")
    p.add_argument("--no-ssl", action="store_true",
                   help="Skip SSL/TLS checks")
    p.add_argument("--no-vuln", action="store_true",
                   help="Skip vulnerability analysis")
    p.add_argument("--json", action="store_true",
                   help="Save JSON report")
    p.add_argument("--csv", action="store_true",
                   help="Save CSV report")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="Show all finding details")
    p.add_argument("-q", "--quiet", action="store_true",
                   help="Minimal output (summary only)")
    return p


if __name__ == "__main__":
    parser = build_parser()
    args   = parser.parse_args()

    try:
        run_assessment(args)
    except KeyboardInterrupt:
        print(f"\n\n{C.YELLOW}Scan interrupted by user.{C.RESET}\n")
        sys.exit(0)
    except PermissionError as e:
        print(f"\n{C.RED}Permission error: {e}{C.RESET}")
        print("Try running with sudo for raw socket operations.")
        sys.exit(1)