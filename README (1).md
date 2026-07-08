# IT Security Assessment Tool v2.0

Multi-threaded network security scanner: port scanning, service fingerprinting, SSL/TLS auditing, vulnerability detection, and OS guessing — with scored, graded reports.

## Features
- Host discovery (ping) + hostname/MAC resolution
- Multi-threaded TCP port scanning (custom ranges or common ports)
- Service/banner detection with 40+ known-service mapping
- SSL/TLS certificate checks (expiry, self-signed, cipher strength)
- Vulnerability & misconfiguration findings (dangerous/insecure services)
- OS fingerprinting from open port patterns
- Security scoring (A+–F grade) per host
- JSON and CSV report export
- Single host, subnet (CIDR), or target-file scanning

## Requirements
Python 3.9+, standard library only (no external dependencies).

## Usage
```bash
python it_security_assessment.py                     # scan localhost
python it_security_assessment.py 192.168.1.1          # single host
python it_security_assessment.py 192.168.1.0/24       # subnet
python it_security_assessment.py -f targets.txt       # from file
python it_security_assessment.py 10.0.0.1 --json      # JSON report
python it_security_assessment.py 10.0.0.1 --csv       # CSV report
```

### Options
| Flag | Description |
|---|---|
| `--ports <range>` | Port range, e.g. `1-1024` or `22,80,443` (default: common ports) |
| `--timeout <sec>` | Socket timeout (default: 1.5) |
| `--threads <n>` | Worker threads (default: 100) |
| `--no-ssl` | Skip SSL/TLS checks |
| `--no-vuln` | Skip vulnerability analysis |
| `--json` / `--csv` | Save report in given format |
| `-v, --verbose` | Show full finding details |
| `-q, --quiet` | Minimal output |

## Disclaimer
For authorized security testing and educational use only. Only scan systems you own or have explicit permission to test.
