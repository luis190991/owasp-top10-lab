# OWASP Top 10:2025 — Security Lab

> **Educational lab** — intentionally vulnerable application for learning web security.
> Run only in isolated environments (GitHub Codespaces, local VM, Docker).
> **Never deploy to a public server.**

## Quick Start

### GitHub Codespaces (recommended)
1. Fork/clone this repo and open in GitHub Codespaces.
2. The devcontainer installs dependencies and initializes the DB automatically.
3. Port 5000 opens in your browser → start hacking.

### Local
```bash
pip install -r requirements.txt
python run.py
# Open http://localhost:5000
```

---

## Lab Structure

| ID | Vulnerability | Key Attacks |
|----|--------------|-------------|
| [A01](http://localhost:5000/a01/) | Broken Access Control | IDOR, missing role check |
| [A02](http://localhost:5000/a02/) | Security Misconfiguration | Debug mode, exposed config, default creds |
| [A03](http://localhost:5000/a03/) | Supply Chain Failures | pip-audit CVEs, unsafe yaml.load, unsigned plugins |
| [A04](http://localhost:5000/a04/) | Cryptographic Failures | MD5 crack, base64 decode, token prediction |
| [A05](http://localhost:5000/a05/) | Injection | SQL injection, OS command injection |
| [A06](http://localhost:5000/a06/) | Insecure Design | Predictable token, negative cart, mass assignment |
| [A07](http://localhost:5000/a07/) | Authentication Failures | Brute force, sequential session ID, plaintext cookie |
| [A08](http://localhost:5000/a08/) | Software & Data Integrity | Pickle RCE, unsigned update |
| [A09](http://localhost:5000/a09/) | Logging & Alerting Failures | Password in logs, silent failures, no anomaly detection |
| [A10](http://localhost:5000/a10/) | Mishandling of Exceptions | Stack trace exposure, path traversal, SQL error leak |

---

## How to Use

Each lab has:
1. **Index page** — explains the vulnerability and lists challenges.
2. **Vulnerable endpoints** — real broken code to exploit.
3. **Fixed endpoints** (where applicable) — side-by-side comparison of the fix.
4. **Solution** — at `/solutions/a01` through `/solutions/a10`.

### Recommended Order
Work through A01–A10 in sequence.
Each builds on concepts from the previous labs.

### Suggested Tools
```bash
# HTTP requests
curl -s -X POST http://localhost:5000/a05/login -d "username=admin&password=' OR '1'='1"

# Brute force simulation
for pw in password sunshine 123456; do
  curl -s -X POST http://localhost:5000/a07/login -d "username=alice&password=$pw"
done

# Dependency audit
pip-audit

# Hash cracking (A04)
hashcat -a 0 -m 0 hashes.txt /usr/share/wordlists/rockyou.txt
```

---

## Architecture

```
lab_dev_sec/
├── .devcontainer/devcontainer.json   # GitHub Codespaces config
├── app/
│   ├── __init__.py                   # Flask app factory
│   ├── database.py                   # SQLite schema + seed data
│   └── labs/
│       ├── a01_access_control.py
│       ├── a02_misconfiguration.py
│       ├── a03_supply_chain.py
│       ├── a04_crypto.py
│       ├── a05_injection.py
│       ├── a06_insecure_design.py
│       ├── a07_auth_failures.py
│       ├── a08_integrity.py
│       ├── a09_logging.py
│       ├── a10_exceptions.py
│       └── solutions.py
├── templates/                        # Jinja2 templates per lab
├── solutions/                        # Solution writeups (a01.md–a10.md)
├── static/                           # Static files
├── logs/                             # Generated at runtime by A09
├── lab.db                            # Generated at startup
├── requirements.txt
└── run.py
```

---

## Reset the Lab
```bash
rm lab.db && python run.py
```

## References
- [OWASP Top 10:2025](https://owasp.org/Top10/2025/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
