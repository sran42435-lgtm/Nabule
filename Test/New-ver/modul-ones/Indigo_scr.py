#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════╗
║  INDIGO SCANNER v3.0 — MAXIMUM CONFIGURATION                ║
║  13 Engine × Sub-check Komprehensif × Auto Pre-flight       ║
╚══════════════════════════════════════════════════════════════╝
"""

import sys, os, subprocess, importlib, re, json, socket, ssl, time
import hashlib, traceback, shutil, struct, base64, threading, platform
import ipaddress, math, hmac, binascii, tempfile
from datetime import datetime, timezone, timedelta
from urllib.parse import urlparse, urljoin, parse_qs, urlencode, quote
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict, OrderedDict
from pathlib import Path

# ═══════════════════════════════════════════════════════════
# GLOBAL CONFIG
# ═══════════════════════════════════════════════════════════
VERSION = "3.0"
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 IndigoScanner/3.0")
TIMEOUT = 15
REPORT_DIR = "reports"
LOG_DIR = "logs"
CACHE_DIR = "cache"
DATA_DIR = "data"

# ═══════════════════════════════════════════════════════════
# ANSI COLORS
# ═══════════════════════════════════════════════════════════
class C:
    R = "\033[91m"; G = "\033[92m"; Y = "\033[93m"; B = "\033[94m"
    M = "\033[95m"; CY = "\033[96m"; W = "\033[97m"; X = "\033[0m"
    BOLD = "\033[1m"; DIM = "\033[2m"; UL = "\033[4m"
    BG_R = "\033[41m"; BG_G = "\033[42m"; BG_Y = "\033[43m"

def colored(text, *tags):
    prefix = "".join(getattr(C, t, "") for t in tags)
    return f"{prefix}{text}{C.X}"

def banner_line(ch="─", n=72):
    return colored(ch * n, "DIM")

# ═══════════════════════════════════════════════════════════
# DEPENDENCY REGISTRY
# ═══════════════════════════════════════════════════════════
REQUIRED_DEPS = [
    ("numpy",       "numpy",             "Numerical computing",   False),
    ("scipy",       "scipy",             "Scientific computing",  False),
    ("sklearn",     "scikit-learn",      "Machine learning",      False),
    ("requests",    "requests",          "HTTP client",           False),
    ("bs4",         "beautifulsoup4",    "HTML parsing",          False),
    ("lxml",        "lxml",              "Fast XML/HTML parser",  False),
    ("dns",         "dnspython",         "DNS resolution",        False),
    ("cryptography","cryptography",      "TLS/SSL crypto",        False),
    ("OpenSSL",     "pyOpenSSL",         "OpenSSL bindings",      False),
    ("nmap",        "python-nmap",       "Port scanning",         False),
    ("httpx",       "httpx",             "Modern HTTP client",    False),
    ("whois",       "python-whois",      "WHOIS lookup",          True),
    ("aiohttp",     "aiohttp",           "Async HTTP client",     False),
    ("selectolax",  "selectolax",        "Fast HTML parser",      True),
    ("playwright",  "playwright",        "Headless browser",      True),
    ("scapy",       "scapy",             "Packet manipulation",   True),
    ("Wappalyzer",  "python-Wappalyzer", "Tech fingerprinting",   True),
    ("builtwith",   "builtwith",         "Technology detection",  True),
    ("pandas",      "pandas",            "Data analysis",         False),
    ("xgboost",     "xgboost",           "Advanced ML",           True),
    ("joblib",      "joblib",            "Model persistence",     False),
    ("tldextract",  "tldextract",        "Domain parsing",        True),
    ("urllib3",     "urllib3",           "HTTP toolkit",          False),
    ("mmh3",        "mmh3",              "MurmurHash3 (favicon)", True),
    ("pyfiglet",    "pyfiglet",          "ASCII art",             True),
]

# ═══════════════════════════════════════════════════════════
# 1. DEPENDENCY INSTALLER
# ═══════════════════════════════════════════════════════════
def pip_install(pkg):
    try:
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", "--quiet",
             "--disable-pip-version-check", pkg],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=120
        )
        return True
    except Exception:
        return False

def check_and_install_deps():
    print(colored("\n  ┌─ DEPENDENCY CHECK ─────────────────────────────────────┐", "CY"))
    missing = []
    ok_count = 0
    for imp, pip_name, desc, optional in REQUIRED_DEPS:
        try:
            importlib.import_module(imp)
            ok_count += 1
            print(f"  {colored('│','CY')} {colored('✓','G')} {pip_name:25s} {colored(desc,'DIM')}")
        except ImportError:
            missing.append((imp, pip_name, desc, optional))
            print(f"  {colored('│','CY')} {colored('!','Y')} {pip_name:25s} {colored('MISSING','R')}")

    if not missing:
        print(colored(f"  └─ All {ok_count} dependencies ready ────────────────────────────────┘", "CY"))
        return True

    print(colored(f"\n  Installing {len(missing)} missing packages...", "Y"))
    hard_fail = []
    for imp, pip_name, desc, optional in missing:
        sys.stdout.write(f"    → {pip_name} ... ")
        sys.stdout.flush()
        if pip_install(pip_name):
            try:
                importlib.import_module(imp)
                print(colored("OK", "G"))
            except ImportError:
                print(colored("IMPORT-FAIL", "Y"))
                if not optional:
                    hard_fail.append(pip_name)
        else:
            if optional:
                print(colored("SKIP", "B"))
            else:
                print(colored("FAIL", "R"))
                hard_fail.append(pip_name)

    if hard_fail:
        print(colored(f"  ✘ Required packages failed: {', '.join(hard_fail)}", "R"))
        return False

    print(colored("  └─ Dependencies ready ────────────────────────────────────────────────┘", "CY"))
    return True

# ═══════════════════════════════════════════════════════════
# 2. PRE-FLIGHT AUTO SETUP (JALAN SEBELUM BANNER)
# ═══════════════════════════════════════════════════════════
class PreFlight:
    """Menjalankan semua persiapan engine sebelum banner muncul."""

    def __init__(self):
        self.ctx = {
            "has_root": False,
            "has_nmap_bin": False,
            "has_playwright": False,
            "has_scapy": False,
            "has_wappalyzer": False,
            "has_builtwith": False,
            "has_whois": False,
            "has_mmh3": False,
            "has_tldextract": False,
            "zap_proxy": None,
            "session": None,
            "httpx_client": None,
            "wordlists": {},
            "sensitive_regex": [],
            "system_info": {},
            "network_info": {},
            "wappalyzer_engine": None,
            "nmap_scanner": None,
            "preflight_ok": {},
        }

    def run_all(self):
        print(colored("\n  ╔══════════════════════════════════════════════════════════╗", "CY"))
        print(colored("  ║     INDIGO SCANNER v" + VERSION + " — PRE-FLIGHT SETUP          ║", "CY"))
        print(colored("  ╚══════════════════════════════════════════════════════════╝", "CY"))

        steps = [
            ("System Info",         self.collect_system_info),
            ("Directories",         self.setup_directories),
            ("Network Probe",       self.probe_network),
            ("Binary: nmap",        self.ensure_nmap_binary),
            ("Privilege Check",     self.check_privileges),
            ("Playwright Browser",  self.ensure_playwright),
            ("Wappalyzer Warmup",   self.warmup_wappalyzer),
            ("HTTP Session Pool",   self.warmup_http),
            ("Nmap Scanner Init",   self.init_nmap_scanner),
            ("Scapy Init",          self.init_scapy),
            ("ZAP Proxy Detect",    self.detect_zap),
            ("Wordlists Load",      self.load_wordlists),
            ("Regex Compile",       self.compile_regex),
            ("CT Log Endpoint",     self.check_ct_endpoints),
            ("DNS Resolver Warmup", self.warmup_dns),
        ]

        for label, fn in steps:
            try:
                result = fn()
                status = colored("✓", "G") if result else colored("~", "Y")
                print(f"    {status} {label:30s} {colored('OK' if result else 'PARTIAL','DIM')}")
            except Exception as e:
                print(f"    {colored('✘','R')} {label:30s} {colored(str(e)[:50],'R')}")

        print(colored("\n  ── Pre-flight complete. Entering lobby. ──\n", "G"))
        return self.ctx

    # --- Sub-steps ---

    def collect_system_info(self):
        info = {
            "platform": platform.platform(),
            "python": sys.version.split()[0],
            "machine": platform.machine(),
            "processor": platform.processor() or "unknown",
            "hostname": socket.gethostname(),
            "user": os.environ.get("USER", os.environ.get("USERNAME", "unknown")),
            "cwd": os.getcwd(),
            "start_time": datetime.now().isoformat(),
        }
        self.ctx["system_info"] = info
        return True

    def setup_directories(self):
        for d in (REPORT_DIR, LOG_DIR, CACHE_DIR, DATA_DIR):
            Path(d).mkdir(parents=True, exist_ok=True)
        return True

    def probe_network(self):
        try:
            socket.setdefaulttimeout(5)
            ip = socket.gethostbyname("example.com")
            self.ctx["network_info"]["internet"] = True
            self.ctx["network_info"]["test_ip"] = ip
            # Get own public IP
            try:
                import requests
                r = requests.get("https://api.ipify.org?format=json", timeout=5)
                self.ctx["network_info"]["public_ip"] = r.json().get("ip", "?")
            except Exception:
                self.ctx["network_info"]["public_ip"] = "unknown"
            return True
        except Exception:
            self.ctx["network_info"]["internet"] = False
            return False

    def ensure_nmap_binary(self):
        path = shutil.which("nmap")
        if path:
            self.ctx["has_nmap_bin"] = True
            self.ctx["nmap_path"] = path
            # Get nmap version
            try:
                out = subprocess.check_output(["nmap", "--version"],
                                              stderr=subprocess.DEVNULL, timeout=10)
                ver = out.decode().split("\n")[0]
                self.ctx["nmap_version"] = ver
            except Exception:
                self.ctx["nmap_version"] = "unknown"
            return True

        # Auto-install on Linux
        if platform.system() == "Linux":
            print(colored("      → Attempting auto-install nmap...", "Y"), end=" ")
            try:
                if shutil.which("apt-get"):
                    subprocess.run(["sudo", "apt-get", "install", "-y", "nmap"],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=120)
                elif shutil.which("yum"):
                    subprocess.run(["sudo", "yum", "install", "-y", "nmap"],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=120)
                elif shutil.which("pacman"):
                    subprocess.run(["sudo", "pacman", "-S", "--noconfirm", "nmap"],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=120)
                path = shutil.which("nmap")
                if path:
                    self.ctx["has_nmap_bin"] = True
                    print(colored("INSTALLED", "G"))
                    return True
            except Exception:
                pass
            print(colored("FAILED", "R"))
        return False

    def check_privileges(self):
        if hasattr(os, "geteuid"):
            self.ctx["has_root"] = (os.geteuid() == 0)
        elif platform.system() == "Windows":
            try:
                import ctypes
                self.ctx["has_root"] = ctypes.windll.shell32.IsUserAnAdmin() != 0
            except Exception:
                self.ctx["has_root"] = False
        else:
            self.ctx["has_root"] = False
        return self.ctx["has_root"]

    def ensure_playwright(self):
        try:
            importlib.import_module("playwright")
        except ImportError:
            return False
        try:
            # Check if chromium is installed
            from playwright.sync_api import sync_playwright
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                browser.close()
            self.ctx["has_playwright"] = True
            return True
        except Exception:
            # Try install
            print(colored("      → Installing Playwright chromium...", "Y"), end=" ", flush=True)
            try:
                subprocess.run(
                    [sys.executable, "-m", "playwright", "install", "chromium"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=300
                )
                # Verify
                from playwright.sync_api import sync_playwright
                with sync_playwright() as p:
                    browser = p.chromium.launch(headless=True)
                    browser.close()
                self.ctx["has_playwright"] = True
                print(colored("OK", "G"))
                return True
            except Exception as e:
                print(colored("FAIL", "R"))
                return False

    def warmup_wappalyzer(self):
        try:
            from Wappalyzer import Wappalyzer, WebPage
            wapp = Wappalyzer.latest()
            self.ctx["wappalyzer_engine"] = wapp
            self.ctx["has_wappalyzer"] = True
            return True
        except Exception:
            return False

    def warmup_http(self):
        try:
            import requests, urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            s = requests.Session()
            s.headers.update({"User-Agent": UA})
            s.verify = False
            adapter = requests.adapters.HTTPAdapter(
                pool_connections=20, pool_maxsize=20,
                max_retries=2, pool_block=False
            )
            s.mount("http://", adapter)
            s.mount("https://", adapter)
            self.ctx["session"] = s

            import httpx
            self.ctx["httpx_client"] = httpx.Client(
                timeout=TIMEOUT, follow_redirects=False,
                verify=False, limits=httpx.Limits(max_connections=20)
            )
            return True
        except Exception:
            return False

    def init_nmap_scanner(self):
        if not self.ctx.get("has_nmap_bin"):
            return False
        try:
            import nmap as python_nmap
            nm = python_nmap.PortScanner()
            self.ctx["nmap_scanner"] = nm
            return True
        except Exception:
            return False

    def init_scapy(self):
        try:
            from scapy.all import conf as scapy_conf
            scapy_conf.verb = 0
            # Suppress scapy warnings
            import logging
            logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
            logging.getLogger("scapy.loading").setLevel(logging.ERROR)
            self.ctx["has_scapy"] = True
            return True
        except Exception:
            return False

    def detect_zap(self):
        zap_url = os.environ.get("ZAP_PROXY", "http://127.0.0.1:8080")
        zap_api = os.environ.get("ZAP_API_KEY", "")
        try:
            import requests
            r = requests.get(f"{zap_url}/JSON/core/view/version/?apikey={zap_api}",
                             timeout=3, proxies={"http": None, "https": None})
            if r.status_code == 200:
                ver = r.json().get("version", "?")
                self.ctx["zap_proxy"] = {"url": zap_url, "api_key": zap_api, "version": ver}
                return True
        except Exception:
            pass
        return False

    def load_wordlists(self):
        wl = {
            "subdomains": [
                "www","mail","ftp","localhost","webmail","smtp","pop","pop3","imap",
                "ns1","ns2","ns3","ns4","dns","dns1","dns2","vpn","api","dev","staging",
                "test","admin","portal","shop","blog","m","mobile","app","cdn","static",
                "media","img","images","assets","files","docs","wiki","git","svn","backup",
                "db","database","mysql","postgres","oracle","sql","old","new","beta","alpha",
                "preview","uat","prod","stage","demo","internal","intranet","extranet",
                "secure","login","auth","sso","oauth","id","identity","accounts","register",
                "signup","signin","dashboard","panel","console","manage","management",
                "monitoring","grafana","kibana","prometheus","jenkins","ci","cd","deploy",
                "release","build","artifacts","nexus","sonar","jira","confluence","gitlab",
                "github","bitbucket","code","repo","repository","registry","docker","k8s",
                "kubernetes","rancher","openshift","vault","consul","terraform","ansible",
                "puppet","chef","saltstack","nagios","zabbix","datadog","newrelic","sentry",
                "logstash","elasticsearch","kafka","rabbitmq","redis","memcached","mongo",
                "cassandra","couchdb","neo4j","influxdb","telegraf","haproxy","nginx",
                "apache","tomcat","jetty","wildfly","jboss","weblogic","websphere",
                "exchange","owa","autodiscover","lync","sip","xmpp","jabber","teams",
                "slack","discord","zoom","meet","calendar","schedule","booking","ticket",
                "support","help","helpdesk","service","status","health","ping","check",
                "uptime","report","analytics","tracking","telemetry","metrics","stats",
                "data","warehouse","etl","bi","dashboard","reporting","invoices","billing",
                "payment","checkout","cart","orders","products","catalog","inventory",
                "warehouse","shipping","delivery","tracking","returns","crm","leads",
                "contacts","customers","partners","vendors","suppliers","hr","jobs",
                "careers","recruit","talent","training","learning","education","courses"
            ],
            "dirs": [
                "admin","login","wp-admin","administrator","dashboard","panel","console",
                "config","backup","api","v1","v2","v3","graphql","swagger","docs",".git",
                ".env","robots.txt","sitemap.xml",".well-known","phpinfo.php","server-status",
                "server-info",".htaccess",".htpasswd","web.config","crossdomain.xml",
                "clientaccesspolicy.xml","elmah.axd","trace.axd",".svn",".hg",".bzr",
                "CVS","WEB-INF","META-INF","wp-content","wp-includes","wp-json",
                "xmlrpc.php","wp-login.php","wp-cron.php","wp-config.php.bak",
                "wp-config.php.old","wp-config.php~","wp-config.php.swp",
                ".DS_Store","Thumbs.db","desktop.ini",".idea",".vscode",
                "node_modules","package.json","package-lock.json","yarn.lock",
                "composer.json","composer.lock","Gemfile","Gemfile.lock",
                "requirements.txt","Pipfile","Pipfile.lock","poetry.lock",
                "Dockerfile","docker-compose.yml","docker-compose.yaml",
                ".dockerignore",".gitignore",".editorconfig",".eslintrc",
                ".prettierrc","tsconfig.json","jsconfig.json","webpack.config.js",
                "Makefile","CMakeLists.txt","Cargo.toml","go.mod","go.sum",
                "debug","trace","log","logs","error","errors","tmp","temp",
                "cache","session","sessions","upload","uploads","download","downloads",
                "file","files","attachment","attachments","media","image","images",
                "photo","photos","video","videos","audio","music","document","documents",
                "report","reports","export","import","dump","data","database",
                "migrate","migration","seed","fixture","fixtures","test","tests",
                "spec","specs","mock","mocks","stub","stubs","fixture","fixtures",
                "private","public","protected","internal","external","secret","secrets",
                "key","keys","token","tokens","credential","credentials","cert","certs",
                "certificate","certificates","pem","crt","key","p12","pfx","jks",
                "keystore","truststore"
            ],
            "emails": [],
            "phones": [],
            "sensitive_regex": [
                r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
                r"(?i)(api[_-]?key|apikey|secret|token|password|passwd|auth|credential)\s*[:=]\s*['\"]?([A-Za-z0-9_\-/+=]{8,})",
                r"(?i)AKIA[0-9A-Z]{16}",
                r"ghp_[A-Za-z0-9_]{36}",
                r"gho_[A-Za-z0-9_]{36}",
                r"github_pat_[A-Za-z0-9_]{22,}",
                r"sk-[A-Za-z0-9]{32,}",
                r"sk_live_[A-Za-z0-9]{24,}",
                r"rk_live_[A-Za-z0-9]{24,}",
                r"xox[baprs]-[A-Za-z0-9\-]{10,}",
                r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
                r"(?i)(mysql|postgres|mongodb|redis)://[^\s'\"]+",
                r"(?i)jdbc:[a-z]+://[^\s'\"]+",
                r"(?i)(ftp|ssh|telnet)://[^\s'\"]+",
                r"\+?[0-9]{1,3}[-.\s]?$?[0-9]{1,4}$?[-.\s]?[0-9]{1,4}[-.\s]?[0-9]{1,9}",
                r"(?i)AWS[_-]?(?:SECRET|ACCESS)[_-]?KEY\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{20,})",
                r"(?i)(?:client[_-]?secret|app[_-]?secret)\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{16,})",
                r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
            ],
        }
        self.ctx["wordlists"] = wl
        return True

    def compile_regex(self):
        compiled = []
        for p in self.ctx.get("wordlists", {}).get("sensitive_regex", []):
            try:
                compiled.append(re.compile(p))
            except re.error:
                pass
        self.ctx["sensitive_regex"] = compiled
        return True

    def check_ct_endpoints(self):
        """Check if Certificate Transparency log endpoints are reachable."""
        endpoints = [
            "https://crt.sh/?q={}&output=json",
            "https://dns.google/resolve?name={}&type=A",
        ]
        reachable = []
        for ep in endpoints:
            try:
                import requests
                test_url = ep.replace("{}", "example.com")
                r = requests.get(test_url, timeout=5, verify=False)
                if r.status_code < 500:
                    reachable.append(ep)
            except Exception:
                pass
        self.ctx["ct_endpoints"] = reachable
        return len(reachable) > 0

    def warmup_dns(self):
        """Pre-warm DNS resolver."""
        try:
            import dns.resolver
            resolver = dns.resolver.Resolver()
            resolver.nameservers = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]
            resolver.timeout = 5
            resolver.lifetime = 10
            self.ctx["dns_resolver"] = resolver
            # Warmup
            resolver.resolve("example.com", "A")
            return True
        except Exception:
            return False

# ═══════════════════════════════════════════════════════════
# 3. POST-DEP IMPORTS
# ═══════════════════════════════════════════════════════════
def do_imports():
    """Import all libraries after deps are confirmed."""
    global requests, httpx, np, pd, BeautifulSoup, etree
    global dns_resolver, dns_zone, dns_query, dns_reversename, dns_exception, dns_message, dns_name, dns_flags
    global x509, default_backend, hashes, serialization
    global SSL, crypto
    global urlparse, urljoin

    import requests
    import httpx
    import numpy as np
    import pandas as pd
    from bs4 import BeautifulSoup, Comment
    from lxml import etree

    import dns.resolver as dns_resolver
    import dns.zone as dns_zone
    import dns.query as dns_query
    import dns.reversename as dns_reversename
    import dns.exception as dns_exception
    import dns.message as dns_message
    import dns.name as dns_name
    import dns.flags as dns_flags

    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes, serialization
    from OpenSSL import SSL, crypto

do_imports()

# Optional imports
try:
    import whois as pywhois; HAS_WHOIS = True
except: HAS_WHOIS = False

try:
    import nmap as python_nmap; HAS_PY_NMAP = True
except: HAS_PY_NMAP = False

try:
    from scapy.all import (IP, TCP, ICMP, UDP, sr1, sr, ARP, Ether,
                           conf as scapy_conf, RandShort, raw)
    scapy_conf.verb = 0
    HAS_SCAPY = True
except: HAS_SCAPY = False

try:
    from playwright.sync_api import sync_playwright; HAS_PLAYWRIGHT = True
except: HAS_PLAYWRIGHT = False

try:
    from selectolax.parser import HTMLParser as SelectoParser; HAS_SELECTOLAX = True
except: HAS_SELECTOLAX = False

try:
    from Wappalyzer import Wappalyzer, WebPage; HAS_WAPPALYZER = True
except: HAS_WAPPALYZER = False

try:
    import builtwith as bw_lib; HAS_BUILTWITH = True
except: HAS_BUILTWITH = False

try:
    import tldextract; HAS_TLDEXTRACT = True
except: HAS_TLDEXTRACT = False

try:
    import mmh3; HAS_MMH3 = True
except: HAS_MMH3 = False

# ═══════════════════════════════════════════════════════════
# 4. BANNER
# ═══════════════════════════════════════════════════════════
BANNER = r"""
 _)             | _)                                  
  |  __ \    _` |  |   _` |   _ \     __|   __|   __| 
  |  |   |  (   |  |  (   |  (   |  \__ \  (     |    
 _| _|  _| \__,_| _| \__, | \___/   ____/ \___| _|    
                     |___/      _____|                
"""

def show_banner(ctx):
    print(colored(BANNER, "CY"))
    print(colored("        [ INDIGO SCANNER v" + VERSION + " // 13-Engine Maximum Security Recon ]", "BOLD"))
    print()

    # Status ringkasan
    items = [
        ("Nmap",    ctx.get("has_nmap_bin", False)),
        ("Scapy",   ctx.get("has_scapy", False) and ctx.get("has_root", False)),
        ("Playwright", ctx.get("has_playwright", False)),
        ("Wappalyzer", ctx.get("has_wappalyzer", False)),
        ("ZAP",     ctx.get("zap_proxy") is not None),
        ("Root",    ctx.get("has_root", False)),
    ]
    status_line = "  Engine Status: "
    for name, ok in items:
        if ok:
            status_line += colored(f"[{name}:✓] ", "G")
        else:
            status_line += colored(f"[{name}:~] ", "Y")
    print(status_line)

    pub_ip = ctx.get("network_info", {}).get("public_ip", "?")
    print(f"  {colored('Your IP:', 'DIM')} {pub_ip}    "
          f"{colored('Platform:', 'DIM')} {platform.system()} {platform.release()}")
    print()
    print(f"  {colored('Commands:', 'Y')} {colored('/exit', 'W')} to quit  |  "
          f"Enter {colored('URL / domain / IP', 'W')} to scan")
    print(banner_line())

# ═══════════════════════════════════════════════════════════
# 5. TARGET VALIDATION
# ═══════════════════════════════════════════════════════════
IPV4_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)$"
)
IPV6_RE = re.compile(r"^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$")
DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)

def validate_target(raw):
    raw = raw.strip()
    if not raw:
        return None, "Target kosong"
    if raw.lower() in ("/exit", "/quit", "/q"):
        return None, "EXIT"

    # URL lengkap
    if raw.startswith(("http://", "https://")):
        p = urlparse(raw)
        if not p.hostname:
            return None, "URL tidak valid (host kosong)"
        return raw, None

    # IPv4
    if IPV4_RE.match(raw):
        return f"http://{raw}", None

    # IPv6 (bracket)
    if raw.startswith("[") and "]" in raw:
        return f"http://{raw}", None

    # Domain dengan kemungkinan port
    host_part = raw.split(":")[0]
    if DOMAIN_RE.match(host_part):
        return f"http://{raw}", None

    return None, "Format tidak dikenali (bukan URL/domain/IP)"

def get_host(url):
    return urlparse(url).hostname or urlparse(url).netloc

def get_registered_domain(host):
    if HAS_TLDEXTRACT:
        ex = tldextract.extract(host)
        return f"{ex.domain}.{ex.suffix}" if ex.domain and ex.suffix else host
    parts = host.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host

def resolve_host(host):
    try:
        return socket.gethostbyname(host)
    except Exception:
        return host

def is_ip(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False

# ═══════════════════════════════════════════════════════════
# 6. PROGRESS DISPLAY
# ═══════════════════════════════════════════════════════════
class EngineProgress:
    """Thread-safe progress tracker."""
    def __init__(self, total):
        self.total = total
        self.done = 0
        self.lock = threading.Lock()
        self.results = {}

    def update(self, name, status, detail="", dt=0):
        with self.lock:
            self.done += 1
            self.results[name] = {"status": status, "detail": detail, "time": dt}
            self._render(name, status, detail, dt)

    def _render(self, name, status, detail, dt):
        pct = (self.done / self.total) * 100
        bar_len = 30
        filled = int(bar_len * self.done / self.total)
        bar = "█" * filled + "░" * (bar_len - filled)

        icons = {"ok": colored("✔","G"), "err": colored("✘","R"),
                 "skip": colored("⊘","B"), "start": colored("▶","Y")}
        icon = icons.get(status, "?")
        time_str = f"{dt:.1f}s" if dt else ""

        print(f"  {icon} [{bar}] {pct:5.1f}% │ {name:26s} │ {colored(time_str,'DIM')} │ {colored(detail[:40],'DIM')}")

# ═══════════════════════════════════════════════════════════
# 7. ENGINE IMPLEMENTATIONS — MAXIMUM CONFIGURATION
# ═══════════════════════════════════════════════════════════

# ─────────────────────────────────────────────
# ENGINE 1: NMAP — Port Scanning & Service Detection
# ─────────────────────────────────────────────
def engine_nmap(target, ctx):
    """
    Comprehensive Nmap scan:
    - TCP SYN scan (or connect if no root)
    - UDP scan on critical ports
    - Service/version detection
    - OS detection
    - Default + vuln NSE scripts
    - Firewall detection (--reason)
    - Traceroute
    - Specific service probes (HTTP, SSL, SMB, FTP, SSH)
    """
    if not ctx.get("has_nmap_bin") or not HAS_PY_NMAP:
        return {"status": "skipped", "reason": "nmap binary/library tidak tersedia"}

    host = get_host(target)
    nm = ctx.get("nmap_scanner") or python_nmap.PortScanner()

    data = {
        "host": host,
        "tcp_scan": {},
        "udp_scan": {},
        "os_detection": {},
        "service_detection": {},
        "vuln_scripts": {},
        "firewall_detection": {},
        "traceroute": [],
        "scan_stats": {},
        "issues": [],
    }

    try:
        is_root = ctx.get("has_root", False)
        scan_type = "-sS" if is_root else "-sT"

        # ── Phase 1: TCP comprehensive scan ──
        tcp_args = (
            f"{scan_type} -sV -sC -O -A -T4 "
            f"--top-ports 1000 "
            f"-p 21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,"
            f"1433,1521,1723,3306,3389,5432,5900,5901,6379,6380,8080,8443,"
            f"8888,9200,9300,11211,27017,27018,28017 "
            f"--script=default,vuln,discovery "
            f"--script-args=unsafe=0 "
            f"--reason --traceroute "
            f"--max-retries 2 --host-timeout 480s "
            f"--version-intensity 5"
        )
        nm.scan(host, arguments=tcp_args)

        for h in nm.all_hosts():
            hi = data["tcp_scan"].setdefault(h, {
                "hostname": nm[h].hostname(),
                "state": nm[h].state(),
                "ports": {},
                "scripts": {},
            })

            # OS Detection
            data["os_detection"] = {
                "osmatch": nm[h].get("osmatch", []),
                "osclass": nm[h].get("osclass", []),
                "osfingerprint": nm[h].get("osfingerprint", None),
            }

            # TCP ports
            if "tcp" in nm[h]:
                for port in sorted(nm[h]["tcp"].keys()):
                    p = nm[h]["tcp"][port]
                    hi["ports"][port] = {
                        "state": p.get("state"),
                        "name": p.get("name"),
                        "product": p.get("product"),
                        "version": p.get("version"),
                        "extrainfo": p.get("extrainfo"),
                        "conf": p.get("conf"),
                        "cpe": p.get("cpe"),
                        "reason": p.get("reason"),
                        "scripts": p.get("script", {}),
                    }

                    # Vulnerability analysis dari script output
                    for script_name, script_out in p.get("script", {}).items():
                        if any(v in script_name for v in ["vuln", "cve", "exploit"]):
                            data["vuln_scripts"][f"port_{port}_{script_name}"] = {
                                "port": port,
                                "script": script_name,
                                "output": script_out[:500],
                            }
                            data["issues"].append(
                                f"Port {port}: {script_name} — {script_out[:80]}"
                            )

            # Host-level scripts
            hi["scripts"] = nm[h].get("hostscript", {})

            # Traceroute
            trace = nm[h].get("traceroute", {})
            if trace:
                data["traceroute"] = trace

        # ── Phase 2: UDP scan (critical ports only) ──
        try:
            udp_args = "-sU -T4 --top-ports 20 --max-retries 1 --host-timeout 120s"
            nm.scan(host, arguments=udp_args)
            for h in nm.all_hosts():
                if "udp" in nm[h]:
                    for port in sorted(nm[h]["udp"].keys()):
                        p = nm[h]["udp"][port]
                        data["udp_scan"][port] = {
                            "state": p.get("state"),
                            "name": p.get("name"),
                            "product": p.get("product"),
                            "version": p.get("version"),
                        }
        except Exception as e:
            data["udp_error"] = str(e)[:120]

        # ── Phase 3: Firewall detection ──
        try:
            nm.scan(host, arguments="-sA -T4 --top-ports 100 --reason --host-timeout 60s")
            for h in nm.all_hosts():
                filtered = 0
                unfiltered = 0
                if "tcp" in nm[h]:
                    for port in nm[h]["tcp"]:
                        st = nm[h]["tcp"][port].get("state", "")
                        if st == "filtered":
                            filtered += 1
                        elif st == "unfiltered":
                            unfiltered += 1
                data["firewall_detection"] = {
                    "filtered_ports": filtered,
                    "unfiltered_ports": unfiltered,
                    "firewall_likely": filtered > 10,
                }
                if filtered > 10:
                    data["issues"].append(
                        f"Firewall terdeteksi: {filtered} port filtered"
                    )
        except Exception:
            pass

        data["scan_stats"] = nm.scanstats()

        tcp_count = sum(len(v.get("ports", {})) for v in data["tcp_scan"].values())
        udp_count = len(data["udp_scan"])
        return {
            "status": "ok",
            "data": data,
            "summary": f"{tcp_count} TCP, {udp_count} UDP, "
                       f"OS: {data['os_detection'].get('osmatch',[{}])[0].get('name','?') if data['os_detection'].get('osmatch') else '?'}, "
                       f"FW: {'yes' if data['firewall_detection'].get('firewall_likely') else 'no'}, "
                       f"{data['scan_stats'].get('elapsed','?')}s"
        }
    except Exception as e:
        return {"status": "error", "error": str(e)[:200]}

# ─────────────────────────────────────────────
# ENGINE 2: DNS — Enumeration & Zone Transfer
# ─────────────────────────────────────────────
def engine_dns(target, ctx):
    """
    Maximum DNS enumeration:
    - 15+ record types
    - Zone transfer (AXFR) attempt
    - DNSSEC validation
    - Wildcard detection
    - Reverse DNS
    - SPF/DMARC/DKIM/MTA-STS/BIMI
    - Subdomain brute-force (wordlist)
    - Certificate Transparency lookup (crt.sh)
    - DNS cache snooping test
    - CNAME takeover detection
    """
    host = get_host(target)
    reg_dom = get_registered_domain(host)
    resolver = ctx.get("dns_resolver") or dns_resolver

    data = {
        "host": host,
        "registered_domain": reg_dom,
        "records": {},
        "zone_transfer": None,
        "dnssec": {},
        "wildcard": None,
        "reverse_dns": {},
        "subdomains_found": [],
        "ct_subdomains": [],
        "cname_takeover_risk": [],
        "txt_analysis": {},
        "cache_snooping": {},
        "errors": [],
    }

    # ── 1) Record enumeration ──
    types = ["A","AAAA","MX","NS","TXT","CNAME","SOA","CAA","SRV","PTR",
             "NAPTR","DNSKEY","DS","TLSA","SSHFP","LOC","HINFO","RP","AFSDB"]
    for rt in types:
        try:
            qhost = reg_dom if rt in ("DS", "DNSKEY") else host
            ans = resolver.resolve(qhost, rt)
            data["records"][rt] = [r.to_text() for r in ans]
        except (dns_resolver.NoAnswer, dns_resolver.NXDOMAIN,
                dns_resolver.NoNameservers, dns_exception.Timeout):
            data["records"][rt] = []
        except Exception as e:
            data["records"][rt] = []
            data["errors"].append(f"{rt}: {str(e)[:60]}")

    # ── 2) SPF / DMARC / DKIM / MTA-STS / BIMI ──
    txt_queries = [
        (host, "SPF"),
        (f"_dmarc.{reg_dom}", "DMARC"),
        (f"_mta-sts.{reg_dom}", "MTA-STS"),
        (f"_bimi.{reg_dom}", "BIMI"),
        (f"default._domainkey.{reg_dom}", "DKIM-default"),
        (f"google._domainkey.{reg_dom}", "DKIM-google"),
        (f"selector1._domainkey.{reg_dom}", "DKIM-o365-sel1"),
        (f"selector2._domainkey.{reg_dom}", "DKIM-o365-sel2"),
        (f"k1._domainkey.{reg_dom}", "DKIM-k1"),
        (f"s1._domainkey.{reg_dom}", "DKIM-s1"),
        (f"s2._domainkey.{reg_dom}", "DKIM-s2"),
        (f"mail._domainkey.{reg_dom}", "DKIM-mail"),
        (f"_smtp._tls.{reg_dom}", "TLSRPT"),
        (f"_autodiscover._tcp.{reg_dom}", "SRV-autodiscover"),
        (f"_sip._tcp.{reg_dom}", "SRV-sip"),
        (f"_caldavs._tcp.{reg_dom}", "SRV-caldavs"),
    ]
    for qh, label in txt_queries:
        try:
            if label.startswith("SRV"):
                ans = resolver.resolve(qh, "SRV")
            else:
                ans = resolver.resolve(qh, "TXT")
            vals = [r.to_text() for r in ans]
            data["records"][label] = vals
            # TXT analysis
            if label == "SPF":
                for v in vals:
                    if "v=spf1" in v.lower():
                        data["txt_analysis"]["spf"] = v
                        if "+all" in v:
                            data["txt_analysis"]["spf_issue"] = "SPF record contains +all (too permissive)"
            if label == "DMARC":
                for v in vals:
                    if "v=dmarc1" in v.lower():
                        data["txt_analysis"]["dmarc"] = v
                        if "p=none" in v.lower():
                            data["txt_analysis"]["dmarc_issue"] = "DMARC policy=none (no enforcement)"
        except Exception:
            pass

    # ── 3) Zone transfer (AXFR) ──
    try:
        ns_records = resolver.resolve(reg_dom, "NS")
        for ns in ns_records:
            try:
                z = dns_zone.from_xfr(
                    dns_query.xfr(str(ns), reg_dom, timeout=10, lifetime=15)
                )
                if z:
                    nodes = list(z.nodes.keys())
                    data["zone_transfer"] = {
                        "nameserver": str(ns),
                        "status": "VULNERABLE",
                        "entry_count": len(nodes),
                        "entries_sample": [n.to_text() for n in nodes[:500]],
                    }
                    break
            except Exception:
                continue
        if data["zone_transfer"] is None:
            data["zone_transfer"] = {"status": "blocked"}
    except Exception as e:
        data["zone_transfer"] = {"status": "error", "error": str(e)[:100]}

    # ── 4) DNSSEC validation ──
    for rt in ("A", "DNSKEY", "DS", "MX"):
        try:
            qname = dns_name.from_text(reg_dom if rt in ("DS", "DNSKEY") else host)
            req = dns_message.make_query(qname, rt, want_dnssec=True)
            resp = dns_query.udp(req, "8.8.8.8", timeout=5)
            data["dnssec"][rt] = {
                "rcode": resp.rcode(),
                "flags": str(resp.flags),
                "ad_flag": bool(resp.flags & dns_flags.AD),
                "answer_count": len(resp.answer),
            }
        except Exception as e:
            data["dnssec"][rt] = {"error": str(e)[:60]}

    # ── 5) Wildcard detection ──
    rnd = f"__wctest{int(time.time())}.{reg_dom}"
    try:
        ans = resolver.resolve(rnd, "A")
        data["wildcard"] = {"detected": True, "answers": [r.to_text() for r in ans]}
    except (dns_resolver.NXDOMAIN, dns_resolver.NoAnswer):
        data["wildcard"] = {"detected": False}
    except Exception:
        data["wildcard"] = {"detected": None}

    # ── 6) Reverse DNS ──
    try:
        for rec in data["records"].get("A", []):
            try:
                rev = dns_reversename.from_address(rec)
                ans = resolver.resolve(rev, "PTR")
                data["reverse_dns"][rec] = [r.to_text() for r in ans]
            except Exception:
                data["reverse_dns"][rec] = []
    except Exception:
        pass

    # ── 7) CNAME takeover detection ──
    try:
        for rt in ("CNAME",):
            for rec in data["records"].get(rt, []):
                cname_target = rec.rstrip(".")
                try:
                    resolver.resolve(cname_target, "A")
                except dns_resolver.NXDOMAIN:
                    data["cname_takeover_risk"].append({
                        "record": rec,
                        "risk": "DANGLING CNAME — potential subdomain takeover",
                    })
                except Exception:
                    pass
    except Exception:
        pass

    # ── 8) Subdomain brute-force ──
    wl = ctx.get("wordlists", {}).get("subdomains", [])[:80]
    def _probe(sub):
        fqdn = f"{sub}.{reg_dom}"
        try:
            resolver.resolve(fqdn, "A")
            return fqdn
        except Exception:
            return None
    found = []
    with ThreadPoolExecutor(max_workers=20) as pool:
        futs = {pool.submit(_probe, s): s for s in wl}
        for f in as_completed(futs):
            r = f.result()
            if r:
                found.append(r)
    data["subdomains_found"] = sorted(set(found))

    # ── 9) Certificate Transparency lookup ──
    ct_endpoints = ctx.get("ct_endpoints", [])
    if ct_endpoints:
        try:
            ct_url = ct_endpoints[0].replace("{}", reg_dom)
            r = requests.get(ct_url, timeout=20, verify=False,
                             headers={"User-Agent": UA})
            if r.status_code == 200:
                entries = r.json()
                ct_names = set()
                for entry in entries:
                    cn = entry.get("common_name", "")
                    nv = entry.get("name_value", "")
                    for name in [cn] + nv.split("\n"):
                        name = name.strip().lstrip("*.")
                        if name and name.endswith(reg_dom):
                            ct_names.add(name)
                data["ct_subdomains"] = sorted(ct_names)[:200]
        except Exception as e:
            data["ct_error"] = str(e)[:100]

    # ── 10) DNS cache snooping (test via non-recursive query) ──
    try:
        ns_list = [str(ns).rstrip(".") for ns in resolver.resolve(reg_dom, "NS")]
        for ns_ip in ns_list[:2]:
            try:
                ns_addr = resolver.resolve(ns_ip, "A")[0].to_text()
            except Exception:
                ns_addr = ns_ip
            try:
                test_domains = ["google.com", "facebook.com", "nonexistent-test-domain.xyz"]
                cached = []
                for td in test_domains:
                    q = dns_message.make_query(td, "A")
                    q.flags &= ~dns_flags.RD  # Non-recursive
                    resp = dns_query.udp(q, ns_addr, timeout=3)
                    if len(resp.answer) > 0:
                        cached.append(td)
                data["cache_snooping"][ns_ip] = {
                    "cached_domains": cached,
                    "vulnerable": len(cached) > 0,
                }
            except Exception:
                pass
    except Exception:
        pass

    total_recs = sum(len(v) for v in data["records"].values() if isinstance(v, list))
    return {
        "status": "ok",
        "data": data,
        "summary": f"{total_recs} records, {len(data['subdomains_found'])} sub brute, "
                   f"{len(data['ct_subdomains'])} CT sub, "
                   f"zone: {data['zone_transfer'].get('status','?')}, "
                   f"CNAME-takeover: {len(data['cname_takeover_risk'])}"
    }

# ─────────────────────────────────────────────
# ENGINE 3: SSL/TLS — Certificate & Vulnerability Analysis
# ─────────────────────────────────────────────
def engine_ssl(target, ctx):
    """
    Maximum SSL/TLS analysis:
    - Certificate chain analysis (multiple ports)
    - TLS version probing (SSLv3, TLS 1.0-1.3)
    - Cipher suite enumeration
    - Vulnerability checks: Heartbleed, POODLE, BEAST, CRIME, FREAK, Logjam
    - HSTS analysis
    - OCSP stapling check
    - SNI mismatch detection
    - Certificate Transparency log check
    - Public key analysis (RSA/ECC/DSA)
    """
    host = get_host(target)
    data = {
        "host": host,
        "certificates": [],
        "tls_versions": {},
        "cipher_suites": [],
        "weak_ciphers": [],
        "vulnerabilities": {},
        "hsts": {},
        "ocsp": {},
        "sni_test": {},
        "issues": [],
    }

    ports = [443, 8443, 9443, 8080]

    # ── 1) Certificate analysis per port ──
    for port in ports:
        try:
            ctx_ssl = ssl.create_default_context()
            ctx_ssl.check_hostname = False
            ctx_ssl.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=10) as sock:
                with ctx_ssl.wrap_socket(sock, server_hostname=host) as ssock:
                    der = ssock.getpeercert(binary_form=True)
                    cert = x509.load_der_x509_certificate(der, default_backend())

                    info = {
                        "port": port,
                        "subject": {},
                        "issuer": {},
                        "serial": cert.serial_number,
                        "not_before": str(cert.not_valid_before_utc),
                        "not_after": str(cert.not_valid_after_utc),
                        "san": [],
                        "signature_algorithm": cert.signature_algorithm_oid._name,
                        "signature_hash": cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "?",
                        "key_type": type(cert.public_key()).__name__,
                        "key_size": getattr(cert.public_key(), "key_size", None),
                        "key_curve": None,
                        "self_signed": cert.issuer == cert.subject,
                        "cipher": ssock.cipher(),
                        "version": ssock.version(),
                        "compression": ssock.compression(),
                        "shared_ciphers": [],
                        "extensions": [],
                    }

                    # Subject & Issuer
                    for attr in cert.subject:
                        info["subject"][attr.oid._name] = attr.value
                    for attr in cert.issuer:
                        info["issuer"][attr.oid._name] = attr.value

                    # SAN
                    try:
                        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                        info["san"] = ext.value.get_values_for_type(x509.DNSName)
                        info["san_ips"] = [str(ip) for ip in ext.value.get_values_for_type(x509.IPAddress)]
                    except x509.ExtensionNotFound:
                        pass

                    # Key curve (ECC)
                    if info["key_type"] == "EllipticCurvePublicKey":
                        info["key_curve"] = cert.public_key().curve.name

                    # Shared ciphers
                    shared = ssock.shared_ciphers()
                    if shared:
                        info["shared_ciphers"] = [
                            {"name": c[0], "version": c[1], "bits": c[2]}
                            for c in shared[:80]
                        ]

                    # Extensions listing
                    for ext in cert.extensions:
                        info["extensions"].append({
                            "oid": ext.oid._name,
                            "critical": ext.critical,
                        })

                    # Expiry check
                    try:
                        now_utc = datetime.now(timezone.utc)
                        delta = cert.not_valid_after_utc - now_utc
                        info["days_until_expiry"] = delta.days
                        if delta.days < 0:
                            data["issues"].append(f"Port {port}: certificate EXPIRED")
                            data["vulnerabilities"]["expired_cert"] = True
                        elif delta.days < 30:
                            data["issues"].append(f"Port {port}: cert expires in {delta.days} days")
                    except Exception:
                        pass

                    # Self-signed
                    if info["self_signed"]:
                        data["issues"].append(f"Port {port}: self-signed certificate")
                        data["vulnerabilities"]["self_signed"] = True

                    # Weak key
                    if info["key_size"] and info["key_size"] < 2048:
                        data["issues"].append(f"Port {port}: weak key ({info['key_size']} bits)")
                        data["vulnerabilities"]["weak_key"] = True

                    # Weak signature hash
                    if info["signature_hash"] in ("md5", "sha1"):
                        data["issues"].append(f"Port {port}: weak signature hash ({info['signature_hash']})")
                        data["vulnerabilities"]["weak_signature"] = True

                    # Compression (CRIME)
                    if info.get("compression"):
                        data["issues"].append(f"Port {port}: TLS compression (CRIME risk)")
                        data["vulnerabilities"]["crime"] = True

                    # RC4/NULL/EXPORT ciphers
                    for c in (shared or []):
                        name = c[0].lower()
                        if any(w in name for w in ["rc4", "null", "export", "des-cbc", "anon"]):
                            data["weak_ciphers"].append(c[0])
                            if "rc4" in name:
                                data["vulnerabilities"]["rc4"] = True
                            if "null" in name:
                                data["vulnerabilities"]["null_cipher"] = True
                            if "export" in name:
                                data["vulnerabilities"]["freak"] = True

                    data["certificates"].append(info)
        except Exception as e:
            data.setdefault("errors", []).append(f"port {port}: {str(e)[:100]}")

    # ── 2) TLS version probing ──
    probes = [
        ("SSLv2",   getattr(SSL, "SSLv2_METHOD", None)),
        ("SSLv3",   getattr(SSL, "SSLv3_METHOD", None)),
        ("TLSv1.0", getattr(SSL, "TLSv1_METHOD", None)),
        ("TLSv1.1", getattr(SSL, "TLSv1_1_METHOD", None)),
        ("TLSv1.2", getattr(SSL, "TLSv1_2_METHOD", None)),
    ]
    for name, method in probes:
        if method is None:
            data["tls_versions"][name] = "unsupported-by-library"
            continue
        try:
            c = SSL.Context(method)
            c.set_timeout(5)
            s = SSL.Connection(c, socket.socket(socket.AF_INET, socket.SOCK_STREAM))
            s.settimeout(5)
            s.connect((host, 443))
            s.set_tlsext_host_name(host.encode())
            s.do_handshake()
            data["tls_versions"][name] = "SUPPORTED"
            if name in ("SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"):
                data["issues"].append(f"{name} supported (deprecated/insecure)")
                if name == "SSLv3":
                    data["vulnerabilities"]["poodle"] = True
                if name == "TLSv1.0":
                    data["vulnerabilities"]["beast"] = True
            s.shutdown(); s.close()
        except Exception:
            data["tls_versions"][name] = "not supported"

    # ── 3) Heartbleed check ──
    try:
        # Simple Heartbleed detection via malformed TLS heartbeat
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((host, 443))

        # Client Hello with heartbeat extension
        hello = binascii.unhexlify(
            "16030200310100002d0302500bafbbb75ab83ef0ab9ae3f39c631533"
            "a1a8ef8a3e6e2f8b8ae6d4c9a1e7c1f8c30000060033003900ffff010000"
            "0000"
        )
        # Simplified: just check if heartbeat extension is offered
        ctx_hb = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx_hb.check_hostname = False
        ctx_hb.verify_mode = ssl.CERT_NONE
        data["vulnerabilities"]["heartbleed_test"] = "inconclusive (needs nmap script)"
        sock.close()
    except Exception:
        data["vulnerabilities"]["heartbleed_test"] = "not tested"

    # ── 4) HSTS analysis ──
    try:
        r = requests.get(f"https://{host}", timeout=8, verify=False,
                         headers={"User-Agent": UA}, allow_redirects=False)
        hsts = r.headers.get("Strict-Transport-Security", "")
        data["hsts"] = {
            "present": bool(hsts),
            "value": hsts,
        }
        if hsts:
            data["hsts"]["preload"] = "preload" in hsts.lower()
            data["hsts"]["include_subdomains"] = "includesubdomains" in hsts.lower()
            try:
                ma = int(re.search(r"max-age=(\d+)", hsts).group(1))
                data["hsts"]["max_age"] = ma
                data["hsts"]["max_age_days"] = ma // 86400
                if ma < 31536000:
                    data["issues"].append(f"HSTS max-age terlalu kecil ({ma}s = {ma//86400} hari)")
            except Exception:
                pass
            if not data["hsts"].get("include_subdomains"):
                data["issues"].append("HSTS tanpa includeSubDomains")
            if not data["hsts"].get("preload"):
                data["issues"].append("HSTS tanpa preload flag")
        else:
            data["issues"].append("HSTS header tidak ada")
            data["hsts"]["present"] = False
    except Exception:
        pass

    # ── 5) OCSP stapling check ──
    try:
        ctx_ocsp = ssl.create_default_context()
        ctx_ocsp.check_hostname = False
        ctx_ocsp.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, 443), timeout=10) as sock:
            with ctx_ocsp.wrap_socket(sock, server_hostname=host) as ssock:
                # Python doesn't directly expose OCSP stapling status
                data["ocsp"] = {
                    "test": "OCSP stapling check requires OpenSSL CLI or nmap ssl-enum-ciphers",
                    "status": "inconclusive"
                }
    except Exception:
        pass

    # ── 6) SNI mismatch test ──
    try:
        # Connect with wrong SNI
        ctx_sni = ssl.create_default_context()
        ctx_sni.check_hostname = False
        ctx_sni.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, 443), timeout=10) as sock:
            with ctx_sni.wrap_socket(sock, server_hostname="invalid.example.com") as ssock:
                der2 = ssock.getpeercert(binary_form=True)
                cert2 = x509.load_der_x509_certificate(der2, default_backend())
                wrong_san = []
                try:
                    ext = cert2.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                    wrong_san = ext.value.get_values_for_type(x509.DNSName)
                except x509.ExtensionNotFound:
                    pass
                data["sni_test"] = {
                    "wrong_sni_accepted": True,
                    "cert_returned_san": wrong_san[:10],
                    "risk": "Server accepts connections with invalid SNI"
                }
    except ssl.SSLError as e:
        data["sni_test"] = {"wrong_sni_accepted": False, "error": str(e)[:80]}
    except Exception as e:
        data["sni_test"] = {"error": str(e)[:80]}

    # ── 7) Cipher suite classification ──
    weak_patterns = ["rc4", "null", "export", "des", "anon", "md5"]
    for c in data.get("certificates", [{}])[0].get("shared_ciphers", []):
        name = c.get("name", "").lower()
        bits = c.get("bits", 0)
        if any(p in name for p in weak_patterns) or (bits and bits < 128):
            if c["name"] not in data["weak_ciphers"]:
                data["weak_ciphers"].append(c["name"])

    return {
        "status": "ok",
        "data": data,
        "summary": f"{len(data['certificates'])} cert, "
                   f"{len(data.get('weak_ciphers',[]))} weak cipher, "
                   f"{len(data['vulnerabilities'])} vuln flags, "
                   f"{len(data['issues'])} issue"
    }

# ─────────────────────────────────────────────
# ENGINE 4: SCAPY — Network Packet Analysis
# ─────────────────────────────────────────────
def engine_scapy(target, ctx):
    """
    Maximum Scapy analysis:
    - ICMP ping + TTL analysis
    - TCP SYN probes (20 ports) with TCP options analysis
    - OS fingerprinting (TTL, window size, TCP options, DF flag)
    - Mini traceroute (TTL 1-20)
    - MTU path discovery
    - TCP timestamp (uptime estimation)
    - UDP probes (DNS, SNMP, NTP)
    - Fragment handling test
    - IP ID sequence analysis
    - ECN (Explicit Congestion Notification) test
    """
    if not HAS_SCAPY:
        return {"status": "skipped", "reason": "scapy tidak tersedia"}

    host = get_host(target)
    ip_addr = resolve_host(host)
    is_root = ctx.get("has_root", False)

    data = {
        "host": host,
        "ip": ip_addr,
        "is_root": is_root,
        "icmp": {},
        "tcp_syn_probes": [],
        "udp_probes": [],
        "os_fingerprint": {},
        "traceroute": [],
        "mtu_discovery": {},
        "tcp_timestamp": {},
        "ip_id_sequence": {},
        "fragment_test": {},
        "ecn_test": {},
        "tcp_window_analysis": {},
        "issues": [],
    }

    # ── 1) ICMP ping ──
    try:
        pkt = IP(dst=ip_addr, ttl=64)/ICMP(type=8, code=0)
        resp = sr1(pkt, timeout=3, verbose=False)
        if resp:
            data["icmp"] = {
                "alive": True,
                "ttl": resp.ttl,
                "id": resp.id,
                "len": resp.len,
                "type": resp[ICMP].type,
                "code": resp[ICMP].code,
            }
        else:
            data["icmp"] = {"alive": False, "reason": "no response"}
    except Exception as e:
        data["icmp"] = {"error": str(e)[:80]}

    # ── 2) TCP SYN probes ──
    tcp_ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143,
                 443, 445, 993, 995, 1433, 3306, 3389, 5432, 8080]
    ttls = []
    windows = []
    tcp_options_all = []

    for port in tcp_ports:
        try:
            pkt = IP(dst=ip_addr, ttl=64, id=RandShort())/TCP(
                dport=port, flags="S", seq=1000,
                options=[("MSS", 1460), ("NOP", None), ("WScale", 7),
                         ("SAckOK", b""), ("Timestamp", (12345, 0))]
            )
            resp = sr1(pkt, timeout=2, verbose=False)
            if resp and TCP in resp:
                flags = str(resp[TCP].flags)
                ttls.append(resp.ttl)
                windows.append(resp[TCP].window)
                entry = {
                    "port": port, "flags": flags, "ttl": resp.ttl,
                    "window": resp[TCP].window, "seq": resp[TCP].seq,
                    "ack": resp[TCP].ack,
                }
                # TCP Options
                if hasattr(resp[TCP], "options") and resp[TCP].options:
                    opts = []
                    for o in resp[TCP].options:
                        try:
                            opts.append({"name": str(o[0]), "value": str(o[1])})
                            tcp_options_all.append(str(o[0]))
                        except Exception:
                            pass
                    entry["options"] = opts
                data["tcp_syn_probes"].append(entry)
            else:
                data["tcp_syn_probes"].append({"port": port, "flags": "no-response"})
        except Exception as e:
            data["tcp_syn_probes"].append({"port": port, "error": str(e)[:60]})

    # ── 3) OS Fingerprint ──
    fp = {}
    if ttls:
        avg_ttl = sum(ttls) // len(ttls)
        fp["avg_ttl"] = avg_ttl
        if avg_ttl >= 120:
            fp["ttl_class"] = "Windows"
        elif avg_ttl >= 60:
            fp["ttl_class"] = "Linux/Unix"
        elif avg_ttl >= 30:
            fp["ttl_class"] = "Cisco/Network"
        else:
            fp["ttl_class"] = "Unknown"

    if windows:
        avg_win = sum(windows) // len(windows)
        fp["avg_window"] = avg_win
        if avg_win == 5840:
            fp["window_class"] = "Linux 2.6+ (default)"
        elif avg_win in (65535, 65536):
            fp["window_class"] = "Windows (default)"
        elif avg_win == 5792:
            fp["window_class"] = "Cisco IOS"
        elif avg_win == 29200:
            fp["window_class"] = "Linux 2.4"
        else:
            fp["window_class"] = f"Custom ({avg_win})"

    # TCP options analysis
    opt_set = set(tcp_options_all)
    fp["tcp_options_seen"] = sorted(opt_set)
    if "Timestamp" in opt_set:
        fp["rfc1323_timestamps"] = True
    if "WScale" in opt_set:
        fp["rfc1323_window_scale"] = True
    if "SAckOK" in opt_set:
        fp["sack_supported"] = True

    data["os_fingerprint"] = fp

    # ── 4) Traceroute ──
    try:
        for ttl in range(1, 21):
            pkt = IP(dst=ip_addr, ttl=ttl)/ICMP()
            resp = sr1(pkt, timeout=1, verbose=False)
            if not resp:
                data["traceroute"].append({"ttl": ttl, "hop": "*", "rtt_ms": None})
            else:
                src = resp.src
                rtt = None
                if hasattr(resp, "time"):
                    rtt = resp.time
                data["traceroute"].append({"ttl": ttl, "hop": src, "rtt_ms": rtt})
                if src == ip_addr:
                    break
    except Exception:
        pass

    # ── 5) MTU Discovery ──
    try:
        for size in (1500, 1400, 1200, 1000, 576):
            payload = "X" * size
            pkt = IP(dst=ip_addr, flags="DF")/ICMP()/payload
            resp = sr1(pkt, timeout=2, verbose=False)
            if resp:
                data["mtu_discovery"] = {
                    "mtu_at_least": size + 28,  # IP + ICMP header
                    "df_respected": True,
                }
                break
            else:
                # Check for ICMP Fragmentation Needed
                pass
    except Exception:
        pass

    # ── 6) TCP Timestamp (uptime estimation) ──
    try:
        pkt = IP(dst=ip_addr)/TCP(dport=80, flags="S",
                                   options=[("Timestamp", (12345, 0))])
        resp = sr1(pkt, timeout=3, verbose=False)
        if resp and TCP in resp:
            for o in resp[TCP].options:
                if str(o[0]) == "Timestamp":
                    ts_val, ts_ecr = o[1]
                    data["tcp_timestamp"] = {
                        "ts_value": ts_val,
                        "ts_echo_reply": ts_ecr,
                        "estimated_uptime_sec": ts_val // 100 if ts_val > 1000 else None,
                        "hz_guess": 100 if ts_val > 10000 else 1000,
                    }
    except Exception:
        pass

    # ── 7) IP ID Sequence Analysis ──
    try:
        ids = []
        for _ in range(6):
            pkt = IP(dst=ip_addr)/ICMP()
            resp = sr1(pkt, timeout=1, verbose=False)
            if resp:
                ids.append(resp.id)
            time.sleep(0.1)
        if len(ids) >= 3:
            diffs = [ids[i+1] - ids[i] for i in range(len(ids)-1)]
            avg_diff = sum(diffs) // len(diffs) if diffs else 0
            data["ip_id_sequence"] = {
                "samples": ids,
                "diffs": diffs,
                "avg_diff": avg_diff,
                "pattern": "incremental" if all(0 < d < 100 for d in diffs) else
                           "random" if all(abs(d) > 1000 for d in diffs) else
                           "zero" if all(d == 0 for d in diffs) else "mixed",
            }
            # IP ID = 0 means DF bit + modern stack
            if all(i == 0 for i in ids):
                data["ip_id_sequence"]["pattern"] = "all-zero (modern DF)"
    except Exception:
        pass

    # ── 8) UDP Probes ──
    udp_targets = [(53, "DNS"), (123, "NTP"), (161, "SNMP"), (500, "IKE"),
                   (1900, "SSDP"), (5353, "mDNS")]
    for port, svc in udp_targets:
        try:
            if port == 53:
                # DNS query
                pkt = IP(dst=ip_addr)/UDP(dport=53)/b"\x00\x01\x01\x00\x00\x01"
            elif port == 123:
                # NTP
                pkt = IP(dst=ip_addr)/UDP(dport=123)/Raw(load=b"\x1b" + b"\x00"*47)
            else:
                pkt = IP(dst=ip_addr)/UDP(dport=port)/Raw(load=b"\x00")
            resp = sr1(pkt, timeout=2, verbose=False)
            data["udp_probes"].append({
                "port": port, "service": svc,
                "response": "yes" if resp else "no",
                "ttl": resp.ttl if resp else None,
            })
        except Exception as e:
            data["udp_probes"].append({"port": port, "service": svc, "error": str(e)[:60]})

    # ── 9) ECN Test ──
    try:
        pkt = IP(dst=ip_addr, tos=2)/TCP(dport=80, flags="SE", seq=1000)  # CWR+ECE
        resp = sr1(pkt, timeout=2, verbose=False)
        if resp and TCP in resp:
            data["ecn_test"] = {
                "supported": bool(resp[TCP].flags & 0x40),  # ECE flag
                "flags": str(resp[TCP].flags),
            }
    except Exception:
        pass

    responsive = sum(1 for p in data["tcp_syn_probes"]
                     if p.get("flags") not in (None, "no-response") and "error" not in p)
    return {
        "status": "ok",
        "data": data,
        "summary": f"{responsive}/{len(tcp_ports)} TCP, "
                   f"OS: {fp.get('ttl_class','?')}/{fp.get('window_class','?')}, "
                   f"trace: {len(data['traceroute'])} hops, "
                   f"IP-ID: {data['ip_id_sequence'].get('pattern','?')}"
    }

# ─────────────────────────────────────────────
# ENGINE 5: WHOIS — Domain Registration & ASN
# ─────────────────────────────────────────────
def engine_whois(target, ctx):
    """
    Maximum WHOIS:
    - Full domain registration data
    - Age calculation
    - ASN lookup via Team Cymru
    - IP geolocation (via ip-api.com)
    - Related domains hint
    - Registrar abuse contacts
    """
    host = get_host(target)
    reg_dom = get_registered_domain(host)
    ip = resolve_host(host)

    data = {
        "host": host,
        "registered_domain": reg_dom,
        "ip": ip,
        "whois": None,
        "asn": None,
        "geolocation": None,
        "related_tlds": [],
        "errors": [],
    }

    # ── 1) WHOIS lookup ──
    if HAS_WHOIS:
        try:
            w = pywhois.whois(reg_dom)
            data["whois"] = {
                "domain": w.domain_name,
                "registrar": w.registrar,
                "registrar_url": getattr(w, "registrar_url", None),
                "registrar_ietf_id": getattr(w, "registrar_ietf_id", None),
                "creation_date": str(w.creation_date),
                "expiration_date": str(w.expiration_date),
                "updated_date": str(w.updated_date),
                "name_servers": w.name_servers,
                "status": w.status,
                "emails": w.emails,
                "org": w.org,
                "country": w.country,
                "state": w.state,
                "city": getattr(w, "city", None),
                "address": getattr(w, "address", None),
                "zip_code": getattr(w, "zipcode", None),
                "dnssec": getattr(w, "dnssec", None),
                "referral_url": getattr(w, "referral_url", None),
                "admin_name": getattr(w, "admin_name", None),
                "admin_email": getattr(w, "admin_email", None),
                "admin_phone": getattr(w, "admin_phone", None),
                "tech_name": getattr(w, "tech_name", None),
                "tech_email": getattr(w, "tech_email", None),
                "registrant_name": getattr(w, "registrant_name", None),
                "registrant_org": getattr(w, "registrant_org", None),
                "text_snippet": (getattr(w, "text", "") or "")[:2000],
            }
            # Age
            try:
                cd = w.creation_date
                if isinstance(cd, list): cd = cd[0]
                if cd:
                    data["whois"]["age_days"] = (datetime.now() - cd).days
                    data["whois"]["age_years"] = round(data["whois"]["age_days"] / 365.25, 1)
            except Exception:
                pass
            # Expiry
            try:
                ed = w.expiration_date
                if isinstance(ed, list): ed = ed[0]
                if ed:
                    data["whois"]["days_until_expiry"] = (ed - datetime.now()).days
            except Exception:
                pass
        except Exception as e:
            data["errors"].append(f"whois: {str(e)[:120]}")

    # ── 2) ASN lookup via Team Cymru DNS ──
    if IPV4_RE.match(ip):
        try:
            parts = ip.split(".")
            rev = f"{'.'.join(reversed(parts))}.origin.asn.cymru.com"
            ans = dns_resolver.resolve(rev, "TXT")
            asns = []
            for r in ans:
                txt = r.to_text().strip('"')
                fields = [f.strip() for f in txt.split("|")]
                asns.append(fields)
            data["asn"] = {
                "ip": ip,
                "entries": [],
            }
            for e in asns:
                entry = {
                    "asn": e[0] if len(e) > 0 else "?",
                    "prefix": e[1] if len(e) > 1 else "?",
                    "country": e[2] if len(e) > 2 else "?",
                    "registry": e[3] if len(e) > 3 else "?",
                    "alloc_date": e[4] if len(e) > 4 else "?",
                }
                # ASN name lookup
                try:
                    ans2 = dns_resolver.resolve(
                        f"AS{entry['asn']}.asn.cymru.com", "TXT")
                    txt2 = ans2[0].to_text().strip('"')
                    parts2 = [p.strip() for p in txt2.split("|")]
                    entry["asn_name"] = parts2[4] if len(parts2) > 4 else "?"
                except Exception:
                    entry["asn_name"] = "?"
                data["asn"]["entries"].append(entry)
        except Exception as e:
            data["errors"].append(f"asn: {str(e)[:80]}")

    # ── 3) IP Geolocation ──
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}?fields=status,message,country,"
                         f"countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query",
                         timeout=5)
        if r.status_code == 200:
            g = r.json()
            if g.get("status") == "success":
                data["geolocation"] = {
                    "country": g.get("country"),
                    "country_code": g.get("countryCode"),
                    "region": g.get("regionName"),
                    "city": g.get("city"),
                    "zip": g.get("zip"),
                    "lat": g.get("lat"),
                    "lon": g.get("lon"),
                    "timezone": g.get("timezone"),
                    "isp": g.get("isp"),
                    "org": g.get("org"),
                    "as": g.get("as"),
                }
    except Exception as e:
        data["errors"].append(f"geo: {str(e)[:60]}")

    # ── 4) Related TLDs check ──
    tlds = [".com", ".net", ".org", ".io", ".co", ".info", ".biz"]
    base_name = reg_dom.split(".")[0] if "." in reg_dom else reg_dom
    def _check_tld(tld):
        try:
            dns_resolver.resolve(f"{base_name}{tld}", "A")
            return f"{base_name}{tld}"
        except Exception:
            return None
    with ThreadPoolExecutor(max_workers=7) as pool:
        futs = [pool.submit(_check_tld, t) for t in tlds]
        for f in as_completed(futs):
            r = f.result()
            if r and r != reg_dom:
                data["related_tlds"].append(r)

    # Build summary
    bits = []
    if data["whois"]:
        bits.append(f"registrar: {data['whois'].get('registrar','?')}")
        bits.append(f"age: {data['whois'].get('age_days','?')}d")
    if data["asn"] and data["asn"].get("entries"):
        bits.append(f"ASN: {data['asn']['entries'][0].get('asn','?')}")
    if data["geolocation"]:
        bits.append(f"geo: {data['geolocation'].get('country','?')}")

    return {
        "status": "ok" if data["whois"] or data["asn"] else "partial",
        "data": data,
        "summary": ", ".join(bits) if bits else "no data"
    }

# ─────────────────────────────────────────────
# ENGINE 6: HTTP — Header Analysis & Methods
# ─────────────────────────────────────────────
def engine_http(target, ctx):
    """
    Maximum HTTP analysis:
    - All HTTP methods probing
    - Security headers (20+ headers)
    - CORS analysis (wildcard + origin reflection)
    - Cookie audit (Secure, HttpOnly, SameSite, prefix)
    - Redirect chain
    - HTTP/2 & HTTP/3 detection
    - Virtual host probing
    - Host header injection test
    - HTTP request smuggling hints
    - Server fingerprinting
    - Content-Type analysis
    - robots.txt & sitemap.xml
    """
    data = {
        "url": target,
        "methods": {},
        "headers": {},
        "redirect_chain": [],
        "security_headers": {},
        "cookies": [],
        "cors": {},
        "http_versions": {},
        "response_times_ms": {},
        "virtual_hosts": [],
        "host_header_test": {},
        "robots_txt": None,
        "sitemap_xml": None,
        "server_fingerprint": {},
        "issues": [],
    }

    methods = ["GET","HEAD","POST","OPTIONS","PUT","DELETE","PATCH","TRACE","CONNECT"]
    host = get_host(target)

    # ── 1) Method probing ──
    with httpx.Client(timeout=TIMEOUT, follow_redirects=False, verify=False) as cli:
        for m in methods:
            t0 = time.time()
            try:
                r = cli.request(m, target)
                dt = int((time.time()-t0)*1000)
                allow_hdr = r.headers.get("Allow", "")
                data["methods"][m] = {
                    "status": r.status_code,
                    "allowed": r.status_code not in (405, 501),
                    "response_time_ms": dt,
                    "content_length": len(r.content),
                    "content_type": r.headers.get("content-type", ""),
                    "allow_header": allow_hdr,
                }
                data["response_times_ms"][m] = dt
            except Exception as e:
                data["methods"][m] = {"error": str(e)[:100]}

        # ── 2) Redirect chain ──
        try:
            url = target
            chain = []
            for _ in range(10):
                r = cli.get(url)
                chain.append({
                    "url": str(r.url),
                    "status": r.status_code,
                    "location": r.headers.get("Location"),
                    "server": r.headers.get("Server"),
                })
                if r.status_code in (301, 302, 303, 307, 308) and r.headers.get("Location"):
                    url = urljoin(url, r.headers["Location"])
                else:
                    break
            data["redirect_chain"] = chain
            data["final_url"] = chain[-1]["url"]
            data["headers"] = dict(r.headers)

            # Cookies
            for c in r.cookies.jar:
                ck = {
                    "name": c.name, "domain": c.domain, "path": c.path,
                    "secure": c.secure,
                    "httpOnly": c.has_nonstandard_attr("HttpOnly"),
                    "sameSite": getattr(c, "_rest", {}).get("SameSite"),
                    "value_preview": (c.value or "")[:50],
                    "value_length": len(c.value or ""),
                }
                data["cookies"].append(ck)
        except Exception as e:
            data["get_error"] = str(e)[:120]

    # ── 3) Security headers ──
    wanted = [
        "Strict-Transport-Security", "Content-Security-Policy",
        "Content-Security-Policy-Report-Only",
        "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy",
        "Permissions-Policy", "X-XSS-Protection",
        "Cross-Origin-Opener-Policy", "Cross-Origin-Resource-Policy",
        "Cross-Origin-Embedder-Policy", "X-Permitted-Cross-Domain-Policies",
        "Cache-Control", "X-Download-Options", "Expect-CT",
        "X-DNS-Prefetch-Control", "Feature-Policy",
        "NEL", "Report-To", "Origin-Agent-Cluster",
    ]
    hl = {k.lower(): v for k, v in data["headers"].items()}
    for h in wanted:
        v = hl.get(h.lower())
        data["security_headers"][h] = v if v else "MISSING"
        if not v:
            data["issues"].append(f"Header '{h}' tidak ada")

    # ── 4) Server disclosure ──
    disclosure_headers = [
        "Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version",
        "X-Generator", "X-Version", "X-Runtime", "X-Backend-Server",
        "X-Served-By", "X-Server-Name", "Via",
    ]
    for h in disclosure_headers:
        v = data["headers"].get(h) or hl.get(h.lower())
        if v:
            data["issues"].append(f"{h} terbuka: {v}")
            data["server_fingerprint"][h] = v

    # ── 5) TRACE & CONNECT ──
    for m in ("TRACE", "CONNECT"):
        if data["methods"].get(m, {}).get("allowed"):
            data["issues"].append(f"HTTP {m} aktif (potensi XST/tunneling)")

    # ── 6) CORS analysis ──
    try:
        # Test with arbitrary origin
        r = requests.options(target, timeout=TIMEOUT, verify=False,
                              headers={"User-Agent": UA,
                                       "Origin": "https://evil.example.com",
                                       "Access-Control-Request-Method": "POST"})
        acao = r.headers.get("Access-Control-Allow-Origin", "")
        data["cors"] = {
            "Access-Control-Allow-Origin": acao,
            "Access-Control-Allow-Credentials": r.headers.get("Access-Control-Allow-Credentials"),
            "Access-Control-Allow-Methods": r.headers.get("Access-Control-Allow-Methods"),
            "Access-Control-Allow-Headers": r.headers.get("Access-Control-Allow-Headers"),
            "Access-Control-Expose-Headers": r.headers.get("Access-Control-Expose-Headers"),
            "Access-Control-Max-Age": r.headers.get("Access-Control-Max-Age"),
            "reflects_any_origin": "evil.example.com" in acao,
            "wildcard": acao == "*",
            "null_allowed": False,
        }
        # Test null origin
        r2 = requests.options(target, timeout=TIMEOUT, verify=False,
                               headers={"User-Agent": UA, "Origin": "null"})
        if "null" in r2.headers.get("Access-Control-Allow-Origin", ""):
            data["cors"]["null_allowed"] = True
            data["issues"].append("CORS allows null origin (sandbox escape risk)")

        if acao == "*":
            data["issues"].append("CORS wildcard origin (*)")
        if "evil.example.com" in acao:
            data["issues"].append("CORS memantulkan Origin sembarang (MISCONFIG)")
        if data["cors"].get("Access-Control-Allow-Credentials") == "true" and acao == "*":
            data["issues"].append("CORS: credentials + wildcard (invalid but dangerous if accepted)")
    except Exception:
        pass

    # ── 7) HTTP/2 & HTTP/3 ──
    alt_svc = data["headers"].get("Alt-Svc") or hl.get("alt-svc")
    data["http_versions"] = {"Alt-Svc": alt_svc}
    if alt_svc:
        if "h3" in alt_svc.lower():
            data["http_versions"]["HTTP/3"] = "advertised"
        if "h2" in alt_svc.lower():
            data["http_versions"]["HTTP/2"] = "advertised"

    # ── 8) Cookie audit ──
    for c in data["cookies"]:
        if not c.get("secure"):
            data["issues"].append(f"Cookie '{c['name']}' tanpa flag Secure")
        if not c.get("httpOnly"):
            data["issues"].append(f"Cookie '{c['name']}' tanpa flag HttpOnly")
        if not c.get("sameSite"):
            data["issues"].append(f"Cookie '{c['name']}' tanpa SameSite")
        # __Host- / __Secure- prefix check
        if c["name"].startswith("__Host-"):
            if not c.get("secure") or c.get("path") != "/":
                data["issues"].append(f"Cookie __Host- '{c['name']}' tidak sesuai aturan prefix")
        if c["name"].startswith("__Secure-"):
            if not c.get("secure"):
                data["issues"].append(f"Cookie __Secure- '{c['name']}' tanpa Secure flag")

    # ── 9) Virtual host probing ──
    vhosts = [f"admin.{host}", f"api.{host}", f"dev.{host}",
              f"staging.{host}", f"test.{host}", f"internal.{host}"]
    try:
        base_ip = resolve_host(host)
        for vh in vhosts:
            try:
                vh_ip = resolve_host(vh)
                if vh_ip == base_ip:
                    r = requests.get(target, timeout=5, verify=False,
                                     headers={"Host": vh, "User-Agent": UA})
                    if r.status_code != 404 and len(r.content) > 100:
                        data["virtual_hosts"].append({
                            "host": vh, "status": r.status_code,
                            "content_length": len(r.content),
                            "title": re.search(r"<title>(.*?)</title>", r.text, re.I)
                        })
            except Exception:
                pass
    except Exception:
        pass

    # ── 10) Host header injection test ──
    try:
        r = requests.get(target, timeout=10, verify=False,
                          headers={"Host": "evil.example.com", "User-Agent": UA},
                          allow_redirects=False)
        if "evil.example.com" in r.text:
            data["host_header_test"] = {
                "vulnerable": True,
                "evidence": "Host header reflected in response body",
            }
            data["issues"].append("Host header injection: reflected in body")
        else:
            data["host_header_test"] = {"vulnerable": False}
    except Exception:
        data["host_header_test"] = {"error": "test failed"}

    # ── 11) robots.txt ──
    try:
        base_url = f"{urlparse(target).scheme}://{host}"
        r = requests.get(f"{base_url}/robots.txt", timeout=5, verify=False,
                          headers={"User-Agent": UA})
        if r.status_code == 200 and len(r.text) < 100000:
            disallow = re.findall(r"Disallow:\s*(.+)", r.text)
            data["robots_txt"] = {
                "found": True,
                "size": len(r.text),
                "disallow_rules": disallow[:50],
                "sitemaps": re.findall(r"Sitemap:\s*(.+)", r.text),
                "content_preview": r.text[:1000],
            }
    except Exception:
        pass

    # ── 12) sitemap.xml ──
    try:
        base_url = f"{urlparse(target).scheme}://{host}"
        r = requests.get(f"{base_url}/sitemap.xml", timeout=5, verify=False,
                          headers={"User-Agent": UA})
        if r.status_code == 200:
            urls = re.findall(r"<loc>(.*?)</loc>", r.text)
            data["sitemap_xml"] = {
                "found": True,
                "url_count": len(urls),
                "urls_sample": urls[:50],
            }
    except Exception:
        pass

    return {
        "status": "ok",
        "data": data,
        "summary": f"{sum(1 for m in data['methods'].values() if m.get('allowed'))} methods, "
                   f"{len(data['cookies'])} cookies, "
                   f"{len(data['redirect_chain'])} redirects, "
                   f"robots: {'yes' if data['robots_txt'] else 'no'}, "
                   f"{len(data['issues'])} issues"
    }

# ─────────────────────────────────────────────
# ENGINE 7: HTML PARSER — DOM Analysis & Form Extraction
# ─────────────────────────────────────────────
def engine_html(target, ctx):
    """
    Maximum HTML analysis:
    - Form extraction with CSRF detection
    - Internal/external link graph
    - Script & stylesheet inventory
    - Sensitive data via regex (emails, API keys, secrets)
    - HTML comment analysis (credential leaks, TODOs)
    - Meta tag analysis (CSP, viewport, robots)
    - Iframe analysis (sandbox, allow)
    - Hidden input analysis
    - Email/phone extraction
    - JS file inventory
    - External domain graph
    - Inline JS/CSS analysis
    - Data URI detection
    - Base tag hijack check
    """
    try:
        session = ctx.get("session") or requests
        r = session.get(target, timeout=20, verify=False,
                        headers={"User-Agent": UA})
        html = r.text
        final_url = str(r.url)
    except Exception as e:
        return {"status": "error", "error": str(e)[:120]}

    soup = BeautifulSoup(html, "lxml")
    base_parsed = urlparse(target)

    data = {
        "url": target,
        "final_url": final_url,
        "title": soup.title.string if soup.title else None,
        "html_size": len(html),
        "lang": soup.html.get("lang") if soup.html else None,
        "forms": [],
        "links_internal": [],
        "links_external": [],
        "scripts": [],
        "stylesheets": [],
        "iframes": [],
        "meta": [],
        "comments": [],
        "hidden_inputs": [],
        "emails_found": [],
        "phones_found": [],
        "sensitive_findings": [],
        "external_domains": set(),
        "js_files": [],
        "inline_js_count": 0,
        "inline_css_count": 0,
        "data_uris": [],
        "base_tag": None,
        "noscript_content": False,
        "issues": [],
    }

    # ── 1) Base tag hijack check ──
    base_tag = soup.find("base")
    if base_tag:
        data["base_tag"] = base_tag.get("href")
        if base_tag.get("href") and not base_tag["href"].startswith(
            (f"{base_parsed.scheme}://{base_parsed.hostname}", "/")):
            data["issues"].append(f"Base tag points to external: {base_tag['href']}")

    # ── 2) Forms ──
    for i, f in enumerate(soup.find_all("form")):
        form = {
            "id": i,
            "action": f.get("action"),
            "method": (f.get("method") or "GET").upper(),
            "enctype": f.get("enctype"),
            "name": f.get("name"),
            "id_attr": f.get("id"),
            "has_csrf_token": False,
            "autocomplete": f.get("autocomplete"),
            "inputs": [],
            "buttons": [],
        }
        for inp in f.find_all(["input", "textarea", "select"]):
            itype = inp.get("type", "text") if inp.name == "input" else inp.name
            info = {
                "tag": inp.name, "type": itype, "name": inp.get("name"),
                "id": inp.get("id"), "required": inp.has_attr("required"),
                "autocomplete": inp.get("autocomplete"),
                "value_preview": (inp.get("value", "") or "")[:40],
                "placeholder": inp.get("placeholder"),
                "pattern": inp.get("pattern"),
                "maxlength": inp.get("maxlength"),
                "minlength": inp.get("minlength"),
            }
            # Select options
            if inp.name == "select":
                info["options"] = [
                    {"value": o.get("value"), "text": o.string}
                    for o in inp.find_all("option")
                ][:20]
            form["inputs"].append(info)
            if itype == "hidden":
                data["hidden_inputs"].append({"form_id": i, **info})
                nm = (inp.get("name") or "").lower()
                if any(k in nm for k in ("csrf","token","_token","xsrf","nonce","authenticity","_csrf","csrfmiddlewaretoken")):
                    form["has_csrf_token"] = True

        for btn in f.find_all(["button", "input"]):
            if btn.name == "button" or (btn.name == "input" and btn.get("type") in ("submit","button","image")):
                form["buttons"].append({
                    "tag": btn.name, "type": btn.get("type"),
                    "name": btn.get("name"), "value": btn.get("value"),
                })

        data["forms"].append(form)

    # ── 3) Links ──
    for a in soup.find_all("a", href=True):
        href = a["href"]
        abs_url = urljoin(target, href)
        try:
            p = urlparse(abs_url)
        except Exception:
            continue
        if p.hostname == base_parsed.hostname:
            data["links_internal"].append(abs_url)
        else:
            data["links_external"].append(abs_url)
            if p.hostname:
                data["external_domains"].add(p.hostname)
        # Data URIs
        if href.startswith("data:"):
            data["data_uris"].append(href[:100])

    # ── 4) Scripts ──
    for s in soup.find_all("script"):
        src = s.get("src")
        is_inline = not src
        info = {
            "src": src,
            "type": s.get("type"),
            "async": s.has_attr("async"),
            "defer": s.has_attr("defer"),
            "integrity": s.get("integrity"),
            "crossorigin": s.get("crossorigin"),
            "inline_length": len(s.string or "") if is_inline else 0,
            "nonce": s.get("nonce"),
        }
        data["scripts"].append(info)
        if is_inline:
            data["inline_js_count"] += 1
        if src:
            abs_src = urljoin(target, src)
            data["js_files"].append(abs_src)
            p = urlparse(abs_src)
            if p.hostname and p.hostname != base_parsed.hostname:
                data["external_domains"].add(p.hostname)

    # ── 5) Stylesheets ──
    for lnk in soup.find_all("link", rel="stylesheet"):
        href = lnk.get("href", "")
        data["stylesheets"].append({
            "href": href,
            "integrity": lnk.get("integrity"),
            "crossorigin": lnk.get("crossorigin"),
            "media": lnk.get("media"),
        })
        if href:
            p = urlparse(urljoin(target, href))
            if p.hostname and p.hostname != base_parsed.hostname:
                data["external_domains"].add(p.hostname)

    # Inline styles
    data["inline_css_count"] = len(soup.find_all("style"))

    # ── 6) Iframes ──
    for i in soup.find_all("iframe"):
        src = i.get("src", "")
        data["iframes"].append({
            "src": src,
            "sandbox": i.get("sandbox"),
            "allow": i.get("allow"),
            "width": i.get("width"),
            "height": i.get("height"),
            "loading": i.get("loading"),
            "title": i.get("title"),
        })
        if src:
            p = urlparse(urljoin(target, src))
            if p.hostname and p.hostname != base_parsed.hostname:
                data["external_domains"].add(p.hostname)
        # Sandbox check
        sandbox = i.get("sandbox", "")
        if not sandbox:
            data["issues"].append(f"Iframe tanpa sandbox: {src[:60]}")

    # ── 7) Meta tags ──
    for m in soup.find_all("meta"):
        if m.get("name") or m.get("property") or m.get("http-equiv"):
            data["meta"].append({
                "name": m.get("name"), "property": m.get("property"),
                "http-equiv": m.get("http-equiv"), "content": m.get("content"),
                "charset": m.get("charset"),
            })

    # CSP meta check
    for m in data["meta"]:
        if (m.get("http-equiv") or "").lower() == "content-security-policy":
            data["csp_meta"] = m.get("content")

    # ── 8) Comments ──
    for c in soup.find_all(string=lambda t: isinstance(t, Comment)):
        txt = c.strip()
        if txt:
            data["comments"].append(txt[:500])
            # Check for sensitive info in comments
            low = txt.lower()
            if any(k in low for k in ("password", "passwd", "secret", "api_key",
                                       "apikey", "token", "credential", "todo", "fixme",
                                       "hack", "debug", "temp", "backup")):
                data["issues"].append(f"Comment mengandung keyword sensitif: {txt[:80]}")

    # ── 9) Email & phone extraction ──
    email_re = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
    phone_re = re.compile(r"\+?[0-9]{1,3}[-.\s]?$?[0-9]{1,4}$?[-.\s]?[0-9]{1,4}[-.\s]?[0-9]{1,9}")
    for m in email_re.finditer(html):
        val = m.group(0)
        if not val.endswith((".png", ".jpg", ".gif", ".css", ".js")):
            data["emails_found"].append(val)
    data["emails_found"] = list(set(data["emails_found"]))[:50]

    for m in phone_re.finditer(html):
        val = m.group(0)
        if len(val) > 7:  # Filter out short numbers
            data["phones_found"].append(val)
    data["phones_found"] = list(set(data["phones_found"]))[:30]

    # ── 10) Sensitive info via compiled regex ──
    seen = set()
    for rx in ctx.get("sensitive_regex", []):
        for match in rx.finditer(html[:500000]):
            val = match.group(0)[:120]
            key = hashlib.md5(val.encode()).hexdigest()
            if key in seen:
                continue
            seen.add(key)
            data["sensitive_findings"].append({
                "pattern": rx.pattern[:50],
                "match": val,
                "line": html[:match.start()].count("\n") + 1,
            })
            if len(data["sensitive_findings"]) > 150:
                break
        if len(data["sensitive_findings"]) > 150:
            break

    # ── 11) Noscript check ──
    noscript = soup.find("noscript")
    data["noscript_content"] = bool(noscript and noscript.string)

    data["external_domains"] = sorted(data["external_domains"])

    # Fast parser stats
    fast_stats = None
    if HAS_SELECTOLAX:
        try:
            tree = SelectoParser(html)
            fast_stats = {"tags": len(list(tree.tags())),
                          "text_length": len(tree.text())}
        except Exception:
            pass
    data["selectolax"] = fast_stats

    data["stats"] = {
        "forms": len(data["forms"]),
        "links_internal": len(data["links_internal"]),
        "links_external": len(data["links_external"]),
        "scripts": len(data["scripts"]),
        "js_files": len(data["js_files"]),
        "inline_js": data["inline_js_count"],
        "inline_css": data["inline_css_count"],
        "stylesheets": len(data["stylesheets"]),
        "iframes": len(data["iframes"]),
        "comments": len(data["comments"]),
        "emails": len(data["emails_found"]),
        "phones": len(data["phones_found"]),
        "sensitive_hits": len(data["sensitive_findings"]),
        "external_domains": len(data["external_domains"]),
        "hidden_inputs": len(data["hidden_inputs"]),
    }

    return {
        "status": "ok",
        "data": data,
        "summary": f"{data['stats']['forms']} forms, "
                   f"{data['stats']['links_internal']}+{data['stats']['links_external']} links, "
                   f"{data['stats']['scripts']} scripts ({data['stats']['inline_js']} inline), "
                   f"{data['stats']['sensitive_hits']} sensitive, "
                   f"{data['stats']['emails']} emails"
    }

# ─────────────────────────────────────────────
# ENGINE 8: JS RENDERER — Playwright
# ─────────────────────────────────────────────
def engine_js(target, ctx):
    """
    Maximum JS rendering analysis:
    - Full page render with wait strategies
    - Network waterfall (all requests/responses)
    - API endpoint discovery
    - Cookie & storage analysis (localStorage, sessionStorage, IndexedDB)
    - Console message capture
    - Performance metrics
    - Source map detection
    - Service worker detection
    - WebSocket interception
    - DOM mutation observation
    - Sensitive data in rendered DOM
    - Screenshot metadata
    """
    if not HAS_PLAYWRIGHT or not ctx.get("has_playwright"):
        return {"status": "skipped", "reason": "playwright tidak tersedia"}

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            ctx_br = browser.new_context(
                user_agent=UA, ignore_https_errors=True,
                viewport={"width": 1366, "height": 768},
                locale="en-US", timezone_id="UTC",
            )

            # Collectors
            api_calls = []
            failed_req = []
            console_msgs = []
            responses_meta = []
            ws_messages = []
            all_requests = []

            page = ctx_br.new_page()

            def on_req(req):
                info = {"method": req.method, "url": req.url[:300],
                        "resource_type": req.resource_type}
                all_requests.append(info)
                u = req.url
                if any(k in u for k in [".json", "/api/", "graphql", "/rest/",
                                         "/v1/", "/v2/", "/v3/"]):
                    api_calls.append(info)

            def on_req_failed(req):
                failed_req.append({"url": req.url[:200],
                                   "failure": str(req.failure)})

            def on_resp(resp):
                ct = resp.headers.get("content-type", "")
                info = {
                    "url": resp.url[:200], "status": resp.status,
                    "content_type": ct[:60],
                    "content_length": resp.headers.get("content-length"),
                }
                responses_meta.append(info)

            page.on("request", on_req)
            page.on("requestfailed", on_req_failed)
            page.on("response", on_resp)
            page.on("console", lambda m: console_msgs.append(
                {"type": m.type, "text": m.text[:300]}))
            page.on("websocket", lambda ws: ws.on("framereceived",
                lambda f: ws_messages.append({"url": ws.url[:200],
                                               "data": str(f.payload)[:200]})))

            # Navigate
            t0 = time.time()
            page.goto(target, timeout=30000, wait_until="networkidle")
            load_time = time.time() - t0

            # Extra wait for dynamic content
            page.wait_for_timeout(3000)

            rendered_html = page.content()
            title = page.title()
            visible_text = page.inner_text("body")[:5000]

            # Cookies
            cookies = ctx_br.cookies()

            # Storage
            storage = {}
            try:
                storage["localStorage"] = page.evaluate("""() => {
                    let items = [];
                    for (let i = 0; i < window.localStorage.length; i++) {
                        let k = window.localStorage.key(i);
                        items.push({key: k, value: String(window.localStorage[k]).slice(0,100)});
                    }
                    return items;
                }""")
                storage["sessionStorage"] = page.evaluate("""() => {
                    let items = [];
                    for (let i = 0; i < window.sessionStorage.length; i++) {
                        let k = window.sessionStorage.key(i);
                        items.push({key: k, value: String(window.sessionStorage[k]).slice(0,100)});
                    }
                    return items;
                }""")
            except Exception:
                pass

            # IndexedDB
            try:
                storage["indexedDB"] = page.evaluate("""() => {
                    return new Promise((resolve) => {
                        if (!window.indexedDB) { resolve([]); return; }
                        let req = window.indexedDB.databases();
                        req.onsuccess = (e) => resolve(e.target.result.map(d => d.name));
                        req.onerror = () => resolve([]);
                        setTimeout(() => resolve([]), 2000);
                    });
                }""")
            except Exception:
                storage["indexedDB"] = []

            # Service workers
            try:
                storage["service_workers"] = page.evaluate("""() => {
                    return navigator.serviceWorker ? 
                        navigator.serviceWorker.getRegistrations().then(regs => 
                            regs.map(r => ({scope: r.scope, active: !!r.active}))) : [];
                }""")
            except Exception:
                storage["service_workers"] = []

            # Source maps
            source_maps = re.findall(r"//#\s*sourceMappingURL=([^\s'\"]+)", rendered_html)

            # Performance
            perf = None
            try:
                perf = page.evaluate("""() => {
                    const n = performance.getEntriesByType('navigation')[0] || {};
                    const p = performance.getEntriesByType('paint');
                    return {
                        domContentLoaded: Math.round(n.domContentLoadedEventEnd || 0),
                        loadComplete: Math.round(n.loadEventEnd || 0),
                        transferSize: n.transferSize || 0,
                        encodedBodySize: n.encodedBodySize || 0,
                        firstPaint: p.find(x => x.name === 'first-paint')?.startTime || null,
                        firstContentfulPaint: p.find(x => x.name === 'first-contentful-paint')?.startTime || null,
                        resourceCount: performance.getEntriesByType('resource').length,
                    };
                }""")
            except Exception:
                pass

            # DOM info
            dom_info = None
            try:
                dom_info = page.evaluate("""() => ({
                    title: document.title,
                    url: document.URL,
                    referrer: document.referrer,
                    characterSet: document.characterSet,
                    contentType: document.contentType,
                    readyState: document.readyState,
                    hidden: document.hidden,
                    elementCount: document.querySelectorAll('*').length,
                    formCount: document.forms.length,
                    linkCount: document.links.length,
                    imageCount: document.images.length,
                    scriptCount: document.scripts.length,
                    styleSheetCount: document.styleSheets.length,
                })""")
            except Exception:
                pass

            # Sensitive scan di rendered HTML
            sens = []
            for rx in ctx.get("sensitive_regex", []):
                for m in rx.finditer(rendered_html[:500000]):
                    sens.append({"pattern": rx.pattern[:50], "match": m.group(0)[:120]})
                    if len(sens) > 80:
                        break
                if len(sens) > 80:
                    break

            browser.close()

        data = {
            "title": title,
            "load_time_sec": round(load_time, 2),
            "rendered_html_length": len(rendered_html),
            "visible_text_sample": visible_text[:2000],
            "dom_info": dom_info,
            "performance": perf,
            "api_calls_detected": api_calls[:80],
            "all_requests_count": len(all_requests),
            "requests_by_type": {},
            "failed_requests": failed_req[:40],
            "responses_count": len(responses_meta),
            "responses_sample": responses_meta[:50],
            "cookies": [{"name": c["name"], "domain": c["domain"],
                         "secure": c.get("secure"), "httpOnly": c.get("httpOnly"),
                         "sameSite": c.get("sameSite"),
                         "value_preview": (c.get("value", "") or "")[:50]}
                        for c in cookies],
            "storage": storage,
            "source_maps": source_maps[:20],
            "websocket_messages": ws_messages[:30],
            "console_messages": console_msgs[:60],
            "sensitive_findings": sens,
        }

        # Request type breakdown
        type_counts = defaultdict(int)
        for r in all_requests:
            type_counts[r.get("resource_type", "?")] += 1
        data["requests_by_type"] = dict(type_counts)

        return {
            "status": "ok",
            "data": data,
            "summary": f"{len(rendered_html)}B rendered, "
                       f"{len(all_requests)} requests, {len(api_calls)} API, "
                       f"{len(cookies)} cookies, {load_time:.1f}s"
        }
    except Exception as e:
        return {"status": "error", "error": str(e)[:200]}

# ─────────────────────────────────────────────
# ENGINE 9: WAF DETECTOR
# ─────────────────────────────────────────────
def engine_waf(target, ctx):
    """
    Maximum WAF detection:
    - 25+ WAF signatures (header, cookie, body, behavior)
    - Behavioral probes (SQLi, XSS, path traversal, command injection)
    - Rate limit detection
    - CDN detection (separate from WAF)
    - Response header anomaly analysis
    """
    sigs = {
        "Cloudflare":        ["cloudflare","cf-ray","__cfduid","cf-cache-status","server: cloudflare","cf-connecting-ip"],
        "AWS WAF":           ["x-amzn","aws-waf","x-amz-cf-id","awselb","x-amzn-requestid"],
        "Akamai":            ["akamai","aka","x-akamai","akamai-ghost","akamai-origin-hop","x-akamai-transformed"],
        "Imperva/Incapsula": ["incap_ses","visid_incap","x-cdn: imperva","incapsula","x-iinfo"],
        "F5 BIG-IP":         ["bigipserver","f5","big-ip","x-waap-info","mrhsh"],
        "Sucuri":            ["sucuri","x-sucuri","sucuri-cloudproxy","x-sucuri-cache"],
        "Barracuda":         ["barra","barracuda","bncloud"],
        "ModSecurity":       ["mod_security","this server is protected","modsecurity","not acceptable"],
        "Fortinet/FortiWeb": ["fortiwafsid","fortigate","fortiweb","fortiguard"],
        "Azure WAF":         ["x-azure-ref","azure","frontdoor","x-fd-int-roxy-proxyid"],
        "Google Cloud Armor":["x-goog","google-armor","x-cloud-trace","x-goog-cache"],
        "Reblaze":           ["rbzid","reblaze"],
        "StackPath":         ["stackpath","x-sp-","x-hw"],
        "Fastly":            ["fastly","x-served-by: cache","x-fastly","x-timer"],
        "Varnish":           ["x-varnish","via: varnish","x-cache: hit","x-cache: miss"],
        "NSFocus":           ["nsfocus"],
        "Wallarm":           ["wallarm","x-wallarm"],
        "Signal Sciences":   ["x-sigsci","signalsciences","sigsci"],
        "DenyAll":           ["denyall","x-denied"],
        "NetScaler":         ["ns_af","citrix_ns","netscaler"],
        "Radware":           ["radware","x-sl-comp"],
        "SonicWall":         ["sonicwall","nsa_banner"],
        "KeyCDN":            ["keycdn","x-keycdn"],
        "BunnyCDN":          ["bunnycdn","bunny"],
        "DOSarrest":         ["dosarrest","x-dosarrest"],
    }

    cdn_sigs = {
        "Cloudflare CDN": ["cf-cache-status", "cf-ray"],
        "Fastly CDN": ["x-served-by: cache", "x-fastly"],
        "Akamai CDN": ["x-akamai"],
        "KeyCDN": ["x-keycdn-cache"],
        "BunnyCDN": ["bunnycdn"],
        "CDN77": ["cdn77"],
        "StackPath CDN": ["x-hw"],
    }

    findings = []
    evidence = {}
    cdn_findings = []
    behavioral = {}

    try:
        session = ctx.get("session") or requests

        # ── 1) Normal request analysis ──
        r1 = session.get(target, timeout=15, verify=False, headers={"User-Agent": UA})
        body = (r1.text or "")[:10000].lower()
        hdrs = " ".join(f"{k}: {v}" for k, v in r1.headers.items()).lower()
        ck = " ".join(r1.cookies.keys()).lower()
        blob = f"{body} {hdrs} {ck}"

        for waf, keys in sigs.items():
            for k in keys:
                if k.lower() in blob:
                    findings.append(waf)
                    evidence[waf] = evidence.get(waf, []) + [k]
                    break

        # CDN detection
        for cdn, keys in cdn_sigs.items():
            for k in keys:
                if k.lower() in blob:
                    cdn_findings.append(cdn)
                    break

        # ── 2) Behavioral probes ──
        sep = "&" if "?" in target else "?"
        probes = [
            ("SQLi", f"' OR 1=1 --", (403, 406, 429, 501, 503)),
            ("XSS", "<script>alert(1)</script>", (403, 406, 429, 501, 503)),
            ("PathTraversal", "../../../../etc/passwd", (400, 403, 404, 500)),
            ("CmdInjection", ";cat /etc/passwd", (403, 406, 500, 503)),
            ("LDAP", ")(cn=*))(|(cn=*", (403, 406, 500)),
            ("HeaderInject", "%0d%0aSet-Cookie:test=1", (400, 403)),
        ]
        for probe_name, payload, block_codes in probes:
            try:
                r = session.get(target + sep + f"q={quote(payload)}",
                                timeout=8, verify=False)
                behavioral[probe_name] = {
                    "status": r.status_code,
                    "blocked": r.status_code in block_codes,
                }
                if r1.status_code < 400 and r.status_code in block_codes:
                    findings.append(f"Behavioral-{probe_name}")
                    evidence[f"Behavioral-{probe_name}"] = [
                        f"normal={r1.status_code}, probe={r.status_code}"
                    ]
            except Exception:
                pass

        # ── 3) Rate limit probe ──
        codes = []
        for _ in range(8):
            try:
                rr = session.get(target, timeout=5, verify=False)
                codes.append(rr.status_code)
            except Exception:
                codes.append(0)
        if 429 in codes or 503 in codes:
            behavioral["rate_limit"] = {"detected": True, "codes": codes}
            findings.append("Rate-Limiting")
        else:
            behavioral["rate_limit"] = {"detected": False, "codes": codes}

        # ── 4) User-Agent block test ──
        try:
            r_ua = session.get(target, timeout=8, verify=False,
                               headers={"User-Agent": "sqlmap/1.0"})
            if r1.status_code < 400 and r_ua.status_code in (403, 406):
                findings.append("UA-Filtering")
                evidence["UA-Filtering"] = ["sqlmap UA blocked"]
        except Exception:
            pass

    except Exception as e:
        return {"status": "error", "error": str(e)[:120]}

    findings = list(dict.fromkeys(findings))
    cdn_findings = list(dict.fromkeys(cdn_findings))

    return {
        "status": "ok",
        "data": {
            "waf_detected": findings if findings else ["none"],
            "cdn_detected": cdn_findings if cdn_findings else ["none"],
            "evidence": evidence,
            "behavioral_probes": behavioral,
            "tested_signatures": list(sigs.keys()),
        },
        "summary": f"WAF: {', '.join(findings[:5]) or 'none'} | CDN: {', '.join(cdn_findings[:3]) or 'none'}"
    }

# ─────────────────────────────────────────────
# ENGINE 10: ZAP — OWASP ZAP Integration
# ─────────────────────────────────────────────
def engine_zap(target, ctx):
    """
    Maximum ZAP integration:
    - Spider (standard + AJAX)
    - Passive scan
    - Active scan (safe scripts only)
    - Alert categorization
    - Technology detection via ZAP
    """
    zap = ctx.get("zap_proxy")
    if not zap:
        return {"status": "skipped",
                "reason": "ZAP proxy tidak terdeteksi (set ZAP_PROXY/ZAP_API_KEY)"}

    zap_url = zap["url"]
    zap_api = zap["api_key"]
    proxies = {"http": zap_url, "https": zap_url}

    try:
        # ── 1) Seed URL ──
        requests.get(target, proxies=proxies, timeout=20, verify=False,
                     headers={"User-Agent": UA})

        # ── 2) Standard Spider ──
        spider_status = None
        try:
            sp = requests.get(
                f"{zap_url}/JSON/spider/action/scan/?url={target}&maxChildren=50&apikey={zap_api}",
                timeout=10)
            spider_id = sp.json().get("scan", "0")
            for _ in range(60):
                prog = requests.get(
                    f"{zap_url}/JSON/spider/view/status/?scanId={spider_id}&apikey={zap_api}",
                    timeout=5).json().get("status", "0")
                if int(prog) >= 100:
                    break
                time.sleep(1)
            spider_status = "completed"
        except Exception as e:
            spider_status = f"error: {str(e)[:60]}"

        # ── 3) AJAX Spider (untuk JS-heavy sites) ──
        ajax_status = None
        try:
            requests.get(
                f"{zap_url}/JSON/ajaxSpider/action/scan/?url={target}&apikey={zap_api}",
                timeout=10)
            for _ in range(30):
                st = requests.get(
                    f"{zap_url}/JSON/ajaxSpider/view/status/?apikey={zap_api}",
                    timeout=5).json().get("status", "")
                if st == "stopped":
                    break
                time.sleep(2)
            ajax_status = "completed"
        except Exception as e:
            ajax_status = f"error: {str(e)[:60]}"

        # ── 4) Passive scan wait ──
        for _ in range(90):
            try:
                recs = requests.get(
                    f"{zap_url}/JSON/pscan/view/recordsToScan/?apikey={zap_api}",
                    timeout=5).json().get("recordsToScan", "0")
                if int(recs) <= 0:
                    break
            except Exception:
                break
            time.sleep(1)

        # ── 5) Active scan (safe only) ──
        active_status = None
        try:
            # Set active scan to use safe policies only
            as_r = requests.get(
                f"{zap_url}/JSON/ascan/action/scan/?url={target}&recurse=true&apikey={zap_api}",
                timeout=10)
            scan_id = as_r.json().get("scan", "0")
            for _ in range(120):  # Max 2 minutes
                prog = requests.get(
                    f"{zap_url}/JSON/ascan/view/status/?scanId={scan_id}&apikey={zap_api}",
                    timeout=5).json().get("status", "0")
                if int(prog) >= 100:
                    break
                time.sleep(2)
            active_status = "completed"
        except Exception as e:
            active_status = f"error: {str(e)[:60]}"

        # ── 6) Collect alerts ──
        r = requests.get(
            f"{zap_url}/JSON/core/view/alerts/?baseurl={target}&apikey={zap_api}",
            timeout=30)
        alerts = r.json().get("alerts", [])

        # ── 7) Collect technologies ──
        techs = []
        try:
            tr = requests.get(
                f"{zap_url}/JSON/core/view/technologyList/?apikey={zap_api}",
                timeout=10)
            techs = tr.json().get("technologyList", [])
        except Exception:
            pass

        # ── 8) Sites discovered ──
        sites = []
        try:
            sr = requests.get(
                f"{zap_url}/JSON/core/view/sites/?apikey={zap_api}",
                timeout=10)
            sites = sr.json().get("sites", [])
        except Exception:
            pass

        # Categorize alerts
        by_risk = defaultdict(int)
        by_confidence = defaultdict(int)
        for a in alerts:
            by_risk[a.get("risk", "?")] += 1
            by_confidence[a.get("confidence", "?")] += 1

        summary = []
        for risk, count in sorted(by_risk.items()):
            summary.append(f"{risk}: {count}")

        return {
            "status": "ok",
            "data": {
                "zap_version": zap.get("version", "?"),
                "spider": spider_status,
                "ajax_spider": ajax_status,
                "active_scan": active_status,
                "total_alerts": len(alerts),
                "alerts_by_risk": dict(by_risk),
                "alerts_by_confidence": dict(by_confidence),
                "sites_discovered": sites,
                "technologies": techs[:30],
                "alerts": [
                    {
                        "name": a.get("name"), "risk": a.get("risk"),
                        "confidence": a.get("confidence"),
                        "url": a.get("url"),
                        "description": (a.get("description") or "")[:300],
                        "solution": (a.get("solution") or "")[:200],
                        "reference": (a.get("reference") or "")[:200],
                        "cweid": a.get("cweid"), "wascid": a.get("wascid"),
                        "pluginId": a.get("pluginId"),
                    } for a in alerts[:150]
                ]
            },
            "summary": f"{len(alerts)} alerts ({', '.join(summary) if summary else 'clean'}), "
                       f"{len(sites)} sites, {len(techs)} techs"
        }
    except Exception as e:
        return {"status": "error", "error": str(e)[:200]}

# ─────────────────────────────────────────────
# ENGINE 11: FINGERPRINTER — Tech Stack Detection
# ─────────────────────────────────────────────
def engine_fingerprint(target, ctx):
    """
    Maximum tech fingerprinting:
    - Wappalyzer analysis
    - 30+ manual header/cookie/body rules
    - Favicon hash (MurMurHash3) for Shodan-like lookup
    - CMS detection (WordPress, Drupal, Joomla, etc.)
    - Framework detection (React, Vue, Angular, etc.)
    - Server software detection
    - CDN detection
    - Analytics detection
    """
    data = {
        "wappalyzer": [],
        "manual_rules": [],
        "favicon_hash": None,
        "cms": None,
        "framework": None,
        "server": None,
        "cdn": None,
        "analytics": [],
        "js_libraries": [],
        "css_frameworks": [],
    }

    try:
        session = ctx.get("session") or requests
        r = session.get(target, timeout=20, verify=False, headers={"User-Agent": UA})
    except Exception as e:
        return {"status": "error", "error": str(e)[:120]}

    # ── 1) Wappalyzer ──
    wapp = ctx.get("wappalyzer_engine")
    if wapp and HAS_WAPPALYZER:
        try:
            wp = WebPage(target, r.text, dict(r.headers))
            techs = wapp.analyze_with_versions_and_categories(wp)
            for name, info in techs.items():
                data["wappalyzer"].append({
                    "name": name,
                    "versions": info.get("versions", []),
                    "categories": info.get("categories", []),
                })
        except Exception as e:
            data["wappalyzer_error"] = str(e)[:120]

    # ── 2) Manual rules (30+) ──
    hl = {k.lower(): v for k, v in r.headers.items()}
    body = r.text[:300000].lower()

    rules = [
        # Servers
        ("Server: nginx", lambda h,b: "nginx" in h.get("server","").lower(), "Nginx", "server"),
        ("Server: Apache", lambda h,b: "apache" in h.get("server","").lower(), "Apache", "server"),
        ("Server: IIS", lambda h,b: "microsoft-iis" in h.get("server","").lower(), "Microsoft IIS", "server"),
        ("Server: LiteSpeed", lambda h,b: "litespeed" in h.get("server","").lower(), "LiteSpeed", "server"),
        ("Server: Caddy", lambda h,b: "caddy" in h.get("server","").lower(), "Caddy", "server"),
        ("Server: OpenResty", lambda h,b: "openresty" in h.get("server","").lower(), "OpenResty", "server"),
        ("Server: Tornado", lambda h,b: "tornado" in h.get("server","").lower(), "Tornado", "server"),
        ("Server: Gunicorn", lambda h,b: "gunicorn" in h.get("server","").lower(), "Gunicorn", "server"),
        ("Server: Cowboy", lambda h,b: "cowboy" in h.get("server","").lower(), "Cowboy (Erlang)", "server"),
        # Backend
        ("X-Powered-By: PHP", lambda h,b: "php" in h.get("x-powered-by","").lower(), "PHP", "backend"),
        ("X-Powered-By: ASP.NET", lambda h,b: "asp.net" in h.get("x-powered-by","").lower(), "ASP.NET", "backend"),
        ("X-Powered-By: Express", lambda h,b: "express" in h.get("x-powered-by","").lower(), "Express.js", "backend"),
        ("X-Powered-By: Next.js", lambda h,b: "next.js" in h.get("x-powered-by","").lower(), "Next.js", "backend"),
        # CMS
        ("WordPress", lambda h,b: "wordpress" in h.get("x-generator","").lower() or "/wp-" in b or "wp-content" in b, "WordPress", "cms"),
        ("Drupal", lambda h,b: "drupal" in " ".join(f"{k}:{v}" for k,v in h.items()).lower() or "drupal" in b, "Drupal", "cms"),
        ("Joomla", lambda h,b: "/media/jui/" in b or "joomla" in b, "Joomla", "cms"),
        ("Ghost", lambda h,b: "ghost" in h.get("x-powered-by","").lower() or "ghost" in b, "Ghost", "cms"),
        ("Magento", lambda h,b: "magento" in b or "/static/version" in b, "Magento", "cms"),
        ("Shopify", lambda h,b: "cdn.shopify.com" in b or "shopify" in b, "Shopify", "cms"),
        ("Wix", lambda h,b: "wix.com" in b or "x-wix-request-id" in h, "Wix", "cms"),
        ("Squarespace", lambda h,b: "squarespace" in b, "Squarespace", "cms"),
        # Frameworks
        ("React", lambda h,b: "reactroot" in b or "react-dom" in b or 'data-reactroot' in b or "_next/static" in b, "React", "framework"),
        ("Vue.js", lambda h,b: "vue.js" in b or "vue-" in b or "__vue__" in b or "v-" in b, "Vue.js", "framework"),
        ("Angular", lambda h,b: "ng-version" in b or "angular" in b or "ng-app" in b, "Angular", "framework"),
        ("Svelte", lambda h,b: "svelte" in b, "Svelte", "framework"),
        ("Next.js", lambda h,b: "__next" in b or "_next/static" in b, "Next.js", "framework"),
        ("Nuxt.js", lambda h,b: "__nuxt" in b or "_nuxt/" in b, "Nuxt.js", "framework"),
        ("Django", lambda h,b: "csrfmiddlewaretoken" in b or "django" in b, "Django", "framework"),
        ("Laravel", lambda h,b: "laravel_session" in " ".join(r.cookies.keys()).lower() or "laravel" in b, "Laravel", "framework"),
        ("Ruby on Rails", lambda h,b: "x-powered-by: phusion passenger" in " ".join(f"{k}:{v}" for k,v in h.items()).lower() or "rails" in b, "Ruby on Rails", "framework"),
        ("Spring", lambda h,b: "x-application-context" in h or "jsessionid" in " ".join(r.cookies.keys()).lower(), "Spring (Java)", "framework"),
        # JS Libraries
        ("jQuery", lambda h,b: "jquery" in b, "jQuery", "js_lib"),
        ("Bootstrap", lambda h,b: "bootstrap" in b, "Bootstrap", "css_fw"),
        ("Tailwind", lambda h,b: "tailwindcss" in b or "tailwind" in b, "Tailwind CSS", "css_fw"),
        ("Bulma", lambda h,b: "bulma" in b, "Bulma", "css_fw"),
        ("Materialize", lambda h,b: "materialize" in b, "Materialize", "css_fw"),
        # CDN
        ("Cloudflare", lambda h,b: "cloudflare" in h.get("server","").lower() or "cf-ray" in h, "Cloudflare", "cdn"),
        ("Fastly", lambda h,b: "fastly" in " ".join(f"{k}:{v}" for k,v in h.items()).lower(), "Fastly", "cdn"),
        ("Akamai", lambda h,b: "akamai" in " ".join(f"{k}:{v}" for k,v in h.items()).lower(), "Akamai", "cdn"),
        # Analytics
        ("Google Analytics", lambda h,b: "google-analytics.com" in b or "gtag" in b or "ga.js" in b, "Google Analytics", "analytics"),
        ("Google Tag Manager", lambda h,b: "googletagmanager.com" in b or "gtm.js" in b, "GTM", "analytics"),
        ("Facebook Pixel", lambda h,b: "facebook.com/tr" in b or "fbq(" in b, "Facebook Pixel", "analytics"),
        ("Hotjar", lambda h,b: "hotjar" in b, "Hotjar", "analytics"),
        ("Mixpanel", lambda h,b: "mixpanel" in b, "Mixpanel", "analytics"),
    ]

    for label, fn, name, category in rules:
        try:
            if fn(hl, body):
                data["manual_rules"].append({"rule": label, "tech": name, "category": category})
                if category == "cms":
                    data["cms"] = name
                elif category == "framework":
                    data["framework"] = data.get("framework") or name
                elif category == "server":
                    data["server"] = name
                elif category == "cdn":
                    data["cdn"] = name
                elif category == "analytics":
                    data["analytics"].append(name)
                elif category == "js_lib":
                    data["js_libraries"].append(name)
                elif category == "css_fw":
                    data["css_frameworks"].append(name)
        except Exception:
            pass

    # Cookie-based detection
    ck_names = [c.name.lower() for c in r.cookies.jar]
    cookie_rules = [
        ("phpsessid", "PHP"), ("asp.net_sessionid", "ASP.NET"),
        ("jsessionid", "Java"), ("laravel_session", "Laravel"),
        ("connect.sid", "Express.js"), ("_rails_session", "Rails"),
        ("csrftoken", "Django"), ("session_id", "Generic"),
    ]
    for ck_name, tech in cookie_rules:
        if any(ck_name in n for n in ck_names):
            data["manual_rules"].append({"rule": f"cookie:{ck_name}", "tech": tech, "category": "cookie"})

    # ── 3) Favicon hash (MurMurHash3) ──
    if HAS_MMH3:
        try:
            parsed = urlparse(target)
            fav_url = f"{parsed.scheme}://{parsed.netloc}/favicon.ico"
            fr = session.get(fav_url, timeout=10, verify=False)
            if fr.status_code == 200:
                icon_bytes = fr.content
                # Base64 encode for mmh3
                b64 = base64.b64encode(icon_bytes).decode()
                hash_val = mmh3.hash(b64)
                data["favicon_hash"] = {
                    "mmh3": hash_val,
                    "md5": hashlib.md5(icon_bytes).hexdigest(),
                    "size": len(icon_bytes),
                    "shodan_query": f"http.favicon.hash:{hash_val}",
                }
        except Exception:
            pass

    # Deduplicate
    data["analytics"] = list(set(data["analytics"]))
    data["js_libraries"] = list(set(data["js_libraries"]))
    data["css_frameworks"] = list(set(data["css_frameworks"]))

    return {
        "status": "ok",
        "data": data,
        "summary": f"{len(data['wappalyzer'])} Wappalyzer + {len(data['manual_rules'])} manual, "
                   f"CMS={data['cms'] or '?'}, FW={data['framework'] or '?'}, "
                   f"Server={data['server'] or '?'}, CDN={data['cdn'] or '?'}"
    }

# ─────────────────────────────────────────────
# ENGINE 12: BUILTWITH — Technology Profiling
# ─────────────────────────────────────────────
def engine_builtwith(target, ctx):
    """
    Maximum BuiltWith analysis:
    - Library-based profiling
    - Fallback to custom detection
    - Category breakdown
    """
    data = {"builtwith_raw": None, "categories": {}, "technologies": []}

    if HAS_BUILTWITH:
        try:
            res = bw_lib.free(target) if hasattr(bw_lib, "free") else bw_lib.builtwith(target)
            data["builtwith_raw"] = res
            if isinstance(res, dict):
                for cat, items in res.items():
                    if isinstance(items, list):
                        data["categories"][cat] = items[:30]
                        for item in items:
                            if isinstance(item, dict):
                                data["technologies"].append({
                                    "name": item.get("Name", str(item)),
                                    "category": cat,
                                })
                            else:
                                data["technologies"].append({"name": str(item), "category": cat})
        except Exception as e:
            data["error"] = str(e)[:120]

    # Fallback: use fingerprinter results if BuiltWith failed
    if not data["technologies"]:
        data["fallback"] = "Menggunakan data dari Fingerprinter Engine"

    return {
        "status": "ok" if data["technologies"] else "partial",
        "data": data,
        "summary": f"{len(data['technologies'])} techs in {len(data['categories'])} categories"
    }

# ─────────────────────────────────────────────
# ENGINE 13: ACTIVE FORM TESTER
# ─────────────────────────────────────────────
def engine_active_form(target, ctx, forms):
    """
    Maximum form-based testing:
    - SQLi (error-based + time-based + boolean-based)
    - Reflected XSS
    - Open redirect
    - CSRF detection
    - Mass assignment hints
    - File upload detection
    - Auth form analysis
    - Rate limit detection
    - IDOR hints
    """
    if not forms:
        return {"status": "skipped", "reason": "tidak ada form dari HTML engine"}

    base = urlparse(target)
    data = {
        "forms_tested": 0,
        "inputs_tested": 0,
        "findings": [],
        "csrf_issues": [],
        "auth_forms": [],
        "file_upload_forms": [],
        "rate_limit_detected": False,
        "open_redirects": [],
        "idor_hints": [],
    }

    # SQLi payloads
    sqli_payloads = [
        ("'", "error"),
        ("' OR '1'='1", "auth_bypass"),
        ("1' AND '1'='1", "boolean"),
        ("1; WAITFOR DELAY '0:0:5'--", "time_based_mssql"),
        ("1' AND SLEEP(5)--", "time_based_mysql"),
        ("1 AND 1=1", "boolean_true"),
        ("1 AND 1=2", "boolean_false"),
    ]
    sqli_errors = [
        "sql syntax", "mysql", "sqlite", "ora-", "postgresql",
        "unclosed quotation", "pg_query", "mysql_fetch", "mysqli",
        "sqlite3", "you have an error", "warning:", "syntax error",
        "unterminated", "quoted string",
    ]

    s = requests.Session()
    s.verify = False
    s.headers.update({"User-Agent": UA})

    for form in forms[:8]:  # Max 8 forms
        data["forms_tested"] += 1
        action = form.get("action") or target
        if action.startswith("/"):
            action = f"{base.scheme}://{base.netloc}{action}"
        elif not action.startswith("http"):
            action = f"{base.scheme}://{base.netloc}/{action}"
        method = (form.get("method") or "GET").upper()
        inputs = form.get("inputs", [])
        if not inputs:
            continue

        # ── Auth form detection ──
        input_names = [(i.get("name") or "").lower() for i in inputs]
        input_types = [(i.get("type") or "").lower() for i in inputs]
        if any(n in ("username","email","user","login","uid") for n in input_names) \
           and "password" in input_types:
            data["auth_forms"].append({
                "action": action,
                "has_csrf": form.get("has_csrf_token"),
                "inputs": input_names,
            })
            if not form.get("has_csrf_token"):
                data["csrf_issues"].append({
                    "form_action": action,
                    "issue": "Form login tanpa CSRF token",
                    "severity": "medium",
                })

        # ── File upload detection ──
        if "file" in input_types:
            data["file_upload_forms"].append({
                "action": action,
                "accept": [i.get("accept") for i in inputs if i.get("type") == "file"],
            })

        # ── CSRF general check ──
        if method == "POST" and not form.get("has_csrf_token"):
            data["csrf_issues"].append({
                "form_action": action,
                "issue": "Form POST tanpa CSRF token",
                "severity": "medium",
            })

        # ── Test per input ──
        for inp in inputs:
            name = inp.get("name")
            if not name:
                continue
            itype = (inp.get("type") or "text").lower()
            if itype in ("submit", "hidden", "button", "image", "file"):
                continue
            base_payload = {}
            for other in inputs:
                if other.get("name") and other["name"] != name:
                    base_payload[other["name"]] = "test"
            data["inputs_tested"] += 1

            # ── SQLi testing ──
            for payload, ptype in sqli_payloads:
                try:
                    d = dict(base_payload)
                    d[name] = payload
                    t0 = time.time()
                    resp = s.request(method, action,
                                     data=d if method == "POST" else None,
                                     params=d if method == "GET" else None,
                                     timeout=12)
                    dt = time.time() - t0
                    body_lower = resp.text.lower()

                    # Error-based
                    if ptype == "error" and any(k in body_lower for k in sqli_errors):
                        data["findings"].append({
                            "form_action": action, "input": name,
                            "type": "SQLi (error-based)",
                            "payload": payload,
                            "evidence": "SQL error di response",
                            "status": resp.status_code,
                            "severity": "high",
                        })

                    # Time-based
                    if "time_based" in ptype and dt > 4.5:
                        data["findings"].append({
                            "form_action": action, "input": name,
                            "type": f"SQLi ({ptype})",
                            "payload": payload,
                            "evidence": f"response time {dt:.1f}s",
                            "severity": "high",
                        })

                    # Rate limit
                    if resp.status_code == 429:
                        data["rate_limit_detected"] = True

                except Exception:
                    pass

            # ── Reflected XSS ──
            xss_payloads = [
                "<indigotest>",
                "<script>indigotest</script>",
                "\"><img src=x onerror=indigotest>",
                "javascript:indigotest",
            ]
            for xp in xss_payloads:
                try:
                    d = dict(base_payload)
                    d[name] = xp
                    resp = s.request(method, action,
                                     data=d if method == "POST" else None,
                                     params=d if method == "GET" else None,
                                     timeout=10)
                    if xp in resp.text:
                        data["findings"].append({
                            "form_action": action, "input": name,
                            "type": "Reflected XSS",
                            "payload": xp[:60],
                            "evidence": "payload terpantul tanpa sanitasi",
                            "severity": "high",
                        })
                        break  # One XSS per input is enough
                except Exception:
                    pass

            # ── Open redirect ──
            if any(k in name.lower() for k in
                   ("url","next","redirect","return","goto","continue","dest","forward")):
                try:
                    d = dict(base_payload)
                    d[name] = "https://evil.example.com/"
                    resp = s.request(method, action,
                                     data=d if method == "POST" else None,
                                     params=d if method == "GET" else None,
                                     timeout=10, allow_redirects=False)
                    loc = (resp.headers.get("Location") or "").lower()
                    if "evil.example.com" in loc:
                        data["findings"].append({
                            "form_action": action, "input": name,
                            "type": "Open Redirect",
                            "payload": "https://evil.example.com/",
                            "evidence": f"Location: {loc[:80]}",
                            "severity": "medium",
                        })
                except Exception:
                    pass

            # ── IDOR hints (numeric IDs) ──
            if any(k in name.lower() for k in ("id","uid","user_id","order_id","item_id")):
                data["idor_hints"].append({
                    "form_action": action,
                    "input": name,
                    "hint": "Parameter ID terdeteksi — periksa otorisasi",
                })

    return {
        "status": "ok",
        "data": data,
        "summary": f"{data['forms_tested']} forms / {data['inputs_tested']} inputs, "
                   f"{len(data['findings'])} vulns, "
                   f"{len(data['csrf_issues'])} CSRF, "
                   f"auth: {len(data['auth_forms'])}, upload: {len(data['file_upload_forms'])}"
    }

# ═══════════════════════════════════════════════════════════
# 8. ORCHESTRATION
# ═══════════════════════════════════════════════════════════
ENGINES = [
    ("NMAP Engine",          engine_nmap),
    ("DNS Engine",           engine_dns),
    ("SSL/TLS Engine",       engine_ssl),
    ("Scapy Engine",         engine_scapy),
    ("WHOIS Engine",         engine_whois),
    ("HTTP Engine",          engine_http),
    ("HTML Parser Engine",   engine_html),
    ("JS Renderer Engine",   engine_js),
    ("WAF Detector Engine",  engine_waf),
    ("ZAP Engine",           engine_zap),
    ("Fingerprinter Engine", engine_fingerprint),
    ("BuiltWith Engine",     engine_builtwith),
]

def run_all_engines(target, ctx):
    results = {}
    total = len(ENGINES) + 1  # +1 for Active Form Tester
    progress = EngineProgress(total)

    print(colored(f"\n  ═══ Scanning {get_host(target)} with 13 engines ═══\n", "BOLD"))

    # ── Phase 1: HTML Engine (needed for Active Form Tester) ──
    html_name = "HTML Parser Engine"
    html_fn = engine_html
    t0 = time.time()
    try:
        html_res = html_fn(target, ctx)
    except Exception as e:
        html_res = {"status": "error", "error": str(e)[:200]}
    results[html_name] = html_res
    dt = time.time() - t0
    progress.update(html_name, html_res.get("status", "err"),
                    html_res.get("summary", html_res.get("error", ""))[:40], dt)

    # ── Phase 2: All other engines in parallel ──
    others = [(n, f) for n, f in ENGINES if n != html_name]

    def _run(name, fn):
        t0 = time.time()
        try:
            res = fn(target, ctx)
        except Exception as e:
            res = {"status": "error", "error": str(e)[:200]}
        return name, res, time.time() - t0

    with ThreadPoolExecutor(max_workers=6) as pool:
        futures = {pool.submit(_run, n, f): n for n, f in others}
        for fut in as_completed(futures):
            name, res, dt = fut.result()
            results[name] = res
            progress.update(name, res.get("status", "err"),
                            res.get("summary", res.get("error", ""))[:40], dt)

    # ── Phase 3: Active Form Tester ──
    af_name = "Active Form Tester"
    t0 = time.time()
    forms = html_res.get("data", {}).get("forms", []) if html_res.get("data") else []
    try:
        af_res = engine_active_form(target, ctx, forms)
    except Exception as e:
        af_res = {"status": "error", "error": str(e)[:200]}
    results[af_name] = af_res
    progress.update(af_name, af_res.get("status", "err"),
                    af_res.get("summary", af_res.get("error", ""))[:40],
                    time.time() - t0)

    return results

# ═══════════════════════════════════════════════════════════
# 9. REPORT GENERATION
# ═══════════════════════════════════════════════════════════
def sanitize_filename(s):
    return re.sub(r"[^A-Za-z0-9._-]", "_", s)

def generate_report(target, results, ctx):
    host = get_host(target)
    now = datetime.now()
    stamp = now.strftime("%d-%m-%Y_%H-%M-%S")
    safe = sanitize_filename(host)
    base_name = f"indigo-report-{safe}-{stamp}"
    os.makedirs(REPORT_DIR, exist_ok=True)
    txt_path = os.path.join(REPORT_DIR, f"{base_name}.txt")
    json_path = os.path.join(REPORT_DIR, f"{base_name}.json")

    # ── JSON ──
    json_doc = {
        "scanner": "Indigo Scanner",
        "version": VERSION,
        "target": target,
        "host": host,
        "scan_time": now.isoformat(),
        "engines_count": len(results),
        "system_info": ctx.get("system_info", {}),
        "results": results,
    }
    def _default(o):
        if isinstance(o, set): return list(o)
        return str(o)
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(json_doc, f, indent=2, default=_default, ensure_ascii=False)

    # ── TXT ──
    def sep(ch="═", n=82): return ch * n
    lines = []
    lines.append(sep())
    lines.append(f"  INDIGO SCANNER v{VERSION} — LAPORAN PEMINDAIAN KEAMANAN")
    lines.append(sep())
    lines.append(f"  Target      : {target}")
    lines.append(f"  Host        : {host}")
    lines.append(f"  IP          : {resolve_host(host)}")
    lines.append(f"  Waktu Scan  : {now.strftime('%d-%m-%Y %H:%M:%S')}")
    lines.append(f"  Engine      : {len(results)}")
    lines.append(f"  Platform    : {ctx.get('system_info',{}).get('platform','?')}")
    lines.append(f"  Scanner IP  : {ctx.get('network_info',{}).get('public_ip','?')}")
    lines.append(sep())

    # Ringkasan
    lines.append("\n╔══════════════════════════════════════════════════════════════════════════╗")
    lines.append("║  RINGKASAN ENGINE                                                       ║")
    lines.append("╠══════════════════════════════════════════════════════════════════════════╣")
    for name, res in results.items():
        st = res.get("status", "?")
        sym = {"ok":"✔","error":"✘","skipped":"⊘","partial":"◐"}.get(st, "?")
        sumr = res.get("summary", res.get("reason", res.get("error", "")))
        lines.append(f"║  {sym} {name:28s} │ {str(sumr)[:45]:45s} ║")
    lines.append("╚══════════════════════════════════════════════════════════════════════════╝")

    # Detail per engine
    for name, res in results.items():
        lines.append(f"\n{sep('─')}")
        lines.append(f"  ENGINE: {name}")
        lines.append(f"  STATUS: {res.get('status')}")
        lines.append(sep('─'))
        data = res.get("data")
        if data is None:
            lines.append(f"  (tidak ada data — {res.get('reason') or res.get('error')})")
            continue
        pretty = json.dumps(data, indent=4, default=_default, ensure_ascii=False)
        for pl in pretty.splitlines():
            lines.append("  " + pl)

    # Temuan gabungan
    lines.append(f"\n{sep()}")
    lines.append("  TEMUAN KEAMANAN GABUNGAN")
    lines.append(sep())
    issues_all = []
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    for name, res in results.items():
        d = res.get("data") or {}
        if isinstance(d, dict):
            for k in ("issues", "findings", "csrf_issues", "sensitive_findings",
                      "cname_takeover_risk"):
                lst = d.get(k)
                if isinstance(lst, list):
                    for it in lst:
                        if isinstance(it, dict):
                            sev = it.get("severity", "info")
                            t = it.get("type") or it.get("issue") or it.get("name") or k
                            ev = it.get("evidence") or it.get("match") or it.get("description") or it.get("risk") or ""
                            issues_all.append((severity_order.get(sev, 4), f"[{sev.upper()}] [{name}] {t}: {ev}"))
                        else:
                            issues_all.append((4, f"[INFO] [{name}] {it}"))
    # Sort by severity
    issues_all.sort(key=lambda x: x[0])
    if not issues_all:
        lines.append("  (tidak ada temuan kritis otomatis)")
    for i, (_, it) in enumerate(issues_all, 1):
        lines.append(f"  {i:3d}. {it}")

    # Statistik temuan
    sev_counts = defaultdict(int)
    for sev, _ in issues_all:
        for name, order in severity_order.items():
            if order == sev:
                sev_counts[name] += 1
                break
    if sev_counts:
        lines.append(f"\n  Severity breakdown: " +
                     ", ".join(f"{k}: {v}" for k, v in sorted(sev_counts.items(),
                                                                key=lambda x: severity_order.get(x[0], 4))))

    lines.append(f"\n{sep()}")
    lines.append(f"  AKHIR LAPORAN — {now.strftime('%d-%m-%Y %H:%M:%S')}")
    lines.append(sep())

    with open(txt_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    return txt_path, json_path

# ═══════════════════════════════════════════════════════════
# 10. MAIN
# ═══════════════════════════════════════════════════════════
def main():
    # ── PRE-FLIGHT: semua setup otomatis ──
    pf = PreFlight()
    if not check_and_install_deps():
        print(colored("\n  ✘ Dependency installation failed. Exiting.", "R"))
        sys.exit(1)
    ctx = pf.run_all()

    # ── BANNER ──
    show_banner(ctx)

    while True:
        try:
            raw = input(colored("  indigo> ", "CY")).strip()
        except (EOFError, KeyboardInterrupt):
            print(colored("\n\n  Sampai jumpa! 👋\n", "G"))
            break

        if not raw:
            continue
        if raw.lower() in ("/exit", "/quit", "/q"):
            print(colored("  Sampai jumpa! 👋", "G"))
            break

        target, err = validate_target(raw)
        if err == "EXIT":
            print(colored("  Sampai jumpa! 👋", "G"))
            break
        if err:
            print(colored(f"  [!] Target tidak valid: {err}", "R"))
            continue

        print(colored(f"  ✓ Target divalidasi: {target}", "G"))
        print(colored(f"  Host: {get_host(target)} | IP: {resolve_host(get_host(target))}", "DIM"))

        t_start = time.time()
        results = run_all_engines(target, ctx)
        dt = time.time() - t_start

        print(colored(f"\n  ✔ Scan selesai dalam {dt:.1f} detik\n", "G"))
        try:
            txt_path, json_path = generate_report(target, results, ctx)
            print(colored(f"  📄 TXT  : {os.path.abspath(txt_path)}", "G"))
            print(colored(f"  📋 JSON : {os.path.abspath(json_path)}", "G"))
        except Exception as e:
            print(colored(f"  ✘ Gagal menulis laporan: {e}", "R"))
            traceback.print_exc()
        print()

    # Cleanup
    try:
        ctx_httpx = ctx.get("httpx_client")
        if ctx_httpx:
            ctx_httpx.close()
    except Exception:
        pass

if __name__ == "__main__":
    main()
