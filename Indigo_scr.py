#!/usr/bin/env python3
"""
Indigo SCR v4.3 - Indigo Security Crawler & Reconnaissance
6 Deep Scanning Engines: NMAP + DNS + SSL + WAF + ZAP + BS4
v4.1 FULL FEATURES + v4.2 ERROR FIXES + v4.3 VULN-BOT INTEGRATION
- ensure_str(): fix tuple/bytes/dict → string
- safe_join(): fix "sequence item 0: expected str" 
- safe_call(): fix "'str' object is not callable"
- WAF dynamic API: fix "'WAFW00F' has no attribute 'identwaf'"
- DNS resolve_dns(): fix unhandled DNS exceptions
- json.dump default=ensure_str: fix serialization
- VULN-BOT integration: AI payload generation after scan
"""

import os
import sys
import time
import json
import re
import ssl as ssl_lib
import socket
import logging
import subprocess
import importlib
import shutil
import platform
from datetime import datetime
from urllib.parse import urlparse, urljoin

# ============================================================
# ENCODING FIX
# ============================================================
os.environ['PYTHONIOENCODING'] = 'utf-8'
try:
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
except Exception:
    pass

# ============================================================
# GLOBAL STATUS
# ============================================================
ZAP_STATUS = {
    "state": "UNKNOWN",
    "message": "",
    "details": [],
    "version": "N/A",
    "scan_mode": "BS4-ONLY",
}

ENGINE_STATUS = {
    "nmap": {"available": False, "reason": ""},
    "dns":  {"available": False, "reason": ""},
    "ssl":  {"available": True,  "reason": "built-in ssl module"},
    "waf":  {"available": False, "reason": ""},
    "zap":  {"available": False, "reason": ""},
    "bs4":  {"available": False, "reason": ""},
}

# ============================================================
# UTILITY HELPERS - Fix tuple/str/join errors
# ============================================================
def ensure_str(val, fallback=""):
    """Konversi APAPUN ke string dengan aman (tuple, bytes, dict, None)."""
    if val is None:
        return fallback
    if isinstance(val, bytes):
        try:
            return val.decode('utf-8', errors='replace')
        except:
            return str(val)
    if isinstance(val, tuple):
        return " - ".join(str(x) for x in val)
    if isinstance(val, list):
        return ", ".join(str(x) for x in val)
    if isinstance(val, dict):
        return json.dumps(val, default=str)
    return str(val)

def safe_join(iterable, sep=", ", fallback=""):
    """Join iterable dengan auto-konversi setiap item ke string."""
    try:
        if not iterable:
            return fallback
        str_items = [ensure_str(item) for item in iterable if item is not None]
        str_items = [s for s in str_items if s and s.strip()]
        if not str_items:
            return fallback
        return sep.join(str_items)
    except Exception:
        return fallback

def safe_call(func, *args, fallback=None, **kwargs):
    """Panggil fungsi/method dengan aman. Handle property vs callable."""
    try:
        if callable(func):
            return func(*args, **kwargs)
        else:
            return func
    except TypeError:
        try:
            return func
        except:
            return fallback
    except Exception:
        return fallback

def safe_int(value, fallback=0):
    """Konversi ke int dengan aman."""
    try:
        if isinstance(value, str):
            return int(value.strip())
        return int(value)
    except (TypeError, ValueError):
        return fallback

def safe_list(value):
    """Pastikan value adalah list."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    if isinstance(value, str):
        return [value]
    return [value]

# ============================================================
# LOGGER
# ============================================================
class ColorFormatter(logging.Formatter):
    C = {'DEBUG':'\033[36m','INFO':'\033[32m','WARNING':'\033[33m',
         'ERROR':'\033[31m','CRITICAL':'\033[1;31m'}
    R = '\033[0m'; B = '\033[1m'; D = '\033[2m'
    def format(self, record):
        color = self.C.get(record.levelname, self.R)
        ts = datetime.fromtimestamp(record.created).strftime('%H:%M:%S')
        pm = {'INFO':'[+]','WARNING':'[!]','ERROR':'[X]','CRITICAL':'[X]','DEBUG':'[D]'}
        sym = pm.get(record.levelname, '[*]')
        return f"{self.D}{ts}{self.R} {color}{self.B}{sym:>3}{self.R} {record.getMessage()}"

logger = logging.getLogger("IndigoSCR")
logger.setLevel(logging.DEBUG)
_handler = logging.StreamHandler(sys.stdout)
_handler.setLevel(logging.DEBUG)
_handler.setFormatter(ColorFormatter())
logger.addHandler(_handler)

# ============================================================
# PHASE 0.5: SYSTEM DEPENDENCIES
# ============================================================
def install_system_dependencies():
    logger.info("=" * 58)
    logger.info("  PHASE 0.5: SYSTEM PACKAGE CHECKER")
    logger.info("=" * 58)

    system = platform.system()

    logger.info("  Checking nmap binary...")
    nmap_path = shutil.which("nmap")
    if nmap_path:
        logger.info(f"  [OK] nmap found: {nmap_path}")
        ENGINE_STATUS["nmap"]["available"] = True
        ENGINE_STATUS["nmap"]["reason"] = f"binary at {nmap_path}"
        return

    if system == "Linux":
        logger.info("  nmap not found. Attempting apt-get install...")
        try:
            subprocess.run(
                ["sudo", "apt-get", "update", "-qq"],
                capture_output=True, text=True, timeout=60
            )
            result = subprocess.run(
                ["sudo", "apt-get", "install", "-y", "-qq", "nmap"],
                capture_output=True, text=True, timeout=120
            )
            if result.returncode == 0 and shutil.which("nmap"):
                logger.info(f"  [OK] nmap installed: {shutil.which('nmap')}")
                ENGINE_STATUS["nmap"]["available"] = True
                ENGINE_STATUS["nmap"]["reason"] = "installed via apt-get"
                return
        except Exception as e:
            logger.warning(f"  [!] apt-get failed: {ensure_str(e)}")

    elif system == "Darwin":
        try:
            subprocess.run(["brew", "install", "nmap"], capture_output=True, timeout=120)
            if shutil.which("nmap"):
                logger.info("  [OK] nmap installed via brew")
                ENGINE_STATUS["nmap"]["available"] = True
                return
        except:
            pass

    logger.warning("  [!] nmap binary not available")
    ENGINE_STATUS["nmap"]["reason"] = "not found, install: sudo apt install nmap"

# ============================================================
# PHASE 1: PYTHON DEPENDENCIES
# ============================================================
REQUIRED_DEPENDENCIES = [
    ("cloudscraper",    "cloudscraper",     "Stealth HTTP (WAF bypass)",      False, "bs4"),
    ("fake_useragent",  "fake-useragent",   "Random User-Agent",             False, "bs4"),
    ("validators",      "validators",       "URL/Domain/IP validation",      False, None),
    ("bs4",             "beautifulsoup4",    "HTML deep parsing",             False, "bs4"),
    ("colorama",        "colorama",          "Terminal colors",               False, None),
    ("nmap",            "python-nmap",       "NMAP port scanner API",         True,  "nmap"),
    ("dns.resolver",    "dnspython",         "DNS reconnaissance",            True,  "dns"),
    ("OpenSSL",         "pyOpenSSL",         "SSL/TLS deep analysis",         True,  "ssl"),
    ("wafw00f",         "wafw00f",           "WAF detection",                 True,  "waf"),
    ("zapv2",           "zaproxy",           "OWASP ZAP Python API",          True,  "zap"),
    ("psutil",          "psutil",            "Process utilities",             True,  None),
]

def check_and_install_dependencies():
    logger.info("=" * 58)
    logger.info("  PHASE 1: PYTHON DEPENDENCY CHECKER")
    logger.info("=" * 58)

    missing = []
    installed = []
    optional_missing = []

    for import_name, pip_name, desc, is_optional, engine_key in REQUIRED_DEPENDENCIES:
        try:
            importlib.import_module(import_name)
            installed.append((pip_name, desc))
            if engine_key and engine_key in ENGINE_STATUS:
                ENGINE_STATUS[engine_key]["available"] = True
                ENGINE_STATUS[engine_key]["reason"] = f"{pip_name} installed"
            logger.info(f"  [OK] {pip_name:<22s} - installed")
        except ImportError:
            if is_optional:
                optional_missing.append((import_name, pip_name, desc, engine_key))
                logger.warning(f"  [--] {pip_name:<22s} - optional, missing")
            else:
                missing.append((import_name, pip_name, desc, engine_key))
                logger.warning(f"  [!!] {pip_name:<22s} - REQUIRED, missing")

    logger.info("")
    total = len(REQUIRED_DEPENDENCIES)
    logger.info(f"  Status: {len(installed)}/{total} OK | {len(missing)} req missing | {len(optional_missing)} opt missing")

    all_to_install = missing + optional_missing
    if not all_to_install:
        logger.info("  All dependencies satisfied!")
        time.sleep(1)
        return True

    logger.info("")
    logger.info(f"  Installing {len(all_to_install)} package(s)...")

    failed_required = []
    failed_optional = []

    for i, (import_name, pip_name, desc, engine_key) in enumerate(all_to_install, 1):
        is_opt = any(im == import_name for im, _, _, _ in optional_missing)
        tag = "optional" if is_opt else "REQUIRED"
        logger.info(f"  [{i}/{len(all_to_install)}] {pip_name} ({tag})...")

        try:
            subprocess.run(
                [sys.executable, "-m", "pip", "uninstall", pip_name, "-y", "--quiet"],
                capture_output=True, text=True, timeout=30
            )
        except Exception:
            pass

        try:
            result = subprocess.run(
                [sys.executable, "-m", "pip", "install", pip_name,
                 "--quiet", "--disable-pip-version-check", "--force-reinstall"],
                capture_output=True, text=True, timeout=180
            )
            if result.returncode == 0:
                importlib.invalidate_caches()
                try:
                    importlib.import_module(import_name)
                    logger.info(f"       [OK] {pip_name} installed!")
                    if engine_key and engine_key in ENGINE_STATUS:
                        ENGINE_STATUS[engine_key]["available"] = True
                        ENGINE_STATUS[engine_key]["reason"] = f"{pip_name} installed"
                except ImportError:
                    if import_name == "zapv2":
                        try:
                            importlib.import_module("zaproxy")
                            logger.info(f"       [OK] {pip_name} (alt import)")
                            if engine_key:
                                ENGINE_STATUS[engine_key]["available"] = True
                                ENGINE_STATUS[engine_key]["reason"] = f"{pip_name} (alt)"
                        except ImportError:
                            (failed_optional if is_opt else failed_required).append(pip_name)
                    else:
                        (failed_optional if is_opt else failed_required).append(pip_name)
            else:
                se = result.stderr[:150] if result.stderr else ""
                logger.error(f"       [X] pip failed: {se}")
                (failed_optional if is_opt else failed_required).append(pip_name)
        except subprocess.TimeoutExpired:
            logger.error(f"       [X] Timeout")
            (failed_optional if is_opt else failed_required).append(pip_name)
        except Exception as e:
            logger.error(f"       [X] {ensure_str(e)}")
            (failed_optional if is_opt else failed_required).append(pip_name)

    logger.info("")
    if failed_required:
        logger.error(f"  FAILED (required): {safe_join(failed_required)}")
        return False
    if failed_optional:
        logger.warning(f"  FAILED (optional): {safe_join(failed_optional)}")

    for import_name, pip_name, desc, engine_key in all_to_install:
        if engine_key and engine_key in ENGINE_STATUS and not ENGINE_STATUS[engine_key]["available"]:
            ENGINE_STATUS[engine_key]["reason"] = f"{pip_name} install failed"

    logger.info("  [OK] Dependency check complete!")
    time.sleep(1)
    return True

# ============================================================
# PHASE 2: ZAP SERVICE
# ============================================================
ZAP_PROXY_HOST = "127.0.0.1"
ZAP_PROXY_PORT = 8080
ZAP_API_KEY = ""
ZAP_PROCESS = None

def is_port_open(host, port, timeout=2):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except:
        return False

def find_zap_binary():
    system = platform.system()
    zap_paths = []
    if system == "Windows":
        zap_paths = [r"C:\Program Files\ZAP\Zed Attack Proxy\zap.bat"]
    elif system == "Darwin":
        zap_paths = ["/Applications/ZAP.app/Contents/Java/zap.sh", "/usr/local/bin/zap.sh"]
    else:
        zap_paths = [
            "/usr/share/zaproxy/zap.sh", "/opt/zaproxy/zap.sh",
            "/usr/local/zaproxy/zap.sh",
            os.path.expanduser("~/ZAP/zap.sh"),
            os.path.expanduser("~/zaproxy/zap.sh"),
            "/snap/bin/zaproxy", "/usr/bin/zap.sh",
        ]
    for name in ["zap.sh", "zap", "zaproxy"]:
        found = shutil.which(name)
        if found:
            zap_paths.insert(0, found)
    zap_home = os.environ.get('ZAP_HOME', '')
    if zap_home:
        zap_paths.insert(0, os.path.join(zap_home, 'zap.sh'))
    for p in zap_paths:
        if os.path.isfile(p):
            return p
    return None

def check_docker_available():
    try:
        r = subprocess.run(["docker", "--version"], capture_output=True, text=True, timeout=5)
        return r.returncode == 0
    except:
        return False

def start_zap_daemon(zap_path=None, use_docker=False):
    global ZAP_PROCESS
    if use_docker:
        logger.info("  Starting ZAP via Docker...")
        try:
            subprocess.run(
                ["docker", "pull", "ghcr.io/zaproxy/zaproxy:stable"],
                capture_output=True, text=True, timeout=300
            )
            ZAP_PROCESS = subprocess.Popen(
                ["docker", "run", "--rm", "--name", "indigo-zap",
                 "-p", f"{ZAP_PROXY_PORT}:{ZAP_PROXY_PORT}",
                 "ghcr.io/zaproxy/zaproxy:stable",
                 "zap.sh", "-daemon", "-host", "0.0.0.0", "-port", str(ZAP_PROXY_PORT),
                 "-config", "api.disablekey=true",
                 "-config", "api.addrs.addr.name=.*",
                 "-config", "api.addrs.addr.regex=true"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            logger.info(f"  Docker ZAP PID: {ZAP_PROCESS.pid}")
            return True
        except Exception as e:
            ZAP_STATUS["details"].append(f"Docker: {ensure_str(e)}")
            return False
    elif zap_path:
        logger.info(f"  Starting ZAP: {zap_path}")
        try:
            ZAP_PROCESS = subprocess.Popen(
                [zap_path, "-daemon", "-host", ZAP_PROXY_HOST,
                 "-port", str(ZAP_PROXY_PORT),
                 "-config", "api.disablekey=true",
                 "-config", "api.addrs.addr.name=.*",
                 "-config", "api.addrs.addr.regex=true"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            logger.info(f"  ZAP daemon PID: {ZAP_PROCESS.pid}")
            return True
        except Exception as e:
            ZAP_STATUS["details"].append(f"Daemon: {ensure_str(e)}")
            return False
    return False

def wait_for_zap_ready(max_wait=90, interval=3):
    logger.info(f"  Waiting for ZAP API (timeout: {max_wait}s)...")
    t0 = time.time()
    while (time.time() - t0) < max_wait:
        if is_port_open(ZAP_PROXY_HOST, ZAP_PROXY_PORT, timeout=2):
            try:
                import urllib.request
                url = f"http://{ZAP_PROXY_HOST}:{ZAP_PROXY_PORT}/JSON/core/view/version/"
                with urllib.request.urlopen(urllib.request.Request(url), timeout=5) as r:
                    data = json.loads(r.read().decode())
                    ver = ensure_str(data.get('version', 'unknown'))
                    el = int(time.time() - t0)
                    logger.info(f"  [OK] ZAP ready! v{ver} ({el}s)")
                    return True, ver
            except:
                pass
        el = int(time.time() - t0)
        dots = "." * ((el % 3) + 1)
        print(f"\r  [*] Waiting... {el}s/{max_wait}s {dots}  ", end='', flush=True)
        time.sleep(interval)
    print("")
    return False, "N/A"

def setup_zap_service():
    global ZAP_STATUS
    ZAP_STATUS["details"] = []

    logger.info("=" * 58)
    logger.info("  PHASE 2: OWASP ZAP SERVICE SETUP")
    logger.info("=" * 58)

    logger.info("  [1/4] Checking existing ZAP...")
    if is_port_open(ZAP_PROXY_HOST, ZAP_PROXY_PORT, timeout=2):
        ready, ver = wait_for_zap_ready(max_wait=15, interval=2)
        if ready:
            ZAP_STATUS.update({
                "state": "ONLINE",
                "message": f"ZAP v{ver} on :{ZAP_PROXY_PORT}",
                "version": ver, "scan_mode": "FULL"
            })
            ZAP_STATUS["details"].append("ZAP API responded OK")
            ENGINE_STATUS["zap"]["available"] = True
            return True
        ZAP_STATUS["details"].append(f"Port {ZAP_PROXY_PORT} open but no ZAP API")
    else:
        ZAP_STATUS["details"].append(f"No ZAP on {ZAP_PROXY_HOST}:{ZAP_PROXY_PORT}")

    logger.info("  [2/4] Searching ZAP binary...")
    zp = find_zap_binary()
    if zp:
        logger.info(f"  [OK] Found: {zp}")
        ZAP_STATUS["details"].append(f"Binary: {zp}")
        if start_zap_daemon(zap_path=zp):
            ZAP_STATUS["details"].append("Daemon launched")
            ready, ver = wait_for_zap_ready(max_wait=90)
            if ready:
                ZAP_STATUS.update({
                    "state": "ONLINE",
                    "message": f"ZAP v{ver} from {os.path.basename(zp)}",
                    "version": ver, "scan_mode": "FULL"
                })
                ENGINE_STATUS["zap"]["available"] = True
                return True
            ZAP_STATUS["details"].append("API timeout 90s (Java? OOM?)")
    else:
        ZAP_STATUS["details"].append("No ZAP binary found")

    logger.info("  [3/4] Docker fallback...")
    if check_docker_available():
        ZAP_STATUS["details"].append("Docker found, trying...")
        if start_zap_daemon(use_docker=True):
            ready, ver = wait_for_zap_ready(max_wait=180, interval=5)
            if ready:
                ZAP_STATUS.update({
                    "state": "ONLINE",
                    "message": f"ZAP v{ver} via Docker",
                    "version": ver, "scan_mode": "FULL"
                })
                ENGINE_STATUS["zap"]["available"] = True
                return True
            ZAP_STATUS["details"].append("Docker timeout 180s")
    else:
        ZAP_STATUS["details"].append("Docker not available")

    ZAP_STATUS.update({
        "state": "OFFLINE",
        "message": "All ZAP start methods failed",
        "scan_mode": "BS4-ONLY"
    })
    ZAP_STATUS["details"].append("")
    ZAP_STATUS["details"].append("To enable ZAP manually:")
    ZAP_STATUS["details"].append("  1) https://www.zaproxy.org/download/")
    ZAP_STATUS["details"].append("  2) docker run -t -p 8080:8080 ghcr.io/zaproxy/zaproxy:stable \\")
    ZAP_STATUS["details"].append("       zap.sh -daemon -host 0.0.0.0 -port 8080")
    ENGINE_STATUS["zap"]["reason"] = "binary/docker not found"
    return False

def cleanup_zap():
    global ZAP_PROCESS
    if ZAP_PROCESS:
        try:
            ZAP_PROCESS.terminate()
            ZAP_PROCESS.wait(timeout=10)
        except:
            try:
                ZAP_PROCESS.kill()
            except:
                pass

# ============================================================
# PHASE 3: IMPORT ALL
# ============================================================
validators = None; cloudscraper = None; BeautifulSoup = None; Comment = None
UserAgent = None; Fore = None; Style = None; ZAPv2 = None; psutil = None

def import_all_dependencies():
    global validators, cloudscraper, BeautifulSoup, Comment, UserAgent
    global Fore, Style, ZAPv2, psutil

    import validators as _v; validators = _v
    import cloudscraper as _c; cloudscraper = _c
    from bs4 import BeautifulSoup as _B, Comment as _C
    BeautifulSoup = _B; Comment = _C
    from fake_useragent import UserAgent as _U; UserAgent = _U
    from colorama import Fore as _F, Style as _S, init as _I
    Fore = _F; Style = _S
    import psutil as _p; psutil = _p
    _I(autoreset=True)

    # ZAP import - coba kedua kemungkinan
    ZAPv2 = None
    try:
        from zapv2 import ZAPv2 as _Z
        ZAPv2 = _Z
        ENGINE_STATUS["zap"]["available"] = True
        ENGINE_STATUS["zap"]["reason"] = "zapv2 module loaded"
        logger.info("  [OK] ZAPv2 imported (from zapv2)")
    except ImportError:
        try:
            from zaproxy import ZAPv2 as _Z
            ZAPv2 = _Z
            ENGINE_STATUS["zap"]["available"] = True
            ENGINE_STATUS["zap"]["reason"] = "zaproxy module loaded"
            logger.info("  [OK] ZAPv2 imported (from zaproxy)")
        except ImportError:
            logger.warning("  [!] ZAPv2 module unavailable")
            ENGINE_STATUS["zap"]["reason"] = "zapv2 module not importable"

    logger.info("  [OK] All modules loaded")

# ============================================================
# BANNER: NEW ASCII ART BANNER
# ============================================================
def show_banner():
    os.system('cls' if os.name == 'nt' else 'clear')

    RED_B = '\033[91m\033[1m'
    R = '\033[0m'
    C = '\033[36m'
    Y = '\033[33m'
    G = '\033[32m'
    D = '\033[2m'
    W = '\033[37m'

    if ZAP_STATUS["state"] == "ONLINE":
        zc = G; zi = "[ONLINE]"; zv = f"v{ZAP_STATUS['version']}"
    else:
        zc = '\033[31m'; zi = "[OFFLINE]"; zv = "---"

    mode = ZAP_STATUS["scan_mode"]

    active = []
    for eng, st in ENGINE_STATUS.items():
        if st["available"] or (eng == "ssl"):
            active.append(eng.upper())
    active_str = safe_join(sorted(set(active)), " + ", "BS4")

    # New ASCII Art Banner
    banner_lines = [
        f"{RED_B} _)             | _)                                  ",
        f"  |  __ \\    _` |  |   _` |   _ \\     __|   __|   __| ",
        f"  |  |   |  (   |  |  (   |  (   |  \\__ \\  (     |    ",
        f" _| _|  _| \\__,_| _| \\__, | \\___/   ____/ \\___| _|    ",
        f"                     |___/      _____|                {R}",
        "",
        f"{RED_B}{'='*58}{R}",
        f"",
        f"{C}[*] Active Engines : {W}{active_str}{R}",
        f"{C}[*] Accept         : {W}URL / Domain / IP Address{R}",
        f"{Y}[*] Version        : {W}4.3{R}",
        f"{C}[*] Mode           : {W}{mode} (ZAP: {zi}){R}",
        f"",
        f"{RED_B}{'='*58}{R}",
        ""
    ]

    print('\n'.join(banner_lines))

# ============================================================
# VALIDATE TARGET
# ============================================================
def validate_target(target_input):
    target = target_input.strip()
    if not target:
        return False, target
    target = target.rstrip('/')
    has_scheme = target.startswith('http://') or target.startswith('https://')
    formatted = target if has_scheme else 'https://' + target
    if validators.url(formatted):
        return True, formatted
    if validators.domain(target):
        return True, 'https://' + target
    ip_part = target.split(':')[0]
    if validators.ipv4(ip_part):
        return True, 'http://' + target
    if validators.ipv6(ip_part.strip('[]')):
        return True, 'http://' + target
    return False, target

# ============================================================
# ENGINE 1: NMAP
# ============================================================
def nmap_scan_engine(target_url):
    results = {
        "host_info": {}, "open_ports": [], "services_detected": [],
        "os_detection": {}, "vulnerability_scripts": [], "scan_statistics": {}
    }
    print(f"\n\033[36m{'='*58}")
    print(f"  [NMAP ENGINE] Port Scan & Service Detection")
    print(f"{'='*58}\033[0m")

    if not shutil.which("nmap"):
        print(f"\033[33m  [!] nmap binary not found, skipping\033[0m")
        return results

    try:
        import nmap as nmap_lib
    except ImportError:
        print(f"\033[33m  [!] python-nmap not installed, skipping\033[0m")
        return results

    parsed = urlparse(target_url)
    hostname = parsed.hostname
    if not hostname:
        print(f"\033[31m  [!] Cannot extract hostname\033[0m")
        return results

    nm = nmap_lib.PortScanner()

    # 1. Port scan + service version
    print(f"\033[33m[*] [1/4] Scanning ports + service detection...\033[0m")
    try:
        nm.scan(hostname, arguments='-sV -sC --top-ports 1000 -T4 --max-retries 2 --host-timeout 120s')
        for host in nm.all_hosts():
            results["host_info"] = {
                "hostname": ensure_str(nm[host].hostname()),
                "state": ensure_str(nm[host].state()),
                "ip": host
            }
            for proto in nm[host].all_protocols():
                for port in sorted(nm[host][proto].keys()):
                    pi = nm[host][proto][port]
                    results["open_ports"].append({
                        "port": port, "protocol": proto,
                        "state": ensure_str(pi.get('state', '')),
                        "service": ensure_str(pi.get('name', '')),
                        "product": ensure_str(pi.get('product', '')),
                        "version": ensure_str(pi.get('version', '')),
                        "extra_info": ensure_str(pi.get('extrainfo', '')),
                        "cpe": ensure_str(pi.get('cpe', ''))
                    })
                    svc = f"{port}/{proto} {pi.get('name','')} {pi.get('product','')} {pi.get('version','')}".strip()
                    results["services_detected"].append(svc)
        print(f"    Open ports: {len(results['open_ports'])}")
        print(f"    Services: {len(results['services_detected'])}")
    except Exception as e:
        print(f"\033[31m    Scan error: {ensure_str(e)[:80]}\033[0m")

    # 2. OS Detection
    print(f"\033[33m[*] [2/4] OS fingerprinting...\033[0m")
    try:
        nm2 = nmap_lib.PortScanner()
        nm2.scan(hostname, arguments='-O --max-retries 1 --host-timeout 60s')
        for host in nm2.all_hosts():
            if 'osmatch' in nm2[host]:
                for om in nm2[host]['osmatch']:
                    results["os_detection"] = {
                        "name": ensure_str(om.get('name', '')),
                        "accuracy": ensure_str(om.get('accuracy', '')),
                        "osclass": [
                            {"type": ensure_str(oc.get('type', '')), "vendor": ensure_str(oc.get('vendor', '')),
                             "osfamily": ensure_str(oc.get('osfamily', '')), "osgen": ensure_str(oc.get('osgen', ''))}
                            for oc in om.get('osclass', [])
                        ]
                    }
                    break
        if results["os_detection"]:
            print(f"    OS: {results['os_detection'].get('name', 'Unknown')}")
        else:
            print(f"    OS: not detected (may need root)")
    except Exception as e:
        print(f"    OS: skipped ({ensure_str(e)[:60]})")

    # 3. Safe NSE
    print(f"\033[33m[*] [3/4] Safe NSE scripts...\033[0m")
    try:
        nm3 = nmap_lib.PortScanner()
        nm3.scan(hostname, arguments='--script=safe --top-ports 100 -T4 --host-timeout 90s')
        for host in nm3.all_hosts():
            for proto in nm3[host].all_protocols():
                for port in nm3[host][proto]:
                    scripts = nm3[host][proto][port].get('script', {})
                    if isinstance(scripts, dict):
                        for sid, out in scripts.items():
                            results["vulnerability_scripts"].append({
                                "port": port, "script": ensure_str(sid),
                                "output": ensure_str(out)[:300]
                            })
        print(f"    NSE results: {len(results['vulnerability_scripts'])}")
    except Exception as e:
        print(f"    NSE: skipped ({ensure_str(e)[:60]})")

    # 4. Stats
    high_risk = [21, 23, 25, 135, 139, 445, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 27017]
    results["scan_statistics"] = {
        "total_open_ports": len(results["open_ports"]),
        "total_services": len(results["services_detected"]),
        "os_detected": bool(results["os_detection"]),
        "nse_results": len(results["vulnerability_scripts"]),
        "high_risk_ports": [p["port"] for p in results["open_ports"] if p["port"] in high_risk]
    }
    print(f"    High-risk ports: {results['scan_statistics']['high_risk_ports'] or 'none'}")
    return results

# ============================================================
# ENGINE 2: DNS RECON (FULL v4.1 + resolve_dns fix)
# ============================================================
def dns_recon_engine(target_url):
    results = {
        "a_records": [], "aaaa_records": [], "mx_records": [],
        "ns_records": [], "txt_records": [], "soa_record": {},
        "cname_records": [], "caa_records": [],
        "spf_analysis": {}, "dmarc_analysis": {},
        "zone_transfer": {"success": False, "records": []},
        "reverse_dns": [], "resolved_ip": ""
    }
    print(f"\n\033[36m{'='*58}")
    print(f"  [DNS ENGINE] DNS Reconnaissance")
    print(f"{'='*58}\033[0m")

    try:
        import dns.resolver
        import dns.reversename
        import dns.zone
        import dns.query
        import dns.exception
    except ImportError:
        print(f"\033[33m  [!] dnspython not installed, skipping\033[0m")
        return results

    parsed = urlparse(target_url)
    domain = parsed.hostname
    if not domain:
        return results
    if domain.startswith('www.'):
        domain = domain[4:]

    # Helper untuk resolve DNS dengan proper error handling (FIX)
    def resolve_dns(d, rdtype, timeout=10):
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = timeout
            resolver.lifetime = timeout
            return resolver.resolve(d, rdtype)
        except dns.resolver.NXDOMAIN:
            return None
        except dns.resolver.NoAnswer:
            return None
        except dns.resolver.NoNameservers:
            return None
        except dns.exception.Timeout:
            return None
        except Exception:
            return None

    # 1. A Records
    print(f"\033[33m[*] [1/8] A Records...\033[0m")
    ans = resolve_dns(domain, 'A')
    if ans:
        results["a_records"] = [ensure_str(r.address) for r in ans]
        if results["a_records"]:
            results["resolved_ip"] = results["a_records"][0]
        print(f"    {len(results['a_records'])} records: {safe_join(results['a_records'][:5])}")
    else:
        print(f"    A: no records")

    # 2. AAAA
    print(f"\033[33m[*] [2/8] AAAA Records...\033[0m")
    ans = resolve_dns(domain, 'AAAA')
    if ans:
        results["aaaa_records"] = [ensure_str(r.address) for r in ans]
        print(f"    {len(results['aaaa_records'])} IPv6 records")
    else:
        print(f"    AAAA: none")

    # 3. MX
    print(f"\033[33m[*] [3/8] MX Records...\033[0m")
    ans = resolve_dns(domain, 'MX')
    if ans:
        results["mx_records"] = [
            {"pref": safe_int(r.preference, 0), "exchange": ensure_str(r.exchange).rstrip('.')}
            for r in ans
        ]
        print(f"    {len(results['mx_records'])} mail servers")
    else:
        print(f"    MX: none")

    # 4. NS
    print(f"\033[33m[*] [4/8] NS Records...\033[0m")
    ans = resolve_dns(domain, 'NS')
    if ans:
        results["ns_records"] = [ensure_str(r.target).rstrip('.') for r in ans]
        print(f"    NS: {safe_join(results['ns_records'][:5])}")
    else:
        print(f"    NS: none")

    # 5. TXT
    print(f"\033[33m[*] [5/8] TXT Records...\033[0m")
    ans = resolve_dns(domain, 'TXT')
    if ans:
        results["txt_records"] = [ensure_str(r) for r in ans]
        print(f"    {len(results['txt_records'])} TXT records")
    else:
        print(f"    TXT: none")

    # 6. SOA
    print(f"\033[33m[*] [6/8] SOA Record...\033[0m")
    ans = resolve_dns(domain, 'SOA')
    if ans:
        for r in ans:
            results["soa_record"] = {
                "mname": ensure_str(r.mname).rstrip('.'),
                "rname": ensure_str(r.rname).rstrip('.'),
                "serial": safe_int(r.serial),
                "refresh": safe_int(r.refresh),
                "retry": safe_int(r.retry),
                "expire": safe_int(r.expire),
                "minimum": safe_int(r.minimum)
            }
        print(f"    SOA: {results['soa_record'].get('mname', 'N/A')}")
    else:
        print(f"    SOA: none")

    # 7. CNAME + CAA
    print(f"\033[33m[*] [7/8] CNAME & CAA...\033[0m")
    ans = resolve_dns(domain, 'CNAME')
    if ans:
        results["cname_records"] = [ensure_str(r.target).rstrip('.') for r in ans]
    ans = resolve_dns(domain, 'CAA')
    if ans:
        for r in ans:
            try:
                tag = r.tag.decode() if isinstance(r.tag, bytes) else ensure_str(r.tag)
                val = r.value.decode() if isinstance(r.value, bytes) else ensure_str(r.value)
                results["caa_records"].append({
                    "flags": safe_int(r.flags), "tag": tag, "value": val
                })
            except:
                pass
    print(f"    CNAME: {len(results['cname_records'])} | CAA: {len(results['caa_records'])}")

    # SPF
    for txt in results["txt_records"]:
        if 'v=spf1' in txt:
            results["spf_analysis"] = {
                "record": txt, "present": True,
                "includes": re.findall(r'include:([^\s]+)', txt)
            }
            break
    if not results["spf_analysis"]:
        results["spf_analysis"] = {"present": False, "risk": "No SPF - spoofing possible"}

    # DMARC
    ans = resolve_dns(f'_dmarc.{domain}', 'TXT')
    if ans:
        for r in ans:
            txt = ensure_str(r)
            if 'v=DMARC1' in txt:
                pol = re.search(r'p=([^\s;]+)', txt)
                results["dmarc_analysis"] = {
                    "record": txt, "present": True,
                    "policy": pol.group(1) if pol else "none"
                }
    if not results["dmarc_analysis"]:
        results["dmarc_analysis"] = {"present": False, "risk": "No DMARC record"}

    # 8. Zone Transfer + Reverse DNS
    print(f"\033[33m[*] [8/8] Zone Transfer & Reverse DNS...\033[0m")
    for ns in results["ns_records"][:3]:
        try:
            z = dns.zone.from_xfr(dns.query.xfr(ns, domain, timeout=10))
            if z:
                results["zone_transfer"]["success"] = True
                results["zone_transfer"]["nameserver"] = ns
                results["zone_transfer"]["records"] = [ensure_str(n) for n in z.nodes.keys()][:50]
                print(f"    [CRITICAL] Zone transfer SUCCESS via {ns}!")
                break
        except:
            pass

    if not results["zone_transfer"]["success"]:
        print(f"    Zone transfer: denied (good)")

    for ip in results["a_records"][:3]:
        try:
            rev = dns.reversename.from_address(ip)
            ans = resolve_dns(ensure_str(rev), 'PTR')
            if ans:
                for r in ans:
                    results["reverse_dns"].append({
                        "ip": ip, "ptr": ensure_str(r.target).rstrip('.')
                    })
        except:
            pass
    print(f"    Reverse DNS: {len(results['reverse_dns'])} PTR records")
    return results

# ============================================================
# ENGINE 3: SSL/TLS (FULL v4.1)
# ============================================================
def ssl_analysis_engine(target_url):
    results = {
        "certificate": {}, "issuer": {}, "validity": {},
        "san_entries": [], "chain_info": {}, "connection_info": {},
        "cipher_suites": [], "vulnerabilities": [], "grade": "Unknown"
    }
    print(f"\n\033[36m{'='*58}")
    print(f"  [SSL ENGINE] TLS/SSL Certificate Analysis")
    print(f"{'='*58}\033[0m")

    parsed = urlparse(target_url)
    hostname = parsed.hostname
    port = parsed.port or 443
    if not hostname:
        return results

    # 1. Fetch cert
    print(f"\033[33m[*] [1/5] Fetching certificate...\033[0m")
    try:
        ctx = ssl_lib.create_default_context()
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                version = ssock.version()

                subject_dict = {}
                for item in cert.get('subject', ()):
                    if item and len(item) > 0:
                        for k, v in item:
                            subject_dict[k] = v

                issuer_dict = {}
                for item in cert.get('issuer', ()):
                    if item and len(item) > 0:
                        for k, v in item:
                            issuer_dict[k] = v

                results["certificate"] = {
                    "subject": subject_dict,
                    "serial": ensure_str(cert.get('serialNumber', '')),
                    "version": ensure_str(cert.get('version', '')),
                }
                results["issuer"] = issuer_dict
                results["validity"] = {
                    "not_before": ensure_str(cert.get('notBefore', '')),
                    "not_after": ensure_str(cert.get('notAfter', '')),
                }
                results["san_entries"] = [
                    {"type": ensure_str(s[0]), "value": ensure_str(s[1])}
                    for s in cert.get('subjectAltName', ())
                ]
                results["connection_info"] = {
                    "tls_version": ensure_str(version),
                    "cipher_suite": ensure_str(cipher[0]) if cipher else '',
                    "cipher_bits": safe_int(cipher[2]) if cipher else 0,
                    "cipher_protocol": ensure_str(cipher[1]) if cipher else ''
                }
                print(f"    Subject: {subject_dict.get('commonName', 'N/A')}")
                print(f"    Issuer: {issuer_dict.get('organizationName', 'N/A')}")
                print(f"    TLS: {version} | Cipher: {cipher[0] if cipher else 'N/A'}")
    except Exception as e:
        print(f"\033[31m    Cert fetch failed: {ensure_str(e)[:80]}\033[0m")
        return results

    # 2. Expiry
    print(f"\033[33m[*] [2/5] Certificate validity...\033[0m")
    try:
        na = results["validity"]["not_after"]
        if na:
            exp = datetime.strptime(na, '%b %d %H:%M:%S %Y %Z')
            days = (exp - datetime.utcnow()).days
            results["validity"]["days_until_expiry"] = days
            if days < 0:
                results["vulnerabilities"].append({
                    "issue": "Certificate EXPIRED",
                    "severity": "CRITICAL",
                    "detail": f"Expired {-days}d ago"
                })
            elif days < 30:
                results["vulnerabilities"].append({
                    "issue": "Expiring soon",
                    "severity": "WARNING",
                    "detail": f"{days}d left"
                })
            print(f"    Expires in: {days} days")
    except:
        print(f"    Could not parse expiry")

    # 3. Protocol
    print(f"\033[33m[*] [3/5] Protocol analysis...\033[0m")
    tls_ver = results["connection_info"].get("tls_version", "")
    if tls_ver in ["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"]:
        results["vulnerabilities"].append({
            "issue": f"Weak protocol: {tls_ver}",
            "severity": "HIGH",
            "detail": "Deprecated protocol version"
        })
    print(f"    Current: {tls_ver}")

    # 4. Cipher
    print(f"\033[33m[*] [4/5] Cipher strength...\033[0m")
    cn = results["connection_info"].get("cipher_suite", "")
    cb = safe_int(results["connection_info"].get("cipher_bits", 0))
    results["cipher_suites"] = [{"name": cn, "bits": cb}]
    weak = ['RC4', 'DES', '3DES', 'MD5', 'NULL', 'EXPORT']
    for w in weak:
        if w.lower() in cn.lower():
            results["vulnerabilities"].append({
                "issue": f"Weak cipher: {cn}",
                "severity": "HIGH",
                "detail": f"Uses {w}"
            })
    if cb < 128:
        results["vulnerabilities"].append({
            "issue": "Weak key",
            "severity": "HIGH",
            "detail": f"{cb} bits"
        })
    print(f"    {cn} ({cb} bits)")

    # 5. pyOpenSSL deep
    print(f"\033[33m[*] [5/5] Deep analysis (pyOpenSSL)...\033[0m")
    try:
        from OpenSSL import SSL, crypto
        ctx2 = SSL.Context(SSL.SSLv23_METHOD)
        sock2 = socket.create_connection((hostname, port), timeout=10)
        ss = SSL.Connection(ctx2, sock2)
        ss.set_tlsext_host_name(hostname.encode())
        ss.set_connect_state()
        ss.do_handshake()
        cert_obj = ss.get_peer_certificate()
        chain = ss.get_peer_cert_chain()

        results["chain_info"] = {
            "chain_length": len(chain) if chain else 0,
            "chain_subjects": []
        }
        if chain:
            for c in chain:
                subj = c.get_subject()
                results["chain_info"]["chain_subjects"].append({
                    "CN": ensure_str(subj.commonName or ""),
                    "O": ensure_str(subj.organizationName or ""),
                    "OU": ensure_str(subj.organizationalUnitName or "")
                })

        fp = ensure_str(cert_obj.digest('sha256'))
        sig = ensure_str(cert_obj.get_signature_algorithm())
        results["certificate"]["fingerprint_sha256"] = fp
        results["certificate"]["signature_algorithm"] = sig

        if 'md5' in sig.lower() or 'sha1' in sig.lower():
            results["vulnerabilities"].append({
                "issue": f"Weak sig: {sig}",
                "severity": "MEDIUM",
                "detail": "Deprecated signature algorithm"
            })

        ss.shutdown()
        sock2.close()
        print(f"    Chain: {results['chain_info']['chain_length']} certs")
        print(f"    Sig: {sig}")
        print(f"    FP: {fp[:35]}...")
    except ImportError:
        print(f"    pyOpenSSL not available, basic only")
    except Exception as e:
        print(f"    Deep: {ensure_str(e)[:60]}")

    # Grade
    sev = [v["severity"] for v in results["vulnerabilities"]]
    if "CRITICAL" in sev:
        results["grade"] = "F"
    elif "HIGH" in sev:
        results["grade"] = "D"
    elif "MEDIUM" in sev:
        results["grade"] = "C"
    elif "WARNING" in sev:
        results["grade"] = "B"
    elif not sev:
        results["grade"] = "A"
    else:
        results["grade"] = "B"
    print(f"    Grade: {results['grade']}")
    return results

# ============================================================
# ENGINE 4: WAF DETECTION (FULL v4.1 + dynamic API fix)
# ============================================================
def waf_detect_engine(target_url):
    results = {
        "waf_detected": False, "primary_waf": "",
        "all_results": [], "detection_details": {}
    }
    print(f"\n\033[36m{'='*58}")
    print(f"  [WAF ENGINE] Web Application Firewall Detection")
    print(f"{'='*58}\033[0m")

    # Method 1: wafw00f (dynamic API detection - FIX)
    print(f"\033[33m[*] [1/2] wafw00f detection...\033[0m")
    try:
        from wafw00f.main import WAFW00F
        attacker = WAFW00F(target_url)
        waf_found = []

        # Coba API v1: identwaf (versi lama)
        if hasattr(attacker, 'identwaf'):
            try:
                w = attacker.identwaf(findall=True)
                if w:
                    waf_found = safe_list(w)
            except Exception:
                pass

        # Coba API v2: identify + getwaf (versi menengah)
        if not waf_found and hasattr(attacker, 'identify'):
            try:
                attacker.identify()
                if hasattr(attacker, 'getwaf'):
                    w = attacker.getwaf()
                    if w:
                        waf_found = safe_list(w)
            except Exception:
                pass

        # Coba API v3: wafname attribute
        if not waf_found and hasattr(attacker, 'wafname'):
            try:
                w = attacker.wafname
                if w and str(w) != 'None':
                    waf_found = [ensure_str(w)]
            except Exception:
                pass

        # Coba API v4: detectwaf
        if not waf_found and hasattr(attacker, 'detectwaf'):
            try:
                w = attacker.detectwaf()
                if w:
                    waf_found = safe_list(w)
            except Exception:
                pass

        # Filter hasil
        waf_found = [ensure_str(w) for w in waf_found if w and str(w) != 'None' and str(w).strip()]

        if waf_found:
            results["waf_detected"] = True
            results["all_results"] = waf_found
            results["primary_waf"] = waf_found[0]
            print(f"    [!] WAF: {results['primary_waf']}")
            if len(waf_found) > 1:
                print(f"    Also: {safe_join(waf_found[1:])}")
        else:
            print(f"    wafw00f: no WAF detected")

    except ImportError:
        print(f"\033[33m    wafw00f not available\033[0m")
    except Exception as e:
        print(f"\033[31m    wafw00f error: {ensure_str(e)[:80]}\033[0m")

    # Method 2: Manual fingerprinting (FULL v4.1 - semua signature)
    print(f"\033[33m[*] [2/2] Manual WAF fingerprinting...\033[0m")
    try:
        session = cloudscraper.create_scraper()
        session.headers.update({'User-Agent': UserAgent().random})
        resp = session.get(target_url, timeout=15)
        hdrs = {k.lower(): v for k, v in resp.headers.items()}

        sigs = {
            "Cloudflare":        {"h": ["cf-ray", "cf-cache-status"], "s": "cloudflare"},
            "AWS WAF/CloudFront":{"h": ["x-amz-cf-id", "x-amzn-requestid"], "s": "cloudfront"},
            "Akamai":            {"h": ["x-akamai-transformed"], "s": "akamai"},
            "Imperva/Incapsula": {"h": ["x-cdn"], "s": "", "c": "incap_ses"},
            "Sucuri":            {"h": ["x-sucuri-id", "x-sucuri-cache"], "s": "sucuri"},
            "F5 BIG-IP":        {"h": ["x-wa-info"], "s": "", "c": "bigipserver"},
            "ModSecurity":       {"h": ["x-mod-security"], "s": "mod_security"},
            "Barracuda":         {"h": ["barracuda"], "s": "", "c": "barra"},
            "Fortinet":          {"h": ["fortiwafsid"], "s": ""},
        }

        detected = []
        for name, sig in sigs.items():
            found = False
            for h in sig.get("h", []):
                if h in hdrs:
                    found = True
                    results["detection_details"][name] = f"Header: {h} = {hdrs[h][:40]}"
                    break
            if not found and sig.get("s") and sig["s"] in hdrs.get("server", "").lower():
                found = True
                results["detection_details"][name] = f"Server: {hdrs.get('server', '')}"
            if not found and sig.get("c") and sig["c"] in hdrs.get("set-cookie", "").lower():
                found = True
                results["detection_details"][name] = f"Cookie: {sig['c']}"
            if found:
                detected.append(name)

        if detected:
            results["waf_detected"] = True
            for w in detected:
                if w not in results["all_results"]:
                    results["all_results"].append(w)
            if not results["primary_waf"]:
                results["primary_waf"] = detected[0]
            print(f"    Manual: {safe_join(detected)}")
        else:
            print(f"    No WAF fingerprints found")
    except Exception as e:
        print(f"\033[31m    Manual error: {ensure_str(e)[:60]}\033[0m")

    if results["waf_detected"]:
        print(f"\n    [!] WAF ACTIVE: {results['primary_waf']}")
    else:
        print(f"\n    No WAF detected")
    return results

# ============================================================
# ENGINE 5: ZAP SCAN (FULL v4.1 + safe_call fix)
# ============================================================
def zap_scan(zap, target_url):
    zr = {
        "spider_urls": [], "ajax_spider_urls": [],
        "passive_alerts": [], "active_alerts": [],
        "technologies_detected": [], "discovered_sites": [],
        "http_messages": [], "scan_statistics": {}
    }
    print(f"\n\033[36m{'='*58}")
    print(f"  [ZAP ENGINE] OWASP ZAP Deep Scan")
    print(f"{'='*58}\033[0m")

    # 1. Spider
    print(f"\033[33m[*] [1/6] Spider...\033[0m")
    try:
        scan_id = safe_call(zap.spider.scan, target_url, maxchildren=50, recurse=True, fallback=0)
        while safe_int(safe_call(zap.spider.status, scan_id, fallback=100)) < 100:
            pct = safe_int(safe_call(zap.spider.status, scan_id, fallback=100))
            print(f"\r    Spider: {pct}%", end='', flush=True)
            time.sleep(1)
        print(f"\r    Spider: 100% [OK]")
        spider_results = safe_call(zap.spider.results, scan_id, fallback=[])
        zr["spider_urls"] = [ensure_str(u) for u in safe_list(spider_results)]
        print(f"    URLs: {len(zr['spider_urls'])}")
    except Exception as e:
        print(f"\033[31m    Spider: {ensure_str(e)[:80]}\033[0m")

    # 2. AjaxSpider
    print(f"\033[33m[*] [2/6] AjaxSpider...\033[0m")
    try:
        safe_call(zap.ajaxSpider.scan, target_url, inscopeonly=True)
        st = time.time()
        while True:
            status = safe_call(zap.ajaxSpider.status, fallback='stopped')
            if ensure_str(status) != 'running' or (time.time() - st) > 60:
                break
            print(f"\r    AjaxSpider: {int(time.time()-st)}s", end='', flush=True)
            time.sleep(2)
        ajax_results = safe_call(zap.ajaxSpider.results, fallback=[])
        zr["ajax_spider_urls"] = [ensure_str(u) for u in safe_list(ajax_results)]
        print(f"\r    AjaxSpider: done. {len(zr['ajax_spider_urls'])} URLs")
    except Exception as e:
        print(f"\033[31m    Ajax: {ensure_str(e)[:80]}\033[0m")

    # 3. Passive Scan
    print(f"\033[33m[*] [3/6] Passive Scan...\033[0m")
    try:
        while safe_int(safe_call(zap.pscan.records_to_scan, fallback=0)) > 0:
            rec = safe_int(safe_call(zap.pscan.records_to_scan, fallback=0))
            print(f"\r    Remaining: {rec}", end='', flush=True)
            time.sleep(1)
        print(f"\r    Passive: complete [OK]              ")

        all_alerts = safe_call(zap.core.alerts, baseurl=target_url, fallback=[])
        if not isinstance(all_alerts, list):
            all_alerts = []

        for a in all_alerts:
            if not isinstance(a, dict):
                continue
            ad = {
                "alert": ensure_str(a.get('alert', '')),
                "risk": ensure_str(a.get('risk', '')),
                "confidence": ensure_str(a.get('confidence', '')),
                "url": ensure_str(a.get('url', '')),
                "param": ensure_str(a.get('param', '')),
                "attack": ensure_str(a.get('attack', '')),
                "evidence": ensure_str(a.get('evidence', ''))[:150],
                "description": ensure_str(a.get('description', ''))[:200],
                "solution": ensure_str(a.get('solution', ''))[:200],
                "cweid": ensure_str(a.get('cweid', '')),
                "wascid": ensure_str(a.get('wascid', '')),
                "plugin_id": ensure_str(a.get('pluginId', ''))
            }
            if ad["risk"] in ['High', 'Medium']:
                zr["active_alerts"].append(ad)
            else:
                zr["passive_alerts"].append(ad)
        print(f"    Alerts: {len(zr['active_alerts'])+len(zr['passive_alerts'])}")
    except Exception as e:
        print(f"\033[31m    Passive: {ensure_str(e)[:80]}\033[0m")

    # 4. Active Scan (FULL v4.1 - dengan duplicate check)
    print(f"\033[33m[*] [4/6] Active Scan...\033[0m")
    try:
        scan_id = safe_call(zap.ascan.scan, target_url, recurse=True, inscopeonly=True, fallback=0)
        while safe_int(safe_call(zap.ascan.status, scan_id, fallback=100)) < 100:
            pct = safe_int(safe_call(zap.ascan.status, scan_id, fallback=100))
            print(f"\r    Active: {pct}%", end='', flush=True)
            time.sleep(2)
        print(f"\r    Active: 100% [OK]")

        # Post-active: collect NEW alerts (deduplicate)
        post_alerts = safe_call(zap.core.alerts, baseurl=target_url, fallback=[])
        if isinstance(post_alerts, list):
            for a in post_alerts:
                if not isinstance(a, dict):
                    continue
                ad = {
                    "alert": ensure_str(a.get('alert', '')),
                    "risk": ensure_str(a.get('risk', '')),
                    "url": ensure_str(a.get('url', '')),
                    "param": ensure_str(a.get('param', '')),
                    "attack": ensure_str(a.get('attack', '')),
                    "evidence": ensure_str(a.get('evidence', ''))[:150],
                    "solution": ensure_str(a.get('solution', ''))[:200],
                    "cweid": ensure_str(a.get('cweid', ''))
                }
                already = any(
                    x.get("alert") == ad["alert"] and x.get("url") == ad["url"]
                    for x in zr["active_alerts"] + zr["passive_alerts"]
                )
                if not already:
                    if ad["risk"] in ['High', 'Medium']:
                        zr["active_alerts"].append(ad)
                    else:
                        zr["passive_alerts"].append(ad)
    except Exception as e:
        print(f"\033[31m    Active: {ensure_str(e)[:80]}\033[0m")

    # 5. Tech
    print(f"\033[33m[*] [5/6] Tech Detection...\033[0m")
    try:
        t = safe_call(zap.technology.get_all, fallback={})
        if isinstance(t, dict):
            zr["technologies_detected"] = [ensure_str(x) for x in t.get('technology', [])]
        elif isinstance(t, list):
            zr["technologies_detected"] = [ensure_str(x) for x in t]
        print(f"    Techs: {safe_join(zr['technologies_detected'][:10]) or 'none'}")
    except Exception as e:
        print(f"\033[31m    Tech: {ensure_str(e)[:80]}\033[0m")

    # 6. Misc (FULL v4.1 - sites + messages)
    print(f"\033[33m[*] [6/6] Misc...\033[0m")
    try:
        sites = safe_call(zap.core.sites, fallback=[])
        zr["discovered_sites"] = [ensure_str(s) for s in safe_list(sites)]
        msgs = safe_call(zap.core.messages, baseurl=target_url, start=0, count=50, fallback=[])
        if isinstance(msgs, list):
            for m in msgs:
                if isinstance(m, dict):
                    zr["http_messages"].append({
                        "url": ensure_str(m.get('requestHeader', '').split('\r\n')[0]) if 'requestHeader' in m else '',
                        "method": ensure_str(m.get('method', '')),
                        "response_code": ensure_str(m.get('responseCode', ''))
                    })
        zr["scan_statistics"] = {
            "total_urls": len(zr["spider_urls"]) + len(zr["ajax_spider_urls"]),
            "total_alerts": len(zr["active_alerts"]) + len(zr["passive_alerts"]),
            "high_risk": sum(1 for a in zr["active_alerts"] if a.get('risk') == 'High'),
            "medium_risk": sum(1 for a in zr["active_alerts"] if a.get('risk') == 'Medium'),
            "low_risk": sum(1 for a in zr["passive_alerts"] if a.get('risk') == 'Low'),
            "info": sum(1 for a in zr["passive_alerts"] if a.get('risk') == 'Informational')
        }
        print(f"    Sites: {len(zr['discovered_sites'])} | Messages: {len(zr['http_messages'])}")
    except Exception as e:
        print(f"\033[31m    Misc: {ensure_str(e)[:80]}\033[0m")
    return zr

# ============================================================
# ENGINE 6: BS4 DEEP EXTRACTION (FULL v4.1 - SEMUA fitur)
# ============================================================
def bs4_deep_extract(scraper, target_url):
    br = {
        "page_metadata": {}, "forms_analysis": [], "links_extracted": {},
        "scripts_analysis": [], "sensitive_comments": [], "emails_found": [],
        "phone_numbers": [], "api_endpoints": [], "javascript_variables": [],
        "meta_data_leakage": [], "hidden_inputs": [], "external_resources": {},
        "technology_fingerprints": [], "path_fuzzing_results": [],
        "header_analysis": {}, "raw_data_stats": {}
    }
    print(f"\n\033[36m{'='*58}")
    print(f"  [BS4 ENGINE] BeautifulSoup Deep Extraction")
    print(f"{'='*58}\033[0m")

    ua = UserAgent()
    session = cloudscraper.create_scraper()
    session.headers.update({
        'User-Agent': ua.random,
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
    })

    try:
        response = session.get(target_url, timeout=20)
        raw_html = response.text
        headers = dict(response.headers)
        status_code = response.status_code
    except Exception as e:
        print(f"\033[31m[!] Fetch failed: {ensure_str(e)[:80]}\033[0m")
        return br, None

    soup = BeautifulSoup(raw_html, 'html.parser')
    pt = urlparse(target_url)
    base_url = f"{pt.scheme}://{pt.netloc}"

    # 1. Metadata (FULL v4.1 - Open Graph included)
    print(f"\033[33m[*] [1/12] Metadata...\033[0m")
    title = ensure_str(soup.title.string) if soup.title else 'No Title'
    mg = soup.find('meta', attrs={'name': 'generator'})
    og = soup.find_all('meta', attrs={'property': re.compile(r'^og:')})
    br["page_metadata"] = {
        "title": title,
        "generator": ensure_str(mg.get('content', '')) if mg else '',
        "open_graph": {ensure_str(t.get('property', '')): ensure_str(t.get('content', '')) for t in og},
        "language": soup.html.get('lang', '') if soup.html else '',
        "http_status": status_code, "content_length": len(raw_html)
    }
    if mg and mg.get('content'):
        br["technology_fingerprints"].append(f"CMS: {mg.get('content')}")

    # 2. Headers
    print(f"\033[33m[*] [2/12] Headers...\033[0m")
    sh = ['Strict-Transport-Security', 'X-Frame-Options', 'X-Content-Type-Options',
          'Content-Security-Policy', 'X-XSS-Protection', 'Referrer-Policy', 'Permissions-Policy']
    missing = [{"header": h, "risk": f"Missing {h}"}
               for h in sh if h.lower() not in [x.lower() for x in headers.keys()]]
    il = {h: headers[h] for h in headers
          if h.lower() in ['server', 'x-powered-by', 'x-aspnet-version']}
    br["header_analysis"] = {
        "all_headers": headers,
        "missing_security_headers": missing,
        "information_leakage": il
    }
    for h, v in il.items():
        br["technology_fingerprints"].append(f"Header [{h}]: {v}")

    # 3. Forms
    print(f"\033[33m[*] [3/12] Forms...\033[0m")
    for i, form in enumerate(soup.find_all('form')):
        fd = {
            "form_id": i + 1, "action": form.get('action', 'self'),
            "method": form.get('method', 'GET').upper(),
            "inputs": [], "potential_vulnerabilities": []
        }
        csrf = False
        for inp in form.find_all('input'):
            id_ = {
                "type": inp.get('type', 'text'), "name": inp.get('name', ''),
                "value": ensure_str(inp.get('value', ''))[:50],
                "hidden": inp.get('type') == 'hidden'
            }
            fd["inputs"].append(id_)
            if inp.get('type') == 'hidden':
                nid = (inp.get('name', '') + inp.get('id', '')).lower()
                if any(k in nid for k in ['csrf', 'token', '_token']):
                    csrf = True
                if inp.get('value'):
                    br["hidden_inputs"].append({
                        "form_id": i + 1, "name": inp.get('name', ''),
                        "value": ensure_str(inp.get('value', ''))[:100]
                    })
        if not csrf and fd["method"] == "POST":
            fd["potential_vulnerabilities"].append({
                "type": "Missing CSRF", "risk": "CSRF vulnerable"
            })
        br["forms_analysis"].append(fd)

    # 4. Links
    print(f"\033[33m[*] [4/12] Links...\033[0m")
    al = soup.find_all('a', href=True)
    internal, external, suspicious = [], [], []
    sp = ['admin', 'login', 'wp-admin', 'phpmyadmin', 'backup', 'config',
          'upload', 'api', 'debug', '.env', '.git']
    for link in al:
        href = link.get('href', '')
        fu = urljoin(target_url, href)
        ld = {"href": href, "full_url": fu, "text": link.get_text(strip=True)[:80]}
        if urlparse(fu).netloc == pt.netloc or not urlparse(href).netloc:
            internal.append(ld)
            if any(p in href.lower() for p in sp):
                suspicious.append(ld)
        else:
            external.append(ld)
    br["links_extracted"] = {
        "total": len(al), "internal_count": len(internal),
        "external_count": len(external), "internal": internal[:50],
        "external": external[:30], "suspicious": suspicious
    }

    # 5. Scripts
    print(f"\033[33m[*] [5/12] Scripts...\033[0m")
    for script in soup.find_all('script'):
        sd = {
            "src": script.get('src', 'inline'), "type": script.get('type', ''),
            "content_length": len(script.string) if script.string else 0
        }
        if script.string:
            apis = re.findall(
                r'(?:https?://[^\s"\'/]+/api/[^\s"\'/]+|/api/[^\s"\'/]+|/v[0-9]+/[^\s"\'/]+)',
                script.string)
            for a in apis:
                br["api_endpoints"].append({"endpoint": a, "source": "inline_script"})
            sec = re.findall(
                r'(?:var|let|const)\s+(\w*(?:key|token|secret|password|auth|apikey)\w*)\s*=\s*["\']([^"\']+)[\'"]',
                script.string, re.I)
            for n, v in sec:
                br["javascript_variables"].append({
                    "variable": n, "value": v[:50], "risk": "Credential exposure"
                })
        br["scripts_analysis"].append(sd)

    # 6. Comments
    print(f"\033[33m[*] [6/12] Comments...\033[0m")
    kw = ['password', 'key', 'secret', 'todo', 'fixme', 'debug',
          'api', 'token', 'admin', 'db_']
    for c in soup.find_all(string=lambda t: isinstance(t, Comment)):
        if any(k in c.lower() for k in kw):
            br["sensitive_comments"].append({
                "type": "HTML", "content": c.strip()[:200],
                "risk": "Sensitive keyword"
            })

    # 7. Emails & Phones
    print(f"\033[33m[*] [7/12] Emails & Phones...\033[0m")
    br["emails_found"] = list(set(
        re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', raw_html)))
    ph = re.findall(r'(?:\+?[\d\s\-$$]{10,15})', raw_html)
    br["phone_numbers"] = list(set(
        [p.strip() for p in ph if len(re.sub(r'\D', '', p)) >= 10][:20]))

    # 8. API
    print(f"\033[33m[*] [8/12] API Endpoints...\033[0m")
    for lt in soup.find_all('link'):
        h = lt.get('href', '')
        if any(k in h.lower() for k in ['api', 'swagger', 'graphql']):
            br["api_endpoints"].append({"endpoint": h, "source": "link_tag"})

    # 9. External (FULL v4.1 - iframes included)
    print(f"\033[33m[*] [9/12] External Resources...\033[0m")
    es = [s.get('src') for s in soup.find_all('script', src=True)]
    est = [l.get('href') for l in soup.find_all('link', rel='stylesheet')]
    ifs = [f.get('src') for f in soup.find_all('iframe', src=True)]
    br["external_resources"] = {
        "scripts": es, "stylesheets": est, "iframes": ifs,
        "total": len(es) + len(est) + len(ifs)
    }

    # 10. Tech (FULL v4.1 - SEMUA fingerprint)
    print(f"\033[33m[*] [10/12] Fingerprinting...\033[0m")
    if soup.find('meta', attrs={'name': 'generator', 'content': re.compile(r'WordPress', re.I)}):
        br["technology_fingerprints"].append("CMS: WordPress")
    if soup.find('link', href=re.compile(r'wp-content|wp-includes')):
        br["technology_fingerprints"].append("CMS: WordPress (wp-content)")
    if soup.find('meta', attrs={'name': 'generator', 'content': re.compile(r'Joomla', re.I)}):
        br["technology_fingerprints"].append("CMS: Joomla")
    if soup.find('meta', attrs={'name': 'generator', 'content': re.compile(r'Drupal', re.I)}):
        br["technology_fingerprints"].append("CMS: Drupal")
    if any('jquery' in (s or '').lower() for s in es):
        br["technology_fingerprints"].append("JS: jQuery")
    if soup.find(id='__next'):
        br["technology_fingerprints"].append("Framework: Next.js")
    if soup.find(id='__nuxt'):
        br["technology_fingerprints"].append("Framework: Nuxt.js")
    if any('bootstrap' in (s or '').lower() for s in es + est):
        br["technology_fingerprints"].append("CSS: Bootstrap")
    if any('react' in (s or '').lower() for s in es):
        br["technology_fingerprints"].append("JS: React")
    if any('vue' in (s or '').lower() for s in es):
        br["technology_fingerprints"].append("JS: Vue.js")
    if soup.find('input', attrs={'name': '_token'}):
        br["technology_fingerprints"].append("Backend: Laravel")

    # 11. Path Fuzzing (FULL v4.1 - 28 paths)
    print(f"\033[33m[*] [11/12] Path Fuzzing...\033[0m")
    fuzz = [
        '/.env', '/.git/config', '/.git/HEAD', '/.htaccess', '/robots.txt',
        '/sitemap.xml', '/.well-known/security.txt', '/wp-config.php.bak',
        '/phpinfo.php', '/server-status', '/.DS_Store', '/web.config',
        '/api/swagger.json', '/api/docs', '/graphql', '/.npmrc',
        '/docker-compose.yml', '/backup.zip', '/backup.sql', '/dump.sql',
        '/admin/', '/wp-admin/', '/phpmyadmin/', '/actuator/health',
        '/.aws/credentials', '/elmah.axd', '/trace.axd', '/.vscode/settings.json'
    ]
    for path in fuzz:
        try:
            r = session.get(f"{base_url}{path}", timeout=5, allow_redirects=False)
            if r.status_code in [200, 301, 302, 403]:
                res = {
                    "path": path, "status_code": r.status_code,
                    "content_length": len(r.text),
                    "content_type": r.headers.get('Content-Type', ''),
                    "redirect": r.headers.get('Location', '') if r.status_code in [301, 302] else ''
                }
                if r.status_code == 200 and path == '/.env':
                    ev = re.findall(r'([A-Z_]+)=([^\\n]+)', r.text)
                    res["exposed_variables"] = [{"key": k, "value": v[:30]} for k, v in ev[:15]]
                br["path_fuzzing_results"].append(res)
        except:
            pass

    # 12. Meta Leakage
    print(f"\033[33m[*] [12/12] Meta Leakage...\033[0m")
    for meta in soup.find_all('meta'):
        n = meta.get('name', meta.get('property', ''))
        c = meta.get('content', '')
        if c and any(k in n.lower() for k in ['author', 'copyright', 'company', 'organization']):
            br["meta_data_leakage"].append({
                "meta_name": n, "content": c, "risk": "Info disclosure"
            })

    br["raw_data_stats"] = {
        "html_size": len(raw_html), "forms": len(br["forms_analysis"]),
        "links": len(al), "scripts": len(br["scripts_analysis"]),
        "emails": len(br["emails_found"]), "phones": len(br["phone_numbers"]),
        "api_endpoints": len(br["api_endpoints"]),
        "hidden_inputs": len(br["hidden_inputs"]),
        "sensitive_comments": len(br["sensitive_comments"]),
        "js_secrets": len(br["javascript_variables"]),
        "path_findings": len(br["path_fuzzing_results"]),
        "technologies": len(br["technology_fingerprints"]),
        "meta_leakage": len(br["meta_data_leakage"])
    }
    return br, raw_html

# ============================================================
# SAVE: JSON + TXT (FULL v4.1 + ensure_str fix)
# ============================================================
def combine_and_save(target_url, nmap_r, dns_r, ssl_r, waf_r, zap_r, bs4_r, raw_html):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    domain = urlparse(target_url).netloc.replace('.', '_').replace(':', '_')

    combined = {
        "report_info": {
            "tool": "Indigo-SCR v4.3", "target": target_url,
            "scan_date": datetime.now().isoformat(),
            "engines": {k: (v["available"] or k == "ssl") for k, v in ENGINE_STATUS.items()},
            "zap_state": ZAP_STATUS["state"], "scan_mode": ZAP_STATUS["scan_mode"]
        },
        "executive_summary": {
            "nmap_open_ports": nmap_r.get("scan_statistics", {}).get("total_open_ports", 0),
            "nmap_high_risk_ports": len(nmap_r.get("scan_statistics", {}).get("high_risk_ports", [])),
            "dns_zone_transfer": dns_r.get("zone_transfer", {}).get("success", False),
            "dns_spf_present": dns_r.get("spf_analysis", {}).get("present", False),
            "dns_dmarc_present": dns_r.get("dmarc_analysis", {}).get("present", False),
            "ssl_grade": ssl_r.get("grade", "Unknown"),
            "ssl_vulnerabilities": len(ssl_r.get("vulnerabilities", [])),
            "waf_detected": waf_r.get("waf_detected", False),
            "waf_product": waf_r.get("primary_waf", "None"),
            "zap_alerts": zap_r.get("scan_statistics", {}).get("total_alerts", 0),
            "zap_high_risk": zap_r.get("scan_statistics", {}).get("high_risk", 0),
            "bs4_sensitive": (len(bs4_r.get("sensitive_comments", [])) +
                              len(bs4_r.get("javascript_variables", [])) +
                              len(bs4_r.get("hidden_inputs", []))),
            "bs4_exposed_paths": len(bs4_r.get("path_fuzzing_results", [])),
            "bs4_emails": len(bs4_r.get("emails_found", [])),
            "bs4_api_endpoints": len(bs4_r.get("api_endpoints", [])),
            "bs4_missing_headers": len(bs4_r.get("header_analysis", {}).get("missing_security_headers", [])),
        },
        "nmap_results": nmap_r,
        "dns_results": dns_r,
        "ssl_results": ssl_r,
        "waf_results": waf_r,
        "owasp_zap_results": zap_r,
        "beautifulsoup_results": bs4_r
    }

    # JSON (FIX: default=ensure_str)
    jf = f"indigo_scr_{domain}_{ts}.json"
    with open(jf, 'w', encoding='utf-8') as f:
        json.dump(combined, f, indent=2, ensure_ascii=False, default=ensure_str)

    # TXT (FULL v4.1 - SEMUA section)
    tf = f"indigo_scr_{domain}_{ts}_RAW.txt"
    with open(tf, 'w', encoding='utf-8') as f:
        W = "=" * 78
        f.write(f"{W}\n  INDIGO-SCR v4.3 - DEEP SCAN RAW REPORT\n{W}\n\n")
        f.write(f"Target    : {target_url}\n")
        f.write(f"Scan Date : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"ZAP State : {ZAP_STATUS['state']} | Mode: {ZAP_STATUS['scan_mode']}\n")
        engines = [k.upper() for k, v in ENGINE_STATUS.items() if v["available"] or k == "ssl"]
        f.write(f"Engines   : {safe_join(engines)}\n\n")

        f.write(f">>> EXECUTIVE SUMMARY\n{'-'*40}\n")
        for k, v in combined["executive_summary"].items():
            f.write(f"  {k:35s}: {ensure_str(v)}\n")

        # NMAP
        f.write(f"\n\n{W}\n>>> NMAP - PORT SCAN & SERVICES\n{W}\n\n")
        if nmap_r["open_ports"]:
            f.write(f"  Host: {nmap_r['host_info'].get('hostname', 'N/A')} ({nmap_r['host_info'].get('ip', 'N/A')})\n")
            f.write(f"  State: {nmap_r['host_info'].get('state', 'N/A')}\n\n")
            hr_ports = nmap_r.get("scan_statistics", {}).get("high_risk_ports", [])
            for p in nmap_r["open_ports"]:
                flag = " [HIGH-RISK]" if p["port"] in hr_ports else ""
                f.write(f"  {p['port']:>5}/{p['protocol']:<4} {p['state']:<6} {p['service']:<15} {p['product']} {p['version']}{flag}\n")
            if nmap_r["os_detection"]:
                f.write(f"\n  OS: {nmap_r['os_detection'].get('name', 'Unknown')} (acc: {nmap_r['os_detection'].get('accuracy', '')}%)\n")
            if nmap_r["vulnerability_scripts"]:
                f.write(f"\n  NSE Script Results:\n")
                for vs in nmap_r["vulnerability_scripts"]:
                    f.write(f"    Port {vs['port']} - {vs['script']}:\n    {vs['output'][:200]}\n\n")
        else:
            f.write("  No NMAP data\n")

        # DNS (FULL v4.1 - semua record types)
        f.write(f"\n\n{W}\n>>> DNS - RECONNAISSANCE\n{W}\n\n")
        f.write(f"  Resolved IP : {dns_r.get('resolved_ip', 'N/A')}\n")
        f.write(f"  A Records   : {safe_join(dns_r['a_records'])}\n")
        f.write(f"  AAAA Records: {safe_join(dns_r['aaaa_records'])}\n")
        f.write(f"  MX Records  : {len(dns_r['mx_records'])} servers\n")
        for mx in dns_r["mx_records"]:
            f.write(f"    [{mx.get('pref', '')}] {mx.get('exchange', '')}\n")
        f.write(f"  NS Records  : {safe_join(dns_r['ns_records'])}\n")
        f.write(f"  TXT Records : {len(dns_r['txt_records'])}\n")
        for txt in dns_r["txt_records"]:
            f.write(f"    {ensure_str(txt)}\n")
        if dns_r["soa_record"]:
            f.write(f"  SOA         : {dns_r['soa_record'].get('mname', '')} (serial: {dns_r['soa_record'].get('serial', '')})\n")
        f.write(f"  CNAME       : {safe_join(dns_r['cname_records'])}\n")
        f.write(f"  CAA         : {len(dns_r['caa_records'])} records\n")
        for caa in dns_r["caa_records"]:
            f.write(f"    flags={caa.get('flags','')} tag={caa.get('tag','')} value={caa.get('value','')}\n")
        f.write(f"  SPF         : {'Present' if dns_r['spf_analysis'].get('present') else 'MISSING'}\n")
        f.write(f"  DMARC       : {'Present (p=' + dns_r['dmarc_analysis'].get('policy', '') + ')' if dns_r['dmarc_analysis'].get('present') else 'MISSING'}\n")
        f.write(f"  Zone Transfer: {'SUCCESS [CRITICAL]' if dns_r['zone_transfer']['success'] else 'Denied (good)'}\n")
        if dns_r["reverse_dns"]:
            f.write(f"  Reverse DNS :\n")
            for rd in dns_r["reverse_dns"]:
                f.write(f"    {rd['ip']} -> {rd['ptr']}\n")

        # SSL (FULL v4.1 - SAN + chain)
        f.write(f"\n\n{W}\n>>> SSL/TLS - CERTIFICATE ANALYSIS\n{W}\n\n")
        if ssl_r["certificate"]:
            f.write(f"  Subject     : {ssl_r['certificate'].get('subject', {})}\n")
            f.write(f"  Issuer      : {ssl_r['issuer']}\n")
            f.write(f"  Valid From  : {ssl_r['validity'].get('not_before', '')}\n")
            f.write(f"  Valid Until : {ssl_r['validity'].get('not_after', '')}\n")
            f.write(f"  Days Left   : {ssl_r['validity'].get('days_until_expiry', 'N/A')}\n")
            f.write(f"  TLS Version : {ssl_r['connection_info'].get('tls_version', '')}\n")
            f.write(f"  Cipher      : {ssl_r['connection_info'].get('cipher_suite', '')} ({ssl_r['connection_info'].get('cipher_bits', 0)} bits)\n")
            f.write(f"  Grade       : {ssl_r['grade']}\n")
            f.write(f"  Fingerprint : {ssl_r['certificate'].get('fingerprint_sha256', 'N/A')}\n")
            f.write(f"  Sig Alg     : {ssl_r['certificate'].get('signature_algorithm', 'N/A')}\n")
            f.write(f"  Chain Length: {ssl_r['chain_info'].get('chain_length', 'N/A')}\n")
            f.write(f"  SAN Entries : {len(ssl_r['san_entries'])}\n")
            for san in ssl_r["san_entries"][:20]:
                f.write(f"    [{san['type']}] {san['value']}\n")
            if ssl_r["vulnerabilities"]:
                f.write(f"\n  Vulnerabilities:\n")
                for v in ssl_r["vulnerabilities"]:
                    f.write(f"    [{v['severity']}] {v['issue']}: {v['detail']}\n")
        else:
            f.write("  No SSL data\n")

        # WAF
        f.write(f"\n\n{W}\n>>> WAF - FIREWALL DETECTION\n{W}\n\n")
        if waf_r["waf_detected"]:
            f.write(f"  WAF DETECTED: {waf_r['primary_waf']}\n")
            f.write(f"  All Results : {safe_join(waf_r['all_results'])}\n")
            if waf_r["detection_details"]:
                f.write(f"  Details     :\n")
                for name, detail in waf_r["detection_details"].items():
                    f.write(f"    {name}: {detail}\n")
        else:
            f.write("  No WAF detected\n")

        # ZAP (FULL v4.1)
        f.write(f"\n\n{W}\n>>> ZAP - VULNERABILITY ALERTS\n{W}\n\n")
        if zap_r.get("active_alerts"):
            f.write("--- HIGH/MEDIUM ---\n\n")
            for i, a in enumerate(zap_r["active_alerts"], 1):
                f.write(f"  [{i}] {a.get('alert', '')}\n")
                f.write(f"      Risk: {a.get('risk', '')} | URL: {a.get('url', '')}\n")
                f.write(f"      Param: {a.get('param', '')} | Attack: {a.get('attack', '')}\n")
                f.write(f"      Evidence: {a.get('evidence', '')}\n")
                f.write(f"      CWE: {a.get('cweid', '')} | Solution: {a.get('solution', '')}\n\n")
        if zap_r.get("passive_alerts"):
            f.write("\n--- LOW/INFO ---\n\n")
            for i, a in enumerate(zap_r["passive_alerts"], 1):
                f.write(f"  [{i}] {a.get('alert', '')} | {a.get('risk', '')} | {a.get('url', '')}\n")

        all_urls = zap_r.get("spider_urls", []) + zap_r.get("ajax_spider_urls", [])
        if all_urls:
            f.write(f"\n\n>>> ZAP - DISCOVERED URLs ({len(all_urls)})\n{'-'*40}\n")
            for u in all_urls[:100]:
                f.write(f"  {ensure_str(u)}\n")

        # BS4 (FULL v4.1 - SEMUA section)
        f.write(f"\n\n{W}\n>>> BS4 - DEEP EXTRACTION\n{W}\n\n")
        ha = bs4_r.get("header_analysis", {})
        f.write("--- HEADERS ---\n")
        for h, v in ha.get("all_headers", {}).items():
            f.write(f"  {h}: {v}\n")
        f.write("\n  Missing Security Headers:\n")
        for mh in ha.get("missing_security_headers", []):
            f.write(f"    [!] {mh['header']}: {mh['risk']}\n")
        f.write("\n  Info Leakage:\n")
        for h, v in ha.get("information_leakage", {}).items():
            f.write(f"    [LEAK] {h}: {v}\n")

        f.write(f"\n\n--- FORMS ({len(bs4_r['forms_analysis'])}) ---\n")
        for form in bs4_r["forms_analysis"]:
            f.write(f"\n  Form #{form['form_id']} | {form['action']} | {form['method']}\n")
            for inp in form['inputs']:
                ht = " [HIDDEN]" if inp['hidden'] else ""
                f.write(f"    [{inp['type']}] name=\"{inp['name']}\" value=\"{inp['value']}\"{ht}\n")
            for vuln in form.get('potential_vulnerabilities', []):
                f.write(f"    [VULN] {vuln['type']}: {vuln['risk']}\n")

        f.write(f"\n\n--- SENSITIVE COMMENTS ({len(bs4_r['sensitive_comments'])}) ---\n")
        for c in bs4_r["sensitive_comments"]:
            f.write(f"  [{c['type']}] {c['content']}\n    Risk: {c['risk']}\n\n")

        f.write(f"\n--- JS SECRETS ({len(bs4_r['javascript_variables'])}) ---\n")
        for s in bs4_r["javascript_variables"]:
            f.write(f"  [SECRET] {s['variable']} = {s['value']}\n")

        f.write(f"\n--- API ENDPOINTS ({len(bs4_r['api_endpoints'])}) ---\n")
        for a in bs4_r["api_endpoints"]:
            f.write(f"  [API] {a['endpoint']} ({a['source']})\n")

        f.write(f"\n--- EMAILS ({len(bs4_r['emails_found'])}) ---\n")
        for e in bs4_r["emails_found"]:
            f.write(f"  {e}\n")

        f.write(f"\n--- PHONES ({len(bs4_r['phone_numbers'])}) ---\n")
        for p in bs4_r["phone_numbers"]:
            f.write(f"  {p}\n")

        f.write(f"\n--- PATH FUZZING ({len(bs4_r['path_fuzzing_results'])}) ---\n")
        for pr in bs4_r["path_fuzzing_results"]:
            f.write(f"  [{pr['status_code']}] {pr['path']} ({pr['content_length']}B, {pr['content_type']})")
            if pr.get('redirect'):
                f.write(f" -> {pr['redirect']}")
            f.write("\n")
            if pr.get('exposed_variables'):
                for v in pr['exposed_variables']:
                    f.write(f"      [EXPOSED] {v['key']} = {v['value']}\n")

        f.write(f"\n--- HIDDEN INPUTS ({len(bs4_r['hidden_inputs'])}) ---\n")
        for h in bs4_r["hidden_inputs"]:
            f.write(f"  Form #{h['form_id']}: \"{h['name']}\" = \"{h['value']}\"\n")

        f.write(f"\n--- TECHNOLOGIES ---\n")
        all_techs = list(set(bs4_r.get("technology_fingerprints", []) + zap_r.get("technologies_detected", [])))
        for t in all_techs:
            f.write(f"  [TECH] {ensure_str(t)}\n")

        f.write(f"\n--- LINKS ---\n")
        ld = bs4_r.get("links_extracted", {})
        f.write(f"  Total: {ld.get('total', 0)} | Internal: {ld.get('internal_count', 0)} | External: {ld.get('external_count', 0)} | Suspicious: {len(ld.get('suspicious', []))}\n")
        for sl in ld.get("suspicious", []):
            f.write(f"    [SUS] {sl['full_url']}\n")

        f.write(f"\n--- EXTERNAL RESOURCES ---\n")
        er = bs4_r.get("external_resources", {})
        f.write(f"  Scripts: {len(er.get('scripts', []))} | Stylesheets: {len(er.get('stylesheets', []))} | Iframes: {len(er.get('iframes', []))}\n")

        f.write(f"\n--- META LEAKAGE ---\n")
        for ml in bs4_r.get("meta_data_leakage", []):
            f.write(f"  [{ml['meta_name']}] {ml['content']} ({ml['risk']})\n")

        # RAW HTML
        f.write(f"\n\n{W}\n>>> RAW HTML DUMP\n{W}\n\n")
        f.write(raw_html if raw_html else "[No HTML]")
        f.write(f"\n\n{W}\n>>> END | Indigo-SCR v4.3 | {datetime.now().isoformat()}\n{W}\n")

    return jf, tf

# ============================================================
# MAIN LOOP WITH VULN-BOT INTEGRATION
# ============================================================
def main():
    while True:
        show_banner()

        try:
            target = input(f"\033[32m[>] Input target (URL/Domain/IP) or /exit: \033[0m")

            if target.strip().lower() in ['/exit', 'exit', '/quit', 'quit', '/q']:
                print(f"\n\033[33m[*] Exit command received.\033[0m")
                cleanup_zap()
                print(f"\033[32m[+] Indigo-SCR terminated. Goodbye!\033[0m\n")
                sys.exit(0)

            if not target.strip():
                continue

            is_valid, formatted = validate_target(target)
            if not is_valid:
                print(f"\n\033[31m+----------------------------------------------------------+")
                print(f"|  [X] '{target}' is NOT a valid target!                   ")
                print(f"|  [X] Accepted: URL, Domain, or IP Address                ")
                print(f"+----------------------------------------------------------+\033[0m")
                time.sleep(3)
                continue

            print(f"\n\033[32m[+] Target: {formatted}\033[0m")

            # ZAP Connection (FIX: safe_call untuk version)
            zap = None
            zap_ok = False
            if ZAPv2 and ZAP_STATUS["state"] == "ONLINE":
                print(f"\n\033[36m[*] Connecting ZAP API...\033[0m")
                if is_port_open(ZAP_PROXY_HOST, ZAP_PROXY_PORT, timeout=2):
                    try:
                        zap = ZAPv2(
                            proxies={
                                'http': f'http://{ZAP_PROXY_HOST}:{ZAP_PROXY_PORT}',
                                'https': f'http://{ZAP_PROXY_HOST}:{ZAP_PROXY_PORT}'
                            },
                            apikey=ZAP_API_KEY
                        )
                        # FIX: Gunakan safe_call untuk hindari "str not callable"
                        ver = safe_call(zap.core.version, fallback="unknown")
                        print(f"\033[32m[+] ZAP Connected! v{ensure_str(ver)}\033[0m")
                        zap_ok = True
                    except Exception as e:
                        print(f"\033[31m[!] ZAP connection failed: {ensure_str(e)[:80]}\033[0m")
                        zap = None

            # Print engine status
            print(f"\n\033[36m{'='*58}")
            print(f"  SCANNING WITH ENGINES:")
            print(f"{'='*58}\033[0m")
            print(f"  [{'+' if ENGINE_STATUS['nmap']['available'] else '-'}] NMAP  - Port Scan & Service Detection")
            print(f"  [{'+' if ENGINE_STATUS['dns']['available'] else '-'}] DNS   - DNS Reconnaissance")
            print(f"  [+] SSL   - TLS/SSL Certificate Analysis")
            print(f"  [{'+' if ENGINE_STATUS['waf']['available'] else '-'}] WAF   - WAF Detection")
            print(f"  [{'+' if zap_ok else '-'}] ZAP   - OWASP ZAP Vulnerability Scanner")
            print(f"  [+] BS4   - BeautifulSoup Deep Extraction")
            print()

            # === RUN ALL 6 ENGINES ===

            nmap_r = nmap_scan_engine(formatted) if ENGINE_STATUS["nmap"]["available"] else {
                "host_info": {}, "open_ports": [], "services_detected": [],
                "os_detection": {}, "vulnerability_scripts": [], "scan_statistics": {}
            }

            dns_r = dns_recon_engine(formatted) if ENGINE_STATUS["dns"]["available"] else {
                "a_records": [], "aaaa_records": [], "mx_records": [],
                "ns_records": [], "txt_records": [], "soa_record": {},
                "cname_records": [], "caa_records": [],
                "spf_analysis": {}, "dmarc_analysis": {},
                "zone_transfer": {"success": False, "records": []},
                "reverse_dns": [], "resolved_ip": ""
            }

            ssl_r = ssl_analysis_engine(formatted)

            waf_r = waf_detect_engine(formatted) if ENGINE_STATUS["waf"]["available"] else {
                "waf_detected": False, "primary_waf": "",
                "all_results": [], "detection_details": {}
            }

            zap_r = {}
            if zap_ok and zap:
                zap_r = zap_scan(zap, formatted)
            else:
                zap_r = {
                    "spider_urls": [], "ajax_spider_urls": [],
                    "passive_alerts": [], "active_alerts": [],
                    "technologies_detected": [], "discovered_sites": [],
                    "http_messages": [],
                    "scan_statistics": {"note": "ZAP not available"}
                }

            bs4_r, raw_html = bs4_deep_extract(cloudscraper.create_scraper(), formatted)

            # Save
            findings = []
            if raw_html:
                jf, tf = combine_and_save(formatted, nmap_r, dns_r, ssl_r, waf_r, zap_r, bs4_r, raw_html)

                # Collect findings for VULN-BOT
                # ZAP findings
                for alert in zap_r.get("active_alerts", []):
                    finding = {
                        "type": "vulnerability",
                        "category": "zap",
                        "name": alert.get("alert", "Unknown"),
                        "severity": alert.get("risk", "Medium"),
                        "url": alert.get("url", formatted),
                        "parameter": alert.get("param", ""),
                        "evidence": alert.get("evidence", ""),
                        "description": alert.get("description", ""),
                        "solution": alert.get("solution", ""),
                        "cwe_id": alert.get("cweid", ""),
                        "wasc_id": alert.get("wascid", "")
                    }
                    findings.append(finding)

                # SSL findings
                for vuln in ssl_r.get("vulnerabilities", []):
                    finding = {
                        "type": "vulnerability", 
                        "category": "ssl",
                        "name": vuln.get("issue", "SSL Issue"),
                        "severity": vuln.get("severity", "Medium"),
                        "url": formatted,
                        "parameter": "",
                        "evidence": vuln.get("detail", ""),
                        "description": f"SSL/TLS vulnerability detected",
                        "solution": "Update SSL configuration",
                        "cwe_id": "",
                        "wasc_id": ""
                    }
                    findings.append(finding)

                # BS4 sensitive findings
                for comment in bs4_r.get("sensitive_comments", []):
                    finding = {
                        "type": "sensitive_data",
                        "category": "bs4",
                        "name": "Sensitive HTML Comment",
                        "severity": "Medium",
                        "url": formatted,
                        "parameter": "",
                        "evidence": comment.get("content", "")[:100],
                        "description": comment.get("risk", ""),
                        "solution": "Remove sensitive comments from HTML",
                        "cwe_id": "CWE-200",
                        "wasc_id": ""
                    }
                    findings.append(finding)

                for js_secret in bs4_r.get("javascript_variables", []):
                    finding = {
                        "type": "sensitive_data",
                        "category": "bs4",
                        "name": "JavaScript Credential Exposure",
                        "severity": "High",
                        "url": formatted,
                        "parameter": js_secret.get("variable", ""),
                        "evidence": f"{js_secret.get('variable', '')} = {js_secret.get('value', '')}",
                        "description": "Credentials exposed in JavaScript",
                        "solution": "Move credentials to secure backend storage",
                        "cwe_id": "CWE-798",
                        "wasc_id": ""
                    }
                    findings.append(finding)

                for path_result in bs4_r.get("path_fuzzing_results", []):
                    if path_result.get("status_code") == 200:
                        finding = {
                            "type": "information_disclosure",
                            "category": "bs4",
                            "name": f"Exposed Path: {path_result.get('path', '')}",
                            "severity": "High" if any(x in path_result.get('path', '') for x in ['.env', '.git', 'backup', 'config']) else "Medium",
                            "url": f"{formatted.rstrip('/')}{path_result.get('path', '')}",
                            "parameter": "",
                            "evidence": f"Status: {path_result.get('status_code')}, Size: {path_result.get('content_length', 0)}",
                            "description": f"Sensitive path accessible",
                            "solution": "Restrict access to sensitive paths",
                            "cwe_id": "CWE-200",
                            "wasc_id": ""
                        }
                        findings.append(finding)

                print(f"\n\033[32m{'='*58}")
                print(f"  [OK] SCAN COMPLETE - ALL 6 ENGINES")
                print(f"{'='*58}\033[0m")
                print(f"  \033[33m|- JSON : {jf}\033[0m")
                print(f"  \033[33m|- TXT  : {tf}\033[0m")
                print(f"  \033[36m|- NMAP  : {nmap_r.get('scan_statistics', {}).get('total_open_ports', 0)} ports open\033[0m")
                zt = 'YES!' if dns_r.get('zone_transfer', {}).get('success') else 'No'
                print(f"  \033[36m|- DNS   : {len(dns_r.get('a_records', []))} A records | Zone Transfer: {zt}\033[0m")
                print(f"  \033[36m|- SSL   : Grade {ssl_r.get('grade', 'N/A')} | {len(ssl_r.get('vulnerabilities', []))} issues\033[0m")
                waf_txt = 'Detected: ' + waf_r.get('primary_waf', '') if waf_r.get('waf_detected') else 'Not detected'
                print(f"  \033[36m|- WAF   : {waf_txt}\033[0m")
                print(f"  \033[36m|- ZAP   : {zap_r.get('scan_statistics', {}).get('total_alerts', 0)} alerts\033[0m")
                print(f"  \033[36m|- BS4   : {bs4_r.get('raw_data_stats', {}).get('sensitive_comments', 0)} sensitive items\033[0m")
                
                # Ask user if they want to run VULN-BOT
                print(f"\n\033[33m[?] Total findings collected: {len(findings)} vulnerabilities/sensitive items\033[0m")
                confirm = input(f"\n\033[32m[Lanjut ke VULN-BOT AI Payload Generation? (y/n): \033[0m").strip().lower()
                
                if confirm == 'y':
                    try:
                        from indigo_vuln_bot import run_vuln_bot
                        print(f"\n\033[36m[*] Starting VULN-BOT AI Payload Generation...\033[0m")
                        vuln_bot_results = run_vuln_bot(findings)
                        
                        # Save VULN-BOT results
                        if vuln_bot_results:
                            vbr_file = f"indigo_vuln_bot_{domain}_{ts}.json"
                            with open(vbr_file, 'w', encoding='utf-8') as f:
                                json.dump(vuln_bot_results, f, indent=2, ensure_ascii=False, default=ensure_str)
                            print(f"\n\033[32m[+] VULN-BOT results saved to: {vbr_file}\033[0m")
                            
                            # Summary
                            total_payloads = sum(len(result.get('generated_payloads', [])) for result in vuln_bot_results)
                            successful_tests = sum(1 for result in vuln_bot_results if result.get('exploit_success', False))
                            print(f"\033[36m[+] Generated {total_payloads} AI payloads\033[0m")
                            print(f"\033[36m[+] {successful_tests} successful exploit attempts\033[0m")
                        else:
                            print(f"\033[33m[!] VULN-BOT returned no results\033[0m")
                    except ImportError:
                        print(f"\033[31m[!] indigo_vuln_bot.py not found. Please ensure it's in the same directory.\033[0m")
                    except Exception as e:
                        print(f"\033[31m[!] VULN-BOT error: {ensure_str(e)}\033[0m")
                        import traceback
                        traceback.print_exc()
            else:
                print(f"\n\033[31m[!] Failed to retrieve data.\033[0m")

            input(f"\n\033[36m[ Press ENTER to scan another target | /exit to quit ]\033[0m")

        except KeyboardInterrupt:
            print(f"\n\n\033[31m[!] Exiting...\033[0m")
            cleanup_zap()
            sys.exit(0)
        except Exception as e:
            print(f"\n\033[31m[!] Error: {ensure_str(e)}\033[0m")
            import traceback
            traceback.print_exc()
            time.sleep(3)

# ============================================================
# BOOTSTRAP
# ============================================================
def bootstrap():
    print("\033[91m\033[1m")
    print("  +==========================================================+")
    print("  |     Indigo-SCR v4.3 - BOOTSTRAP SEQUENCE                |")
    print("  |     6 Scanning Engines: NMAP DNS SSL WAF ZAP BS4         |")
    print("  +==========================================================+")
    print("\033[0m")
    time.sleep(1)

    install_system_dependencies()
    logger.info("")
    time.sleep(0.5)

    if not check_and_install_dependencies():
        logger.critical("Required dependencies failed. Cannot continue.")
        sys.exit(1)
    logger.info("")
    time.sleep(0.5)

    logger.info("=" * 58)
    logger.info("  PHASE 1.5: IMPORTING MODULES")
    logger.info("=" * 58)
    try:
        import_all_dependencies()
    except Exception as e:
        logger.critical(f"Import failed: {e}")
        sys.exit(1)
    logger.info("")
    time.sleep(0.5)

    zap_ready = setup_zap_service()

    logger.info("")
    logger.info("=" * 58)
    logger.info("  ENGINE STATUS SUMMARY")
    logger.info("=" * 58)
    for eng, st in ENGINE_STATUS.items():
        avail = st["available"] or eng == "ssl" or (eng == "zap" and zap_ready)
        icon = "[OK]" if avail else "[--]"
        reason = ensure_str(st["reason"]) or ("ready" if avail else "unavailable")
        logger.info(f"  {icon} {eng.upper():<6} {reason}")
    logger.info("")

    active_count = sum(1 for k, v in ENGINE_STATUS.items()
                       if v["available"] or k == "ssl" or (k == "zap" and zap_ready))
    logger.info(f"  {active_count}/6 engines active")
    logger.info("")
    logger.info("=" * 58)
    logger.info("  BOOTSTRAP COMPLETE")
    logger.info("=" * 58)
    time.sleep(2)

    try:
        main()
    except (KeyboardInterrupt, SystemExit):
        pass
    finally:
        cleanup_zap()

# ============================================================
# RUN
# ============================================================
if __name__ == "__main__":
    bootstrap()
