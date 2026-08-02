#!/usr/bin/env python3
"""
Indigo ML Knowledge Master v3.0 — Full Modular Architecture
=============================================================
Pure analyzer and recommender engine with 12 modular components.

ARCHITECTURE:
  Scanner (File 1)
    → Collector
    → Feature Extractor
    → Knowledge ML (File 3) — 12 Modules
    → Generator ML (File 2)
    → Validator
    → Feedback Loop

MODULES:
  1.  TargetContext        — Target specification
  2.  TechnologyContext     — Technology stack analysis
  3.  BehavioralContext     — Application response behavior
  4.  SurfaceMapping        — Attack surface enumeration
  5.  FeatureExtraction     — ML feature vectors from observations
  6.  HypothesisEngine      — Multi-hypothesis generation & ranking
  7.  ConstraintEngine      — Input/output constraints for generator
  8.  StrategyRecommendation — Intelligent strategy selection
  9.  EvidenceLog           — Explainable AI evidence trail
  10. FeedbackEngine        — Learning from test results
  11. GeneratorDirectives   — Structured instructions for File 2
  12. LearningMetadata      — Model versioning & dataset tracking

DEPENDENCIES:
  numpy, scipy, scikit-learn
"""

import os
import sys
import json
import time
import re
import math
import hashlib
import warnings
import traceback
import argparse
from datetime import datetime
from collections import defaultdict, Counter
from typing import List, Dict, Any, Optional, Tuple, Set
from dataclasses import dataclass, field, asdict
from enum import Enum
from copy import deepcopy

warnings.filterwarnings("ignore")


# ============================================================
# DEPENDENCY MANAGEMENT
# ============================================================
def check_deps():
    required = [("numpy", "numpy"), ("scipy", "scipy"), ("sklearn", "scikit-learn")]
    missing = []
    for imp, pip_name in required:
        try:
            __import__(imp)
        except ImportError:
            missing.append(pip_name)
    if missing:
        import subprocess
        for pkg in missing:
            subprocess.run([sys.executable, "-m", "pip", "install", pkg, "-q"])
        print(f"Installed: {missing}. Please re-run.")
        sys.exit(0)

check_deps()

import numpy as np
from scipy import stats as sp_stats
from scipy.special import softmax as sp_softmax
from sklearn.ensemble import (
    RandomForestClassifier,
    GradientBoostingClassifier,
    AdaBoostClassifier,
)
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import cross_val_score
from sklearn.naive_bayes import GaussianNB
from sklearn.svm import SVC
from sklearn.neural_network import MLPClassifier


# ============================================================
# COLORS & UTILITIES
# ============================================================
class C:
    R = "\033[31m"; G = "\033[32m"; Y = "\033[33m"; B = "\033[34m"
    M = "\033[35m"; CY = "\033[36m"; W = "\033[37m"
    BO = "\033[1m"; D = "\033[2m"; RS = "\033[0m"

def banner(text, color=C.CY):
    print(f"\n{color}{'='*66}")
    print(f"  {text}")
    print(f"{'='*66}{C.RS}\n")

def section(text, color=C.B):
    print(f"\n{color}{'─'*54}")
    print(f"  {text}")
    print(f"{'─'*54}{C.RS}\n")

def bar_chart(value, width=20, color=C.G):
    filled = int(value * width)
    return f"{color}{'█' * filled}{'░' * (width - filled)}{C.RS}"

def progress_bar(cur, total, width=30, prefix=""):
    pct = cur / total if total > 0 else 0
    filled = int(width * pct)
    bar = "█" * filled + "░" * (width - filled)
    print(f"\r  {prefix}[{C.G}{bar}{C.RS}] {pct:.0%} ({cur}/{total})", end="", flush=True)
    if cur >= total:
        print()


# ============================================================
# MODULE 1: TARGET CONTEXT
# ============================================================
class TargetContext:
    """
    Module 1: Describes the target in detail.
    Extracts host, port, scheme, method, endpoint, parameters.
    """
    
    @staticmethod
    def extract(scan_results: Dict) -> Dict:
        """Extract target context from scan results."""
        meta = scan_results.get("scan_metadata", {})
        target_url = meta.get("target_url", "")
        
        # Parse URL
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(target_url)
        
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        scheme = parsed.scheme or "http"
        endpoint = parsed.path or "/"
        query_params = list(parse_qs(parsed.query).keys())
        
        # Extract parameters from findings
        findings = scan_results.get("findings_for_ml", [])
        params = set()
        methods = set()
        
        for f in findings:
            if f.get("parameter"):
                params.add(f["parameter"])
            if f.get("method"):
                methods.add(f["method"].upper())
        
        # From forms
        forms = scan_results.get("forms", [])
        for form in forms:
            for inp in form.get("inputs", []):
                if inp.get("name"):
                    params.add(inp["name"])
            if form.get("method"):
                methods.add(form["method"].upper())
        
        # From query parameters in crawled URLs
        crawled = scan_results.get("crawled_urls", [])
        for url in crawled:
            p = urlparse(url if isinstance(url, str) else url.get("url", ""))
            for k in parse_qs(p.query).keys():
                params.add(k)
        
        primary_method = "POST" if "POST" in methods else ("GET" if methods else "GET")
        
        context = {
            "host": host,
            "port": port,
            "scheme": scheme,
            "method": primary_method,
            "endpoint": endpoint,
            "parameters": sorted(list(params)),
            "query_parameters": query_params,
            "all_methods": sorted(list(methods)) if methods else ["GET"],
            "base_url": f"{scheme}://{host}:{port}" if port not in [80, 443] else f"{scheme}://{host}",
            "full_url": target_url,
        }
        
        return context
    
    @staticmethod
    def print_summary(ctx: Dict):
        print(f"    Host:       {ctx['host']}")
        print(f"    Port:       {ctx['port']}")
        print(f"    Scheme:     {ctx['scheme']}")
        print(f"    Endpoint:   {ctx['endpoint']}")
        print(f"    Method:     {ctx['method']}")
        print(f"    Parameters: {ctx['parameters']}")


# ============================================================
# MODULE 2: TECHNOLOGY CONTEXT
# ============================================================
class TechnologyContext:
    """
    Module 2: Describes the technology stack.
    Server, backend, framework, database, CDN, WAF, JS framework, CMS.
    """
    
    # Knowledge base for tech-vuln correlations
    TECH_VULN_MATRIX = {
        "php": {"sqli": 0.70, "xss": 0.65, "lfi": 0.75, "rce": 0.55, "xxe": 0.40},
        "mysql": {"sqli": 0.80},
        "mariadb": {"sqli": 0.80},
        "postgresql": {"sqli": 0.75, "rce": 0.20},
        "mssql": {"sqli": 0.80, "rce": 0.25},
        "sqlite": {"sqli": 0.70},
        "oracle": {"sqli": 0.75},
        "mongodb": {"nosqli": 0.75},
        "redis": {"rce": 0.50, "ssrf": 0.40},
        "elasticsearch": {"rce": 0.45, "nosqli": 0.55},
        "node.js": {"xss": 0.55, "ssrf": 0.40, "rce": 0.35},
        "express.js": {"xss": 0.60, "ssrf": 0.45},
        "next.js": {"xss": 0.45, "ssrf": 0.40},
        "react": {"xss": 0.35},
        "vue.js": {"xss": 0.40},
        "angular": {"xss": 0.30},
        "django": {"sqli": 0.25, "ssti": 0.50, "xss": 0.40},
        "flask": {"sqli": 0.45, "ssti": 0.65, "xss": 0.50},
        "jinja2": {"ssti": 0.75},
        "java": {"sqli": 0.55, "xxe": 0.60, "deserialization": 0.55, "rce": 0.40},
        "spring": {"sqli": 0.45, "deserialization": 0.50, "rce": 0.40},
        "struts": {"rce": 0.70, "sqli": 0.50, "xxe": 0.45},
        "tomcat": {"rce": 0.35, "lfi": 0.40},
        "asp.net": {"sqli": 0.55, "xxe": 0.45, "xss": 0.55},
        "ruby on rails": {"sqli": 0.35, "xss": 0.50, "ssti": 0.40},
        "apache": {"lfi": 0.40, "rce": 0.20},
        "nginx": {"lfi": 0.30, "ssrf": 0.25},
        "iis": {"lfi": 0.35, "rce": 0.25},
        "wordpress": {"sqli": 0.55, "xss": 0.70, "lfi": 0.45},
        "drupal": {"sqli": 0.50, "xss": 0.60, "rce": 0.45},
        "joomla": {"sqli": 0.55, "xss": 0.65},
        "laravel": {"sqli": 0.35, "ssti": 0.55},
        "magento": {"sqli": 0.55, "xss": 0.60, "rce": 0.45},
    }
    
    # WAF profiles
    WAF_PROFILES = {
        "cloudflare": {
            "encoding": ["unicode_encode", "case_variation", "url_encode", "hex_encode"],
            "techniques": ["whitespace_variation", "comment_injection", "http_parameter_pollution"],
            "effectiveness_modifier": -0.15,
        },
        "mod_security": {
            "encoding": ["double_url_encode", "comment_injection", "unicode_normalize"],
            "techniques": ["null_byte", "case_variation", "content_type_confusion"],
            "effectiveness_modifier": -0.20,
        },
        "aws_waf": {
            "encoding": ["url_encode", "multipart_wrap", "chunked_encode"],
            "techniques": ["array_param", "http2_manipulation"],
            "effectiveness_modifier": -0.10,
        },
        "sucuri": {
            "encoding": ["url_encode", "unicode_escape"],
            "techniques": ["header_injection", "cookie_injection"],
            "effectiveness_modifier": -0.10,
        },
        "imperva": {
            "encoding": ["triple_url_encode", "unicode_escape"],
            "techniques": ["protocol_smuggling", "nested_encode"],
            "effectiveness_modifier": -0.20,
        },
        "generic": {
            "encoding": ["url_encode", "double_url_encode"],
            "techniques": ["case_variation", "whitespace_variation"],
            "effectiveness_modifier": -0.10,
        },
    }
    
    # Stack profiles
    STACK_PROFILES = {
        "lamp": {"techs": ["php", "apache", "mysql"], "boost": {"sqli": 0.15, "lfi": 0.10}},
        "lemp": {"techs": ["php", "nginx", "mysql"], "boost": {"sqli": 0.15, "lfi": 0.05}},
        "mean": {"techs": ["mongodb", "express.js", "angular", "node.js"], "boost": {"nosqli": 0.15, "ssrf": 0.10}},
        "mern": {"techs": ["mongodb", "express.js", "react", "node.js"], "boost": {"nosqli": 0.15, "ssrf": 0.10}},
        "django_stack": {"techs": ["django", "postgresql"], "boost": {"ssti": 0.10, "sqli": -0.10}},
        "spring_stack": {"techs": ["spring", "java", "tomcat"], "boost": {"deserialization": 0.15, "xxe": 0.10}},
    }
    
    @classmethod
    def extract(cls, scan_results: Dict) -> Dict:
        """Extract technology context from scan results."""
        techs = scan_results.get("technologies", [])
        waf_info = scan_results.get("waf_info", {})
        headers = scan_results.get("response_headers", {})
        
        # Classify technologies
        server = None
        backend = None
        framework = None
        database = None
        cdn = None
        waf = None
        js_framework = None
        cms = None
        all_techs = []
        
        for tech in techs:
            name = tech.get("name", "") if isinstance(tech, dict) else str(tech)
            cats = tech.get("categories", []) if isinstance(tech, dict) else []
            confidence = tech.get("confidence", 0.7) if isinstance(tech, dict) else 0.7
            
            all_techs.append({"name": name, "categories": cats, "confidence": confidence})
            
            name_lower = name.lower()
            
            # Classify
            if any(c in cats for c in ["Web Server", "Server"]):
                server = name
            elif any(c in cats for c in ["Backend", "Language", "Runtime"]):
                backend = name
            elif any(c in cats for c in ["Framework", "Web Framework"]):
                if any(js in name_lower for js in ["react", "vue", "angular", "next", "svelte"]):
                    js_framework = name
                else:
                    framework = name
            elif any(c in cats for c in ["Database", "DB"]):
                database = name
            elif any(c in cats for c in ["CDN", "Cache"]):
                cdn = name
            elif any(c in cats for c in ["WAF", "Security"]):
                waf = name
            elif any(c in cats for c in ["CMS"]):
                cms = name
            
            # Fallback classification by name
            if not server:
                for s in ["apache", "nginx", "iis", "lighttpd", "caddy"]:
                    if s in name_lower:
                        server = name
            if not database:
                for db in ["mysql", "mariadb", "postgresql", "mssql", "oracle", "sqlite", "mongodb", "redis"]:
                    if db in name_lower:
                        database = name
            if not cms:
                for c in ["wordpress", "drupal", "joomla", "magento", "prestashop"]:
                    if c in name_lower:
                        cms = name
            
            # Check WAF
            if not waf:
                for w in ["cloudflare", "mod_security", "aws_waf", "sucuri", "imperva", "akamai"]:
                    if w.replace("_", " ") in name_lower or w in name_lower:
                        waf = name
        
        # WAF from scan
        if not waf and waf_info.get("detected"):
            waf = waf_info.get("name", "Unknown WAF")
        
        # CDN detection from headers
        if not cdn and headers:
            for h_key, h_val in headers.items():
                h_lower = (h_key + " " + str(h_val)).lower()
                if "cloudflare" in h_lower:
                    cdn = "Cloudflare"
                elif "akamai" in h_lower:
                    cdn = "Akamai"
                elif "fastly" in h_lower:
                    cdn = "Fastly"
                elif "cloudfront" in h_lower:
                    cdn = "CloudFront"
        
        # Detect stack profile
        detected_tech_names = set(t["name"].lower() for t in all_techs)
        detected_stack = None
        
        for stack_name, stack_info in cls.STACK_PROFILES.items():
            stack_techs = set(stack_info["techs"])
            overlap = detected_tech_names & stack_techs
            if len(overlap) >= 2:
                detected_stack = {
                    "name": stack_name,
                    "matched": list(overlap),
                    "coverage": len(overlap) / len(stack_techs),
                    "boost": stack_info["boost"],
                }
                break
        
        # Build vulnerability implications
        vuln_implications = {}
        for tech in all_techs:
            t_name = tech["name"].lower()
            t_conf = tech["confidence"]
            for key, vulns in cls.TECH_VULN_MATRIX.items():
                if key in t_name or t_name in key:
                    for vtype, prob in vulns.items():
                        weighted = prob * t_conf
                        vuln_implications[vtype] = max(vuln_implications.get(vtype, 0), weighted)
        
        # Apply stack boost
        if detected_stack:
            for vtype, boost in detected_stack.get("boost", {}).items():
                vuln_implications[vtype] = min(vuln_implications.get(vtype, 0) + boost, 1.0)
        
        # WAF profile
        waf_profile = cls.WAF_PROFILES["generic"]
        if waf:
            waf_lower = waf.lower()
            for key, profile in cls.WAF_PROFILES.items():
                if key.replace("_", " ") in waf_lower or key in waf_lower:
                    waf_profile = profile
                    break
        
        context = {
            "server": server,
            "backend": backend,
            "framework": framework,
            "database": database,
            "cdn": cdn,
            "waf": waf,
            "javascript_framework": js_framework,
            "cms": cms,
            "all_detected": all_techs,
            "detected_stack": detected_stack,
            "vuln_implications": vuln_implications,
            "waf_profile": waf_profile,
            "waf_detected": waf is not None,
        }
        
        return context
    
    @classmethod
    def get_tech_vuln_prob(cls, tech_name: str, vuln_type: str) -> float:
        """Get probability for a tech-vuln combination."""
        t_lower = tech_name.lower()
        for key, vulns in cls.TECH_VULN_MATRIX.items():
            if key in t_lower or t_lower in key:
                return vulns.get(vuln_type, 0.0)
        return 0.0
    
    @classmethod
    def get_waf_bypass(cls, waf_name: str) -> Dict:
        """Get WAF bypass profile."""
        if not waf_name:
            return cls.WAF_PROFILES["generic"]
        w_lower = waf_name.lower()
        for key, profile in cls.WAF_PROFILES.items():
            if key.replace("_", " ") in w_lower or key in w_lower:
                return profile
        return cls.WAF_PROFILES["generic"]
    
    @staticmethod
    def print_summary(ctx: Dict):
        fields = ["server", "backend", "framework", "database", "cdn", "waf",
                   "javascript_framework", "cms"]
        for f in fields:
            val = ctx.get(f)
            if val:
                label = f.replace("_", " ").title()
                print(f"    {label:<22} {val}")
        
        if ctx.get("detected_stack"):
            stack = ctx["detected_stack"]
            print(f"    {'Stack':<22} {stack['name']} ({', '.join(stack['matched'])})")
        
        implications = ctx.get("vuln_implications", {})
        if implications:
            sorted_imp = sorted(implications.items(), key=lambda x: x[1], reverse=True)
            print(f"\n    Vulnerability Implications:")
            for vtype, prob in sorted_imp[:6]:
                color = C.R if prob >= 0.7 else C.Y if prob >= 0.4 else C.G
                print(f"      {vtype:<15} {bar_chart(prob, 15, color)} {prob:.2f}")


# ============================================================
# MODULE 3: BEHAVIORAL CONTEXT
# ============================================================
class BehavioralContext:
    """
    Module 3: How the application respondss.
    Baseline metrics, redirects, compression, cache behavior.
    """
    
    @staticmethod
    def extract(scan_results: Dict) -> Dict:
        """Extract behavioral context from scan results."""
        findings = scan_results.get("findings_for_ml", [])
        meta = scan_results.get("scan_metadata", {})
        headers = scan_results.get("response_headers", {})
        
        # Baseline metrics
        baseline_status = 200
        baseline_length = 0
        baseline_time_ms = 0
        
        # From scan metadata
        if meta.get("baseline_response"):
            bl = meta["baseline_response"]
            baseline_status = bl.get("status", 200)
            baseline_length = bl.get("length", 0)
            baseline_time_ms = bl.get("time_ms", 0)
        
        # From findings (aggregate)
        response_times = []
        response_lengths = []
        response_statuses = []
        
        for f in findings:
            if f.get("response_time_ms"):
                response_times.append(f["response_time_ms"])
            if f.get("response_length"):
                response_lengths.append(f["response_length"])
            if f.get("status_code"):
                response_statuses.append(f["status_code"])
        
        if response_times:
            baseline_time_ms = int(np.median(response_times))
        if response_lengths:
            baseline_length = int(np.median(response_lengths))
        if response_statuses:
            baseline_status = Counter(response_statuses).most_common(1)[0][0]
        
        # Detect behavioral patterns
        redirects = False
        compression = False
        cache = False
        cors_enabled = False
        hsts_enabled = False
        csp_enabled = False
        cookie_flags = {}
        
        if headers:
            header_lower = {k.lower(): v.lower() for k, v in headers.items()}
            
            redirects = "location" in header_lower
            compression = "content-encoding" in header_lower
            cache = "cache-control" in header_lower or "etag" in header_lower
            cors_enabled = "access-control-allow-origin" in header_lower
            hsts_enabled = "strict-transport-security" in header_lower
            csp_enabled = "content-security-policy" in header_lower
            
            # Cookie analysis
            set_cookie = header_lower.get("set-cookie", "")
            cookie_flags = {
                "httponly": "httponly" in set_cookie,
                "secure": "secure" in set_cookie,
                "samesite": "samesite" in set_cookie,
            }
        
        # Error handling behavior
        error_handling = "unknown"
        error_patterns = set()
        for f in findings:
            evidence = f.get("evidence", "").lower()
            if "error" in evidence or "exception" in evidence:
                error_handling = "verbose"
                error_patterns.add("verbose_errors")
            elif "500" in str(f.get("status_code", "")):
                error_handling = "server_error"
            elif "403" in str(f.get("status_code", "")):
                error_handling = "blocked"
                error_patterns.add("waf_blocking")
        
        # Response variability
        time_variance = float(np.var(response_times)) if len(response_times) > 1 else 0.0
        length_variance = float(np.var(response_lengths)) if len(response_lengths) > 1 else 0.0
        
        context = {
            "baseline": {
                "status": baseline_status,
                "time_ms": baseline_time_ms,
                "length": baseline_length,
            },
            "redirects": redirects,
            "compression": compression,
            "cache": cache,
            "cors_enabled": cors_enabled,
            "hsts_enabled": hsts_enabled,
            "csp_enabled": csp_enabled,
            "cookie_flags": cookie_flags,
            "error_handling": error_handling,
            "error_patterns": sorted(list(error_patterns)),
            "response_variability": {
                "time_variance": round(time_variance, 2),
                "length_variance": round(length_variance, 2),
                "samples": len(response_times),
            },
            "timing_anomaly_detected": time_variance > 5000,  # High variance might indicate timing-based vuln
        }
        
        return context
    
    @staticmethod
    def print_summary(ctx: Dict):
        bl = ctx.get("baseline", {})
        print(f"    Baseline Status:  {bl.get('status', 'N/A')}")
        print(f"    Baseline Time:    {bl.get('time_ms', 'N/A')} ms")
        print(f"    Baseline Length:  {bl.get('length', 'N/A')} bytes")
        print(f"    Redirects:        {ctx.get('redirects', False)}")
        print(f"    Compression:      {ctx.get('compression', False)}")
        print(f"    Cache:            {ctx.get('cache', False)}")
        print(f"    Error Handling:   {ctx.get('error_handling', 'unknown')}")
        print(f"    Timing Anomaly:   {ctx.get('timing_anomaly_detected', False)}")


# ============================================================
# MODULE 4: SURFACE MAPPING
# ============================================================
class SurfaceMapping:
    """
    Module 4: All attack surface areas discovered.
    Forms, cookies, headers, query params, JSON params, uploads, API endpoints.
    """
    
    @staticmethod
    def extract(scan_results: Dict) -> Dict:
        """Extract surface mapping from scan results."""
        forms = scan_results.get("forms", [])
        findings = scan_results.get("findings_for_ml", [])
        vulns = scan_results.get("vulnerabilities", [])
        crawled = scan_results.get("crawled_urls", [])
        headers = scan_results.get("response_headers", {})
        
        # Forms
        form_surfaces = []
        for form in forms:
            form_entry = {
                "action": form.get("action", ""),
                "method": form.get("method", "GET").upper(),
                "inputs": [],
                "has_file_upload": False,
                "input_count": 0,
            }
            for inp in form.get("inputs", []):
                inp_entry = {
                    "name": inp.get("name", ""),
                    "type": inp.get("type", "text"),
                    "required": inp.get("required", False),
                }
                form_entry["inputs"].append(inp_entry)
                if inp.get("type", "").lower() == "file":
                    form_entry["has_file_upload"] = True
            form_entry["input_count"] = len(form_entry["inputs"])
            form_surfaces.append(form_entry)
        
        # Cookies
        cookie_surfaces = []
        set_cookie = headers.get("Set-Cookie", headers.get("set-cookie", ""))
        if set_cookie:
            for cookie_str in set_cookie.split(","):
                parts = cookie_str.strip().split(";")
                if parts:
                    name_val = parts[0].split("=")
                    cookie_surfaces.append({
                        "name": name_val[0].strip() if name_val else "",
                        "flags": [p.strip().lower() for p in parts[1:]],
                    })
        
        # Headers (interesting ones)
        header_surfaces = []
        interesting_headers = [
            "x-forwarded-for", "x-forwarded-host", "x-original-url",
            "x-rewrite-url", "x-real-ip", "host", "referer",
            "user-agent", "x-api-key", "authorization", "cookie",
        ]
        if headers:
            for h_key in headers.keys():
                if h_key.lower() in interesting_headers:
                    header_surfaces.append({
                        "name": h_key,
                        "injectable": True,
                    })
        
        # Query parameters (from findings + crawled URLs)
        query_params = set()
        from urllib.parse import urlparse, parse_qs
        
        for f in findings:
            url = f.get("url", "")
            parsed = urlparse(url)
            for k in parse_qs(parsed.query).keys():
                query_params.add(k)
        
        for url in crawled:
            u = url if isinstance(url, str) else url.get("url", "")
            parsed = urlparse(u)
            for k in parse_qs(parsed.query).keys():
                query_params.add(k)
        
        query_param_surfaces = [{"name": p, "source": "url"} for p in sorted(query_params)]
        
        # JSON parameters (from findings with POST + JSON)
        json_params = set()
        for f in findings:
            if f.get("method", "").upper() == "POST" and f.get("content_type", "") == "application/json":
                if f.get("parameter"):
                    json_params.add(f["parameter"])
        
        json_param_surfaces = [{"name": p} for p in sorted(json_params)]
        
        # Upload points
        upload_surfaces = [f for f in form_surfaces if f.get("has_file_upload")]
        
        # API endpoints
        api_surfaces = []
        for url in crawled:
            u = url if isinstance(url, str) else url.get("url", "")
            if any(p in u.lower() for p in ["/api/", "/rest/", "/graphql", "/v1/", "/v2/"]):
                api_surfaces.append({"url": u, "type": "api"})
        
        # Parameters from findings
        finding_params = set()
        for f in findings:
            if f.get("parameter"):
                finding_params.add(f["parameter"])
        
        mapping = {
            "forms": form_surfaces,
            "cookies": cookie_surfaces,
            "headers": header_surfaces,
            "query_parameters": query_param_surfaces,
            "json_parameters": json_param_surfaces,
            "upload_points": upload_surfaces,
            "api_endpoints": api_surfaces,
            "total_parameters": len(finding_params | query_params | json_params),
            "total_forms": len(form_surfaces),
            "total_attack_points": (
                len(form_surfaces) + len(cookie_surfaces) + len(header_surfaces) +
                len(query_param_surfaces) + len(json_param_surfaces) +
                len(upload_surfaces) + len(api_surfaces)
            ),
        }
        
        return mapping
    
    @staticmethod
    def print_summary(ctx: Dict):
        print(f"    Forms:            {ctx['total_forms']}")
        print(f"    Query Params:     {len(ctx['query_parameters'])}")
        print(f"    JSON Params:      {len(ctx['json_parameters'])}")
        print(f"    Cookies:          {len(ctx['cookies'])}")
        print(f"    Headers:          {len(ctx['headers'])}")
        print(f"    Upload Points:    {len(ctx['upload_points'])}")
        print(f"    API Endpoints:    {len(ctx['api_endpoints'])}")
        print(f"    Total Attack Pts: {ctx['total_attack_points']}")


# ============================================================
# MODULE 5: FEATURE EXTRACTION
# ============================================================
class FeatureExtraction:
    """
    Module 5: Extract ML features from observations.
    Response similarity, timing difference, reflected input, error patterns,
    HTML changes, DOM changes, header changes, TLS fingerprint, cookie mutation,
    session rotation.
    """
    
    # Parameter name → vulnerability hints
    PARAM_VULN_HINTS = {
        "id": {"sqli": 0.30, "lfi": 0.10},
        "page": {"lfi": 0.35, "sqli": 0.15},
        "file": {"lfi": 0.50, "rce": 0.15},
        "path": {"lfi": 0.45, "rce": 0.10},
        "url": {"ssrf": 0.50, "lfi": 0.15},
        "redirect": {"ssrf": 0.40, "xss": 0.15},
        "next": {"ssrf": 0.35},
        "return": {"ssrf": 0.35},
        "search": {"xss": 0.30, "sqli": 0.20, "ssti": 0.10},
        "query": {"xss": 0.30, "sqli": 0.20},
        "q": {"xss": 0.30, "sqli": 0.20},
        "name": {"xss": 0.20, "sqli": 0.15, "ssti": 0.10},
        "username": {"sqli": 0.25, "xss": 0.10},
        "user": {"sqli": 0.25},
        "email": {"xss": 0.15, "sqli": 0.15},
        "password": {"sqli": 0.20},
        "comment": {"xss": 0.30, "ssti": 0.15},
        "message": {"xss": 0.30, "ssti": 0.15},
        "title": {"xss": 0.25},
        "content": {"xss": 0.25, "ssti": 0.15},
        "body": {"xss": 0.25, "ssti": 0.15},
        "template": {"ssti": 0.50},
        "lang": {"lfi": 0.30},
        "locale": {"lfi": 0.25},
        "include": {"lfi": 0.45},
        "require": {"lfi": 0.40},
        "exec": {"rce": 0.50},
        "cmd": {"rce": 0.55},
        "command": {"rce": 0.50},
        "ping": {"rce": 0.45},
        "host": {"rce": 0.30, "ssrf": 0.35},
        "ip": {"rce": 0.25, "ssrf": 0.30},
        "data": {"xxe": 0.20, "sqli": 0.15},
        "xml": {"xxe": 0.45},
        "callback": {"xss": 0.25, "ssrf": 0.20},
        "sort": {"sqli": 0.25},
        "order": {"sqli": 0.25},
        "limit": {"sqli": 0.20},
        "table": {"sqli": 0.25},
        "column": {"sqli": 0.20},
    }
    
    # Form type detection
    FORM_PATTERNS = {
        "login": {
            "url_patterns": [r"login", r"signin", r"auth", r"session"],
            "input_patterns": [r"user", r"pass", r"email", r"login"],
            "vuln_priority": ["sqli", "xss", "auth_bypass"],
            "technique_priority": {"sqli": ["auth_bypass", "time_based", "boolean_based"]},
        },
        "search": {
            "url_patterns": [r"search", r"find", r"query", r"lookup"],
            "input_patterns": [r"search", r"query", r"q", r"keyword"],
            "vuln_priority": ["xss", "sqli", "ssti"],
            "technique_priority": {"sqli": ["union_based", "error_based", "time_based"]},
        },
        "registration": {
            "url_patterns": [r"register", r"signup", r"create"],
            "input_patterns": [r"name", r"email", r"password", r"username"],
            "vuln_priority": ["xss", "sqli", "ssti"],
            "technique_priority": {"sqli": ["error_based", "time_based"]},
        },
        "file_upload": {
            "url_patterns": [r"upload", r"file", r"attach", r"import"],
            "input_patterns": [r"file", r"upload", r"attachment"],
            "vuln_priority": ["rce", "lfi", "xss", "ssrf"],
            "technique_priority": {},
        },
        "comment": {
            "url_patterns": [r"comment", r"post", r"reply", r"feedback"],
            "input_patterns": [r"comment", r"message", r"body", r"content"],
            "vuln_priority": ["xss", "ssti", "sqli"],
            "technique_priority": {},
        },
        "admin": {
            "url_patterns": [r"admin", r"manage", r"dashboard", r"panel"],
            "input_patterns": [r"admin", r"action", r"command"],
            "vuln_priority": ["rce", "sqli", "ssrf", "xss"],
            "technique_priority": {},
        },
        "api": {
            "url_patterns": [r"api", r"endpoint", r"rest", r"graphql"],
            "input_patterns": [r"id", r"key", r"token", r"format"],
            "vuln_priority": ["sqli", "ssrf", "xxe", "rce"],
            "technique_priority": {},
        },
    }
    
    @classmethod
    def extract(cls, scan_results: Dict, tech_ctx: Dict, behavioral_ctx: Dict) -> Dict:
        """Extract all features from scan observations."""
        findings = scan_results.get("findings_for_ml", [])
        vulns = scan_results.get("vulnerabilities", [])
        forms = scan_results.get("forms", [])
        headers = scan_results.get("response_headers", {})
        
        features_per_finding = []
        
        for finding in findings:
            feat = {}
            
            # --- 1. Response Similarity ---
            feat["response_similarity"] = cls._compute_response_similarity(finding)
            
            # --- 2. Timing Difference ---
            feat["timing_difference"] = cls._compute_timing_difference(finding, behavioral_ctx)
            
            # --- 3. Reflected Input ---
            feat["reflected_input"] = cls._detect_reflected_input(finding)
            
            # --- 4. Error Pattern ---
            feat["error_pattern"] = cls._detect_error_pattern(finding)
            
            # --- 5. HTML Changes ---
            feat["html_changes"] = cls._detect_html_changes(finding)
            
            # --- 6. DOM Changes ---
            feat["dom_changes"] = cls._detect_dom_changes(finding)
            
            # --- 7. Header Changes ---
            feat["header_changes"] = cls._detect_header_changes(finding)
            
            # --- 8. TLS Fingerprint ---
            feat["tls_fingerprint"] = cls._detect_tls_fingerprint(scan_results)
            
            # --- 9. Cookie Mutation ---
            feat["cookie_mutation"] = cls._detect_cookie_mutation(scan_results)
            
            # --- 10. Session Rotation ---
            feat["session_rotation"] = cls._detect_session_rotation(scan_results)
            
            # --- 11. Parameter Hints ---
            param = finding.get("parameter", "")
            param_lower = param.lower()
            param_hints = {}
            for key, hints in cls.PARAM_VULN_HINTS.items():
                if key in param_lower or param_lower in key:
                    param_hints = hints
                    break
            feat["param_vuln_hints"] = param_hints
            
            # --- 12. Form Context ---
            form_context = cls._classify_form(finding, forms)
            feat["form_type"] = form_context.get("form_type", "generic")
            feat["form_vuln_priority"] = form_context.get("vuln_priority", [])
            feat["form_technique_priority"] = form_context.get("technique_priority", {})
            
            # --- 13. Technology Correlation ---
            vtype = finding.get("vuln_type", "other")
            tech_prob = 0.0
            all_techs = tech_ctx.get("all_detected", [])
            for tech in all_techs:
                t_name = tech.get("name", "")
                prob = TechnologyContext.get_tech_vuln_prob(t_name, vtype)
                tech_prob = max(tech_prob, prob)
            feat["tech_correlation"] = tech_prob
            
            # --- 14. Evidence Strength ---
            feat["evidence_strength"] = cls._compute_evidence_strength(finding)
            
            # --- 15. Payload Characteristics ---
            feat["payload_features"] = cls._extract_payload_features(finding)
            
            # --- 16. URL Features ---
            feat["url_features"] = cls._extract_url_features(finding)
            
            features_per_finding.append({
                "finding_ref": finding,
                "features": feat,
            })
        
        # Aggregate features
        aggregate = {
            "total_features_extracted": sum(len(f["features"]) for f in features_per_finding),
            "avg_evidence_strength": np.mean([
                f["features"]["evidence_strength"] for f in features_per_finding
            ]) if features_per_finding else 0.0,
            "avg_timing_diff": np.mean([
                f["features"]["timing_difference"] for f in features_per_finding
            ]) if features_per_finding else 0.0,
            "reflections_detected": sum(1 for f in features_per_finding if f["features"]["reflected_input"]),
            "errors_detected": sum(1 for f in features_per_finding if f["features"]["error_pattern"]["detected"]),
            "timing_anomalies": sum(1 for f in features_per_finding if f["features"]["timing_difference"] > 2.0),
        }
        
        return {
            "per_finding": features_per_finding,
            "aggregate": aggregate,
        }
    
    @staticmethod
    def _compute_response_similarity(finding):
        """How similar is the response to baseline? (1.0 = identical)"""
        baseline_len = finding.get("baseline_length", 0)
        response_len = finding.get("response_length", 0)
        
        if baseline_len == 0 or response_len == 0:
            return 0.5
        
        diff_ratio = abs(baseline_len - response_len) / max(baseline_len, 1)
        return max(0.0, 1.0 - diff_ratio)
    
    @staticmethod
    def _compute_timing_difference(finding, behavioral_ctx):
        """How much longer did the response take vs baseline?"""
        baseline_time = behavioral_ctx.get("baseline", {}).get("time_ms", 0)
        response_time = finding.get("response_time_ms", 0)
        
        if baseline_time == 0 or response_time == 0:
            # Check evidence for timing clues
            evidence = finding.get("evidence", "").lower()
            if "delay" in evidence or "sleep" in evidence or "time" in evidence:
                # Try to extract delay from evidence
                match = re.search(r'(\d+\.?\d*)\s*s', evidence)
                if match:
                    return float(match.group(1))
                return 3.0  # Assume significant delay
            return 0.0
        
        diff_seconds = (response_time - baseline_time) / 1000.0
        return max(0.0, diff_seconds)
    
    @staticmethod
    def _detect_reflected_input(finding):
        """Is the input reflected in the response?"""
        evidence = finding.get("evidence", "").lower()
        if "reflect" in evidence or "mirror" in evidence or "echo" in evidence:
            return True
        
        payload = finding.get("payload", "")
        if payload and finding.get("response_contains_payload", False):
            return True
        
        return False
    
    @staticmethod
    def _detect_error_pattern(finding):
        """Detect error patterns in response."""
        evidence = finding.get("evidence", "").lower()
        
        patterns = {
            "sql_error": any(p in evidence for p in ["sql", "syntax", "mysql", "postgresql", "ora-", "sqlite"]),
            "server_error": any(p in evidence for p in ["500", "internal server", "exception", "traceback"]),
            "waf_block": any(p in evidence for p in ["403", "blocked", "forbidden", "denied", "firewall"]),
            "validation_error": any(p in evidence for p in ["invalid", "required", "format", "validation"]),
        }
        
        detected = any(patterns.values())
        return {
            "detected": detected,
            "patterns": {k: v for k, v in patterns.items() if v},
            "raw": finding.get("evidence", "")[:200],
        }
    
    @staticmethod
    def _detect_html_changes(finding):
        """Detect HTML structure changes."""
        evidence = finding.get("evidence", "").lower()
        changes = {
            "new_elements": "new element" in evidence or "injected" in evidence,
            "modified_content": "content changed" in evidence or "modified" in evidence,
            "broken_layout": "broken" in evidence or "malformed" in evidence,
        }
        return {k: v for k, v in changes.items() if v}
    
    @staticmethod
    def _detect_dom_changes(finding):
        """Detect DOM-level changes."""
        evidence = finding.get("evidence", "").lower()
        return {
            "dom_modified": "dom" in evidence or "javascript" in evidence,
            "script_injected": "script" in evidence and "inject" in evidence,
        }
    
    @staticmethod
    def _detect_header_changes(finding):
        """Detect response header changes."""
        evidence = finding.get("evidence", "").lower()
        return {
            "new_headers": "header" in evidence and ("new" in evidence or "changed" in evidence),
            "redirect_header": "location" in evidence or "redirect" in evidence,
        }
    
    @staticmethod
    def _detect_tls_fingerprint(scan_results):
        """TLS fingerprint analysis."""
        tls = scan_results.get("tls_info", {})
        return {
            "version": tls.get("version", "unknown"),
            "cipher": tls.get("cipher", "unknown"),
            "certificate_valid": tls.get("valid", True),
        }
    
    @staticmethod
    def _detect_cookie_mutation(scan_results):
        """Detect if cookies change after input."""
        headers = scan_results.get("response_headers", {})
        set_cookie = headers.get("Set-Cookie", headers.get("set-cookie", ""))
        return {
            "cookies_set": bool(set_cookie),
            "cookie_count": len(set_cookie.split(",")) if set_cookie else 0,
        }
    
    @staticmethod
    def _detect_session_rotation(scan_results):
        """Detect session ID rotation."""
        headers = scan_results.get("response_headers", {})
        set_cookie = headers.get("Set-Cookie", headers.get("set-cookie", ""))
        session_keywords = ["session", "sess", "jsessionid", "phpsessid", "asp.net_sessionid"]
        
        rotated = False
        if set_cookie:
            for kw in session_keywords:
                if kw in set_cookie.lower():
                    rotated = True
                    break
        
        return {"detected": rotated}
    
    @staticmethod
    def _compute_evidence_strength(finding):
        """Compute evidence strength score (0.0 - 1.0)."""
        evidence = finding.get("evidence", "").lower()
        score = 0.0
        
        # Strong indicators
        if any(p in evidence for p in ["delay", "sleep", "timeout"]):
            score = max(score, 0.9)
        if any(p in evidence for p in ["error", "syntax", "exception"]):
            score = max(score, 0.8)
        if any(p in evidence for p in ["reflect", "mirror", "echo"]):
            score = max(score, 0.7)
        if any(p in evidence for p in ["file content", "etc/passwd", "win.ini"]):
            score = max(score, 0.85)
        if any(p in evidence for p in ["template", "evaluated", "expression"]):
            score = max(score, 0.75)
        
        # Medium indicators
        if evidence and len(evidence) > 50:
            score = max(score, 0.5)
        if finding.get("confidence", 0) > 0.7:
            score = max(score, 0.6)
        
        # Source weighting
        source = finding.get("source", "")
        if source == "active_test":
            score = max(score, 0.4)
        elif source == "zap":
            score = max(score, 0.35)
        
        return score if score > 0 else 0.2
    
    @staticmethod
    def _extract_payload_features(finding):
        """Extract features from the payload used."""
        payload = finding.get("payload", "")
        return {
            "length": len(payload),
            "has_quotes": "'" in payload or '"' in payload,
            "has_sql_comments": "--" in payload or "#" in payload,
            "has_html_tags": "<" in payload and ">" in payload,
            "has_encoding": "%" in payload or "\\" in payload,
            "has_logical_operators": any(op in payload for op in ["OR", "AND", "||", "&&"]),
            "has_path_traversal": ".." in payload or "%2e%2e" in payload.lower(),
            "has_template_expr": "{{" in payload or "${" in payload or "<%=" in payload,
            "has_command_sep": any(sep in payload for sep in [";", "|", "`", "$(", "||"]),
        }
    
    @staticmethod
    def _extract_url_features(finding):
        """Extract features from the URL."""
        from urllib.parse import urlparse
        url = finding.get("url", "")
        parsed = urlparse(url)
        
        return {
            "has_query_params": bool(parsed.query),
            "is_php": ".php" in url.lower(),
            "is_asp": any(ext in url.lower() for ext in [".asp", ".aspx"]),
            "is_jsp": ".jsp" in url.lower(),
            "path_depth": len([p for p in parsed.path.split("/") if p]),
            "has_extension": "." in parsed.path.split("/")[-1] if parsed.path else False,
        }
    
    @classmethod
    def _classify_form(cls, finding, forms):
        """Classify the form context for a finding."""
        url = finding.get("url", "").lower()
        param = finding.get("parameter", "").lower()
        
        scores = {}
        for form_type, patterns in cls.FORM_PATTERNS.items():
            score = 0.0
            
            for pattern in patterns["url_patterns"]:
                if re.search(pattern, url):
                    score += 0.5
                    break
            
            for pattern in patterns["input_patterns"]:
                if re.search(pattern, param):
                    score += 0.4
                    break
            
            scores[form_type] = score
        
        if scores:
            best = max(scores, key=scores.get)
            if scores[best] > 0.2:
                result = {
                    "form_type": best,
                    "confidence": min(scores[best], 1.0),
                    "vuln_priority": cls.FORM_PATTERNS[best]["vuln_priority"],
                    "technique_priority": cls.FORM_PATTERNS[best].get("technique_priority", {}),
                }
                return result
        
        return {
            "form_type": "generic",
            "confidence": 0.3,
            "vuln_priority": ["xss", "sqli"],
            "technique_priority": {},
        }
    
    @classmethod
    def get_param_hints(cls, param_name: str) -> Dict:
        """Get vulnerability hints for a parameter name."""
        p_lower = param_name.lower().strip()
        
        # Exact match
        if p_lower in cls.PARAM_VULN_HINTS:
            return cls.PARAM_VULN_HINTS[p_lower]
        
        # Partial match
        hints = {}
        for key, vuln_hints in cls.PARAM_VULN_HINTS.items():
            if key in p_lower or p_lower in key:
                for vuln, score in vuln_hints.items():
                    hints[vuln] = max(hints.get(vuln, 0), score * 0.7)
        
        return hints if hints else {"xss": 0.10, "sqli": 0.10}
    
    @staticmethod
    def print_summary(ctx: Dict):
        agg = ctx.get("aggregate", {})
        print(f"    Total Features:       {agg.get('total_features_extracted', 0)}")
        print(f"    Avg Evidence:         {agg.get('avg_evidence_strength', 0):.2f}")
        print(f"    Avg Timing Diff:      {agg.get('avg_timing_diff', 0):.2f}s")
        print(f"    Reflections:          {agg.get('reflections_detected', 0)}")
        print(f"    Errors:               {agg.get('errors_detected', 0)}")
        print(f"    Timing Anomalies:     {agg.get('timing_anomalies', 0)}")


# ============================================================
# MODULE 6: HYPOTHESIS ENGINE
# ============================================================
class HypothesisEngine:
    """
    Module 6: Generate and rank multiple hypotheses.
    Not just one guess — many possibilities with confidence scores.
    """
    
    # Payload effectiveness database
    PAYLOAD_EFFECTIVENESS = {
        "sqli": {
            "time_based": {"base": 0.78, "blind": 0.85, "non_blind": 0.60},
            "error_based": {"base": 0.65, "blind": 0.30, "non_blind": 0.80},
            "boolean_based": {"base": 0.72, "blind": 0.80, "non_blind": 0.55},
            "union_based": {"base": 0.60, "blind": 0.20, "non_blind": 0.85},
            "auth_bypass": {"base": 0.55, "login": 0.70, "non_login": 0.20},
        },
        "xss": {
            "reflected": {"base": 0.45, "search_param": 0.65, "input_param": 0.50},
            "dom_based": {"base": 0.40, "js_context": 0.55},
            "stored": {"base": 0.50, "comment": 0.55, "profile": 0.45},
        },
        "lfi": {
            "path_traversal": {"base": 0.55, "file_param": 0.75, "page_param": 0.70},
            "php_wrapper": {"base": 0.40, "php_backend": 0.65},
            "null_byte": {"base": 0.30, "old_php": 0.55},
        },
        "rce": {
            "command_injection": {"base": 0.40, "ping_param": 0.70, "exec_param": 0.65},
            "code_injection": {"base": 0.35, "eval_param": 0.60},
        },
        "ssti": {
            "expression_injection": {"base": 0.50, "template_param": 0.75},
            "class_enumeration": {"base": 0.35, "python_backend": 0.55},
        },
        "ssrf": {
            "internal_access": {"base": 0.45, "url_param": 0.70},
            "cloud_metadata": {"base": 0.40, "cloud_hosted": 0.65},
        },
        "xxe": {
            "file_read": {"base": 0.35, "xml_input": 0.70},
            "ssrf_via_xxe": {"base": 0.30, "xml_input": 0.60},
        },
    }
    
    @classmethod
    def generate(cls, findings: List[Dict], tech_ctx: Dict, feature_ctx: Dict,
                 behavioral_ctx: Dict) -> List[Dict]:
        """Generate ranked hypotheses for all findings."""
        hypotheses = []
        
        features_per_finding = feature_ctx.get("per_finding", [])
        
        for feat_entry in features_per_finding:
            finding = feat_entry["finding_ref"]
            features = feat_entry["features"]
            
            vtype = finding.get("vuln_type", "other")
            param = finding.get("parameter", "")
            
            # Generate multiple hypotheses per finding
            finding_hypotheses = cls._generate_for_finding(
                finding, features, tech_ctx, behavioral_ctx
            )
            
            hypotheses.extend(finding_hypotheses)
        
        # Sort by confidence
        hypotheses.sort(key=lambda x: x["confidence"], reverse=True)
        
        return hypotheses
    
    @classmethod
    def _generate_for_finding(cls, finding, features, tech_ctx, behavioral_ctx):
        """Generate hypotheses for a single finding."""
        hypotheses = []
        vtype = finding.get("vuln_type", "other")
        param = finding.get("parameter", "")
        
        # --- Hypothesis 1: Direct exploitation of detected vuln type ---
        conf1 = cls._compute_hypothesis_confidence(
            finding, features, tech_ctx, behavioral_ctx, vtype
        )
        hypotheses.append({
            "family": vtype,
            "technique": cls._infer_technique(finding, features),
            "confidence": round(conf1, 2),
            "reasoning": f"Direct {vtype} exploitation based on scan evidence",
        })
        
        # --- Hypothesis 2: Related vuln types ---
        related_types = cls._get_related_vuln_types(vtype)
        for rel_type in related_types:
            conf2 = cls._compute_hypothesis_confidence(
                finding, features, tech_ctx, behavioral_ctx, rel_type
            ) * 0.7  # Lower confidence for related types
            
            if conf2 > 0.2:
                hypotheses.append({
                    "family": rel_type,
                    "technique": "exploratory",
                    "confidence": round(conf2, 2),
                    "reasoning": f"Related to {vtype} via {cls._get_relation_reason(vtype, rel_type)}",
                })
        
        # --- Hypothesis 3: Tech-driven hypotheses ---
        vuln_impl = tech_ctx.get("vuln_implications", {})
        for impl_type, impl_prob in vuln_impl.items():
            if impl_type != vtype and impl_prob > 0.3:
                conf3 = impl_prob * 0.5 * features.get("evidence_strength", 0.3)
                if conf3 > 0.15:
                    hypotheses.append({
                        "family": impl_type,
                        "technique": "tech_driven",
                        "confidence": round(conf3, 2),
                        "reasoning": f"Technology stack suggests {impl_type} possibility",
                    })
        
        # --- Hypothesis 4: Form-context driven ---
        form_priority = features.get("form_vuln_priority", [])
        for i, fp_type in enumerate(form_priority):
            if fp_type != vtype:
                conf4 = (0.4 - i * 0.1) * features.get("evidence_strength", 0.3)
                if conf4 > 0.15:
                    hypotheses.append({
                        "family": fp_type,
                        "technique": "form_context",
                        "confidence": round(conf4, 2),
                        "reasoning": f"Form type ({features.get('form_type', 'unknown')}) suggests {fp_type}",
                    })
        
        # Sort by confidence
        hypotheses.sort(key=lambda x: x["confidence"], reverse=True)
        
        # Deduplicate by family
        seen = set()
        deduped = []
        for h in hypotheses:
            key = f"{h['family']}_{h['technique']}"
            if key not in seen:
                seen.add(key)
                deduped.append(h)
        
        return deduped[:5]  # Max 5 hypotheses per finding
    
    @classmethod
    def _compute_hypothesis_confidence(cls, finding, features, tech_ctx,
                                        behavioral_ctx, target_vuln_type):
        """Compute confidence for a hypothesis."""
        components = {}
        
        # 1. ML feature score
        components["evidence"] = features.get("evidence_strength", 0.2)
        
        # 2. Technology correlation
        all_techs = tech_ctx.get("all_detected", [])
        tech_prob = 0.0
        for tech in all_techs:
            prob = TechnologyContext.get_tech_vuln_prob(tech.get("name", ""), target_vuln_type)
            tech_prob = max(tech_prob, prob)
        components["tech"] = tech_prob
        
        # 3. Parameter hints
        param = finding.get("parameter", "")
        param_hints = FeatureExtraction.get_param_hints(param)
        components["param"] = param_hints.get(target_vuln_type, 0.05)
        
        # 4. Payload effectiveness
        eff_data = cls.PAYLOAD_EFFECTIVENESS.get(target_vuln_type, {})
        max_eff = 0.0
        for technique, data in eff_data.items():
            base = data.get("base", 0.3)
            max_eff = max(max_eff, base)
        components["effectiveness"] = max_eff
        
        # 5. Behavioral signals
        timing_diff = features.get("timing_difference", 0)
        if timing_diff > 3.0 and target_vuln_type == "sqli":
            components["behavioral"] = 0.8
        elif features.get("reflected_input") and target_vuln_type == "xss":
            components["behavioral"] = 0.7
        elif features.get("error_pattern", {}).get("detected") and target_vuln_type == "sqli":
            components["behavioral"] = 0.75
        else:
            components["behavioral"] = 0.2
        
        # 6. Form context
        form_type = features.get("form_type", "generic")
        form_priority = features.get("form_vuln_priority", [])
        if target_vuln_type in form_priority:
            idx = form_priority.index(target_vuln_type)
            components["form"] = 0.8 - idx * 0.2
        else:
            components["form"] = 0.2
        
        # 7. Original finding confidence
        components["original"] = float(finding.get("confidence", 0.5))
        
        # Weighted combination
        weights = {
            "evidence": 0.20,
            "tech": 0.15,
            "param": 0.10,
            "effectiveness": 0.15,
            "behavioral": 0.15,
            "form": 0.10,
            "original": 0.15,
        }
        
        combined = sum(components.get(k, 0) * w for k, w in weights.items())
        
        # WAF modifier
        if tech_ctx.get("waf_detected"):
            waf_profile = tech_ctx.get("waf_profile", {})
            modifier = waf_profile.get("effectiveness_modifier", -0.10)
            combined += modifier
        
        return float(np.clip(combined, 0.0, 1.0))
    
    @staticmethod
    def _infer_technique(finding, features):
        """Infer the most likely technique from evidence."""
        evidence = finding.get("evidence", "").lower()
        payload = finding.get("payload", "").lower()
        
        if "sleep" in evidence or "delay" in evidence or "sleep" in payload:
            return "time_based"
        elif "error" in evidence or "union" in payload or "select" in payload:
            return "error_based"
        elif "reflect" in evidence or "<" in payload:
            return "reflected"
        elif ".." in payload or "etc/passwd" in payload:
            return "path_traversal"
        elif "{{" in payload or "${" in payload:
            return "expression_injection"
        elif any(sep in payload for sep in [";", "|", "`", "$("]):
            return "command_injection"
        else:
            return "generic"
    
    @staticmethod
    def _get_related_vuln_types(vtype):
        """Get related vulnerability types."""
        relations = {
            "sqli": ["xss", "lfi", "rce"],
            "xss": ["ssti", "sqli"],
            "lfi": ["rce", "ssrf"],
            "rce": ["lfi", "ssrf"],
            "ssti": ["rce", "xss"],
            "ssrf": ["lfi", "rce", "xxe"],
            "xxe": ["ssrf", "lfi"],
        }
        return relations.get(vtype, [])
    
    @staticmethod
    def _get_relation_reason(v1, v2):
        """Explain why two vuln types are related."""
        reasons = {
            ("sqli", "xss"): "shared input handling weakness",
            ("sqli", "lfi"): "database file access potential",
            ("sqli", "rce"): "database command execution",
            ("xss", "ssti"): "shared output encoding weakness",
            ("lfi", "rce"): "file inclusion to code execution",
            ("ssrf", "lfi"): "server-side request to file access",
            ("ssti", "rce"): "template evaluation to code execution",
        }
        return reasons.get((v1, v2), reasons.get((v2, v1), "shared attack surface"))
    
    @staticmethod
    def print_summary(hypotheses: List[Dict]):
        print(f"    Total Hypotheses: {len(hypotheses)}")
        if hypotheses:
            print(f"\n    Top Hypotheses:")
            for h in hypotheses[:8]:
                conf = h["confidence"]
                color = C.R if conf >= 0.7 else C.Y if conf >= 0.4 else C.G
                print(f"      {bar_chart(conf, 15, color)} {conf:.2f} "
                      f"[{h['family']}] technique={h['technique']}")
                print(f"        {C.D}{h['reasoning']}{C.RS}")


# ============================================================
# MODULE 7: CONSTRAINT ENGINE
# ============================================================
class ConstraintEngine:
    """
    Module 7: Define constraints for the Generator.
    Max input length, encoding, case sensitivity, allowed methods.
    """
    
    @staticmethod
    def compute(target_ctx: Dict, tech_ctx: Dict, behavioral_ctx: Dict,
                surface_ctx: Dict) -> Dict:
        """Compute constraints for payload generation."""
        
        # Max input length (based on technology)
        max_input_length = 256  # Default
        backend = (tech_ctx.get("backend") or "").lower()
        framework = (tech_ctx.get("framework") or "").lower()
        
        if "django" in framework or "laravel" in framework:
            max_input_length = 512  # Frameworks often have larger limits
        elif "flask" in framework:
            max_input_length = 1024
        elif "asp.net" in framework:
            max_input_length = 2048
        
        # Encoding candidates
        encoding_candidates = ["url_encode"]  # Always include basic
        
        waf_profile = tech_ctx.get("waf_profile", {})
        waf_encoding = waf_profile.get("encoding", [])
        for enc in waf_encoding:
            if enc not in encoding_candidates:
                encoding_candidates.append(enc)
        
        # Case sensitivity
        case_sensitive = True
        if "php" in backend:
            case_sensitive = False  # PHP is often case-insensitive for function names
        elif "asp.net" in framework:
            case_sensitive = False
        
        # Allowed methods
        allowed_methods = target_ctx.get("all_methods", ["GET", "POST"])
        
        # Content types
        content_types = ["application/x-www-form-urlencoded"]
        if "POST" in allowed_methods:
            content_types.append("multipart/form-data")
            content_types.append("application/json")
        
        # Special characters to avoid (based on WAF)
        avoid_chars = []
        if tech_ctx.get("waf_detected"):
            avoid_chars = ["<script>", "UNION SELECT", "DROP TABLE"]
        
        # Rate limiting
        max_requests_per_second = 10
        if tech_ctx.get("waf_detected"):
            max_requests_per_second = 5
        
        # Timeout settings
        timeout_seconds = 30
        if behavioral_ctx.get("timing_anomaly_detected"):
            timeout_seconds = 60  # Longer timeout for timing-based tests
        
        constraints = {
            "max_input_length": max_input_length,
            "encoding_candidates": encoding_candidates,
            "case_variation": not case_sensitive,
            "case_sensitive": case_sensitive,
            "allowed_methods": allowed_methods,
            "content_types": content_types,
            "avoid_patterns": avoid_chars,
            "waf_detected": tech_ctx.get("waf_detected", False),
            "max_requests_per_second": max_requests_per_second,
            "timeout_seconds": timeout_seconds,
            "retry_on_block": True,
            "max_retries": 3,
            "bypass_techniques": waf_profile.get("techniques", []),
        }
        
        return constraints
    
    @staticmethod
    def print_summary(ctx: Dict):
        print(f"    Max Input Length:     {ctx['max_input_length']}")
        print(f"    Encoding Candidates:  {ctx['encoding_candidates']}")
        print(f"    Case Variation:       {ctx['case_variation']}")
        print(f"    Allowed Methods:      {ctx['allowed_methods']}")
        print(f"    WAF Detected:         {ctx['waf_detected']}")
        print(f"    Max Req/sec:          {ctx['max_requests_per_second']}")
        print(f"    Timeout:              {ctx['timeout_seconds']}s")
        if ctx.get("bypass_techniques"):
            print(f"    Bypass Techniques:    {ctx['bypass_techniques']}")


# ============================================================
# MODULE 8: STRATEGY RECOMMENDATION
# ============================================================
class StrategyRecommendation:
    """
    Module 8: Recommend the best strategy for the Generator.
    """
    
    @staticmethod
    def recommend(hypotheses: List[Dict], constraints: Dict,
                  tech_ctx: Dict, behavioral_ctx: Dict) -> Dict:
        """Recommend generation strategy."""
        
        if not hypotheses:
            return {
                "recommended_strategy": "exploratory",
                "exploration_ratio": 0.8,
                "mutation_strength": "low",
                "reasoning": "No strong hypotheses — broad exploration needed",
            }
        
        # Analyze hypothesis distribution
        top_conf = hypotheses[0]["confidence"] if hypotheses else 0
        avg_conf = np.mean([h["confidence"] for h in hypotheses[:5]])
        conf_spread = top_conf - (hypotheses[-1]["confidence"] if hypotheses else 0)
        
        # Count high-confidence hypotheses
        high_conf_count = sum(1 for h in hypotheses if h["confidence"] >= 0.6)
        medium_conf_count = sum(1 for h in hypotheses if 0.4 <= h["confidence"] < 0.6)
        
        # WAF impact
        waf_present = constraints.get("waf_detected", False)
        
        # Determine strategy
        if top_conf >= 0.8 and high_conf_count >= 2:
            strategy = "focused"
            exploration_ratio = 0.1
            mutation = "high"
            reasoning = f"High confidence ({top_conf:.2f}) with {high_conf_count} strong hypotheses"
            
        elif top_conf >= 0.6 and high_conf_count >= 1:
            if waf_present:
                strategy = "focused_bypass"
                exploration_ratio = 0.2
                mutation = "high"
                reasoning = f"Good confidence ({top_conf:.2f}) but WAF present — focus on bypass"
            else:
                strategy = "targeted"
                exploration_ratio = 0.3
                mutation = "medium"
                reasoning = f"Good confidence ({top_conf:.2f}) — targeted variation"
                
        elif top_conf >= 0.4:
            strategy = "balanced"
            exploration_ratio = 0.5
            mutation = "medium"
            reasoning = f"Moderate confidence ({top_conf:.2f}) — balanced exploration/exploitation"
            
        else:
            strategy = "exploratory"
            exploration_ratio = 0.8
            mutation = "low"
            reasoning = f"Low confidence ({top_conf:.2f}) — broad exploration needed"
        
        # Adjust for timing anomaly
        if behavioral_ctx.get("timing_anomaly_detected"):
            reasoning += " + timing anomaly detected → include time-based techniques"
        
        # Technology-aware adjustments
        stack = tech_ctx.get("detected_stack")
        if stack:
            reasoning += f" + stack: {stack['name']}"
        
        # Candidate count based on strategy
        count_map = {
            "focused": 150,
            "focused_bypass": 200,
            "targeted": 100,
            "balanced": 75,
            "exploratory": 50,
        }
        
        diversity_map = {
            "focused": 0.20,
            "focused_bypass": 0.30,
            "targeted": 0.35,
            "balanced": 0.50,
            "exploratory": 0.70,
        }
        
        return {
            "recommended_strategy": strategy,
            "exploration_ratio": exploration_ratio,
            "mutation_strength": mutation,
            "candidate_count": count_map.get(strategy, 75),
            "diversity": diversity_map.get(strategy, 0.5),
            "reasoning": reasoning,
            "top_hypothesis_confidence": round(top_conf, 2),
            "avg_hypothesis_confidence": round(float(avg_conf), 2),
            "high_confidence_count": high_conf_count,
            "waf_impact": waf_present,
        }
    
    @staticmethod
    def print_summary(ctx: Dict):
        strategy = ctx.get("recommended_strategy", "N/A")
        color = C.R if "focused" in strategy else C.Y if "targeted" in strategy else C.G
        print(f"    Strategy:        {color}{C.BO}{strategy}{C.RS}")
        print(f"    Exploration:     {ctx.get('exploration_ratio', 0):.0%}")
        print(f"    Mutation:        {ctx.get('mutation_strength', 'N/A')}")
        print(f"    Candidates:      {ctx.get('candidate_count', 0)}")
        print(f"    Diversity:       {ctx.get('diversity', 0):.2f}")
        print(f"    {C.D}Reasoning: {ctx.get('reasoning', 'N/A')}{C.RS}")


# ============================================================
# MODULE 9: EVIDENCE LOG
# ============================================================
class EvidenceLog:
    """
    Module 9: Explainable AI — log WHY the model is confident.
    """
    
    @staticmethod
    def build(findings: List[Dict], feature_ctx: Dict, hypotheses: List[Dict],
              tech_ctx: Dict, behavioral_ctx: Dict) -> List[Dict]:
        """Build evidence trail for each hypothesis."""
        evidence_log = []
        
        features_per_finding = feature_ctx.get("per_finding", [])
        
        for feat_entry in features_per_finding:
            finding = feat_entry["finding_ref"]
            features = feat_entry["features"]
            vtype = finding.get("vuln_type", "other")
            
            evidence_items = []
            
            # 1. Direct evidence from scan
            raw_evidence = finding.get("evidence", "")
            if raw_evidence:
                evidence_items.append({
                    "type": "scan_evidence",
                    "description": raw_evidence[:200],
                    "weight": 0.30,
                    "source": finding.get("source", "unknown"),
                })
            
            # 2. Technology correlation
            all_techs = tech_ctx.get("all_detected", [])
            for tech in all_techs:
                prob = TechnologyContext.get_tech_vuln_prob(tech.get("name", ""), vtype)
                if prob > 0.3:
                    evidence_items.append({
                        "type": "technology_correlation",
                        "description": f"{tech['name']} has {prob:.0%} correlation with {vtype}",
                        "weight": prob * 0.20,
                        "source": "knowledge_base",
                    })
            
            # 3. Timing anomaly
            timing_diff = features.get("timing_difference", 0)
            if timing_diff > 2.0:
                evidence_items.append({
                    "type": "timing_anomaly",
                    "description": f"Response delayed by {timing_diff:.1f}s (baseline: {behavioral_ctx.get('baseline', {}).get('time_ms', 0)}ms)",
                    "weight": min(timing_diff / 10.0, 0.25),
                    "source": "behavioral_analysis",
                })
            
            # 4. Reflected input
            if features.get("reflected_input"):
                evidence_items.append({
                    "type": "reflected_input",
                    "description": f"Parameter '{finding.get('parameter', '')}' reflected in response",
                    "weight": 0.20,
                    "source": "response_analysis",
                })
            
            # 5. Error pattern
            error_info = features.get("error_pattern", {})
            if error_info.get("detected"):
                patterns = error_info.get("patterns", {})
                pattern_names = list(patterns.keys())
                evidence_items.append({
                    "type": "error_pattern",
                    "description": f"Error patterns detected: {', '.join(pattern_names)}",
                    "weight": 0.20,
                    "source": "response_analysis",
                })
            
            # 6. Parameter hints
            param_hints = features.get("param_vuln_hints", {})
            if param_hints.get(vtype, 0) > 0.2:
                evidence_items.append({
                    "type": "parameter_hint",
                    "description": f"Parameter '{finding.get('parameter', '')}' commonly vulnerable to {vtype} ({param_hints[vtype]:.0%})",
                    "weight": param_hints[vtype] * 0.15,
                    "source": "knowledge_base",
                })
            
            # 7. Form context
            form_type = features.get("form_type", "generic")
            if form_type != "generic":
                evidence_items.append({
                    "type": "form_context",
                    "description": f"Form classified as '{form_type}' — prioritizes {vtype}",
                    "weight": 0.10,
                    "source": "context_analysis",
                })
            
            # 8. Payload characteristics
            payload_feat = features.get("payload_features", {})
            if payload_feat.get("has_quotes") and vtype == "sqli":
                evidence_items.append({
                    "type": "payload_analysis",
                    "description": "Payload contains SQL-relevant quote characters",
                    "weight": 0.10,
                    "source": "payload_analysis",
                })
            if payload_feat.get("has_path_traversal") and vtype == "lfi":
                evidence_items.append({
                    "type": "payload_analysis",
                    "description": "Payload contains path traversal sequences",
                    "weight": 0.15,
                    "source": "payload_analysis",
                })
            
            # 9. Stack detection
            stack = tech_ctx.get("detected_stack")
            if stack and vtype in stack.get("boost", {}):
                boost = stack["boost"][vtype]
                if boost > 0:
                    evidence_items.append({
                        "type": "stack_profile",
                        "description": f"Stack '{stack['name']}' boosts {vtype} probability by +{boost:.2f}",
                        "weight": boost * 0.15,
                        "source": "knowledge_base",
                    })
            
            # 10. WAF impact
            if tech_ctx.get("waf_detected"):
                evidence_items.append({
                    "type": "waf_impact",
                    "description": f"WAF detected ({tech_ctx.get('waf', 'unknown')}) — may reduce exploitation probability",
                    "weight": -0.10,
                    "source": "waf_analysis",
                })
            
            # Sort by weight
            evidence_items.sort(key=lambda x: abs(x["weight"]), reverse=True)
            
            evidence_log.append({
                "finding_vuln_type": vtype,
                "finding_parameter": finding.get("parameter", ""),
                "finding_url": finding.get("url", ""),
                "evidence_count": len(evidence_items),
                "total_weight": round(sum(e["weight"] for e in evidence_items), 3),
                "evidence": evidence_items,
            })
        
        return evidence_log
    
    @staticmethod
    def print_summary(evidence_log: List[Dict]):
        total_evidence = sum(e["evidence_count"] for e in evidence_log)
        print(f"    Total Evidence Items: {total_evidence}")
        print(f"    Findings with Evidence: {len(evidence_log)}")
        
        if evidence_log:
            print(f"\n    Top Evidence Chains:")
            for entry in evidence_log[:3]:
                print(f"\n      [{entry['finding_vuln_type']}] param={entry['finding_parameter']}")
                for ev in entry["evidence"][:4]:
                    weight = ev["weight"]
                    color = C.G if weight > 0 else C.R
                    sign = "+" if weight > 0 else ""
                    print(f"        {color}{sign}{weight:.2f}{C.RS} [{ev['type']}] {ev['description'][:60]}")


# ============================================================
# MODULE 10: FEEDBACK ENGINE
# ============================================================
class FeedbackEngine:
    """
    Module 10: Learn from test results.
    Tracks tested, interesting, confirmed, false positives.
    """
    
    def __init__(self, feedback_file="./indigo_results/feedback_history.json"):
        self.feedback_file = feedback_file
        self.history = self._load_history()
    
    def _load_history(self):
        """Load feedback history from file."""
        if os.path.exists(self.feedback_file):
            try:
                with open(self.feedback_file, 'r') as f:
                    return json.load(f)
            except:
                pass
        return {
            "sessions": [],
            "aggregate": {
                "total_tested": 0,
                "total_interesting": 0,
                "total_confirmed": 0,
                "total_false_positive": 0,
                "avg_hit_rate": 0.0,
            },
        }
    
    def _save_history(self):
        """Save feedback history."""
        os.makedirs(os.path.dirname(self.feedback_file), exist_ok=True)
        with open(self.feedback_file, 'w') as f:
            json.dump(self.history, f, indent=2)
    
    def record_session(self, session_data: Dict):
        """Record a feedback session."""
        self.history["sessions"].append(session_data)
        
        # Update aggregates
        agg = self.history["aggregate"]
        agg["total_tested"] += session_data.get("tested", 0)
        agg["total_interesting"] += session_data.get("interesting", 0)
        agg["total_confirmed"] += session_data.get("confirmed", 0)
        agg["total_false_positive"] += session_data.get("false_positive", 0)
        
        if agg["total_tested"] > 0:
            agg["avg_hit_rate"] = (agg["total_confirmed"] + agg["total_interesting"]) / agg["total_tested"]
        
        self._save_history()
    
    def get_feedback_summary(self) -> Dict:
        """Get current feedback summary."""
        agg = self.history["aggregate"]
        return {
            "tested": agg["total_tested"],
            "interesting": agg["total_interesting"],
            "confirmed": agg["total_confirmed"],
            "false_positive": agg["total_false_positive"],
            "hit_rate": round(agg["avg_hit_rate"], 3),
            "sessions_count": len(self.history["sessions"]),
            "last_session": self.history["sessions"][-1] if self.history["sessions"] else None,
        }
    
    def get_learning_adjustments(self) -> Dict:
        """Get adjustments based on historical feedback."""
        agg = self.history["aggregate"]
        
        adjustments = {
            "confidence_modifier": 0.0,
            "strategy_modifier": None,
            "technique_preferences": {},
        }
        
        if agg["total_tested"] < 10:
            return adjustments  # Not enough data
        
        hit_rate = agg["avg_hit_rate"]
        
        # Adjust confidence based on historical accuracy
        if hit_rate > 0.5:
            adjustments["confidence_modifier"] = 0.05  # Slightly boost confidence
        elif hit_rate < 0.2:
            adjustments["confidence_modifier"] = -0.10  # Reduce confidence
        
        # Analyze which techniques worked best
        technique_stats = defaultdict(lambda: {"tested": 0, "success": 0})
        for session in self.history["sessions"]:
            for tech_result in session.get("technique_results", []):
                tech = tech_result.get("technique", "unknown")
                technique_stats[tech]["tested"] += 1
                if tech_result.get("success", False):
                    technique_stats[tech]["success"] += 1
        
        for tech, stats in technique_stats.items():
            if stats["tested"] >= 5:
                success_rate = stats["success"] / stats["tested"]
                adjustments["technique_preferences"][tech] = round(success_rate, 3)
        
        return adjustments
    
    @staticmethod
    def print_summary(ctx: Dict):
        print(f"    Tested:           {ctx.get('tested', 0)}")
        print(f"    Interesting:      {ctx.get('interesting', 0)}")
        print(f"    Confirmed:        {ctx.get('confirmed', 0)}")
        print(f"    False Positives:  {ctx.get('false_positive', 0)}")
        print(f"    Hit Rate:         {ctx.get('hit_rate', 0):.1%}")
        print(f"    Sessions:         {ctx.get('sessions_count', 0)}")


# ============================================================
# MODULE 11: GENERATOR DIRECTIVES
# ============================================================
class GeneratorDirectives:
    """
    Module 11: Build structured directives for Generator ML (File 2).
    This is the final output that tells the Generator what to do.
    """
    
    @staticmethod
    def build(target_ctx: Dict, tech_ctx: Dict, behavioral_ctx: Dict,
              surface_ctx: Dict, feature_ctx: Dict, hypotheses: List[Dict],
              constraints: Dict, strategy: Dict, evidence_log: List[Dict],
              feedback: Dict) -> List[Dict]:
        """Build generator directives from all modules."""
        
        tasks = []
        features_per_finding = feature_ctx.get("per_finding", [])
        
        # Map evidence to findings
        evidence_map = {}
        for ev in evidence_log:
            key = f"{ev['finding_vuln_type']}_{ev['finding_parameter']}"
            evidence_map[key] = ev
        
        for i, feat_entry in enumerate(features_per_finding, 1):
            finding = feat_entry["finding_ref"]
            features = feat_entry["features"]
            vtype = finding.get("vuln_type", "other")
            param = finding.get("parameter", "")
            
            # Get hypotheses for this finding
            finding_hypotheses = [
                h for h in hypotheses
                if h["family"] == vtype or any(
                    h["reasoning"].find(vtype) >= 0 for _ in [1]
                )
            ][:5]
            
            # If no matching hypotheses, create a default one
            if not finding_hypotheses:
                finding_hypotheses = [{
                    "family": vtype,
                    "technique": "generic",
                    "confidence": float(finding.get("confidence", 0.5)),
                    "reasoning": "Default hypothesis from scan finding",
                }]
            
            # Get evidence for this finding
            ev_key = f"{vtype}_{param}"
            ev_entry = evidence_map.get(ev_key, {})
            evidence_items = [e["description"] for e in ev_entry.get("evidence", [])[:6]]
            
            # Determine priority
            top_conf = finding_hypotheses[0]["confidence"] if finding_hypotheses else 0.5
            if top_conf >= 0.8:
                priority = "critical"
            elif top_conf >= 0.6:
                priority = "high"
            elif top_conf >= 0.4:
                priority = "medium"
            else:
                priority = "low"
            
            # Determine technique family
            technique_family = finding_hypotheses[0].get("technique", "generic") if finding_hypotheses else "generic"
            
            # Focus techniques
            focus_techniques = list(set(
                h.get("technique", "generic") for h in finding_hypotheses[:3]
            ))
            
            # Add form-context technique priorities
            form_tech_priority = features.get("form_technique_priority", {})
            if vtype in form_tech_priority:
                focus_techniques = form_tech_priority[vtype] + focus_techniques
                focus_techniques = list(dict.fromkeys(focus_techniques))  # Dedupe, preserve order
            
            # Build task
            task = {
                "task_id": f"scan-{datetime.now().strftime('%Y%m%d')}-{i:03d}",
                
                # Module 1: Target
                "target": {
                    "host": target_ctx["host"],
                    "port": target_ctx["port"],
                    "scheme": target_ctx["scheme"],
                    "method": finding.get("method", target_ctx["method"]),
                    "endpoint": finding.get("url", target_ctx["endpoint"]),
                    "parameter": param,
                    "parameters": target_ctx["parameters"],
                },
                
                # Module 2: Technology
                "technology": {
                    "server": tech_ctx.get("server"),
                    "backend": tech_ctx.get("backend"),
                    "framework": tech_ctx.get("framework"),
                    "database": tech_ctx.get("database"),
                    "cdn": tech_ctx.get("cdn"),
                    "waf": tech_ctx.get("waf"),
                    "javascript_framework": tech_ctx.get("javascript_framework"),
                    "cms": tech_ctx.get("cms"),
                },
                
                # Module 3: Behavioral
                "behavioral": {
                    "baseline_status": behavioral_ctx.get("baseline", {}).get("status", 200),
                    "baseline_time_ms": behavioral_ctx.get("baseline", {}).get("time_ms", 0),
                    "baseline_length": behavioral_ctx.get("baseline", {}).get("length", 0),
                    "timing_anomaly": behavioral_ctx.get("timing_anomaly_detected", False),
                    "error_handling": behavioral_ctx.get("error_handling", "unknown"),
                },
                
                # Module 6: Hypotheses
                "hypotheses": finding_hypotheses,
                
                # Module 7: Constraints
                "constraints": {
                    "max_input_length": constraints["max_input_length"],
                    "encoding_candidates": constraints["encoding_candidates"],
                    "case_variation": constraints["case_variation"],
                    "allowed_methods": constraints["allowed_methods"],
                    "waf_detected": constraints["waf_detected"],
                    "bypass_techniques": constraints.get("bypass_techniques", []),
                    "timeout_seconds": constraints["timeout_seconds"],
                },
                
                # Module 8: Strategy
                "strategy": {
                    "recommended_strategy": strategy["recommended_strategy"],
                    "exploration_ratio": strategy["exploration_ratio"],
                    "mutation_strength": strategy["mutation_strength"],
                },
                
                # Module 9: Evidence
                "evidence": evidence_items,
                
                # Module 11: Generator-specific
                "generator_request": {
                    "priority": priority,
                    "candidate_count": strategy.get("candidate_count", 75),
                    "vulnerability_family": vtype,
                    "technique_family": technique_family,
                    "focus_techniques": focus_techniques,
                    "diversity": strategy.get("diversity", 0.5),
                    "families_to_test": list(set(h["family"] for h in finding_hypotheses)),
                },
                
                # Module 12: Metadata
                "metadata": {
                    "model_version": "knowledge-v3.0",
                    "generated_at": datetime.now().isoformat(),
                    "confidence": round(top_conf, 2),
                    "source": "active_scan",
                    "analysis_module_count": 12,
                },
            }
            
            tasks.append(task)
        
        # Sort by priority (critical first)
        priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        tasks.sort(key=lambda t: (
            priority_order.get(t["generator_request"]["priority"], 4),
            -t["metadata"]["confidence"],
        ))
        
        return tasks
    
    @staticmethod
    def print_summary(tasks: List[Dict]):
        print(f"    Total Tasks: {len(tasks)}")
        
        # Count by priority
        prio_counts = Counter(t["generator_request"]["priority"] for t in tasks)
        print(f"    Critical: {C.R}{prio_counts.get('critical', 0)}{C.RS}  "
              f"High: {C.Y}{prio_counts.get('high', 0)}{C.RS}  "
              f"Medium: {C.CY}{prio_counts.get('medium', 0)}{C.RS}  "
              f"Low: {C.G}{prio_counts.get('low', 0)}{C.RS}")
        
        # Count by vuln family
        family_counts = Counter(t["generator_request"]["vulnerability_family"] for t in tasks)
        if family_counts:
            print(f"\n    Vulnerability Families:")
            for family, count in family_counts.most_common():
                print(f"      {family:<15} {count} tasks")
        
        # Top tasks
        if tasks:
            print(f"\n    Top 5 Tasks:")
            for task in tasks[:5]:
                conf = task["metadata"]["confidence"]
                color = C.R if conf >= 0.7 else C.Y if conf >= 0.4 else C.G
                prio = task["generator_request"]["priority"]
                vtype = task["generator_request"]["vulnerability_family"]
                param = task["target"]["parameter"]
                print(f"      {bar_chart(conf, 12, color)} {conf:.2f} [{prio}] "
                      f"{vtype} param={param}")


# ============================================================
# MODULE 12: LEARNING METADATA
# ============================================================
class LearningMetadata:
    """
    Module 12: Track model version, dataset, and learning progress.
    """
    
    def __init__(self, model_dir="./indigo_models"):
        self.model_dir = model_dir
        self.version = "knowledge-v3.0"
        self.dataset_id = f"dataset-{datetime.now().strftime('%Y%m')}"
    
    def build(self, scan_results: Dict, tasks: List[Dict],
              feedback: Dict, ml_accuracy: float = 0.0) -> Dict:
        """Build learning metadata."""
        
        # Compute overall confidence
        if tasks:
            avg_conf = np.mean([t["metadata"]["confidence"] for t in tasks])
            max_conf = max(t["metadata"]["confidence"] for t in tasks)
        else:
            avg_conf = 0.0
            max_conf = 0.0
        
        # Feature sources
        feature_sources = [
            "active_scan",
            "technology_detection",
            "behavioral_analysis",
            "knowledge_base",
            "ml_models",
        ]
        
        if feedback.get("sessions_count", 0) > 0:
            feature_sources.append("feedback_loop")
        
        return {
            "model_version": self.version,
            "dataset_id": self.dataset_id,
            "model_accuracy": round(ml_accuracy, 3),
            "overall_confidence": round(float(avg_conf), 3),
            "max_confidence": round(float(max_conf), 3),
            "source": "active_scan",
            "feature_sources": feature_sources,
            "knowledge_base_entries": {
                "tech_vuln_matrix": len(TechnologyContext.TECH_VULN_MATRIX),
                "waf_profiles": len(TechnologyContext.WAF_PROFILES),
                "param_hints": len(FeatureExtraction.PARAM_VULN_HINTS),
                "form_patterns": len(FeatureExtraction.FORM_PATTERNS),
                "payload_effectiveness": len(HypothesisEngine.PAYLOAD_EFFECTIVENESS),
                "stack_profiles": len(TechnologyContext.STACK_PROFILES),
            },
            "ml_models_trained": 5,  # RF, GB, NB, SVM, NN
            "training_samples": 3000,
            "feedback_sessions": feedback.get("sessions_count", 0),
            "feedback_hit_rate": feedback.get("hit_rate", 0.0),
            "generated_at": datetime.now().isoformat(),
        }
    
    @staticmethod
    def print_summary(ctx: Dict):
        print(f"    Model Version:     {ctx.get('model_version', 'N/A')}")
        print(f"    Dataset:           {ctx.get('dataset_id', 'N/A')}")
        print(f"    Model Accuracy:    {ctx.get('model_accuracy', 0):.1%}")
        print(f"    Overall Conf:      {ctx.get('overall_confidence', 0):.3f}")
        print(f"    KB Entries:        {sum(ctx.get('knowledge_base_entries', {}).values())}")
        print(f"    ML Models:         {ctx.get('ml_models_trained', 0)}")
        print(f"    Feedback Sessions: {ctx.get('feedback_sessions', 0)}")


# ============================================================
# ML PROBABILITY ANALYZER (Core ML Engine)
# ============================================================
class MLProbabilityAnalyzer:
    """
    Core ML engine for probability prediction.
    Ensemble of 5 classifiers.
    """
    
    def __init__(self, model_dir="./indigo_models"):
        self.model_dir = model_dir
        self.models = {}
        self.scaler = None
        self.trained = False
        self.accuracy = 0.0
    
    def _build_feature_vector(self, finding, features, tech_ctx, behavioral_ctx):
        """Build numerical feature vector."""
        vec = []
        
        # Vuln type one-hot (11 features)
        vuln_types = ["sqli", "xss", "lfi", "rce", "ssti", "ssrf", "xxe",
                       "csrf", "nosqli", "deserialization", "other"]
        vtype = finding.get("vuln_type", "other")
        vec.extend([1.0 if v == vtype else 0.0 for v in vuln_types])
        
        # Severity
        sev_map = {"Critical": 1.0, "High": 0.75, "Medium": 0.5, "Low": 0.25, "Info": 0.1}
        vec.append(sev_map.get(finding.get("severity", "Medium"), 0.5))
        
        # Confidence
        vec.append(float(finding.get("confidence", 0.5)))
        
        # Tech correlation
        vec.append(features.get("tech_correlation", 0.0))
        
        # Evidence strength
        vec.append(features.get("evidence_strength", 0.2))
        
        # Timing difference
        vec.append(min(features.get("timing_difference", 0.0) / 10.0, 1.0))
        
        # Response similarity
        vec.append(features.get("response_similarity", 0.5))
        
        # Reflected input
        vec.append(1.0 if features.get("reflected_input") else 0.0)
        
        # Error pattern
        vec.append(1.0 if features.get("error_pattern", {}).get("detected") else 0.0)
        
        # WAF
        vec.append(1.0 if tech_ctx.get("waf_detected") else 0.0)
        
        # Method
        vec.append(1.0 if finding.get("method", "GET") == "POST" else 0.0)
        
        # Payload features
        pf = features.get("payload_features", {})
        vec.append(min(pf.get("length", 0) / 100.0, 1.0))
        vec.append(1.0 if pf.get("has_quotes") else 0.0)
        vec.append(1.0 if pf.get("has_sql_comments") else 0.0)
        vec.append(1.0 if pf.get("has_html_tags") else 0.0)
        vec.append(1.0 if pf.get("has_path_traversal") else 0.0)
        vec.append(1.0 if pf.get("has_template_expr") else 0.0)
        vec.append(1.0 if pf.get("has_command_sep") else 0.0)
        
        # URL features
        uf = features.get("url_features", {})
        vec.append(1.0 if uf.get("has_query_params") else 0.0)
        vec.append(1.0 if uf.get("is_php") else 0.0)
        vec.append(1.0 if uf.get("is_asp") else 0.0)
        vec.append(min(uf.get("path_depth", 0) / 5.0, 1.0))
        
        # Form context
        form_priority = features.get("form_vuln_priority", [])
        form_score = 0.0
        if vtype in form_priority:
            idx = form_priority.index(vtype)
            form_score = 1.0 - idx * 0.25
        vec.append(form_score)
        
        # Param hints
        param_hints = features.get("param_vuln_hints", {})
        vec.append(param_hints.get(vtype, 0.05))
        
        return np.array(vec, dtype=np.float64)
    
    def _generate_training_data(self, n=3000):
        """Generate synthetic training data."""
        X, y = [], []
        vuln_types = ["sqli", "xss", "lfi", "rce", "ssti", "ssrf", "xxe", "other"]
        techs = list(TechnologyContext.TECH_VULN_MATRIX.keys())
        params = list(FeatureExtraction.PARAM_VULN_HINTS.keys())
        
        np.random.seed(42)
        
        for _ in range(n):
            vtype = np.random.choice(vuln_types)
            tech = np.random.choice(techs)
            param = np.random.choice(params)
            waf = np.random.random() < 0.3
            
            finding = {
                "vuln_type": vtype,
                "severity": np.random.choice(["Critical", "High", "Medium", "Low"]),
                "confidence": np.random.uniform(0.3, 0.9),
                "parameter": param,
                "method": np.random.choice(["GET", "POST"]),
                "evidence": np.random.choice([
                    "Response delayed 5s", "SQL syntax error",
                    "Payload reflected", "File content found",
                    "Template evaluated", "", "",
                ]),
                "payload": np.random.choice([
                    "' OR SLEEP(5)--", "<script>alert(1)</script>",
                    "../../../etc/passwd", "{{7*7}}", "; sleep 5", "", "",
                ]),
                "url": np.random.choice([
                    "http://target/page.php?id=1",
                    "http://target/search?q=test",
                    "http://target/login",
                ]),
            }
            
            # Build features (simplified for training)
            tech_prob = TechnologyContext.get_tech_vuln_prob(tech, vtype)
            param_hints = FeatureExtraction.get_param_hints(param)
            param_prob = param_hints.get(vtype, 0.05)
            
            evidence = finding["evidence"].lower()
            ev_strength = 0.2
            if "delay" in evidence:
                ev_strength = 0.9
            elif "error" in evidence:
                ev_strength = 0.8
            elif "reflect" in evidence:
                ev_strength = 0.7
            
            features = {
                "tech_correlation": tech_prob,
                "evidence_strength": ev_strength,
                "timing_difference": 5.0 if "delay" in evidence else 0.0,
                "response_similarity": np.random.uniform(0.3, 0.9),
                "reflected_input": "reflect" in evidence,
                "error_pattern": {"detected": "error" in evidence},
                "payload_features": {
                    "length": len(finding["payload"]),
                    "has_quotes": "'" in finding["payload"],
                    "has_sql_comments": "--" in finding["payload"],
                    "has_html_tags": "<" in finding["payload"],
                    "has_path_traversal": ".." in finding["payload"],
                    "has_template_expr": "{{" in finding["payload"],
                    "has_command_sep": ";" in finding["payload"],
                },
                "url_features": {
                    "has_query_params": "?" in finding["url"],
                    "is_php": ".php" in finding["url"],
                    "is_asp": ".asp" in finding["url"],
                    "path_depth": 2,
                },
                "form_vuln_priority": ["sqli", "xss"],
                "param_vuln_hints": param_hints,
            }
            
            tech_ctx = {"waf_detected": waf}
            behavioral_ctx = {"baseline": {"time_ms": 150}}
            
            vec = self._build_feature_vector(finding, features, tech_ctx, behavioral_ctx)
            X.append(vec)
            
            # Label
            combined = tech_prob * 0.4 + float(finding["confidence"]) * 0.3 + ev_strength * 0.3
            if waf:
                combined *= 0.7
            label = 1 if (combined + np.random.normal(0, 0.08)) > 0.5 else 0
            y.append(label)
        
        return np.array(X), np.array(y)
    
    def train(self):
        """Train ML models."""
        print(f"  {C.CY}Training ML ensemble...{C.RS}")
        
        X, y = self._generate_training_data(3000)
        
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)
        
        models = {
            "random_forest": RandomForestClassifier(n_estimators=200, max_depth=15, random_state=42, class_weight="balanced"),
            "gradient_boost": GradientBoostingClassifier(n_estimators=150, max_depth=8, learning_rate=0.1, random_state=42),
            "naive_bayes": GaussianNB(),
            "svm": SVC(probability=True, kernel="rbf", C=1.0, random_state=42),
            "neural_net": MLPClassifier(hidden_layer_sizes=(128, 64, 32), max_iter=500, random_state=42, early_stopping=True),
        }
        
        results = {}
        for name, model in models.items():
            model.fit(X_scaled, y)
            cv = cross_val_score(model, X_scaled, y, cv=5, scoring="accuracy")
            results[name] = cv.mean()
            self.models[name] = model
            print(f"    {name:<20} {bar_chart(cv.mean(), 15, C.G)} {cv.mean():.3f} ±{cv.std():.3f}")
        
        self.accuracy = max(results.values())
        self.trained = True
        
        return results
    
    def predict(self, finding, features, tech_ctx, behavioral_ctx):
        """Predict exploitation probability."""
        if not self.trained:
            self.train()
        
        vec = self._build_feature_vector(finding, features, tech_ctx, behavioral_ctx)
        vec_scaled = self.scaler.transform(vec.reshape(1, -1))
        
        probs = []
        weights = {"random_forest": 1.2, "gradient_boost": 1.3, "naive_bayes": 0.8, "svm": 1.0, "neural_net": 1.1}
        
        for name, model in self.models.items():
            try:
                prob = model.predict_proba(vec_scaled)[0]
                probs.append((prob[1] if len(prob) > 1 else prob[0], weights.get(name, 1.0)))
            except:
                continue
        
        if not probs:
            return 0.5
        
        total_w = sum(w for _, w in probs)
        weighted = sum(p * w for p, w in probs) / total_w
        
        return float(np.clip(weighted, 0.0, 1.0))


# ============================================================
# COLLECTOR (Pre-processor)
# ============================================================
class Collector:
    """
    Collects and normalizes all data from scan results.
    First step in the pipeline.
    """
    
    @staticmethod
    def collect(scan_results: Dict) -> Dict:
        """Collect and normalize scan data."""
        # Ensure all expected keys exist
        defaults = {
            "findings_for_ml": [],
            "vulnerabilities": [],
            "technologies": [],
            "forms": [],
            "waf_info": {},
            "scan_metadata": {},
            "response_headers": {},
            "crawled_urls": [],
            "tls_info": {},
        }
        
        collected = {}
        for key, default in defaults.items():
            collected[key] = scan_results.get(key, default)
        
        # Also merge non-ML vulnerabilities into findings_for_ml if needed
        findings = list(collected["findings_for_ml"])
        existing_keys = set(
            f"{f.get('vuln_type', '')}_{f.get('parameter', '')}_{f.get('url', '')}"
            for f in findings
        )
        
        for vuln in collected["vulnerabilities"]:
            vt = vuln.get("type", vuln.get("vuln_type", "other"))
            if vt in ["sqli", "xss", "lfi", "rce", "ssti", "ssrf", "xxe", "nosqli"]:
                key = f"{vt}_{vuln.get('parameter', '')}_{vuln.get('url', '')}"
                if key not in existing_keys:
                    findings.append({
                        "vuln_type": vt,
                        "name": vuln.get("name", ""),
                        "severity": vuln.get("severity", "Medium"),
                        "url": vuln.get("url", ""),
                        "parameter": vuln.get("parameter", ""),
                        "method": vuln.get("method", "GET"),
                        "evidence": vuln.get("evidence", ""),
                        "payload": vuln.get("payload", ""),
                        "confidence": vuln.get("confidence", 0.5),
                        "source": vuln.get("source", "passive"),
                    })
                    existing_keys.add(key)
        
        collected["findings_for_ml"] = findings
        
        return collected


# ============================================================
# MAIN KNOWLEDGE MASTER (Orchestrator)
# ============================================================
class MLKnowledgeMaster:
    """
    Main orchestrator — runs all 12 modules in sequence.
    """
    
    def __init__(self, model_dir="./indigo_models"):
        self.model_dir = model_dir
        self.ml_analyzer = MLProbabilityAnalyzer(model_dir)
        self.feedback_engine = FeedbackEngine()
        os.makedirs(model_dir, exist_ok=True)
    
    def analyze(self, scan_results: Dict) -> Dict:
        """
        Full analysis pipeline — all 12 modules.
        
        Args:
            scan_results: Output from File 1 scanner
            
        Returns:
            Complete analysis output with all module results
        """
        banner("INDIGO ML KNOWLEDGE MASTER v3.0", C.M)
        start_time = time.time()
        
        # ============================
        # COLLECTOR
        # ============================
        section("Collector — Normalizing Scan Data", C.B)
        collected = Collector.collect(scan_results)
        findings = collected["findings_for_ml"]
        
        print(f"    Findings collected: {len(findings)}")
        print(f"    Technologies: {len(collected['technologies'])}")
        print(f"    Forms: {len(collected['forms'])}")
        
        if not findings:
            print(f"\n    {C.Y}No findings to analyze.{C.RS}")
            return self._empty_output(collected["scan_metadata"].get("target_url", ""))
        
        # ============================
        # TRAIN ML MODELS
        # ============================
        section("ML Model Training", C.B)
        ml_results = self.ml_analyzer.train()
        
        # ============================
        # MODULE 1: TARGET CONTEXT
        # ============================
        section("Module 1: Target Context", C.CY)
        target_ctx = TargetContext.extract(collected)
        TargetContext.print_summary(target_ctx)
        
        # ============================
        # MODULE 2: TECHNOLOGY CONTEXT
        # ============================
        section("Module 2: Technology Context", C.CY)
        tech_ctx = TechnologyContext.extract(collected)
        TechnologyContext.print_summary(tech_ctx)
        
        # ============================
        # MODULE 3: BEHAVIORAL CONTEXT
        # ============================
        section("Module 3: Behavioral Context", C.CY)
        behavioral_ctx = BehavioralContext.extract(collected)
        BehavioralContext.print_summary(behavioral_ctx)
        
        # ============================
        # MODULE 4: SURFACE MAPPING
        # ============================
        section("Module 4: Surface Mapping", C.CY)
        surface_ctx = SurfaceMapping.extract(collected)
        SurfaceMapping.print_summary(surface_ctx)
        
        # ============================
        # MODULE 5: FEATURE EXTRACTION
        # ============================
        section("Module 5: Feature Extraction", C.CY)
        feature_ctx = FeatureExtraction.extract(collected, tech_ctx, behavioral_ctx)
        FeatureExtraction.print_summary(feature_ctx)
        
        # ============================
        # ML PROBABILITY (per finding)
        # ============================
        section("ML Probability Analysis", C.B)
        features_per_finding = feature_ctx.get("per_finding", [])
        
        for feat_entry in features_per_finding:
            finding = feat_entry["finding_ref"]
            features = feat_entry["features"]
            
            ml_prob = self.ml_analyzer.predict(finding, features, tech_ctx, behavioral_ctx)
            feat_entry["ml_probability"] = ml_prob
            
            # Combined probability
            tech_prob = features.get("tech_correlation", 0)
            param_hints = features.get("param_vuln_hints", {})
            param_prob = param_hints.get(finding.get("vuln_type", ""), 0.05)
            evidence_str = features.get("evidence_strength", 0.2)
            
            combined = (
                ml_prob * 0.35 +
                tech_prob * 0.20 +
                param_prob * 0.15 +
                evidence_str * 0.20 +
                float(finding.get("confidence", 0.5)) * 0.10
            )
            
            if tech_ctx.get("waf_detected"):
                combined *= 0.85
            
            feat_entry["combined_probability"] = float(np.clip(combined, 0.0, 1.0))
        
        # Print ML results
        print(f"    ML Probability Results:")
        for feat_entry in features_per_finding[:10]:
            finding = feat_entry["finding_ref"]
            ml_p = feat_entry.get("ml_probability", 0)
            comb_p = feat_entry.get("combined_probability", 0)
            print(f"      ML={ml_p:.2f} Combined={comb_p:.2f} "
                  f"[{finding.get('vuln_type')}] param={finding.get('parameter')}")
        
        # ============================
        # MODULE 6: HYPOTHESIS ENGINE
        # ============================
        section("Module 6: Hypothesis Engine", C.CY)
        hypotheses = HypothesisEngine.generate(
            findings, tech_ctx, feature_ctx, behavioral_ctx
        )
        HypothesisEngine.print_summary(hypotheses)
        
        # ============================
        # MODULE 7: CONSTRAINT ENGINE
        # ============================
        section("Module 7: Constraint Engine", C.CY)
        constraints = ConstraintEngine.compute(target_ctx, tech_ctx, behavioral_ctx, surface_ctx)
        ConstraintEngine.print_summary(constraints)
        
        # ============================
        # MODULE 8: STRATEGY RECOMMENDATION
        # ============================
        section("Module 8: Strategy Recommendation", C.CY)
        strategy = StrategyRecommendation.recommend(
            hypotheses, constraints, tech_ctx, behavioral_ctx
        )
        StrategyRecommendation.print_summary(strategy)
        
        # ============================
        # MODULE 9: EVIDENCE LOG
        # ============================
        section("Module 9: Evidence Log", C.CY)
        evidence_log = EvidenceLog.build(
            findings, feature_ctx, hypotheses, tech_ctx, behavioral_ctx
        )
        EvidenceLog.print_summary(evidence_log)
        
        # ============================
        # MODULE 10: FEEDBACK ENGINE
        # ============================
        section("Module 10: Feedback Engine", C.CY)
        feedback_summary = self.feedback_engine.get_feedback_summary()
        FeedbackEngine.print_summary(feedback_summary)
        
        learning_adj = self.feedback_engine.get_learning_adjustments()
        if learning_adj.get("confidence_modifier", 0) != 0:
            print(f"    Learning Adjustment: conf_modifier={learning_adj['confidence_modifier']:+.2f}")
        
        # ============================
        # MODULE 11: GENERATOR DIRECTIVES
        # ============================
        section("Module 11: Generator Directives", C.CY)
        tasks = GeneratorDirectives.build(
            target_ctx, tech_ctx, behavioral_ctx, surface_ctx,
            feature_ctx, hypotheses, constraints, strategy,
            evidence_log, feedback_summary
        )
        GeneratorDirectives.print_summary(tasks)
        
        # ============================
        # MODULE 12: LEARNING METADATA
        # ============================
        section("Module 12: Learning Metadata", C.CY)
        learning_meta = LearningMetadata(self.model_dir).build(
            collected, tasks, feedback_summary, self.ml_analyzer.accuracy
        )
        LearningMetadata.print_summary(learning_meta)
        
        # ============================
        # BUILD FINAL OUTPUT
        # ============================
        elapsed = (time.time() - start_time) * 1000
        
        output = {
            "scan_id": collected["scan_metadata"].get("scan_id",
                       f"scan-{datetime.now().strftime('%Y%m%d-%H%M%S')}"),
            "target_url": target_ctx.get("full_url", ""),
            
            # Module 1
            "target_context": target_ctx,
            
            # Module 2
            "technology_context": {
                "server": tech_ctx.get("server"),
                "backend": tech_ctx.get("backend"),
                "framework": tech_ctx.get("framework"),
                "database": tech_ctx.get("database"),
                "cdn": tech_ctx.get("cdn"),
                "waf": tech_ctx.get("waf"),
                "javascript_framework": tech_ctx.get("javascript_framework"),
                "cms": tech_ctx.get("cms"),
            },
            
            # Module 3
            "behavioral_context": {
                "baseline": behavioral_ctx.get("baseline"),
                "redirects": behavioral_ctx.get("redirects"),
                "compression": behavioral_ctx.get("compression"),
                "cache": behavioral_ctx.get("cache"),
            },
            
            # Module 4
            "surface_mapping": {
                "forms": surface_ctx.get("forms", []),
                "cookies": surface_ctx.get("cookies", []),
                "headers": surface_ctx.get("headers", []),
                "query_parameters": surface_ctx.get("query_parameters", []),
                "json_parameters": surface_ctx.get("json_parameters", []),
                "upload_points": surface_ctx.get("upload_points", []),
                "api_endpoints": surface_ctx.get("api_endpoints", []),
            },
            
            # Module 5
            "feature_extraction": {
                "aggregate": feature_ctx.get("aggregate", {}),
            },
            
            # Module 6
            "hypotheses": hypotheses,
            
            # Module 7
            "constraints": constraints,
            
            # Module 8
            "strategy": strategy,
            
            # Module 9
            "evidence": evidence_log,
            
            # Module 10
            "feedback": feedback_summary,
            
            # Module 12
            "learning_metadata": learning_meta,
            
            # Analysis summary
            "analysis_summary": {
                "total_findings": len(findings),
                "total_hypotheses": len(hypotheses),
                "total_tasks": len(tasks),
                "total_evidence_items": sum(e["evidence_count"] for e in evidence_log),
                "analysis_time_ms": round(elapsed, 2),
                "waf_present": tech_ctx.get("waf_detected", False),
                "technologies_detected": len(tech_ctx.get("all_detected", [])),
            },
            
            # Generator instructions
            "generator_instructions": {
                "respect_constraints": True,
                "apply_encoding_chain": tech_ctx.get("waf_detected", False),
                "prioritize_high_confidence": True,
                "stop_on_success": False,
                "max_requests_per_second": constraints.get("max_requests_per_second", 10),
            },
            
            # Module 11: Tasks (directives for Generator)
            "tasks": tasks,
        }
        
        # Print final summary
        self._print_final_summary(output)
        
        # Save
        self._save_output(output)
        
        return output
    
    def _print_final_summary(self, output):
        """Print final analysis summary."""
        banner("ANALYSIS COMPLETE — ALL 12 MODULES", C.G)
        
        summary = output["analysis_summary"]
        strategy = output["strategy"]
        
        print(f"  Target:           {output['target_url']}")
        print(f"  Findings:         {summary['total_findings']}")
        print(f"  Hypotheses:       {summary['total_hypotheses']}")
        print(f"  Tasks:            {summary['total_tasks']}")
        print(f"  Evidence Items:   {summary['total_evidence_items']}")
        print(f"  Strategy:         {C.BO}{strategy.get('recommended_strategy', 'N/A')}{C.RS}")
        print(f"  WAF Present:      {summary['waf_present']}")
        print(f"  Technologies:     {summary['technologies_detected']}")
        print(f"  Analysis Time:    {summary['analysis_time_ms']/1000:.1f}s")
        
        # Top tasks
        tasks = output.get("tasks", [])
        if tasks:
            print(f"\n  {C.BO}Top Tasks for Generator:{C.RS}")
            for task in tasks[:5]:
                conf = task["metadata"]["confidence"]
                color = C.R if conf >= 0.7 else C.Y if conf >= 0.4 else C.G
                prio = task["generator_request"]["priority"]
                vtype = task["generator_request"]["vulnerability_family"]
                param = task["target"]["parameter"]
                tech = task["generator_request"]["technique_family"]
                print(f"    {bar_chart(conf, 12, color)} {conf:.2f} [{C.BO}{prio}{C.RS}] "
                      f"{vtype} → {param} ({tech})")
        
        print(f"\n  {C.CY}→ Directives ready for Generator ML (File 2){C.RS}")
        print(f"  {C.D}  Will auto-feed without confirmation{C.RS}")
    
    def _save_output(self, output):
        """Save analysis output to JSON."""
        out_dir = "./indigo_results"
        os.makedirs(out_dir, exist_ok=True)
        
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        filepath = os.path.join(out_dir, f"ml_knowledge_{ts}.json")
        
        # Make serializable
        def make_serializable(obj):
            if isinstance(obj, (np.integer,)):
                return int(obj)
            elif isinstance(obj, (np.floating,)):
                return float(obj)
            elif isinstance(obj, np.ndarray):
                return obj.tolist()
            elif isinstance(obj, datetime):
                return obj.isoformat()
            return obj
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(output, f, indent=2, ensure_ascii=False, default=make_serializable)
        
        print(f"\n  {C.G}Output saved: {filepath}{C.RS}")
    
    def _empty_output(self, target_url):
        """Return empty output when no findings."""
        return {
            "scan_id": f"scan-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
            "target_url": target_url,
            "target_context": {},
            "technology_context": {},
            "behavioral_context": {},
            "surface_mapping": {},
            "feature_extraction": {},
            "hypotheses": [],
            "constraints": {},
            "strategy": {"recommended_strategy": "exploratory"},
            "evidence": [],
            "feedback": self.feedback_engine.get_feedback_summary(),
            "learning_metadata": {},
            "analysis_summary": {
                "total_findings": 0,
                "total_hypotheses": 0,
                "total_tasks": 0,
                "total_evidence_items": 0,
                "analysis_time_ms": 0,
            },
            "generator_instructions": {},
            "tasks": [],
        }
    
    def feed_to_generator(self, directives: Dict):
        """Feed directives to Generator ML (File 2)."""
        print(f"\n{C.CY}{'='*60}")
        print(f"  Feeding directives to Generator ML (File 2)...")
        print(f"{'='*60}{C.RS}\n")
        
        try:
            from indigo_generator import MLGenerator
            generator = MLGenerator()
            results = generator.process_directives(directives)
            return results
        except ImportError:
            print(f"  {C.Y}indigo_generator not found. Directives saved to file.{C.RS}")
            return None
        except Exception as e:
            print(f"  {C.R}Generator error: {e}{C.RS}")
            traceback.print_exc()
            return None
    
    def record_feedback(self, feedback_data: Dict):
        """Record feedback from Generator/Validator."""
        self.feedback_engine.record_session(feedback_data)


# ============================================================
# STANDALONE MODE
# ============================================================
def main():
    parser = argparse.ArgumentParser(
        description="Indigo ML Knowledge Master v3.0 — 12-Module Analyzer"
    )
    parser.add_argument("--scan-file", "-f", help="Scan results JSON file")
    parser.add_argument("--target", "-t", help="Target URL (run fresh scan)")
    parser.add_argument("--no-confirm", action="store_true")
    parser.add_argument("--feed-generator", action="store_true",
                       help="Auto-feed to Generator ML")
    args = parser.parse_args()
    
    master = MLKnowledgeMaster()
    scan_results = None
    
    if args.scan_file:
        print(f"\n  Loading: {args.scan_file}")
        with open(args.scan_file, 'r') as f:
            scan_results = json.load(f)
    
    elif args.target:
        print(f"\n  Scanning: {args.target}")
        try:
            from indigo_scr import run_full_scan
            scan_results = run_full_scan(args.target)
        except ImportError:
            print(f"  {C.R}indigo_scr not found.{C.RS}")
            sys.exit(1)
    
    else:
        results_dir = "./indigo_results"
        if os.path.exists(results_dir):
            files = sorted([f for f in os.listdir(results_dir)
                          if f.startswith("indigo_scan_") and f.endswith(".json")],
                         reverse=True)
            if files:
                latest = os.path.join(results_dir, files[0])
                print(f"\n  Found: {latest}")
                
                if not args.no_confirm:
                    if input(f"  Analyze? (Y/N): ").strip().upper() != "Y":
                        sys.exit(0)
                
                with open(latest, 'r') as f:
                    scan_results = json.load(f)
            else:
                print(f"  {C.Y}No scan files found.{C.RS}")
                sys.exit(1)
    
    if not scan_results:
        print(f"  {C.R}No scan results.{C.RS}")
        sys.exit(1)
    
    # Confirmation
    if not args.no_confirm:
        meta = scan_results.get("scan_metadata", {})
        print(f"\n  {C.BO}Scan loaded:{C.RS}")
        print(f"    Target: {meta.get('target_url', 'N/A')}")
        print(f"    Findings: {len(scan_results.get('findings_for_ml', []))}")
        print(f"    Vulnerabilities: {len(scan_results.get('vulnerabilities', []))}")
        print(f"    Technologies: {len(scan_results.get('technologies', []))}")
        
        if input(f"\n  {C.CY}Lanjut ke analisis ML Knowledge? (Y/N): {C.RS}").strip().upper() != "Y":
            sys.exit(0)
    
    # Run analysis (all 12 modules)
    directives = master.analyze(scan_results)
    
    # Auto-feed to Generator
    if args.feed_generator or directives.get("tasks"):
        print(f"\n  {C.CY}→ Auto-feeding to Generator ML (File 2)...{C.RS}")
        master.feed_to_generator(directives)


if __name__ == "__main__":
    main()
