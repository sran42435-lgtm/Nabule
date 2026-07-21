# scraper.py
import undetected_chromedriver as uc
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, NoSuchElementException
import time
import json
import subprocess
import os
import requests
from bs4 import BeautifulSoup
from logger import get_logger

logger = get_logger(__name__)

class BrowserScraper:
    def __init__(self, headless=True, proxy=None, user_agent=None):
        self.headless = headless
        self.proxy = proxy
        self.user_agent = user_agent or "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        self.driver = None
        self.js_scraper_path = os.path.join(os.path.dirname(__file__), "browser_emulator.js")
        self.go_scraper_bin = os.path.join(os.path.dirname(__file__), "scraper_go")
        self._use_selenium = True  # akan di-set false jika gagal inisiasi

    def _init_driver(self):
        options = uc.ChromeOptions()
        if self.headless:
            options.add_argument("--headless=new")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--disable-gpu")
        options.add_argument("--window-size=1920,1080")
        options.add_argument("--disable-blink-features=AutomationControlled")
        options.add_argument(f"user-agent={self.user_agent}")
        if self.proxy:
            options.add_argument(f"--proxy-server={self.proxy}")
        # 🔧 FIX: set binary_location ke string kosong (agar auto-detection berjalan)
        options.binary_location = ""
        try:
            self.driver = uc.Chrome(options=options, version_main=None)
            self.driver.execute_script("Object.defineProperty(navigator, 'webdriver', {get: () => undefined})")
            logger.info("Undetected ChromeDriver initialized.")
            self._use_selenium = True
        except Exception as e:
            logger.error(f"Gagal inisiasi ChromeDriver: {e}. Fallback ke requests-only.")
            self._use_selenium = False
            self.driver = None

    def scrape_with_selenium(self, url, wait_for=5):
        if not self._use_selenium:
            logger.warning("Selenium tidak aktif, pakai fallback requests.")
            return self._fallback_requests(url)
        if not self.driver:
            self._init_driver()
            if not self._use_selenium:
                return self._fallback_requests(url)
        try:
            self.driver.get(url)
            WebDriverWait(self.driver, wait_for).until(
                EC.presence_of_element_located((By.TAG_NAME, "body"))
            )
            self.driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
            time.sleep(2)
            page_source = self.driver.page_source
            forms = self.driver.find_elements(By.TAG_NAME, "form")
            form_data = []
            for f in forms:
                action = f.get_attribute("action") or ""
                method = f.get_attribute("method") or "get"
                inputs = f.find_elements(By.TAG_NAME, "input")
                input_data = []
                for inp in inputs:
                    input_data.append({
                        "name": inp.get_attribute("name"),
                        "type": inp.get_attribute("type"),
                        "value": inp.get_attribute("value")
                    })
                form_data.append({"action": action, "method": method, "inputs": input_data})
            cookies = self.driver.get_cookies()
            logger.info(f"Selenium scrape sukses: {url}, forms: {len(form_data)}")
            return {
                "url": url,
                "title": self.driver.title,
                "html": page_source,
                "forms": form_data,
                "cookies": cookies,
                "status": "success"
            }
        except TimeoutException:
            logger.error(f"Timeout saat scrape {url}")
            return {"url": url, "status": "timeout"}
        except Exception as e:
            logger.error(f"Error selenium: {e}")
            return {"url": url, "status": "error", "message": str(e)}

    def _fallback_requests(self, url):
        """Fallback jika Chrome gagal — pakai requests + BeautifulSoup."""
        try:
            resp = requests.get(url, timeout=10)
            html = resp.text
            soup = BeautifulSoup(html, 'html.parser')
            forms = []
            for form in soup.find_all('form'):
                action = form.get('action') or ''
                method = form.get('method') or 'get'
                inputs = []
                for inp in form.find_all('input'):
                    inputs.append({
                        'name': inp.get('name') or '',
                        'type': inp.get('type') or 'text',
                        'value': inp.get('value') or ''
                    })
                forms.append({"action": action, "method": method, "inputs": inputs})
            return {
                "url": url,
                "title": soup.title.string if soup.title else '',
                "html": html,
                "forms": forms,
                "cookies": resp.cookies.get_dict(),
                "status": "success"
            }
        except Exception as e:
            logger.error(f"Fallback requests gagal: {e}")
            return {"url": url, "status": "error", "message": str(e)}

    def scrape_with_js(self, url):
        try:
            result = subprocess.run(
                ["node", self.js_scraper_path, url],
                capture_output=True,
                text=True,
                timeout=30
            )
            if result.returncode != 0:
                logger.error(f"JS scraper error: {result.stderr}")
                return {"status": "error", "message": result.stderr}
            data = json.loads(result.stdout)
            logger.info(f"JS scraper sukses: {url}")
            return data
        except Exception as e:
            logger.error(f"Gagal menjalankan JS scraper: {e}")
            return {"status": "error", "message": str(e)}

    def scrape_with_go(self, url):
        try:
            if not os.path.exists(self.go_scraper_bin):
                logger.warning("Go scraper binary tidak ditemukan, build dulu.")
                subprocess.run(["go", "build", "-o", self.go_scraper_bin, "scraper_go.go"], check=True)
            result = subprocess.run(
                [self.go_scraper_bin, url],
                capture_output=True,
                text=True,
                timeout=30
            )
            if result.returncode != 0:
                logger.error(f"Go scraper error: {result.stderr}")
                return {"status": "error", "message": result.stderr}
            data = json.loads(result.stdout)
            logger.info(f"Go scraper sukses: {url}")
            return data
        except Exception as e:
            logger.error(f"Gagal menjalankan Go scraper: {e}")
            return {"status": "error", "message": str(e)}

    def full_aggressive_scan(self, url):
        results = {
            "selenium": self.scrape_with_selenium(url),
            "js": self.scrape_with_js(url),
            "go": self.scrape_with_go(url)
        }
        combined = {
            "url": url,
            "title": results["selenium"].get("title", ""),
            "forms": results["selenium"].get("forms", []),
            "cookies": results["selenium"].get("cookies", []),
            "js_data": results.get("js", {}),
            "go_data": results.get("go", {}),
            "technologies": self._detect_tech(results),
            "waf": self._detect_waf(results)
        }
        return combined

    def _detect_tech(self, results):
        tech = []
        html = results["selenium"].get("html", "")
        if "jquery" in html.lower():
            tech.append("jQuery")
        if "react" in html.lower():
            tech.append("React")
        if "angular" in html.lower():
            tech.append("Angular")
        if "vue" in html.lower():
            tech.append("Vue.js")
        if "bootstrap" in html.lower():
            tech.append("Bootstrap")
        return tech

    def _detect_waf(self, results):
        try:
            resp = requests.get(results["url"], timeout=5)
            headers = resp.headers
            server = headers.get("Server", "").lower()
            if "cloudflare" in server:
                return "Cloudflare"
            if "akamai" in server:
                return "Akamai"
            if "incapsula" in server:
                return "Incapsula"
            if "sucuri" in server:
                return "Sucuri"
            return "Unknown"
        except:
            return "Unknown"

    def close(self):
        if self.driver:
            self.driver.quit()
            logger.info("ChromeDriver closed.")

_scraper_instance = None
def get_scraper():
    global _scraper_instance
    if _scraper_instance is None:
        _scraper_instance = BrowserScraper(headless=True)
    return _scraper_instance
