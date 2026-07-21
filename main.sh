#!/bin/bash
DB="targets.db"
SCHEMA="schema.sql"

clear
cat << "EOF"
  ___   _   _  _    ___  _   _   ___   _   _    ___    ___   _   _   _____   ___   _   _   _____ 
 / _ \ | \ | || |  / _ \| \ | | / _ \ | \ | |  / _ \  / _ \ | \ | | |  __ \ / _ \ | \ | | / ____|
| |_| ||  \| || | | |_| ||  \| || |_| ||  \| | | |_| || |_| ||  \| | | |  | | |_| ||  \| || |  __
|  _  || . ` || | |  _  || . ` ||  _  || . ` | |  _  ||  _  || . ` | | |  | |  _  || . ` || | |_ |
| | | || |\  || | | | | || |\  || | | || |\  | | | | || | | || |\  | | |__| | | | || |\  || |__| |
|_| |_||_| \_||_| |_| |_||_| \_||_| |_||_| \_| |_| |_||_| |_||_| \_| |_____/|_| |_||_| \_| \_____|
                                                                                                    
=============================================================================
       SQLGENERATE - AGGRESSIVE MODE with PAYLOAD VALIDATION
       Version 4.0  |  (c) 2026 ZmZ Industries
=============================================================================
EOF

echo "[*] Memeriksa dependensi..."

# Python
if ! command -v python3 &> /dev/null; then
    echo "[!] Python3 tidak ditemukan. Install dulu."
    exit 1
fi
pip install -q undetected-chromedriver selenium beautifulsoup4 lxml cssselect requests
pip install -q --upgrade urllib3

# Node.js
if ! command -v node &> /dev/null; then
    echo "[!] Node.js tidak ditemukan. Install dulu (https://nodejs.org)."
    exit 1
fi
if [ ! -d "node_modules" ]; then
    echo "[*] Menginstall Node.js dependencies..."
    npm init -y > /dev/null
    npm install puppeteer-extra puppeteer-extra-plugin-stealth puppeteer-extra-plugin-recaptcha puppeteer-extra-plugin-proxy puppeteer-extra-plugin-block-resources > /dev/null
fi

# Go
if ! command -v go &> /dev/null; then
    echo "[!] Go tidak ditemukan. Install dulu (https://golang.org)."
    exit 1
fi
if [ ! -f "scraper_go" ]; then
    echo "[*] Build Go scraper..."
    go mod init scraper > /dev/null 2>&1
    go get github.com/go-rod/rod github.com/go-rod/stealth > /dev/null
    go build -o scraper_go scraper_go.go > /dev/null
fi

# DB
if [ ! -f "$DB" ]; then
    echo "[+] Membuat database baru..."
    sqlite3 "$DB" < "$SCHEMA"
    echo "[+] Database siap."
fi

while true; do
    echo ""
    read -p "Masukkan target URL/IP/domain (contoh: http://site.com) atau 'exit': " target
    if [[ "$target" == "exit" ]]; then
        echo "[!] Keluar."
        break
    fi
    if [[ -z "$target" ]]; then
        echo "[!] Target kosong, coba lagi."
        continue
    fi

    sqlite3 "$DB" "INSERT INTO targets (url) VALUES ('$target');"
    echo "[+] Target '$target' disimpan."

    echo "[*] Menjalankan SQLGENERATE aggresive scanner..."
    python3 generator.py
    echo "[*] Selesai. Cek app.log untuk log detail."
done

echo "[*] Terima kasih, sampai jumpa."
