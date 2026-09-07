# VishaSQL 🐍

Full-featured *SQL Injection scanner* — detects **error-based, boolean-blind,
time-blind, and union-based** injection, plus union data extraction.

> ⚠️ *For authorized security testing only.* Use solely on systems you own
> or have explicit permission to test (e.g., your own lab, bug bounty scope,
> or written authorization).

## ✨ Features

- ✅ Error-based detection (MySQL / MSSQL / Oracle / PostgreSQL / SQLite)
- ✅ Boolean-based blind detection
- ✅ Time-based blind detection (SLEEP / WAITFOR DELAY / pg_sleep)
- ✅ Union-based column discovery + reflection detection
- ✅ Optional --dump (union-based data extraction)
- ✅ Proxy support (Burp Suite) + custom headers / cookies
- ✅ Multi-threaded parameter scanning

## 📦 Install

```bash
git clone https://github.com/annfinjr/vishasql.git
cd vishasql
pip3 install requests
python3 vishasql.py

GET request with query params
python3 vishasql.py "http://target/item.php?id=1"

POST form
python3 vishasql.py "http://target/login.php" -d "user=admin&pass=x"

Authenticated (cookies) + Burp proxy
python3 vishasql.py "http://target/item.php?id=1" \
    -c "PHPSESSID=abc123; security=low" \
    -P http://127.0.0.1:8080

Test only specific parameters
python3 vishasql.py "http://target/page.php?id=1&cat=5" -p "id,cat"

Dump data (union-based, reflected output required)
python3 vishasql.py "http://target/item.php?id=1" --dump

🧪 Testing against your own lab
Try it on deliberately vulnerable apps (never test unauthorized targets):
# DVWA
docker run -d -p 8080:80 vulnerables/web-dvwa

# sqli-labs (SQLi-focused, 75 lessons)
docker run -d -p 8081:80 acgpiano/sqli-labs
