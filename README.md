# VishaSQL 🐍
Full-featured *SQL Injection scanner* — detects **error-based, boolean-blind,
time-blind, and union-based** injection, plus union data extraction.

> ⚠️ *For authorized security testing only.* Use solely on systems you own
> or have explicit permission to test.

## Features
- ✅ Error-based detection (MySQL / MSSQL / Oracle / PostgreSQL / SQLite)
- ✅ Boolean-based blind detection
- ✅ Time-based blind detection
- ✅ Union-based column discovery + reflection detection
- ✅ Optional --dump (union + reflection)
- ✅ Proxy support + custom headers/cookies

## Install
```bash
pip3 install requests
