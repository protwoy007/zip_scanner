#!/usr/bin/env python3
import bisect
import io
import json
import posixpath
import re
import sys
import tempfile
import threading
import urllib.parse
import webbrowser
import zipfile
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOST = "127.0.0.1"
PORTS = range(8765, 8775)
PORT = None

MAX_UPLOAD = 2 * 1024 ** 3
MAX_FILE = 25 * 1024 ** 2
MAX_NESTED = 200 * 1024 ** 2
MAX_TOTAL = 3 * 1024 ** 3
MAX_ENTRIES = 100000
MAX_FINDINGS = 5000
PER_TYPE_PER_FILE = 25
MAX_DEPTH = 2

NESTED_EXT = {".zip", ".docx", ".xlsx", ".pptx", ".odt", ".ods", ".jar", ".apk"}
BINARY_EXT = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".ico", ".tif", ".tiff", ".heic",
    ".mp3", ".wav", ".flac", ".aac", ".ogg", ".mp4", ".mkv", ".avi", ".mov", ".webm",
    ".pdf", ".exe", ".dll", ".so", ".dylib", ".class", ".o", ".a", ".bin", ".iso",
    ".woff", ".woff2", ".ttf", ".otf", ".eot", ".7z", ".rar", ".gz", ".bz2", ".xz",
    ".tar", ".psd", ".ai", ".sqlite", ".sqlite3", ".db", ".pyc", ".whl", ".dex",
}


def luhn(digits):
    d = [int(c) for c in digits][::-1]
    return (sum(d[0::2]) + sum(sum(divmod(x * 2, 10)) for x in d[1::2])) % 10 == 0


def _generic_secret_ok(v):
    low = v.lower()
    if re.match(r"(?i)^(your|my|example|sample|changeme|change_me|placeholder|dummy|test|"
                r"xxx+|\*+|<.*>|\$\{.*\}|\{\{.*\}\}|%.*%|none|null|true|false|undefined|todo|"
                r"password|secret|string|required|empty)", v):
        return False
    if any(t in low for t in ("process.env", "getenv", "environ", "config.", "input(", "getpass")):
        return False
    if re.match(r"^[A-Za-z_][\w.]*(\(\))?$", v) and ("_" in v or "." in v or v.endswith("()")):
        return False
    if len(set(v)) <= 2:
        return False
    return True


def _email_ok(v):
    low = v.lower()
    tld = low.rsplit(".", 1)[-1]
    if tld in {"png", "jpg", "jpeg", "gif", "svg", "webp", "css", "js", "map", "woff", "woff2", "local", "internal"}:
        return False
    if low.endswith(("@example.com", "@example.org", "@test.com", "@localhost")):
        return False
    if "noreply" in low or "no-reply" in low:
        return False
    return True


def _card_ok(v):
    d = re.sub(r"\D", "", v)
    if not 13 <= len(d) <= 19 or len(set(d)) < 4 or d[0] not in "3456":
        return False
    return luhn(d)


PATTERNS = [
    ("Private key block", "critical",
     r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----", 0, None),
    ("AWS access key ID", "critical", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", 0, None),
    ("AWS secret key", "critical",
     r"(?i)aws.{0,25}(?:secret|sk).{0,25}[\"']([A-Za-z0-9/+=]{40})[\"']", 1, None),
    ("GitHub token", "critical",
     r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{50,}\b", 0, None),
    ("Stripe live key", "critical", r"\b[sr]k_live_[0-9a-zA-Z]{20,}\b", 0, None),
    ("Service-account JSON", "critical", r"\"type\"\s*:\s*\"service_account\"", 0, None),
    ("Database URL with password", "critical",
     r"\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqp|mssql)://[^\s:/@\"']+:[^\s@/\"']+@[^\s\"']+", 0, None),
    ("Google API key", "high", r"\bAIza[0-9A-Za-z_\-]{35}\b", 0, None),
    ("Slack token", "high", r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b", 0, None),
    ("Slack webhook", "high", r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+", 0, None),
    ("Discord webhook", "high",
     r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[\w-]+", 0, None),
    ("Telegram bot token", "high", r"\b\d{8,10}:[A-Za-z0-9_-]{35}\b", 0, None),
    ("SendGrid key", "high", r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b", 0, None),
    ("JWT", "high",
     r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b", 0, None),
    ("Bearer token", "high",
     r"(?i)authorization[\"']?\s*[:=]\s*[\"']?bearer\s+([A-Za-z0-9._~+/-]{20,})", 1, None),
    ("National ID number", "high",
     r"(?i)\b(?:nid|national[\s_-]*id)(?:[\s_-]*(?:no|number|card))?\D{0,15}(\d{10}|\d{13}|\d{17})\b", 1, None),
    ("Hard-coded password/secret", "medium",
     r"(?i)(?:password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?token|auth[_-]?token|"
     r"private[_-]?key|client[_-]?secret)[\"']?\s*[:=]\s*[\"']?([^\s\"',;#`]{6,200})", 1, _generic_secret_ok),
    ("Credit card number", "medium", r"(?<![\d.])(?:\d[ -]?){12,18}\d(?![\d.])", 0, _card_ok),
    ("Phone number (BD)", "medium", r"(?<![\d+])(?:\+?88)?01[3-9]\d{8}(?!\d)", 0, None),
    ("Email address", "low", r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", 0, _email_ok),
]
COMPILED = [(n, s, re.compile(rx), g, v) for n, s, rx, g, v in PATTERNS]

FILE_RULES = [
    (r"(^|/)id_(rsa|dsa|ecdsa|ed25519)$", "critical", "SSH private key file", None),
    (r"(^|/)\.aws/credentials$", "critical", "AWS credentials file", None),
    (r"(^|/)\.git-credentials$", "critical", "Git credentials file", None),
    (r"(^|/)\.env(\.[^/]+)?$", "high", ".env file",
     lambda p: not p.endswith((".example", ".sample", ".template", ".dist"))),
    (r"\.(pem|key|p12|pfx|jks|keystore|ppk)$", "high", "Key / certificate file", None),
    (r"(^|/)(credentials?|secrets?)\.(json|ya?ml|txt|xml|ini)$", "high", "Credentials file", None),
    (r"(^|/)(\.npmrc|\.pypirc|\.netrc|\.htpasswd|wp-config\.php)$", "high", "Config with credentials", None),
    (r"(^|/)(passwords?|logins?)\.(txt|csv|xlsx?|json)$", "high", "Password list", None),
    (r"(^|/)(nid|passport|national[-_ ]?id)[^/]*\.(jpe?g|png|pdf)$", "high", "Possible ID document", None),
    (r"(google-services\.json|googleservice-info\.plist)$", "medium", "Firebase config", None),
    (r"\.(sqlite3?|db|sql|bak|dump)$", "medium", "Database / backup file", None),
    (r"(^|/)\.ssh/", "medium", ".ssh folder", None),
]
FILE_COMPILED = [(re.compile(rx), s, lbl, v) for rx, s, lbl, v in FILE_RULES]


def mask(s):
    s = s.strip()
    if len(s) <= 8:
        return s[:2] + "*" * (len(s) - 2)
    return s[:4] + "*" * min(len(s) - 6, 12) + s[-2:]


class Ctx:
    def __init__(self, terms):
        self.findings = []
        self.skipped = []
        self.files_scanned = 0
        self.entries = 0
        self.bytes = 0
        self.seen = set()
        self.git_reported = False
        self.truncated = False
        self.terms = [(t, re.compile(re.escape(t), re.I)) for t in terms]

    def add(self, sev, label, path, line, preview):
        if len(self.findings) >= MAX_FINDINGS:
            self.truncated = True
            return
        key = (label, path, line, preview)
        if key in self.seen:
            return
        self.seen.add(key)
        self.findings.append({"severity": sev, "type": label, "file": path,
                              "line": line, "preview": preview})

    def skip(self, path, reason):
        if len(self.skipped) < 2000:
            self.skipped.append({"file": path, "reason": reason})


def check_name(path, ctx):
    low = path.lower()
    if "/.git/" in "/" + low and not ctx.git_reported:
        ctx.git_reported = True
        ctx.add("medium", ".git folder included", path, None, "Contains full commit history")
    for rx, sev, label, valid in FILE_COMPILED:
        if rx.search(low) and (valid is None or valid(low)):
            ctx.add(sev, label, path, None, "File name matches a sensitive pattern")
            break
    for term, trx in ctx.terms:
        if trx.search(path):
            ctx.add("high", "Your term in file name", path, None, mask(term))


def snippet(text, start, end, masked):
    a = max(0, start - 30, text.rfind("\n", 0, start) + 1)
    nl = text.find("\n", end)
    b = min(len(text), end + 30, nl if nl != -1 else len(text))
    out = text[a:start] + masked + text[end:b]
    return re.sub(r"\s+", " ", out).strip()[:160]


def scan_text(path, text, ctx):
    starts = [0] + [m.end() for m in re.finditer("\n", text)]
    counts = {}

    def line_of(pos):
        return bisect.bisect_right(starts, pos)

    def push(sev, label, s, e, shown):
        n = counts.get(label, 0)
        if n >= PER_TYPE_PER_FILE:
            return
        counts[label] = n + 1
        ctx.add(sev, label, path, line_of(s), snippet(text, s, e, shown))

    for label, sev, rx, grp, valid in COMPILED:
        for m in rx.finditer(text):
            val = m.group(grp)
            if valid and not valid(val):
                continue
            s, e = m.start(grp), m.end(grp)
            shown = val if label == "Private key block" else mask(val)
            push(sev, label, s, e, shown)
    for term, trx in ctx.terms:
        for m in trx.finditer(text):
            push("high", "Your custom term", m.start(), m.end(), mask(m.group(0)))


def decode(data):
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return data.decode("utf-16", errors="replace")
    if b"\x00" in data[:8192]:
        return None
    return data.decode("utf-8", errors="replace")


def scan_zip(zf, prefix, depth, ctx):
    for info in zf.infolist():
        if ctx.entries >= MAX_ENTRIES:
            ctx.skip(prefix, "entry limit reached")
            return
        ctx.entries += 1
        if info.is_dir():
            continue
        path = prefix + info.filename
        check_name(path, ctx)
        if info.flag_bits & 0x1:
            ctx.skip(path, "password-protected, could not read")
            continue
        ext = posixpath.splitext(info.filename.lower())[1]
        try:
            if ext in NESTED_EXT and depth < MAX_DEPTH and info.file_size <= MAX_NESTED:
                with zf.open(info) as f:
                    blob = f.read(MAX_NESTED + 1)
                try:
                    with zipfile.ZipFile(io.BytesIO(blob)) as inner:
                        scan_zip(inner, path + "!/", depth + 1, ctx)
                    continue
                except zipfile.BadZipFile:
                    pass
            if ext in BINARY_EXT:
                ctx.skip(path, "binary file type")
                continue
            if info.file_size > MAX_FILE:
                ctx.skip(path, "larger than 25 MB")
                continue
            if ctx.bytes >= MAX_TOTAL:
                ctx.skip(path, "total size limit reached")
                continue
            with zf.open(info) as f:
                data = f.read(MAX_FILE + 1)
        except (RuntimeError, NotImplementedError, zipfile.BadZipFile, zlib.error, OSError) as e:
            ctx.skip(path, "unreadable: %s" % type(e).__name__)
            continue
        if len(data) > MAX_FILE:
            ctx.skip(path, "larger than 25 MB")
            continue
        ctx.bytes += len(data)
        text = decode(data)
        if text is None:
            ctx.skip(path, "binary content")
            continue
        ctx.files_scanned += 1
        scan_text(path, text, ctx)


def run_scan(fileobj, terms):
    ctx = Ctx(terms)
    with zipfile.ZipFile(fileobj) as zf:
        scan_zip(zf, "", 0, ctx)
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    ctx.findings.sort(key=lambda f: (order[f["severity"]], f["file"], f["line"] or 0))
    counts = {k: 0 for k in order}
    for f in ctx.findings:
        counts[f["severity"]] += 1
    return {
        "summary": {"files_scanned": ctx.files_scanned, "files_skipped": len(ctx.skipped),
                    "entries": ctx.entries, "mb_scanned": round(ctx.bytes / 1024 ** 2, 1),
                    "counts": counts, "truncated": ctx.truncated},
        "findings": ctx.findings,
        "skipped": ctx.skipped,
    }


class Handler(BaseHTTPRequestHandler):
    server_version = "LocalZipScanner"

    def log_message(self, *a):
        pass

    def _trusted(self):
        host = (self.headers.get("Host") or "").lower()
        if host not in ("127.0.0.1:%d" % PORT, "localhost:%d" % PORT):
            return False
        origin = self.headers.get("Origin")
        if origin and origin.lower() not in ("http://127.0.0.1:%d" % PORT, "http://localhost:%d" % PORT):
            return False
        return True

    def _send(self, code, body, ctype):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy",
                         "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code, obj):
        self._send(code, json.dumps(obj).encode("utf-8"), "application/json; charset=utf-8")

    def do_GET(self):
        if not self._trusted():
            return self._json(403, {"error": "Forbidden"})
        if self.path.split("?")[0] == "/":
            return self._send(200, PAGE.encode("utf-8"), "text/html; charset=utf-8")
        self._json(404, {"error": "Not found"})

    def do_POST(self):
        if not self._trusted():
            return self._json(403, {"error": "Forbidden"})
        if self.path != "/scan":
            return self._json(404, {"error": "Not found"})
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if length <= 0:
            return self._json(400, {"error": "Empty upload."})
        if length > MAX_UPLOAD:
            return self._json(413, {"error": "Zip is larger than 2 GB."})
        terms = []
        raw = self.headers.get("X-Terms")
        if raw:
            try:
                terms = [t.strip() for t in json.loads(urllib.parse.unquote(raw)) if t.strip()][:50]
            except Exception:
                terms = []
        with tempfile.SpooledTemporaryFile(max_size=64 * 1024 ** 2) as tmp:
            left = length
            while left > 0:
                chunk = self.rfile.read(min(1024 * 1024, left))
                if not chunk:
                    break
                tmp.write(chunk)
                left -= len(chunk)
            tmp.seek(0)
            if not zipfile.is_zipfile(tmp):
                return self._json(400, {"error": "That file is not a valid .zip archive."})
            tmp.seek(0)
            try:
                result = run_scan(tmp, terms)
            except zipfile.BadZipFile:
                return self._json(400, {"error": "The zip is corrupted and could not be opened."})
            except Exception as e:
                return self._json(500, {"error": "Scan failed: %s" % e})
        self._json(200, result)


PAGE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Zip Scanner</title>
<style>
:root{
  --bg:#f4f5f9; --panel:#ffffff; --ink:#161a2b; --muted:#667085; --line:#e4e7ee; --soft:#f0f2f8;
  --accent:#4f46e5; --accent-2:#7c3aed; --accent-ink:#ffffff;
  --crit:#dc2626; --high:#ea580c; --med:#ca8a04; --low:#2563eb; --ok:#16a34a;
  --crit-bg:#fef2f2; --high-bg:#fff4ec; --med-bg:#fefce8; --low-bg:#eff6ff; --ok-bg:#f0fdf4;
  --shadow:0 1px 2px rgba(16,24,40,.05),0 8px 24px rgba(16,24,40,.06);
  --mono:ui-monospace,"Cascadia Code",Consolas,Menlo,monospace;
}
@media (prefers-color-scheme:dark){
  :root{
    --bg:#0d0f1a; --panel:#161a2b; --ink:#eef0f8; --muted:#98a2b8; --line:#262c44; --soft:#1d2236;
    --accent:#818cf8; --accent-2:#a78bfa; --accent-ink:#0d0f1a;
    --crit:#f87171; --high:#fb923c; --med:#facc15; --low:#60a5fa; --ok:#4ade80;
    --crit-bg:#2a1518; --high-bg:#2a1b12; --med-bg:#2a2410; --low-bg:#13203a; --ok-bg:#112419;
    --shadow:0 1px 2px rgba(0,0,0,.4),0 8px 24px rgba(0,0,0,.35);
  }
}
*{box-sizing:border-box}
html,body{margin:0}
body{background:var(--bg);color:var(--ink);font:15px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;-webkit-font-smoothing:antialiased}
body::before{content:"";position:fixed;inset:0 0 auto 0;height:320px;background:radial-gradient(60% 100% at 50% 0,color-mix(in srgb,var(--accent) 16%,transparent),transparent);pointer-events:none}
main{position:relative;max-width:960px;margin:0 auto;padding:40px 20px 72px}
header{display:flex;align-items:center;gap:14px;margin-bottom:28px}
.logo{width:46px;height:46px;border-radius:14px;display:grid;place-items:center;color:#fff;background:linear-gradient(135deg,var(--accent),var(--accent-2));box-shadow:0 6px 16px color-mix(in srgb,var(--accent) 40%,transparent)}
.logo svg{width:24px;height:24px}
h1{font-size:24px;margin:0;letter-spacing:-.02em}
.sub{color:var(--muted);margin:2px 0 0;font-size:14px}
.badge{margin-left:auto;display:inline-flex;align-items:center;gap:6px;font-size:12px;font-weight:600;color:var(--ok);background:var(--ok-bg);border:1px solid color-mix(in srgb,var(--ok) 30%,transparent);border-radius:999px;padding:5px 11px;white-space:nowrap}
.badge i{width:7px;height:7px;border-radius:50%;background:var(--ok)}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:18px;padding:22px;box-shadow:var(--shadow)}
#drop{position:relative;border:2px dashed var(--line);border-radius:14px;padding:40px 16px;text-align:center;cursor:pointer;background:var(--soft);transition:border-color .15s,background .15s,transform .15s}
#drop:hover,#drop.over{border-color:var(--accent);background:color-mix(in srgb,var(--accent) 8%,var(--soft))}
#drop.over{transform:scale(1.01)}
#drop:focus-visible,button:focus-visible,input:focus-visible,textarea:focus-visible,summary:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
.up{width:56px;height:56px;margin:0 auto 12px;border-radius:50%;display:grid;place-items:center;color:var(--accent);background:color-mix(in srgb,var(--accent) 12%,transparent)}
.up svg{width:26px;height:26px}
#drop b{display:block;font-size:17px}
#drop span{display:block;color:var(--muted);font-size:14px;margin-top:2px}
.pick{display:inline-block;margin-top:14px;background:var(--accent);color:var(--accent-ink);border-radius:10px;padding:8px 16px;font-weight:600;font-size:14px}
label.t{display:block;margin:22px 0 6px;font-weight:600;font-size:14px}
textarea{width:100%;min-height:78px;resize:vertical;border:1px solid var(--line);border-radius:12px;padding:11px 12px;background:var(--soft);color:var(--ink);font:13px/1.5 var(--mono)}
textarea:focus{border-color:var(--accent)}
.hint{color:var(--muted);font-size:13px;margin:6px 0 0}
#status{margin-top:16px;color:var(--muted);font-size:14px}
#status:empty{display:none}
.bar{height:8px;background:var(--soft);border-radius:999px;overflow:hidden;margin-top:10px}
.bar i{display:block;height:100%;width:0;border-radius:999px;background:linear-gradient(90deg,var(--accent),var(--accent-2));transition:width .12s}
.bar.busy i{width:35%!important;animation:slide 1.1s ease-in-out infinite}
@keyframes slide{0%{margin-left:-35%}100%{margin-left:100%}}
#results{margin-top:26px}
.verdict{display:flex;gap:16px;align-items:flex-start;border-radius:18px;padding:20px;border:1px solid var(--line);background:var(--panel);box-shadow:var(--shadow)}
.vi{flex:none;width:46px;height:46px;border-radius:14px;display:grid;place-items:center}
.vi svg{width:24px;height:24px}
.vb{flex:1;min-width:0}
.verdict h2{margin:0 0 4px;font-size:19px;letter-spacing:-.01em}
.verdict p{margin:0;color:var(--muted)}
.verdict.bad{border-color:color-mix(in srgb,var(--crit) 45%,var(--line));background:var(--crit-bg)}
.verdict.bad .vi{background:var(--crit);color:#fff}
.verdict.warn{border-color:color-mix(in srgb,var(--med) 45%,var(--line));background:var(--med-bg)}
.verdict.warn .vi{background:var(--med);color:#fff}
.verdict.ok{border-color:color-mix(in srgb,var(--ok) 40%,var(--line));background:var(--ok-bg)}
.verdict.ok .vi{background:var(--ok);color:#fff}
.stats{display:flex;flex-wrap:wrap;gap:8px;margin:14px 0 0}
.stats span{font-size:12.5px;color:var(--muted);background:color-mix(in srgb,var(--panel) 70%,transparent);border:1px solid var(--line);border-radius:999px;padding:3px 10px}
.tiles{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:18px 0 0}
.tile{text-align:left;font:inherit;color:var(--ink);background:var(--panel);border:1px solid var(--line);border-top:3px solid var(--c);border-radius:14px;padding:12px 14px;cursor:pointer;box-shadow:var(--shadow);transition:opacity .15s,transform .15s}
.tile:hover{transform:translateY(-1px)}
.tile[aria-pressed="false"]{opacity:.45}
.tile:disabled{opacity:.35;cursor:default;transform:none}
.tile b{display:block;font-size:26px;line-height:1.1;color:var(--c)}
.tile span{font-size:13px;color:var(--muted)}
.tile.critical{--c:var(--crit)}.tile.high{--c:var(--high)}.tile.medium{--c:var(--med)}.tile.low{--c:var(--low)}
.tools{display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin:20px 0 12px}
input[type=search]{flex:1;min-width:180px;border:1px solid var(--line);border-radius:12px;padding:9px 12px;background:var(--panel);color:var(--ink);font:inherit}
input[type=search]:focus{border-color:var(--accent)}
.btn{border:1px solid var(--line);background:var(--panel);color:var(--ink);border-radius:12px;padding:9px 14px;font:inherit;font-weight:600;font-size:14px;cursor:pointer;transition:border-color .15s}
.btn:hover{border-color:var(--accent)}
.btn.primary{background:var(--accent);color:var(--accent-ink);border-color:transparent}
.btn.primary:hover{filter:brightness(1.08)}
.rows{display:grid;gap:10px}
.row{display:grid;gap:6px;padding:13px 15px 13px 18px;background:var(--panel);border:1px solid var(--line);border-left:4px solid var(--c);border-radius:12px}
.row.critical{--c:var(--crit)}.row.high{--c:var(--high)}.row.medium{--c:var(--med)}.row.low{--c:var(--low)}
.top{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.sev{font-size:11px;font-weight:700;letter-spacing:.04em;text-transform:uppercase;border-radius:999px;padding:2px 9px;color:var(--c);background:color-mix(in srgb,var(--c) 14%,transparent)}
.what{font-weight:600}
.where{font-family:var(--mono);font-size:12.5px;color:var(--muted);word-break:break-all}
.prev{display:block;font-family:var(--mono);font-size:12.5px;background:var(--soft);border-radius:8px;padding:7px 10px;word-break:break-all}
.empty{padding:28px;text-align:center;color:var(--muted);background:var(--panel);border:1px dashed var(--line);border-radius:12px}
details{margin-top:20px;background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:12px 16px}
summary{cursor:pointer;color:var(--muted);font-weight:600}
.skips{font-family:var(--mono);font-size:12.5px;color:var(--muted);margin-top:10px;max-height:240px;overflow:auto}
.skips div{padding:2px 0;word-break:break-all}
.note{margin-top:22px;color:var(--muted);font-size:13px;text-align:center}
@media (max-width:640px){.tiles{grid-template-columns:repeat(2,1fr)}.badge{display:none}.verdict{flex-direction:column}}
@media (prefers-reduced-motion:reduce){*{transition:none!important;animation:none!important}}
</style>
</head>
<body>
<main>
  <header>
    <div class="logo">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l8 3v6c0 4.5-3.2 8-8 9-4.8-1-8-4.5-8-9V6l8-3z"/><path d="M9 12l2 2 4-4"/></svg>
    </div>
    <div>
      <h1>Zip Scanner</h1>
      <p class="sub">Find passwords, keys, tokens and IDs before you share a zip.</p>
    </div>
    <span class="badge"><i></i>Runs locally</span>
  </header>

  <div class="panel">
    <div id="drop" tabindex="0" role="button" aria-label="Choose a zip file">
      <div class="up">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 16V4"/><path d="M7 9l5-5 5 5"/><path d="M4 16v3a1 1 0 001 1h14a1 1 0 001-1v-3"/></svg>
      </div>
      <b>Drop a .zip here</b>
      <span>Scanned on this computer and deleted right after.</span>
      <div class="pick">Choose file</div>
    </div>
    <input id="file" type="file" accept=".zip,application/zip" hidden>

    <label class="t" for="terms">Your own words to look for (optional)</label>
    <textarea id="terms" placeholder="One per line, e.g. your phone number, home address, a password you use"></textarea>
    <p class="hint">Case-insensitive. Matches are shown masked.</p>

    <div id="status" aria-live="polite"></div>
  </div>

  <div id="results"></div>
</main>

<script>
const $ = s => document.querySelector(s);
const SEV = ['critical','high','medium','low'];
const LABEL = {critical:'Critical',high:'High',medium:'Medium',low:'Low'};
const ICON = {
  bad:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l9 16H3L12 3z"/><path d="M12 10v4"/><path d="M12 17h.01"/></svg>',
  warn:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M12 8v4"/><path d="M12 16h.01"/></svg>',
  ok:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12l5 5 9-10"/></svg>'
};
let report = null, fileName = '', active = new Set(SEV);

const drop = $('#drop'), input = $('#file');
drop.addEventListener('click', () => input.click());
drop.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); input.click(); } });
['dragenter','dragover'].forEach(n => drop.addEventListener(n, e => { e.preventDefault(); drop.classList.add('over'); }));
['dragleave','drop'].forEach(n => drop.addEventListener(n, e => { e.preventDefault(); drop.classList.remove('over'); }));
drop.addEventListener('drop', e => { const f = e.dataTransfer.files[0]; if (f) start(f); });
input.addEventListener('change', () => { if (input.files[0]) start(input.files[0]); input.value = ''; });

function el(tag, cls, text) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined) n.textContent = text;
  return n;
}

function start(file) {
  fileName = file.name;
  $('#results').replaceChildren();
  const status = $('#status');
  status.replaceChildren(el('div', '', 'Uploading ' + file.name + ' (' + (file.size / 1048576).toFixed(1) + ' MB)...'));
  const bar = el('div', 'bar'), fill = el('i');
  bar.appendChild(fill); status.appendChild(bar);

  const terms = $('#terms').value.split('\n').map(s => s.trim()).filter(Boolean);
  const xhr = new XMLHttpRequest();
  xhr.open('POST', '/scan');
  xhr.setRequestHeader('X-Terms', encodeURIComponent(JSON.stringify(terms)));
  xhr.upload.onprogress = e => {
    if (e.lengthComputable) fill.style.width = (e.loaded / e.total * 100) + '%';
    if (e.loaded === e.total) { status.firstChild.textContent = 'Scanning...'; bar.classList.add('busy'); }
  };
  xhr.onerror = () => { status.textContent = 'Could not reach the local scanner. Is the script still running?'; };
  xhr.onload = () => {
    let data = null;
    try { data = JSON.parse(xhr.responseText); } catch (e) {}
    if (xhr.status !== 200 || !data) {
      status.textContent = (data && data.error) || 'Scan failed.';
      return;
    }
    status.replaceChildren();
    report = data; active = new Set(SEV);
    render();
    $('#results').scrollIntoView({behavior: 'smooth', block: 'start'});
  };
  xhr.send(file);
}

function render() {
  const root = $('#results'); root.replaceChildren();
  const s = report.summary, c = s.counts;
  const total = SEV.reduce((a, k) => a + c[k], 0);

  const v = el('div', 'verdict'), icon = el('div', 'vi'), body = el('div', 'vb');
  let kind, title, text;
  if (c.critical || c.high) {
    kind = 'bad'; title = 'Confidential data likely found';
    text = c.critical + ' critical and ' + c.high + ' high-severity items. Remove or rotate these before sharing the zip.';
  } else if (total) {
    kind = 'warn'; title = total + ' item' + (total > 1 ? 's' : '') + ' to review';
    text = 'Nothing critical, but personal details like emails or phone numbers were found.';
  } else {
    kind = 'ok'; title = 'No known patterns found';
    text = 'This check is pattern-based. It cannot catch every kind of private data.';
  }
  v.classList.add(kind);
  icon.innerHTML = ICON[kind];
  body.append(el('h2', '', title), el('p', '', text));
  const st = el('div', 'stats');
  [s.files_scanned + ' files scanned', s.files_skipped + ' skipped', s.mb_scanned + ' MB read', fileName]
    .forEach(t => st.appendChild(el('span', '', t)));
  body.appendChild(st);
  if (s.truncated) body.appendChild(el('p', '', 'Too many findings: list is cut at 5000.'));
  v.append(icon, body);
  root.appendChild(v);

  if (total) {
    const tiles = el('div', 'tiles');
    SEV.forEach(k => {
      const b = el('button', 'tile ' + k);
      b.append(el('b', '', String(c[k])), el('span', '', LABEL[k]));
      if (!c[k]) { b.disabled = true; tiles.appendChild(b); return; }
      b.setAttribute('aria-pressed', 'true');
      b.onclick = () => {
        active.has(k) ? active.delete(k) : active.add(k);
        b.setAttribute('aria-pressed', active.has(k));
        list();
      };
      tiles.appendChild(b);
    });
    root.appendChild(tiles);

    const tools = el('div', 'tools');
    const q = el('input'); q.type = 'search'; q.placeholder = 'Filter by file or type';
    q.oninput = list; q.id = 'q'; tools.appendChild(q);
    const dl = el('button', 'btn primary', 'Download report');
    dl.onclick = download; tools.appendChild(dl);
    const again = el('button', 'btn', 'Scan another');
    again.onclick = () => { root.replaceChildren(); window.scrollTo({top: 0, behavior: 'smooth'}); input.click(); };
    tools.appendChild(again);
    root.appendChild(tools);
    const rows = el('div', 'rows'); rows.id = 'rows'; root.appendChild(rows);
    list();
  }

  if (report.skipped.length) {
    const d = el('details'); d.appendChild(el('summary', '', 'Files not scanned (' + report.skipped.length + ')'));
    const box = el('div', 'skips');
    report.skipped.slice(0, 500).forEach(x => box.appendChild(el('div', '', x.file + '  -  ' + x.reason)));
    d.appendChild(box); root.appendChild(d);
  }
  root.appendChild(el('p', 'note', 'Previews are masked. Passwords inside images, PDFs or password-protected zips are not scanned.'));
}

function list() {
  const box = $('#rows'); box.replaceChildren();
  const q = ($('#q') ? $('#q').value : '').toLowerCase();
  const items = report.findings.filter(f => active.has(f.severity) &&
    (!q || f.file.toLowerCase().includes(q) || f.type.toLowerCase().includes(q)));
  if (!items.length) { box.appendChild(el('div', 'empty', 'Nothing matches this filter.')); return; }
  items.slice(0, 1000).forEach(f => {
    const r = el('div', 'row ' + f.severity);
    const top = el('div', 'top');
    top.append(el('span', 'sev', LABEL[f.severity]), el('span', 'what', f.type));
    r.append(top, el('div', 'where', f.file + (f.line ? ':' + f.line : '')), el('code', 'prev', f.preview));
    box.appendChild(r);
  });
  if (items.length > 1000) box.appendChild(el('div', 'empty', 'Showing 1000 of ' + items.length + '. Download the report for all.'));
}

function download() {
  const blob = new Blob([JSON.stringify(report, null, 2)], {type: 'application/json'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'zip-scan-report.json';
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}
</script>
</body>
</html>
"""


def main():
    global PORT
    server = None
    for p in PORTS:
        try:
            PORT = p
            server = ThreadingHTTPServer((HOST, p), Handler)
            break
        except OSError:
            continue
    if server is None:
        sys.exit("No free port between %d and %d." % (PORTS[0], PORTS[-1]))
    url = "http://127.0.0.1:%d" % PORT
    print("Zip scanner running at %s  (Ctrl+C to stop)" % url)
    threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
