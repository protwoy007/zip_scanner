import atexit
import bisect
import bz2
import concurrent.futures
import gzip
import html
import io
import json
import lzma
import math
import os
import platform
import posixpath
import re
import secrets
import shutil
import sqlite3
import struct
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import urllib.parse
import uuid
import webbrowser
import zipfile
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

APP_NAME = "GitShield ZIP Scanner"
APP_CREDIT = "Khaled 2026"
HOST = "127.0.0.1"
PORTS = range(8765, 8785)
PORT = None
AUTH_TOKEN = secrets.token_urlsafe(24)

MAX_UPLOAD = 4 * 1024 ** 3
MAX_FILE = 100 * 1024 ** 2
MAX_NESTED = 300 * 1024 ** 2
MAX_TOTAL = 6 * 1024 ** 3
MAX_ENTRIES = 250000
MAX_FINDINGS = 20000
PER_TYPE_PER_FILE = 40
MAX_DEPTH = 6
MAX_WORKERS = min(16, max(4, (os.cpu_count() or 4) * 2))

GITHUB_WARN_BYTES = 50 * 1024 ** 2
GITHUB_BLOCK_BYTES = 100 * 1024 ** 2

ZIP_LIKE_EXT = {
    ".zip", ".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp",
    ".jar", ".war", ".ear", ".apk", ".ipa", ".whl", ".egg", ".epub",
}
TAR_EXT = {".tar", ".tgz", ".tbz2", ".txz"}
SINGLE_COMP_EXT = {".gz", ".bz2", ".xz"}
IMAGE_EXT = {".jpg", ".jpeg", ".png", ".tif", ".tiff", ".webp", ".gif"}
SQLITE_EXT = {".sqlite", ".sqlite3", ".db", ".db3", ".s3db"}

SESSION_ROOT = tempfile.mkdtemp(prefix="gitshield_khaled_")
SESSIONS = {}
SCANS = {}
STATE_LOCK = threading.Lock()


def _cleanup_all():
    shutil.rmtree(SESSION_ROOT, ignore_errors=True)


atexit.register(_cleanup_all)


def luhn(digits):
    d = [int(c) for c in digits][::-1]
    return (sum(d[0::2]) + sum(sum(divmod(x * 2, 10)) for x in d[1::2])) % 10 == 0


def shannon_entropy(s):
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = float(len(s))
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _generic_secret_ok(v):
    low = v.lower()
    if re.match(
        r"(?i)^(your|my|example|sample|changeme|change_me|placeholder|dummy|test|"
        r"xxx+|\*+|<.*>|\$\{.*\}|\{\{.*\}\}|%.*%|none|null|true|false|undefined|todo|"
        r"password|secret|string|required|empty|replace|insert|enter|fake|mock)",
        v,
    ):
        return False
    if any(t in low for t in ("process.env", "getenv", "environ", "config.", "input(", "getpass", "os.env", "settings.")):
        return False
    if re.match(r"^[A-Za-z_][\w.]*(\(\))?$", v) and ("_" in v or "." in v or v.endswith("()")):
        return False
    if len(set(v)) <= 3:
        return False
    return True


def _entropy_secret_ok(v):
    if not _generic_secret_ok(v):
        return False
    if "/" in v and v.count("/") >= 3:
        return False
    if re.match(r"^[0-9a-fA-F]{32,64}$", v):
        return shannon_entropy(v) >= 3.4
    has_u = any(c.isupper() for c in v)
    has_l = any(c.islower() for c in v)
    has_d = any(c.isdigit() for c in v)
    if (has_u + has_l + has_d) < 2:
        return False
    return shannon_entropy(v) >= 4.1


def _openai_ok(v):
    if v.startswith(("sk-proj-", "sk-svcacct-", "sk-admin-")):
        return len(v) >= 36
    if "T3BlbkFJ" in v:
        return True
    return len(v) >= 48 and shannon_entropy(v) >= 4.2


def _email_ok(v):
    low = v.lower()
    tld = low.rsplit(".", 1)[-1]
    if tld in {
        "png", "jpg", "jpeg", "gif", "svg", "webp", "ico", "css", "js", "ts",
        "map", "woff", "woff2", "ttf", "eot", "local", "internal", "invalid", "lan",
    }:
        return False
    if low.endswith(("@example.com", "@example.org", "@example.net", "@test.com", "@localhost", "@users.noreply.github.com")):
        return False
    if "noreply" in low or "no-reply" in low or "donotreply" in low:
        return False
    return True


def _card_ok(v):
    d = re.sub(r"\D", "", v)
    if not 13 <= len(d) <= 19 or len(set(d)) < 4 or d[0] not in "3456":
        return False
    return luhn(d)


def _iban_ok(v):
    s = v.replace(" ", "").upper()
    if not 15 <= len(s) <= 34:
        return False
    try:
        rearranged = s[4:] + s[:4]
        digits = "".join(str(ord(c) - 55) if c.isalpha() else c for c in rearranged)
        return int(digits) % 97 == 1
    except Exception:
        return False


def _win_user_ok(v):
    return v.lower() not in {
        "public", "default", "all users", "user", "username", "yourname", "your_name",
        "example", "runner", "runneradmin", "admin", "administrator", "guest", "owner",
        "temp", "test", "ci", "github", "vscode", "docker", "app", "name",
    }


def _unix_user_ok(v):
    return v.lower() not in {
        "runner", "ubuntu", "user", "username", "root", "app", "node", "www",
        "www-data", "nobody", "ci", "github", "actions", "vscode", "codespace",
        "dev", "admin", "shared", "guest", "test", "example", "docker", "jenkins",
    }


def _twilio_ok(v):
    body = v[2:]
    return any(c.isdigit() for c in body) and any(c.isalpha() for c in body)


PATTERNS = [
    ("Private key block", "critical", "secret",
     r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY(?: BLOCK)?-----", 0, None, True),
    ("AWS access key ID", "critical", "secret",
     r"\b(?:AKIA|ASIA|AIDA|AROA|AIPA|ANPA|ANVA)[0-9A-Z]{16}\b", 0, None, True),
    ("AWS secret access key", "critical", "secret",
     r"(?i)aws[_-]?secret[_-]?(?:access[_-]?)?key.{0,20}[\"']([A-Za-z0-9/+=]{40})[\"']", 1, None, True),
    ("GitHub token", "critical", "secret",
     r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{50,}\b", 0, None, True),
    ("GitLab personal token", "critical", "secret",
     r"\bglpat-[A-Za-z0-9_\-]{20,}\b", 0, None, True),
    ("OpenAI API key", "critical", "secret",
     r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{32,}\b", 0, _openai_ok, True),
    ("Anthropic API key", "critical", "secret",
     r"\bsk-ant-api\d{2}-[A-Za-z0-9_\-]{40,}\b", 0, None, True),
    ("HuggingFace token", "critical", "secret",
     r"\bhf_[A-Za-z0-9]{30,}\b", 0, None, True),
    ("Stripe live key", "critical", "secret",
     r"\b(?:sk|rk)_live_[0-9a-zA-Z]{20,}\b", 0, None, True),
    ("GCP service-account JSON", "critical", "secret",
     r"\"type\"\s*:\s*\"service_account\"", 0, None, True),
    ("Azure storage connection string", "critical", "secret",
     r"DefaultEndpointsProtocol=https;AccountName=[^;\s]+;AccountKey=[A-Za-z0-9+/=]{40,}", 0, None, True),
    ("Database URL with password", "critical", "secret",
     r"\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|mariadb|redis|rediss|amqp|amqps|mssql)://[^\s:/@\"']+:[^\s@/\"']+@[^\s\"']+", 0, None, True),
    ("URL with embedded credentials", "critical", "secret",
     r"https?://[A-Za-z0-9._%+-]+:[^/\s@\"']{4,}@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", 0, None, True),
    ("NPM access token", "critical", "secret",
     r"\bnpm_[A-Za-z0-9]{30,}\b", 0, None, True),
    ("PyPI API token", "critical", "secret",
     r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{40,}\b", 0, None, True),
    ("Shopify access token", "critical", "secret",
     r"\bshp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}\b", 0, None, True),
    ("DigitalOcean token", "critical", "secret",
     r"\bdo[po]_v1_[a-f0-9]{64}\b", 0, None, True),
    ("Google / Firebase / Gemini API key", "high", "secret",
     r"\bAIza[0-9A-Za-z_\-]{35}\b", 0, None, True),
    ("Slack token", "high", "secret",
     r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b|\bxapp-\d-[A-Za-z0-9-]{10,}\b", 0, None, True),
    ("Slack webhook URL", "high", "secret",
     r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+", 0, None, True),
    ("Discord webhook URL", "high", "secret",
     r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[\w-]+", 0, None, True),
    ("Telegram bot token", "high", "secret",
     r"\b\d{8,10}:[A-Za-z0-9_-]{35}\b", 0, None, True),
    ("SendGrid API key", "high", "secret",
     r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b", 0, None, True),
    ("Mailgun API key", "high", "secret",
     r"\bkey-[0-9a-zA-Z]{32}\b", 0, None, True),
    ("Twilio Account / API key", "high", "secret",
     r"\b(?:AC|SK)[0-9a-fA-F]{32}\b", 0, _twilio_ok, False),
    ("JWT token", "high", "secret",
     r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b", 0, None, True),
    ("Authorization Bearer token", "high", "secret",
     r"(?i)authorization[\"']?\s*[:=]\s*[\"']?bearer\s+([A-Za-z0-9._~+/-]{20,})", 1, None, True),
    ("High-entropy secret value", "high", "secret",
     r"(?i)(?:token|api[_-]?key|secret|auth|cred|signing[_-]?key|master[_-]?key|encryption[_-]?key|supabase|firebase|cloudflare|vercel)[\"']?\s*[:=]\s*[\"']([A-Za-z0-9+/=_\-]{24,160})[\"']", 1, _entropy_secret_ok, False),
    ("Hard-coded password / secret", "medium", "secret",
     r"(?i)(?:password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?token|auth[_-]?token|private[_-]?key|client[_-]?secret|db[_-]?pass|jwt[_-]?secret)[\"']?\s*[:=]\s*[\"']?([^\s\"',;#`]{6,200})", 1, _generic_secret_ok, False),
    ("Firebase database URL", "low", "secret",
     r"https://[a-z0-9-]+\.firebaseio\.com\b", 0, None, True),
    ("National ID (NID) number", "high", "pii",
     r"(?i)\b(?:nid|national[\s_-]*id|voter[\s_-]*id)(?:[\s_-]*(?:no|number|card))?\D{0,15}(\d{10}|\d{13}|\d{17})\b", 1, None, True),
    ("Passport number", "high", "pii",
     r"(?i)\bpassport(?:[\s_-]*(?:no|num|number|id))?\s*[:=#-]?\s*([A-Z]{1,2}\d{7,8})\b", 1, None, True),
    ("Social Security Number (SSN)", "high", "pii",
     r"(?i)\b(?:ssn|social[\s_-]*security)[^\d\n]{0,15}(\d{3}-\d{2}-\d{4})\b", 1, None, True),
    ("Credit / debit card number", "high", "pii",
     r"(?<![\d.])(?:\d[ -]?){12,18}\d(?![\d.])", 0, _card_ok, False),
    ("Bank IBAN number", "high", "pii",
     r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b", 0, _iban_ok, False),
    ("Windows local username path", "medium", "pii",
     r"(?i)[A-Z]:[/\\]{1,2}Users[/\\]{1,2}([^/\\\"'\s<>|?*]{2,40})[/\\]{1,2}", 1, _win_user_ok, True),
    ("macOS / Linux local username path", "medium", "pii",
     r"(?<![A-Za-z0-9])/(?:Users|home)/([A-Za-z0-9._-]{2,40})/", 1, _unix_user_ok, True),
    ("Phone number (Bangladesh)", "medium", "pii",
     r"(?<![\d+])(?:\+?88)?01[3-9]\d{8}(?!\d)", 0, None, True),
    ("International phone number", "medium", "pii",
     r"(?i)\b(?:phone|mobile|cell|tel|whatsapp|contact)\s*[:=#-]?\s*(\+\d{1,3}[\s.-]?(?:\(?\d{2,4}\)?[\s.-]?){2,4}\d{2,4})\b", 1, None, True),
    ("GPS coordinates in file", "medium", "pii",
     r"(?i)lat(?:itude)?[\"']?\s*[:=]\s*[-+]?\d{1,2}\.\d{4,}\s*[,;\s]+lon(?:g|gitude)?[\"']?\s*[:=]\s*[-+]?\d{1,3}\.\d{4,}", 0, None, True),
    ("Personal email address", "low", "pii",
     r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", 0, _email_ok, True),
    ("Private network IPv4", "low", "pii",
     r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b", 0, None, False),
]
COMPILED = [(n, s, c, re.compile(rx), g, v, b) for n, s, c, rx, g, v, b in PATTERNS]

FILE_RULES = [
    (r"(^|/)id_(rsa|dsa|ecdsa|ed25519)$", "critical", "file", "SSH private key file", None),
    (r"(^|/)\.aws/credentials$", "critical", "file", "AWS credentials file", None),
    (r"(^|/)\.git-credentials$", "critical", "file", "Git credentials file", None),
    (r"(^|/)\.kube/config$", "critical", "file", "Kubernetes cluster config", None),
    (r"(^|/)\.docker/config\.json$", "critical", "file", "Docker auth config", None),
    (r"(^|/)\.env(\.[^/]+)?$", "high", "file", "Environment secrets (.env) file",
     lambda p: not p.endswith((".example", ".sample", ".template", ".dist"))),
    (r"\.(pem|key|p12|pfx|jks|keystore|ppk|kdbx)$", "high", "file", "Private key / keystore / vault file", None),
    (r"(^|/)(credentials?|secrets?|service[-_]?account)[^/]*\.(json|ya?ml|txt|xml|ini|toml)$", "high", "file", "Credentials / secrets file", None),
    (r"(^|/)(\.npmrc|\.pypirc|\.netrc|\.htpasswd|wp-config\.php|\.pgpass|\.my\.cnf)$", "high", "file", "Config file with credentials", None),
    (r"(^|/)(passwords?|logins?|accounts?|recovery[-_]?codes?|backup[-_]?codes?)[^/]*\.(txt|csv|xlsx?|json|md)$", "high", "file", "Password / recovery list", None),
    (r"(^|/)(\.bash_history|\.zsh_history|consolehost_history\.txt)$", "high", "pii", "Shell command history file", None),
    (r"(^|/).*(nid|passport|national[-_ ]?id|birth[-_ ]?cert|driving[-_ ]?licen[cs]e|aadhaar|ssn|bank[-_ ]?statement)[^/]*\.(jpe?g|png|pdf|webp|heic)$", "high", "pii", "Possible personal ID / financial document", None),
    (r"(^|/).*(cv|resume|biodata)[^/]*\.(pdf|docx?|txt)$", "medium", "pii", "Resume / personal bio document", None),
    (r"(google-services\.json|googleservice-info\.plist|firebase[-_]?config\.js)$", "medium", "file", "Firebase config file", None),
    (r"\.(sqlite3?|db|db3|sql|bak|dump)$", "medium", "file", "Database / backup dump", None),
    (r"(^|/)\.ssh/", "high", "file", ".ssh directory included", None),
    (r"(^|/)(thumbs\.db|\.ds_store|desktop\.ini)$", "low", "github", "OS junk file (add to .gitignore)", None),
]
FILE_COMPILED = [(re.compile(rx), s, c, lbl, v) for rx, s, c, lbl, v in FILE_RULES]

GITHUB_DIR_FLAGS = [
    ("/.git/", "high", ".git folder included", "Contains full commit history and possibly deleted secrets", ".git/"),
    ("/node_modules/", "medium", "node_modules folder included", "Large dependency folder should not be pushed to GitHub", "node_modules/"),
    ("/__pycache__/", "low", "__pycache__ folder included", "Compiled Python cache should be ignored", "__pycache__/"),
    ("/.venv/", "medium", "Python virtualenv (.venv) included", "Local virtual environment leaks system paths", ".venv/"),
    ("/venv/", "medium", "Python virtualenv (venv) included", "Local virtual environment leaks system paths", "venv/"),
    ("/.idea/", "low", "JetBrains .idea folder included", "IDE config may contain local paths", ".idea/"),
]

ASCII_STR_RX = re.compile(rb"[\x20-\x7e]{6,}")
UTF16_STR_RX = re.compile(rb"(?:[\x20-\x7e]\x00){6,}")
PDF_META_RX = re.compile(rb"/(Author|Creator|Producer|Title|Subject)\s*\(([^)]{2,200})\)")
OFFICE_META_RX = re.compile(r"<(?:dc:creator|cp:lastModifiedBy|dc:title)>([^<]{2,150})</(?:dc:creator|cp:lastModifiedBy|dc:title)>", re.I)


def mask(s):
    s = s.strip()
    if len(s) <= 6:
        return s[:2] + "*" * max(1, len(s) - 2)
    if len(s) <= 12:
        return s[:3] + "*" * (len(s) - 5) + s[-2:]
    return s[:4] + "*" * min(len(s) - 7, 14) + s[-3:]


def snippet(text, start, end, shown):
    a = max(0, start - 35, text.rfind("\n", 0, start) + 1)
    nl = text.find("\n", end)
    b = min(len(text), end + 35, nl if nl != -1 else len(text))
    out = text[a:start] + shown + text[end:b]
    return re.sub(r"\s+", " ", out).strip()[:180]


def make_full_path(root_label, rel_path):
    if not root_label:
        return rel_path
    if os.path.isdir(root_label):
        return os.path.normpath(os.path.join(root_label, rel_path.replace("/", os.sep)))
    return root_label + " :: " + rel_path


class ScanState:
    def __init__(self, scan_id, root_label, terms, mode, disk_root, temp_zip=False):
        self.scan_id = scan_id
        self.root_label = root_label
        self.mode = mode
        self.disk_root = disk_root
        self.temp_zip = temp_zip
        self.extract_dir = os.path.join(SESSION_ROOT, "ext_" + scan_id)
        self.terms = [(t, re.compile(re.escape(t), re.I)) for t in terms]
        self.lock = threading.Lock()
        self.findings = []
        self.notes = []
        self.seen = set()
        self.dir_flagged = set()
        self.gitignore_suggestions = set()
        self.files_scanned = 0
        self.entries = 0
        self.bytes_scanned = 0
        self.truncated = False
        self.status = "scanning"
        self.current_file = ""
        self.error = None
        self.started_at = time.time()
        self.finished_at = None

    def add_items(self, items, gitignore_add=None):
        with self.lock:
            if gitignore_add:
                self.gitignore_suggestions.update(gitignore_add)
            for sev, cat, label, rel_path, line, prev in items:
                if len(self.findings) >= MAX_FINDINGS:
                    self.truncated = True
                    return
                key = (label, rel_path, line, prev)
                if key in self.seen:
                    continue
                self.seen.add(key)
                self.findings.append({
                    "severity": sev,
                    "category": cat,
                    "type": label,
                    "file": rel_path,
                    "full_path": make_full_path(self.root_label, rel_path),
                    "line": line,
                    "preview": prev,
                })

    def add_note(self, rel_path, reason):
        with self.lock:
            if len(self.notes) < 3000:
                self.notes.append({
                    "file": rel_path,
                    "full_path": make_full_path(self.root_label, rel_path),
                    "reason": reason,
                })

    def flag_dir_once(self, token, sev, label, rel_path, preview, gi):
        with self.lock:
            if token in self.dir_flagged:
                return
            self.dir_flagged.add(token)
            if gi:
                self.gitignore_suggestions.add(gi)
            self.findings.append({
                "severity": sev,
                "category": "github",
                "type": label,
                "file": rel_path,
                "full_path": make_full_path(self.root_label, rel_path),
                "line": None,
                "preview": preview,
            })

    def bump(self, scanned_delta=0, bytes_delta=0, current=None):
        with self.lock:
            self.files_scanned += scanned_delta
            self.bytes_scanned += bytes_delta
            if current is not None:
                self.current_file = current

    def build_report(self):
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        with self.lock:
            findings = sorted(
                self.findings,
                key=lambda f: (order[f["severity"]], f["file"], f["line"] or 0),
            )
            counts = {k: 0 for k in order}
            cats = {"secret": 0, "pii": 0, "github": 0, "file": 0, "metadata": 0}
            pii_files = set()
            flagged_files = set()
            for f in findings:
                counts[f["severity"]] += 1
                cats[f["category"]] = cats.get(f["category"], 0) + 1
                flagged_files.add(f["file"])
                if f["category"] == "pii":
                    pii_files.add(f["file"])
            elapsed = round((self.finished_at or time.time()) - self.started_at, 2)
            gi = sorted(self.gitignore_suggestions)
            return {
                "scan_id": self.scan_id,
                "credit": APP_CREDIT,
                "mode": self.mode,
                "root": self.root_label,
                "summary": {
                    "files_scanned": self.files_scanned,
                    "files_flagged": len(flagged_files),
                    "pii_files": len(pii_files),
                    "notes_count": len(self.notes),
                    "entries": self.entries,
                    "mb_scanned": round(self.bytes_scanned / 1048576.0, 2),
                    "elapsed_sec": elapsed,
                    "counts": counts,
                    "categories": cats,
                    "truncated": self.truncated,
                },
                "gitignore": "\n".join(gi),
                "findings": findings,
                "notes": self.notes,
            }


def check_path_rules(rel_path, size_bytes, state):
    low = "/" + rel_path.lower().replace("\\", "/")
    out = []
    gi = set()
    for token, sev, label, prev, gi_line in GITHUB_DIR_FLAGS:
        if token in low:
            state.flag_dir_once(token, sev, label, rel_path, prev, gi_line)
    if size_bytes >= GITHUB_BLOCK_BYTES:
        out.append(("critical", "github", "File exceeds GitHub 100 MB limit", rel_path, None,
                    "%.1f MB - GitHub will reject pushing this file without Git LFS" % (size_bytes / 1048576.0)))
        gi.add(rel_path)
    elif size_bytes >= GITHUB_WARN_BYTES:
        out.append(("high", "github", "Large file (> 50 MB GitHub warning)", rel_path, None,
                    "%.1f MB - GitHub warns on files larger than 50 MB" % (size_bytes / 1048576.0)))
    for rx, sev, cat, label, valid in FILE_COMPILED:
        if rx.search(rel_path.lower()) and (valid is None or valid(rel_path.lower())):
            out.append((sev, cat, label, rel_path, None, "Sensitive filename detected"))
            base = posixpath.basename(rel_path)
            if base.startswith(".env"):
                gi.add(".env*")
            elif base.lower() in ("thumbs.db", ".ds_store", "desktop.ini"):
                gi.add(base)
            elif rel_path.lower().endswith((".pem", ".key", ".p12", ".pfx", ".sqlite", ".sqlite3", ".db")):
                gi.add("*" + posixpath.splitext(base)[1])
            break
    for term, trx in state.terms:
        if trx.search(rel_path):
            out.append(("high", "pii", "Your personal term in file path", rel_path, None, mask(term)))
    if out or gi:
        state.add_items(out, gi)


def scan_text_content(rel_path, text, state, binary_mode=False):
    starts = [0] + [m.end() for m in re.finditer("\n", text)] if not binary_mode else None
    counts = {}
    out = []

    def line_of(pos):
        if starts is None:
            return None
        return bisect.bisect_right(starts, pos)

    def push(sev, cat, label, s, e, shown):
        n = counts.get(label, 0)
        if n >= PER_TYPE_PER_FILE:
            return
        counts[label] = n + 1
        out.append((sev, cat, label, rel_path, line_of(s), snippet(text, s, e, shown)))

    for label, sev, cat, rx, grp, valid, allow_bin in COMPILED:
        if binary_mode and not allow_bin:
            continue
        for m in rx.finditer(text):
            val = m.group(grp)
            if valid and not valid(val):
                continue
            s, e = m.start(grp), m.end(grp)
            shown = val if label in ("Private key block", "Windows local username path", "macOS / Linux local username path") else mask(val)
            push(sev, cat, label, s, e, shown)

    for term, trx in state.terms:
        for m in trx.finditer(text):
            push("high", "pii", "Your custom personal term", m.start(), m.end(), mask(m.group(0)))

    if rel_path.lower().endswith(("docprops/core.xml", "meta.xml")):
        for m in OFFICE_META_RX.finditer(text):
            val = m.group(1).strip()
            if val:
                push("medium", "pii", "Document author metadata", m.start(1), m.end(1), val)

    if rel_path.lower().endswith((".git/config", ".gitconfig")):
        for m in re.finditer(r"(?im)^\s*(?:name|email)\s*=\s*(.+)$", text):
            push("medium", "pii", "Git identity metadata", m.start(1), m.end(1), m.group(1).strip())

    if out:
        state.add_items(out)


def parse_png_metadata(rel_path, data, state):
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        return
    pos = 8
    chunks_text = []
    out = []
    n = len(data)
    while pos + 12 <= n:
        length = struct.unpack(">I", data[pos:pos + 4])[0]
        ctype = data[pos + 4:pos + 8]
        cdata = data[pos + 8:pos + 8 + length]
        pos += 12 + length
        if ctype == b"tEXt":
            parts = cdata.split(b"\x00", 1)
            if len(parts) == 2:
                k = parts[0].decode("latin-1", "replace")
                v = parts[1].decode("utf-8", "replace")
                chunks_text.append(k + ": " + v)
                if k.lower() in ("author", "artist", "copyright", "comment", "description", "source", "software"):
                    out.append(("medium", "metadata", "PNG metadata (" + k + ")", rel_path, None, v[:140]))
        elif ctype == b"zTXt":
            parts = cdata.split(b"\x00", 1)
            if len(parts) == 2 and len(parts[1]) > 1:
                k = parts[0].decode("latin-1", "replace")
                try:
                    v = zlib.decompress(parts[1][1:]).decode("utf-8", "replace")
                    chunks_text.append(k + ": " + v)
                    out.append(("medium", "metadata", "PNG compressed metadata (" + k + ")", rel_path, None, v[:140]))
                except Exception:
                    pass
        elif ctype == b"iTXt":
            parts = cdata.split(b"\x00", 5)
            if len(parts) >= 6:
                k = parts[0].decode("latin-1", "replace")
                comp = parts[1] == b"\x01"
                raw_v = parts[5]
                try:
                    if comp:
                        raw_v = zlib.decompress(raw_v)
                    v = raw_v.decode("utf-8", "replace")
                    chunks_text.append(k + ": " + v)
                    out.append(("medium", "metadata", "PNG international metadata (" + k + ")", rel_path, None, v[:140]))
                except Exception:
                    pass
        elif ctype == b"IEND":
            break
    if out:
        state.add_items(out)
    if chunks_text:
        scan_text_content(rel_path, "\n".join(chunks_text), state, binary_mode=True)


def _read_tiff_ascii(tiff, offset, count):
    if count <= 4:
        return ""
    if offset + count > len(tiff):
        return ""
    return tiff[offset:offset + count].split(b"\x00", 1)[0].decode("utf-8", "replace").strip()


def parse_jpeg_metadata(rel_path, data, state):
    if not data.startswith(b"\xff\xd8"):
        return
    pos = 2
    n = len(data)
    out = []
    extra_text = []
    tag_names = {
        0x010F: "Camera Make",
        0x0110: "Camera Model",
        0x0131: "Software",
        0x0132: "Capture Date",
        0x013B: "Author / Artist",
        0x8298: "Copyright",
    }
    while pos + 4 <= n:
        if data[pos] != 0xFF:
            break
        marker = data[pos + 1]
        if marker in (0xD9, 0xDA):
            break
        if marker in (0xD8, 0x01) or (0xD0 <= marker <= 0xD7):
            pos += 2
            continue
        seg_len = struct.unpack(">H", data[pos + 2:pos + 4])[0]
        seg = data[pos + 4:pos + 2 + seg_len]
        pos += 2 + seg_len
        if marker == 0xFE:
            txt = seg.decode("utf-8", "replace").strip()
            if txt:
                extra_text.append(txt)
                out.append(("low", "metadata", "JPEG comment metadata", rel_path, None, txt[:140]))
        elif marker == 0xE1:
            if seg.startswith(b"Exif\x00\x00") and len(seg) > 14:
                tiff = seg[6:]
                endian = "<" if tiff[:2] == b"II" else (">" if tiff[:2] == b"MM" else None)
                if endian:
                    try:
                        ifd0 = struct.unpack(endian + "I", tiff[4:8])[0]
                        if ifd0 + 2 <= len(tiff):
                            entries = struct.unpack(endian + "H", tiff[ifd0:ifd0 + 2])[0]
                            for i in range(min(entries, 128)):
                                ep = ifd0 + 2 + i * 12
                                if ep + 12 > len(tiff):
                                    break
                                tag, typ, cnt, val_off = struct.unpack(endian + "HHII", tiff[ep:ep + 12])
                                if tag == 0x8825:
                                    out.append(("high", "pii", "Image EXIF GPS location data", rel_path, None,
                                                "Photo contains embedded GPS coordinates - strip EXIF before GitHub upload"))
                                elif tag in tag_names and typ == 2:
                                    if cnt <= 4:
                                        txt = tiff[ep + 8:ep + 8 + cnt].split(b"\x00", 1)[0].decode("utf-8", "replace").strip()
                                    else:
                                        txt = _read_tiff_ascii(tiff, val_off, cnt)
                                    if txt:
                                        sev = "medium" if tag in (0x013B, 0x8298) else "low"
                                        cat = "pii" if tag in (0x013B, 0x8298) else "metadata"
                                        out.append((sev, cat, "Image EXIF " + tag_names[tag], rel_path, None, txt[:140]))
                                        extra_text.append(txt)
                    except Exception:
                        pass
            elif seg.startswith(b"http://ns.adobe.com/xap/1.0/\x00"):
                xmp = seg[29:].decode("utf-8", "replace")
                extra_text.append(xmp)
    if out:
        state.add_items(out)
    if extra_text:
        scan_text_content(rel_path, "\n".join(extra_text), state, binary_mode=True)


def parse_pdf_content(rel_path, data, state):
    out = []
    chunks = []
    for m in PDF_META_RX.finditer(data):
        k = m.group(1).decode("latin-1", "replace")
        v = m.group(2).decode("utf-8", "replace").strip()
        if v:
            sev = "medium" if k in ("Author", "Creator") else "low"
            cat = "pii" if k == "Author" else "metadata"
            out.append((sev, cat, "PDF metadata (" + k + ")", rel_path, None, v[:140]))
            chunks.append(v)
    pos = 0
    total_extracted = 0
    while total_extracted < 4 * 1024 * 1024:
        s = data.find(b"stream", pos)
        if s == -1:
            break
        start = s + 6
        if start < len(data) and data[start:start + 2] == b"\r\n":
            start += 2
        elif start < len(data) and data[start:start + 1] in (b"\n", b"\r"):
            start += 1
        e = data.find(b"endstream", start)
        if e == -1:
            break
        pos = e + 9
        raw = data[start:e].strip()
        if not raw or len(raw) > 10 * 1024 * 1024:
            continue
        decomp = raw
        try:
            decomp = zlib.decompress(raw)
        except Exception:
            try:
                decomp = zlib.decompress(raw, -zlib.MAX_WBITS)
            except Exception:
                pass
        if len(decomp) <= 5 * 1024 * 1024:
            strings = re.findall(rb"\(([^()\\]*(?:\\.[^()\\]*)*)\)", decomp)
            if strings:
                joined = b" ".join(strings).decode("utf-8", "replace")
                chunks.append(joined)
                total_extracted += len(joined)
            else:
                ascii_hits = ASCII_STR_RX.findall(decomp)
                if ascii_hits:
                    joined = b"\n".join(ascii_hits[:2000]).decode("latin-1", "replace")
                    chunks.append(joined)
                    total_extracted += len(joined)
    if out:
        state.add_items(out)
    if chunks:
        scan_text_content(rel_path, "\n".join(chunks), state, binary_mode=False)


def parse_sqlite_content(rel_path, data, state):
    if not data.startswith(b"SQLite format 3\x00"):
        return False
    fd, tmp_path = tempfile.mkstemp(prefix="sq_", suffix=".db", dir=SESSION_ROOT)
    conn = None
    try:
        os.write(fd, data)
        os.close(fd)
        conn = sqlite3.connect("file:%s?mode=ro" % urllib.parse.quote(tmp_path.replace("\\", "/")), uri=True)
        cur = conn.cursor()
        tables = [r[0] for r in cur.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
        collected = []
        total_chars = 0
        for tbl in tables[:100]:
            collected.append("TABLE " + str(tbl))
            safe_tbl = tbl.replace('"', '""')
            try:
                rows = cur.execute('SELECT * FROM "%s" LIMIT 2500' % safe_tbl).fetchall()
                for row in rows:
                    line = " | ".join(str(v) for v in row if v is not None and not isinstance(v, bytes))
                    if line:
                        collected.append(line)
                        total_chars += len(line)
                    if total_chars > 3 * 1024 * 1024:
                        break
            except Exception:
                pass
            if total_chars > 3 * 1024 * 1024:
                break
        if collected:
            scan_text_content(rel_path, "\n".join(collected), state, binary_mode=False)
        return True
    except Exception:
        return False
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass
        try:
            os.unlink(tmp_path)
        except Exception:
            pass


def extract_binary_strings(data):
    parts = []
    a_hits = ASCII_STR_RX.findall(data[:8 * 1024 * 1024])
    if a_hits:
        parts.append(b"\n".join(a_hits[:15000]).decode("latin-1", "replace"))
    u_hits = UTF16_STR_RX.findall(data[:4 * 1024 * 1024])
    if u_hits:
        parts.append("\n".join(x.decode("utf-16-le", "replace") for x in u_hits[:6000]))
    return "\n".join(parts)


def decode_text_if_plain(data):
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return data.decode("utf-16", errors="replace")
    if data[:3] == b"\xef\xbb\xbf":
        return data[3:].decode("utf-8", errors="replace")
    sample = data[:8192]
    if b"\x00" in sample:
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        ctrl = sum(1 for b in sample if b < 9 or (13 < b < 32))
        if len(sample) > 0 and (ctrl / len(sample)) > 0.2:
            return None
        return data.decode("latin-1", errors="replace")


def analyze_blob(rel_path, data, depth, state):
    state.bump(current=rel_path)
    ext = posixpath.splitext(rel_path.lower())[1]
    low = rel_path.lower()

    if depth < MAX_DEPTH and len(data) <= MAX_NESTED:
        if ext in ZIP_LIKE_EXT or data[:4] == b"PK\x03\x04":
            try:
                with zipfile.ZipFile(io.BytesIO(data)) as inner:
                    scan_zip_obj(inner, rel_path + "!/", depth + 1, state)
                return
            except Exception:
                pass
        if low.endswith((".tar.gz", ".tar.bz2", ".tar.xz")) or ext in TAR_EXT:
            try:
                with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tf:
                    scan_tar_obj(tf, rel_path + "!/", depth + 1, state)
                return
            except Exception:
                pass
        if ext in SINGLE_COMP_EXT:
            try:
                if ext == ".gz":
                    inner_data = gzip.decompress(data)
                elif ext == ".bz2":
                    inner_data = bz2.decompress(data)
                else:
                    inner_data = lzma.decompress(data)
                if len(inner_data) <= MAX_FILE:
                    inner_name = posixpath.splitext(rel_path)[0] or (rel_path + ".decompressed")
                    analyze_blob(rel_path + "!/" + posixpath.basename(inner_name), inner_data, depth + 1, state)
                    return
            except Exception:
                pass

    state.bump(scanned_delta=1, bytes_delta=len(data))

    if ext == ".pdf" or data[:5] == b"%PDF-":
        parse_pdf_content(rel_path, data, state)
        return

    if ext in IMAGE_EXT or data[:8] == b"\x89PNG\r\n\x1a\n" or data[:2] == b"\xff\xd8":
        parse_png_metadata(rel_path, data, state)
        parse_jpeg_metadata(rel_path, data, state)
        extracted = extract_binary_strings(data[:512 * 1024])
        if extracted:
            scan_text_content(rel_path, extracted, state, binary_mode=True)
        return

    if ext in SQLITE_EXT or data[:16] == b"SQLite format 3\x00":
        if parse_sqlite_content(rel_path, data, state):
            return

    text = decode_text_if_plain(data)
    if text is not None:
        scan_text_content(rel_path, text, state, binary_mode=False)
    else:
        extracted = extract_binary_strings(data)
        if extracted:
            scan_text_content(rel_path, extracted, state, binary_mode=True)


def scan_tar_obj(tf, prefix, depth, state):
    for member in tf.getmembers():
        if state.entries >= MAX_ENTRIES:
            state.add_note(prefix, "entry limit reached")
            return
        state.entries += 1
        if not member.isfile():
            continue
        rel_path = prefix + member.name.lstrip("/")
        check_path_rules(rel_path, member.size, state)
        if member.size > MAX_FILE:
            state.add_note(rel_path, "exceeds 100 MB per-file inspection limit (path & size still checked)")
            continue
        try:
            f = tf.extractfile(member)
            if f is None:
                continue
            data = f.read(MAX_FILE + 1)
            if len(data) <= MAX_FILE:
                analyze_blob(rel_path, data, depth, state)
        except Exception as e:
            state.add_note(rel_path, "unreadable: " + type(e).__name__)


def scan_zip_obj(zf, prefix, depth, state, pool=None):
    futures = set()
    max_in_flight = MAX_WORKERS * 4
    for info in zf.infolist():
        if state.entries >= MAX_ENTRIES:
            state.add_note(prefix, "entry limit reached")
            break
        state.entries += 1
        if info.is_dir():
            continue
        rel_path = prefix + info.filename
        check_path_rules(rel_path, info.file_size, state)
        if info.flag_bits & 0x1:
            state.add_items([("high", "file", "Encrypted zip entry (cannot scan contents)", rel_path, None,
                              "Password-protected entry inside archive")])
            state.add_note(rel_path, "password-protected entry")
            continue
        ext = posixpath.splitext(info.filename.lower())[1]
        is_nested = ext in ZIP_LIKE_EXT or ext in TAR_EXT or ext in SINGLE_COMP_EXT or info.filename.lower().endswith((".tar.gz", ".tar.bz2", ".tar.xz"))
        size_cap = MAX_NESTED if (is_nested and depth < MAX_DEPTH) else MAX_FILE
        if info.file_size > size_cap:
            state.add_note(rel_path, "larger than %.0f MB inspection cap (path & GitHub size still checked)" % (size_cap / 1048576.0))
            continue
        if state.bytes_scanned >= MAX_TOTAL:
            state.add_note(rel_path, "total byte cap reached")
            continue
        try:
            with zf.open(info) as f:
                data = f.read(size_cap + 1)
        except Exception as e:
            state.add_note(rel_path, "unreadable: " + type(e).__name__)
            continue
        if len(data) > size_cap:
            state.add_note(rel_path, "uncompressed data exceeded inspection cap")
            continue
        if pool is not None:
            futures.add(pool.submit(analyze_blob, rel_path, data, depth, state))
            if len(futures) >= max_in_flight:
                done, futures = concurrent.futures.wait(futures, return_when=concurrent.futures.FIRST_COMPLETED)
                for fut in done:
                    try:
                        fut.result()
                    except Exception as e:
                        state.add_note(rel_path, "worker error: " + type(e).__name__)
        else:
            analyze_blob(rel_path, data, depth, state)
    if futures:
        for fut in concurrent.futures.as_completed(futures):
            try:
                fut.result()
            except Exception as e:
                state.add_note(prefix, "worker error: " + type(e).__name__)


def _scan_disk_file(full_path, rel_path, size_bytes, state):
    check_path_rules(rel_path, size_bytes, state)
    ext = posixpath.splitext(rel_path.lower())[1]
    is_nested = ext in ZIP_LIKE_EXT or ext in TAR_EXT or ext in SINGLE_COMP_EXT or rel_path.lower().endswith((".tar.gz", ".tar.bz2", ".tar.xz"))
    cap = MAX_NESTED if is_nested else MAX_FILE
    if size_bytes > cap:
        state.add_note(rel_path, "larger than %.0f MB inspection cap (path & GitHub size still checked)" % (cap / 1048576.0))
        return
    try:
        with open(full_path, "rb") as f:
            data = f.read(cap + 1)
        if len(data) <= cap:
            analyze_blob(rel_path, data, 0, state)
    except Exception as e:
        state.add_note(rel_path, "unreadable: " + type(e).__name__)


def execute_scan_background(state):
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
            if state.mode == "zip":
                with zipfile.ZipFile(state.disk_root, "r") as zf:
                    scan_zip_obj(zf, "", 0, state, pool=pool)
            elif state.mode == "dir":
                futures = set()
                max_in_flight = MAX_WORKERS * 4
                for root, dirs, files in os.walk(state.disk_root):
                    for fn in files:
                        if state.entries >= MAX_ENTRIES:
                            state.add_note(state.root_label, "entry limit reached")
                            break
                        state.entries += 1
                        full = os.path.join(root, fn)
                        rel = os.path.relpath(full, state.disk_root).replace("\\", "/")
                        try:
                            sz = os.path.getsize(full)
                        except OSError:
                            continue
                        futures.add(pool.submit(_scan_disk_file, full, rel, sz, state))
                        if len(futures) >= max_in_flight:
                            done, futures = concurrent.futures.wait(futures, return_when=concurrent.futures.FIRST_COMPLETED)
                            for fut in done:
                                fut.result()
                for fut in concurrent.futures.as_completed(futures):
                    fut.result()
        state.finished_at = time.time()
        state.status = "done"
    except zipfile.BadZipFile:
        state.error = "Invalid or corrupted .zip archive."
        state.status = "error"
        state.finished_at = time.time()
    except Exception as e:
        state.error = "Scan failed: " + str(e)
        state.status = "error"
        state.finished_at = time.time()


def _read_entry_from_zip_chain(disk_zip, rel_path):
    parts = rel_path.split("!/")
    with open(disk_zip, "rb") as f:
        cur_blob = f.read()
    for idx, part in enumerate(parts):
        is_last = idx == len(parts) - 1
        bio = io.BytesIO(cur_blob)
        if zipfile.is_zipfile(bio):
            bio.seek(0)
            with zipfile.ZipFile(bio, "r") as zf:
                cur_blob = zf.read(part)
                if is_last:
                    return cur_blob
                continue
        bio.seek(0)
        try:
            with tarfile.open(fileobj=bio, mode="r:*") as tf:
                member = tf.getmember(part)
                fobj = tf.extractfile(member)
                cur_blob = fobj.read()
                if is_last:
                    return cur_blob
                continue
        except Exception:
            pass
        if is_last:
            return cur_blob
    raise FileNotFoundError(rel_path)


def _safe_extract_target(state, rel_path):
    if state.mode == "dir":
        target = os.path.normpath(os.path.join(state.disk_root, rel_path.replace("/", os.sep)))
        real_root = os.path.realpath(state.disk_root)
        real_target = os.path.realpath(target)
        if not (real_target == real_root or real_target.startswith(real_root + os.sep)):
            raise ValueError("Unsafe path")
        if not os.path.exists(real_target):
            raise FileNotFoundError(real_target)
        return real_target
    data = _read_entry_from_zip_chain(state.disk_root, rel_path)
    clean_parts = []
    for seg in rel_path.replace("!/", "/").replace("\\", "/").split("/"):
        seg = seg.strip()
        if not seg or seg in (".", ".."):
            continue
        seg = re.sub(r'[<>:"|?*]', "_", seg)
        clean_parts.append(seg)
    if not clean_parts:
        clean_parts = ["extracted_file"]
    dest = os.path.join(state.extract_dir, *clean_parts)
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    with open(dest, "wb") as f:
        f.write(data)
    return dest


def open_on_os(target_path, action="reveal"):
    sys_name = platform.system()
    if sys_name == "Windows":
        if action == "open":
            os.startfile(target_path)
        else:
            subprocess.Popen(["explorer", "/select,", os.path.normpath(target_path)])
    elif sys_name == "Darwin":
        if action == "open":
            subprocess.Popen(["open", target_path])
        else:
            subprocess.Popen(["open", "-R", target_path])
    else:
        if action == "open":
            subprocess.Popen(["xdg-open", target_path])
        else:
            subprocess.Popen(["xdg-open", os.path.dirname(target_path)])


def pick_local_path(kind):
    if kind == "dir":
        tk_code = (
            "import tkinter as tk, tkinter.filedialog as fd; "
            "r=tk.Tk(); r.withdraw(); r.attributes('-topmost', True); "
            "p=fd.askdirectory(title='Select Project Folder to Scan'); "
            "print(p or '')"
        )
    else:
        tk_code = (
            "import tkinter as tk, tkinter.filedialog as fd; "
            "r=tk.Tk(); r.withdraw(); r.attributes('-topmost', True); "
            "p=fd.askopenfilename(title='Select ZIP Archive to Scan', filetypes=[('ZIP archives','*.zip'),('All files','*.*')]); "
            "print(p or '')"
        )
    try:
        res = subprocess.run([sys.executable, "-c", tk_code], capture_output=True, text=True, timeout=180)
        if res.returncode == 0:
            return res.stdout.strip()
    except Exception:
        pass
    if platform.system() == "Windows":
        if kind == "dir":
            ps = (
                "Add-Type -AssemblyName System.Windows.Forms; "
                "$d = New-Object System.Windows.Forms.FolderBrowserDialog; "
                "if($d.ShowDialog() -eq 'OK'){ Write-Output $d.SelectedPath }"
            )
        else:
            ps = (
                "Add-Type -AssemblyName System.Windows.Forms; "
                "$d = New-Object System.Windows.Forms.OpenFileDialog; "
                "$d.Filter = 'ZIP files (*.zip)|*.zip|All files (*.*)|*.*'; "
                "if($d.ShowDialog() -eq 'OK'){ Write-Output $d.FileName }"
            )
        try:
            res = subprocess.run(["powershell", "-NoProfile", "-Command", ps], capture_output=True, text=True, timeout=180)
            if res.returncode == 0:
                return res.stdout.strip()
        except Exception:
            pass
    return ""


def get_file_preview(state, rel_path, target_line):
    if state.mode == "dir":
        full = _safe_extract_target(state, rel_path)
        with open(full, "rb") as f:
            data = f.read(2 * 1024 * 1024)
        disk_path = full
    else:
        data = _read_entry_from_zip_chain(state.disk_root, rel_path)
        disk_path = make_full_path(state.root_label, rel_path)
    text = decode_text_if_plain(data)
    if text is None:
        text = extract_binary_strings(data[:512 * 1024]) or "(Binary file - no printable text preview)"
    all_lines = text.splitlines()
    total = len(all_lines)
    if target_line and 1 <= target_line <= total:
        start = max(1, target_line - 25)
        end = min(total, target_line + 25)
    else:
        start = 1
        end = min(total, 120)
    out = [{"num": i, "text": all_lines[i - 1][:500]} for i in range(start, end + 1)]
    return {"disk_path": disk_path, "total_lines": total, "target_line": target_line, "lines": out}


def register_scan(state):
    with STATE_LOCK:
        SCANS[state.scan_id] = state
        SESSIONS[state.scan_id] = state
    t = threading.Thread(target=execute_scan_background, args=(state,), daemon=True)
    t.start()


class Handler(BaseHTTPRequestHandler):
    server_version = "GitShieldKhaled2026"

    def log_message(self, *a):
        pass

    def _trusted(self, require_token=False):
        host = (self.headers.get("Host") or "").lower()
        if host not in ("127.0.0.1:%d" % PORT, "localhost:%d" % PORT):
            return False
        origin = self.headers.get("Origin")
        if origin and origin.lower() not in ("http://127.0.0.1:%d" % PORT, "http://localhost:%d" % PORT):
            return False
        if require_token and self.headers.get("X-Token") != AUTH_TOKEN:
            return False
        return True

    def _send(self, code, body, ctype):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'",
        )
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code, obj):
        self._send(code, json.dumps(obj).encode("utf-8"), "application/json; charset=utf-8")

    def _read_json(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return None
        if length <= 0 or length > 2 * 1024 * 1024:
            return None
        raw = self.rfile.read(length)
        try:
            return json.loads(raw.decode("utf-8"))
        except Exception:
            return None

    def do_GET(self):
        if not self._trusted():
            return self._json(403, {"error": "Forbidden"})
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/":
            page = PAGE.replace("__AUTH_TOKEN__", AUTH_TOKEN).replace("__CREDIT__", APP_CREDIT)
            return self._send(200, page.encode("utf-8"), "text/html; charset=utf-8")
        if parsed.path.startswith("/status/"):
            if self.headers.get("X-Token") != AUTH_TOKEN:
                return self._json(403, {"error": "Forbidden"})
            sid = parsed.path.split("/status/", 1)[1]
            with STATE_LOCK:
                st = SCANS.get(sid)
            if not st:
                return self._json(404, {"error": "Scan not found"})
            if st.status == "done":
                return self._json(200, {"status": "done", "report": st.build_report()})
            if st.status == "error":
                return self._json(200, {"status": "error", "error": st.error})
            elapsed = max(0.01, time.time() - st.started_at)
            with st.lock:
                return self._json(200, {
                    "status": "scanning",
                    "files_scanned": st.files_scanned,
                    "entries": st.entries,
                    "findings_so_far": len(st.findings),
                    "mb_scanned": round(st.bytes_scanned / 1048576.0, 1),
                    "speed_fps": round(st.files_scanned / elapsed, 1),
                    "current_file": st.current_file,
                })
        self._json(404, {"error": "Not found"})

    def do_POST(self):
        if not self._trusted(require_token=True):
            return self._json(403, {"error": "Forbidden"})
        path = urllib.parse.urlparse(self.path).path

        if path == "/pick":
            body = self._read_json() or {}
            chosen = pick_local_path(body.get("kind", "zip"))
            return self._json(200, {"path": chosen})

        if path == "/scan-upload":
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                length = 0
            if length <= 0:
                return self._json(400, {"error": "Empty upload."})
            if length > MAX_UPLOAD:
                return self._json(413, {"error": "Zip exceeds 4 GB limit."})
            terms = []
            raw_terms = self.headers.get("X-Terms")
            if raw_terms:
                try:
                    terms = [t.strip() for t in json.loads(urllib.parse.unquote(raw_terms)) if t.strip()][:100]
                except Exception:
                    terms = []
            orig_name = urllib.parse.unquote(self.headers.get("X-Filename") or "uploaded.zip")
            sid = uuid.uuid4().hex[:12]
            tmp_zip = os.path.join(SESSION_ROOT, "up_" + sid + ".zip")
            left = length
            with open(tmp_zip, "wb") as out:
                while left > 0:
                    chunk = self.rfile.read(min(1024 * 1024, left))
                    if not chunk:
                        break
                    out.write(chunk)
                    left -= len(chunk)
            if not zipfile.is_zipfile(tmp_zip):
                try:
                    os.unlink(tmp_zip)
                except OSError:
                    pass
                return self._json(400, {"error": "Not a valid .zip archive."})
            state = ScanState(sid, orig_name, terms, "zip", tmp_zip, temp_zip=True)
            register_scan(state)
            return self._json(200, {"scan_id": sid})

        if path == "/scan-local":
            body = self._read_json()
            if not body:
                return self._json(400, {"error": "Invalid JSON body."})
            target = (body.get("path") or "").strip().strip('"').strip("'")
            terms = [t.strip() for t in (body.get("terms") or []) if isinstance(t, str) and t.strip()][:100]
            if not target or not os.path.exists(target):
                return self._json(400, {"error": "Path does not exist on this computer."})
            sid = uuid.uuid4().hex[:12]
            if os.path.isdir(target):
                state = ScanState(sid, os.path.abspath(target), terms, "dir", os.path.abspath(target), temp_zip=False)
                register_scan(state)
                return self._json(200, {"scan_id": sid})
            if os.path.isfile(target) and zipfile.is_zipfile(target):
                state = ScanState(sid, os.path.abspath(target), terms, "zip", os.path.abspath(target), temp_zip=False)
                register_scan(state)
                return self._json(200, {"scan_id": sid})
            return self._json(400, {"error": "Selected path must be a folder or valid .zip archive."})

        if path == "/open":
            body = self._read_json() or {}
            sid = body.get("scan_id")
            rel = body.get("file") or ""
            action = body.get("action") or "reveal"
            with STATE_LOCK:
                st = SESSIONS.get(sid)
            if not st:
                return self._json(404, {"error": "Scan session expired. Please rescan."})
            try:
                disk_path = _safe_extract_target(st, rel)
                open_on_os(disk_path, action=action)
                return self._json(200, {"ok": True, "disk_path": disk_path})
            except Exception as e:
                return self._json(500, {"error": "Could not open file: " + str(e)})

        if path == "/preview":
            body = self._read_json() or {}
            sid = body.get("scan_id")
            rel = body.get("file") or ""
            line = body.get("line")
            with STATE_LOCK:
                st = SESSIONS.get(sid)
            if not st:
                return self._json(404, {"error": "Scan session expired."})
            try:
                data = get_file_preview(st, rel, line)
                return self._json(200, data)
            except Exception as e:
                return self._json(500, {"error": "Preview unavailable: " + str(e)})

        self._json(404, {"error": "Not found"})


class ReusableThreadingHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


PAGE = r"""<!doctype html>
<html lang="en" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>GitShield ZIP Scanner — __CREDIT__</title>
<style>
:root{
  --bg:#090c14; --panel:#111625; --panel-2:#171d31; --ink:#f1f5f9; --muted:#94a3b8; --line:#232c45; --soft:#0e1320;
  --accent:#6366f1; --accent-2:#06b6d4; --accent-ink:#ffffff;
  --crit:#ef4444; --high:#f97316; --med:#eab308; --low:#38bdf8; --ok:#22c55e; --pii:#ec4899;
  --crit-bg:#2a1215; --high-bg:#2b190d; --med-bg:#29230b; --low-bg:#0d2236; --ok-bg:#0d2618;
  --shadow:0 10px 30px rgba(0,0,0,.45);
  --mono:ui-monospace,"Cascadia Code",Consolas,Menlo,monospace;
}
[data-theme="light"]{
  --bg:#f4f6fb; --panel:#ffffff; --panel-2:#f8fafc; --ink:#0f172a; --muted:#64748b; --line:#e2e8f0; --soft:#eef2f7;
  --accent:#4f46e5; --accent-2:#0891b2; --accent-ink:#ffffff;
  --crit:#dc2626; --high:#ea580c; --med:#ca8a04; --low:#0284c7; --ok:#16a34a; --pii:#db2777;
  --crit-bg:#fef2f2; --high-bg:#fff7ed; --med-bg:#fefce8; --low-bg:#f0f9ff; --ok-bg:#f0fdf4;
  --shadow:0 8px 24px rgba(15,23,42,.08);
}
*{box-sizing:border-box}
html,body{margin:0;min-height:100%}
body{background:var(--bg);color:var(--ink);font:14.5px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;-webkit-font-smoothing:antialiased}
body::before{content:"";position:fixed;inset:0 0 auto 0;height:360px;background:radial-gradient(70% 100% at 50% 0,color-mix(in srgb,var(--accent) 22%,transparent),transparent);pointer-events:none}
main{position:relative;max-width:1120px;margin:0 auto;padding:28px 20px 80px}
header{display:flex;align-items:center;gap:14px;flex-wrap:wrap;margin-bottom:24px}
.logo{width:48px;height:48px;border-radius:14px;display:grid;place-items:center;color:#fff;background:linear-gradient(135deg,var(--accent),var(--accent-2));box-shadow:0 6px 20px color-mix(in srgb,var(--accent) 45%,transparent)}
.logo svg{width:26px;height:26px}
h1{font-size:23px;margin:0;letter-spacing:-.02em}
.sub{color:var(--muted);margin:2px 0 0;font-size:13.5px}
.hdr-right{margin-left:auto;display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.pill{display:inline-flex;align-items:center;gap:6px;font-size:12px;font-weight:600;border-radius:999px;padding:5px 11px;border:1px solid var(--line);background:var(--panel)}
.pill.ok{color:var(--ok);background:var(--ok-bg);border-color:color-mix(in srgb,var(--ok) 35%,transparent)}
.pill.ok i{width:7px;height:7px;border-radius:50%;background:var(--ok)}
.pill.credit{color:var(--accent-2);border-color:color-mix(in srgb,var(--accent-2) 35%,transparent)}
select.lang,button.icon-btn{background:var(--panel);color:var(--ink);border:1px solid var(--line);border-radius:10px;padding:6px 10px;font:inherit;font-size:12.5px;font-weight:600;cursor:pointer}
select.lang:hover,button.icon-btn:hover{border-color:var(--accent)}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:18px;padding:22px;box-shadow:var(--shadow)}
.grid-in{display:grid;grid-template-columns:1.25fr 1fr;gap:18px}
#drop{position:relative;border:2px dashed var(--line);border-radius:14px;padding:30px 16px;text-align:center;cursor:pointer;background:var(--soft);transition:border-color .15s,background .15s,transform .15s;display:flex;flex-direction:column;justify-content:center;align-items:center}
#drop:hover,#drop.over{border-color:var(--accent);background:color-mix(in srgb,var(--accent) 10%,var(--soft))}
#drop.over{transform:scale(1.01)}
.up{width:52px;height:52px;margin-bottom:10px;border-radius:50%;display:grid;place-items:center;color:var(--accent-2);background:color-mix(in srgb,var(--accent) 16%,transparent)}
.up svg{width:24px;height:24px}
#drop b{font-size:16px}
#drop span{color:var(--muted);font-size:13px;margin-top:3px}
.pick-row{display:flex;gap:8px;flex-wrap:wrap;justify-content:center;margin-top:14px}
.local-box{display:flex;flex-direction:column;gap:10px;background:var(--soft);border:1px solid var(--line);border-radius:14px;padding:16px}
.local-box h3{margin:0;font-size:14.5px}
.local-box p{margin:0;font-size:12.5px;color:var(--muted)}
.path-row{display:flex;gap:8px}
.path-row input{flex:1;min-width:0;border:1px solid var(--line);border-radius:10px;padding:9px 11px;background:var(--panel);color:var(--ink);font:12.5px var(--mono)}
.path-row input:focus,textarea:focus,input[type=search]:focus{outline:none;border-color:var(--accent)}
.btn{border:1px solid var(--line);background:var(--panel-2);color:var(--ink);border-radius:10px;padding:8px 13px;font:inherit;font-weight:600;font-size:13px;cursor:pointer;display:inline-flex;align-items:center;gap:6px;transition:border-color .15s,filter .15s}
.btn:hover{border-color:var(--accent)}
.btn.primary{background:linear-gradient(135deg,var(--accent),var(--accent-2));color:#fff;border-color:transparent}
.btn.primary:hover{filter:brightness(1.08)}
.btn.sm{padding:5px 10px;font-size:12px;border-radius:8px}
.btn.pii-btn{border-color:color-mix(in srgb,var(--pii) 45%,var(--line));color:var(--pii)}
label.t{display:block;margin:18px 0 6px;font-weight:600;font-size:13.5px}
textarea{width:100%;min-height:68px;resize:vertical;border:1px solid var(--line);border-radius:12px;padding:10px 12px;background:var(--soft);color:var(--ink);font:12.5px/1.5 var(--mono)}
.hint{color:var(--muted);font-size:12.5px;margin:5px 0 0}
#status{margin-top:16px;font-size:13.5px;color:var(--muted)}
#status:empty{display:none}
.prog-meta{display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;font-size:12.5px;margin-bottom:6px}
.prog-file{font-family:var(--mono);font-size:12px;color:var(--accent-2);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:100%;margin-top:6px}
.bar{height:8px;background:var(--soft);border-radius:999px;overflow:hidden}
.bar i{display:block;height:100%;width:0;border-radius:999px;background:linear-gradient(90deg,var(--accent),var(--accent-2));transition:width .15s}
.bar.busy i{width:35%!important;animation:slide 1s ease-in-out infinite}
@keyframes slide{0%{margin-left:-35%}100%{margin-left:100%}}
#results{margin-top:24px}
.verdict{display:flex;gap:16px;align-items:flex-start;border-radius:18px;padding:20px;border:1px solid var(--line);background:var(--panel);box-shadow:var(--shadow)}
.vi{flex:none;width:48px;height:48px;border-radius:14px;display:grid;place-items:center;color:#fff}
.vi svg{width:24px;height:24px}
.vb{flex:1;min-width:0}
.verdict h2{margin:0 0 4px;font-size:19px}
.verdict p{margin:0;color:var(--muted)}
.verdict.bad{border-color:color-mix(in srgb,var(--crit) 45%,var(--line));background:var(--crit-bg)}
.verdict.bad .vi{background:var(--crit)}
.verdict.warn{border-color:color-mix(in srgb,var(--med) 45%,var(--line));background:var(--med-bg)}
.verdict.warn .vi{background:var(--med)}
.verdict.ok{border-color:color-mix(in srgb,var(--ok) 40%,var(--line));background:var(--ok-bg)}
.verdict.ok .vi{background:var(--ok)}
.stats{display:flex;flex-wrap:wrap;gap:8px;margin-top:12px}
.stats span{font-size:12px;color:var(--ink);background:color-mix(in srgb,var(--panel) 80%,transparent);border:1px solid var(--line);border-radius:999px;padding:3px 10px}
.tiles{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-top:16px}
.tile{text-align:left;font:inherit;color:var(--ink);background:var(--panel);border:1px solid var(--line);border-top:3px solid var(--c);border-radius:14px;padding:12px 14px;cursor:pointer;transition:opacity .15s,transform .15s}
.tile:hover{transform:translateY(-1px)}
.tile[aria-pressed="false"]{opacity:.4}
.tile:disabled{opacity:.3;cursor:default;transform:none}
.tile b{display:block;font-size:25px;line-height:1.1;color:var(--c)}
.tile span{font-size:12.5px;color:var(--muted)}
.tile.critical{--c:var(--crit)}.tile.high{--c:var(--high)}.tile.medium{--c:var(--med)}.tile.low{--c:var(--low)}
.tabs{display:flex;gap:8px;flex-wrap:wrap;margin:18px 0 12px}
.tab{background:var(--panel);color:var(--muted);border:1px solid var(--line);border-radius:999px;padding:6px 13px;font:inherit;font-size:12.5px;font-weight:600;cursor:pointer}
.tab.active{background:var(--accent);color:#fff;border-color:transparent}
.tab.pii.active{background:var(--pii)}
.tools{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin:12px 0 14px}
input[type=search]{flex:1;min-width:200px;border:1px solid var(--line);border-radius:10px;padding:8px 12px;background:var(--panel);color:var(--ink);font:inherit}
.rows{display:grid;gap:10px}
.row{display:grid;gap:8px;padding:14px 16px;background:var(--panel);border:1px solid var(--line);border-left:4px solid var(--c);border-radius:12px}
.row.critical{--c:var(--crit)}.row.high{--c:var(--high)}.row.medium{--c:var(--med)}.row.low{--c:var(--low)}
.top{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.sev{font-size:10.5px;font-weight:700;letter-spacing:.04em;text-transform:uppercase;border-radius:999px;padding:2px 8px;color:var(--c);background:color-mix(in srgb,var(--c) 15%,transparent)}
.cat{font-size:10.5px;font-weight:700;text-transform:uppercase;border-radius:999px;padding:2px 8px;color:var(--accent-2);background:color-mix(in srgb,var(--accent-2) 14%,transparent)}
.cat.pii{color:var(--pii);background:color-mix(in srgb,var(--pii) 16%,transparent)}
.cat.github{color:var(--med);background:color-mix(in srgb,var(--med) 16%,transparent)}
.what{font-weight:600;font-size:14px}
.actions{margin-left:auto;display:flex;gap:6px;flex-wrap:wrap}
.where{font-family:var(--mono);font-size:12px;color:var(--accent-2);word-break:break-all;background:var(--soft);padding:6px 10px;border-radius:8px;border:1px solid var(--line)}
.prev{display:block;font-family:var(--mono);font-size:12px;background:var(--soft);border-radius:8px;padding:8px 10px;word-break:break-all;color:var(--ink)}
.file-group{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:15px 16px;display:grid;gap:10px}
.fg-head{display:flex;align-items:flex-start;gap:10px;flex-wrap:wrap}
.fg-path{font-family:var(--mono);font-size:12.5px;color:var(--accent-2);word-break:break-all;flex:1;min-width:220px}
.fg-badges{display:flex;gap:6px;flex-wrap:wrap}
.fg-list{display:grid;gap:6px;border-top:1px solid var(--line);padding-top:10px}
.fg-item{display:flex;align-items:center;gap:8px;flex-wrap:wrap;font-size:12.5px}
.empty{padding:28px;text-align:center;color:var(--muted);background:var(--panel);border:1px dashed var(--line);border-radius:12px}
details{margin-top:16px;background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:12px 16px}
summary{cursor:pointer;color:var(--ink);font-weight:600;font-size:13.5px}
.skips{font-family:var(--mono);font-size:12px;color:var(--muted);margin-top:10px;max-height:220px;overflow:auto}
.skips div{padding:3px 0;word-break:break-all}
.gi-box{font-family:var(--mono);font-size:12px;background:var(--soft);border:1px solid var(--line);border-radius:10px;padding:10px;margin-top:10px;white-space:pre-wrap}
footer{margin-top:36px;text-align:center;color:var(--muted);font-size:12.5px;border-top:1px solid var(--line);padding-top:16px}
.modal-bg{position:fixed;inset:0;background:rgba(0,0,0,.72);display:none;place-items:center;padding:20px;z-index:100}
.modal-bg.open{display:grid}
.modal{background:var(--panel);border:1px solid var(--line);border-radius:16px;width:min(920px,96vw);max-height:86vh;display:flex;flex-direction:column;overflow:hidden;box-shadow:var(--shadow)}
.modal-h{display:flex;align-items:center;gap:10px;padding:14px 16px;border-bottom:1px solid var(--line)}
.modal-path{font-family:var(--mono);font-size:12px;color:var(--accent-2);word-break:break-all;flex:1}
.modal-b{overflow:auto;padding:12px 0;background:var(--soft);font:12.5px/1.6 var(--mono)}
.code-ln{display:flex;padding:1px 14px;gap:14px}
.code-ln.hit{background:color-mix(in srgb,var(--crit) 24%,transparent);border-left:3px solid var(--crit)}
.code-num{color:var(--muted);min-width:44px;text-align:right;user-select:none}
.code-txt{white-space:pre-wrap;word-break:break-all;flex:1}
.toast{position:fixed;bottom:22px;right:22px;background:var(--panel-2);color:var(--ink);border:1px solid var(--accent);border-radius:10px;padding:10px 15px;font-size:13px;font-weight:600;box-shadow:var(--shadow);opacity:0;transform:translateY(10px);transition:opacity .2s,transform .2s;pointer-events:none;z-index:200}
.toast.show{opacity:1;transform:translateY(0)}
@media (max-width:780px){.grid-in{grid-template-columns:1fr}.tiles{grid-template-columns:repeat(2,1fr)}}
</style>
</head>
<body>
<main>
  <header>
    <div class="logo">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l8 3v6c0 4.5-3.2 8-8 9-4.8-1-8-4.5-8-9V6l8-3z"/><path d="M9 12l2 2 4-4"/></svg>
    </div>
    <div>
      <h1 data-i18n="title">GitShield ZIP Scanner</h1>
      <p class="sub" data-i18n="sub">Deep pre-GitHub security & personal info scanner. Scans archives, PDFs, images, SQLite & binaries.</p>
    </div>
    <div class="hdr-right">
      <span class="pill ok"><i></i><span data-i18n="localBadge">100% Local</span></span>
      <span class="pill credit">Created by __CREDIT__</span>
      <select id="langSel" class="lang" aria-label="Language">
        <option value="en">English</option>
        <option value="bn">বাংলা</option>
        <option value="es">Español</option>
        <option value="ar">العربية</option>
      </select>
      <button id="themeBtn" class="icon-btn" type="button">Theme</button>
    </div>
  </header>

  <div class="panel">
    <div class="grid-in">
      <div id="drop" tabindex="0" role="button">
        <div class="up">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 16V4"/><path d="M7 9l5-5 5 5"/><path d="M4 16v3a1 1 0 001 1h14a1 1 0 001-1v-3"/></svg>
        </div>
        <b data-i18n="dropTitle">Drop a .zip archive here</b>
        <span data-i18n="dropSub">Scans nested zips, PDFs, EXIF metadata, databases & binaries locally.</span>
        <div class="pick-row">
          <button type="button" class="btn primary" id="uploadBtn" data-i18n="chooseZip">Choose .zip File</button>
        </div>
      </div>

      <div class="local-box">
        <h3 data-i18n="directTitle">Fast Local Path / Folder Scan (Recommended)</h3>
        <p data-i18n="directSub">Zero upload delay. Shows exact full disk paths and opens files straight in Windows Explorer.</p>
        <div class="path-row">
          <input id="localPath" type="text" placeholder="C:\Users\...\project.zip or folder path">
          <button type="button" class="btn primary" id="scanPathBtn" data-i18n="scanNow">Scan</button>
        </div>
        <div class="pick-row" style="justify-content:flex-start;margin-top:4px">
          <button type="button" class="btn" id="pickZipBtn" data-i18n="browseZip">Browse Local .zip</button>
          <button type="button" class="btn" id="pickDirBtn" data-i18n="browseDir">Browse Project Folder</button>
        </div>
      </div>
    </div>
    <input id="file" type="file" accept=".zip,application/zip" hidden>

    <label class="t" for="terms" data-i18n="termsLabel">Your Personal Info / Custom Words to Hunt For (Recommended)</label>
    <textarea id="terms" placeholder="One per line: your full name, username, phone number, home address, personal email, secret keywords"></textarea>
    <p class="hint" data-i18n="termsHint">Searches inside filenames, code, PDFs, SQLite databases, image metadata, and compiled binaries.</p>

    <div id="status" aria-live="polite"></div>
  </div>

  <div id="results"></div>

  <footer>
    GitShield Advanced ZIP & GitHub Pre-Upload Scanner &bull; Created by <strong>__CREDIT__</strong> &bull; Runs 100% locally on your machine
  </footer>
</main>

<div id="modalBg" class="modal-bg">
  <div class="modal">
    <div class="modal-h">
      <div id="modalPath" class="modal-path"></div>
      <button id="modalReveal" class="btn sm primary" type="button" data-i18n="goToFile">Open in Explorer</button>
      <button id="modalClose" class="btn sm" type="button">Close</button>
    </div>
    <div id="modalBody" class="modal-b"></div>
  </div>
</div>

<div id="toast" class="toast"></div>

<script>
const TOKEN = '__AUTH_TOKEN__';
const CREDIT = '__CREDIT__';
const $ = s => document.querySelector(s);
const SEV = ['critical','high','medium','low'];

const I18N = {
  en: {
    title:'GitShield ZIP Scanner',
    sub:'Deep pre-GitHub security & personal info scanner. Scans archives, PDFs, images, SQLite & binaries.',
    localBadge:'100% Local',
    dropTitle:'Drop a .zip archive here',
    dropSub:'Scans nested zips, PDFs, EXIF metadata, databases & binaries locally.',
    chooseZip:'Choose .zip File',
    directTitle:'Fast Local Path / Folder Scan (Recommended)',
    directSub:'Zero upload delay. Shows exact full disk paths and opens files straight in Explorer.',
    scanNow:'Scan',
    browseZip:'Browse Local .zip',
    browseDir:'Browse Project Folder',
    termsLabel:'Your Personal Info / Custom Words to Hunt For (Recommended)',
    termsHint:'Searches inside filenames, code, PDFs, SQLite databases, image metadata, and binaries.',
    goToFile:'Open in Explorer',
    openFile:'Open File',
    inspect:'Inspect Code',
    copyPath:'Copy Path',
    tabAll:'All Findings',
    tabPii:'Personal Info (PII)',
    tabSecret:'Secrets & Keys',
    tabGithub:'GitHub Blockers',
    tabFile:'Files & Metadata',
    viewFlat:'All Matches',
    viewFile:'Group by File',
    dlJson:'Export JSON',
    dlHtml:'Export HTML Report',
    copyGi:'Copy .gitignore',
    filterPh:'Filter by full path, file, or finding type...',
    verdictBad:'Do NOT upload to GitHub yet',
    verdictWarn:'Review before uploading to GitHub',
    verdictOk:'Looks clean for GitHub upload',
    crit:'Critical', high:'High', med:'Medium', low:'Low',
    openedMsg:'Opened file location in Explorer',
    copiedMsg:'Copied to clipboard'
  },
  bn: {
    title:'GitShield ZIP স্ক্যানার',
    sub:'GitHub-এ আপলোডের আগে প্রাইভেট তথ্য ও সিক্রেট খুঁজুন। আর্কাইভ, PDF, ছবি, SQLite ও বাইনারি সব স্ক্যান করে।',
    localBadge:'১০০% লোকাল',
    dropTitle:'এখানে .zip ফাইল ড্রপ করুন',
    dropSub:'নেস্টেড জিপ, PDF, EXIF মেটাডাটা, ডাটাবেস ও বাইনারি ফাইল সম্পূর্ণ স্ক্যান করে।',
    chooseZip:'.zip ফাইল বাছাই করুন',
    directTitle:'দ্রুত লোকাল পাথ / ফোল্ডার স্ক্যান (সুপারিশকৃত)',
    directSub:'আপলোডের সময় লাগবে না। সম্পূর্ণ ডিস্ক পাথ দেখাবে এবং সরাসরি ফাইলে নিয়ে যাবে।',
    scanNow:'স্ক্যান করুন',
    browseZip:'লোকাল .zip বাছাই',
    browseDir:'প্রজেক্ট ফোল্ডার বাছাই',
    termsLabel:'আপনার ব্যক্তিগত তথ্য / কাস্টম শব্দ (খুঁজে বের করার জন্য)',
    termsHint:'ফাইলের নাম, কোড, PDF, SQLite ডাটাবেস, ছবির মেটাডাটা ও বাইনারির ভেতর খুঁজবে।',
    goToFile:'ফাইলে যান (Explorer)',
    openFile:'ফাইল খুলুন',
    inspect:'কোড দেখুন',
    copyPath:'পাথ কপি',
    tabAll:'সব ফলাফল',
    tabPii:'ব্যক্তিগত তথ্য (PII)',
    tabSecret:'সিক্রেট ও কী',
    tabGithub:'GitHub সমস্যা',
    tabFile:'ফাইল ও মেটাডাটা',
    viewFlat:'সব ম্যাচ',
    viewFile:'ফাইল অনুযায়ী',
    dlJson:'JSON ডাউনলোড',
    dlHtml:'HTML রিপোর্ট',
    copyGi:'.gitignore কপি',
    filterPh:'ফাইল পাথ বা ধরন দিয়ে খুঁজুন...',
    verdictBad:'এখনই GitHub-এ আপলোড করবেন না',
    verdictWarn:'GitHub-এ আপলোডের আগে যাচাই করুন',
    verdictOk:'GitHub আপলোডের জন্য নিরাপদ মনে হচ্ছে',
    crit:'জরুরি', high:'উচ্চ', med:'মাঝারি', low:'নিম্ন',
    openedMsg:'Explorer-এ ফাইলটি খোলা হয়েছে',
    copiedMsg:'ক্লিপবোর্ডে কপি হয়েছে'
  },
  es: {
    title:'GitShield Escáner ZIP',
    sub:'Escáner avanzado previo a GitHub para secretos e información personal. Analiza archivos, PDF, imágenes, SQLite y binarios.',
    localBadge:'100% Local',
    dropTitle:'Arrastra un archivo .zip aquí',
    dropSub:'Analiza zips anidados, PDF, metadatos EXIF, bases de datos y binarios localmente.',
    chooseZip:'Elegir archivo .zip',
    directTitle:'Escaneo rápido local / carpeta (Recomendado)',
    directSub:'Sin subida. Muestra rutas completas reales y abre el archivo directo en el explorador.',
    scanNow:'Escanear',
    browseZip:'Buscar .zip local',
    browseDir:'Buscar carpeta',
    termsLabel:'Tu información personal / palabras clave (Recomendado)',
    termsHint:'Busca en nombres de archivo, código, PDF, SQLite, metadatos de imágenes y binarios.',
    goToFile:'Ir al archivo',
    openFile:'Abrir archivo',
    inspect:'Ver código',
    copyPath:'Copiar ruta',
    tabAll:'Todos',
    tabPii:'Info Personal (PII)',
    tabSecret:'Secretos y Claves',
    tabGithub:'Riesgos GitHub',
    tabFile:'Archivos y Metadatos',
    viewFlat:'Todas las coincidencias',
    viewFile:'Agrupar por archivo',
    dlJson:'Exportar JSON',
    dlHtml:'Exportar HTML',
    copyGi:'Copiar .gitignore',
    filterPh:'Filtrar por ruta completa, archivo o tipo...',
    verdictBad:'NO subir a GitHub todavía',
    verdictWarn:'Revisar antes de subir a GitHub',
    verdictOk:'Listo para subir a GitHub',
    crit:'Crítico', high:'Alto', med:'Medio', low:'Bajo',
    openedMsg:'Archivo abierto en el explorador',
    copiedMsg:'Copiado al portapapeles'
  },
  ar: {
    title:'GitShield فاحص ملفات ZIP',
    sub:'فحص متقدم للأسرار والبيانات الشخصية قبل الرفع إلى GitHub. يفحص الأرشيفات وPDF والصور وSQLite والملفات الثنائية.',
    localBadge:'محلي 100%',
    dropTitle:'اسحب ملف .zip هنا',
    dropSub:'يفحص الملفات المضغوطة المتداخلة وPDF وبيانات EXIF وقواعد البيانات محلياً.',
    chooseZip:'اختر ملف .zip',
    directTitle:'فحص محلي سريع لمسار أو مجلد (موصى به)',
    directSub:'بدون تأخير رفع. يعرض المسار الكامل ويفتح الملف مباشرة في المستكشف.',
    scanNow:'فحص',
    browseZip:'تصفح .zip محلي',
    browseDir:'تصفح مجلد مشروع',
    termsLabel:'بياناتك الشخصية / كلمات مخصصة للبحث',
    termsHint:'يبحث داخل أسماء الملفات والأكواد وPDF وقواعد البيانات والصور والملفات الثنائية.',
    goToFile:'الانتقال للملف',
    openFile:'فتح الملف',
    inspect:'عرض الكود',
    copyPath:'نسخ المسار',
    tabAll:'الكل',
    tabPii:'بيانات شخصية',
    tabSecret:'أسرار ومفاتيح',
    tabGithub:'مشاكل GitHub',
    tabFile:'ملفات وبيانات وصفية',
    viewFlat:'كل النتائج',
    viewFile:'تجميع حسب الملف',
    dlJson:'تصدير JSON',
    dlHtml:'تصدير HTML',
    copyGi:'نسخ .gitignore',
    filterPh:'تصفية حسب المسار الكامل أو النوع...',
    verdictBad:'لا ترفع إلى GitHub بعد',
    verdictWarn:'راجع النتائج قبل الرفع إلى GitHub',
    verdictOk:'يبدو آمناً للرفع إلى GitHub',
    crit:'حرج', high:'مرتفع', med:'متوسط', low:'منخفض',
    openedMsg:'تم فتح موقع الملف في المستكشف',
    copiedMsg:'تم النسخ إلى الحافظة'
  }
};

const ICON = {
  bad:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 3l9 16H3L12 3z"/><path d="M12 10v4"/><path d="M12 17h.01"/></svg>',
  warn:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="9"/><path d="M12 8v4"/><path d="M12 16h.01"/></svg>',
  ok:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 12l5 5 9-10"/></svg>'
};

let lang = 'en';
let report = null;
let activeSev = new Set(SEV);
let activeCat = 'all';
let viewMode = 'file';
let pollTimer = null;
let modalCurrentFile = null;

function t(k) { return (I18N[lang] && I18N[lang][k]) || I18N.en[k] || k; }
function sevLabel(s) { return s === 'critical' ? t('crit') : s === 'high' ? t('high') : s === 'medium' ? t('med') : t('low'); }

function applyLang() {
  document.documentElement.lang = lang;
  document.documentElement.dir = lang === 'ar' ? 'rtl' : 'ltr';
  document.querySelectorAll('[data-i18n]').forEach(n => { n.textContent = t(n.dataset.i18n); });
  if (report) render();
}

$('#langSel').addEventListener('change', e => { lang = e.target.value; applyLang(); });
$('#themeBtn').addEventListener('click', () => {
  const cur = document.documentElement.getAttribute('data-theme');
  document.documentElement.setAttribute('data-theme', cur === 'dark' ? 'light' : 'dark');
});

function toast(msg) {
  const n = $('#toast');
  n.textContent = msg;
  n.classList.add('show');
  clearTimeout(n._tm);
  n._tm = setTimeout(() => n.classList.remove('show'), 2400);
}

function el(tag, cls, text) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined) n.textContent = text;
  return n;
}

function getTerms() {
  return $('#terms').value.split('\n').map(s => s.trim()).filter(Boolean);
}

const drop = $('#drop'), input = $('#file');
$('#uploadBtn').addEventListener('click', e => { e.stopPropagation(); input.click(); });
drop.addEventListener('click', () => input.click());
drop.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); input.click(); } });
['dragenter','dragover'].forEach(n => drop.addEventListener(n, e => { e.preventDefault(); drop.classList.add('over'); }));
['dragleave','drop'].forEach(n => drop.addEventListener(n, e => { e.preventDefault(); drop.classList.remove('over'); }));
drop.addEventListener('drop', e => { const f = e.dataTransfer.files[0]; if (f) startUpload(f); });
input.addEventListener('change', () => { if (input.files[0]) startUpload(input.files[0]); input.value = ''; });

async function pickNative(kind) {
  try {
    const res = await fetch('/pick', {
      method:'POST',
      headers:{'Content-Type':'application/json','X-Token':TOKEN},
      body:JSON.stringify({kind})
    });
    const d = await res.json();
    if (d.path) {
      $('#localPath').value = d.path;
      startLocal(d.path);
    }
  } catch (e) {
    toast('Could not open file picker');
  }
}

$('#pickZipBtn').addEventListener('click', () => pickNative('zip'));
$('#pickDirBtn').addEventListener('click', () => pickNative('dir'));
$('#scanPathBtn').addEventListener('click', () => {
  const p = $('#localPath').value.trim();
  if (p) startLocal(p);
});
$('#localPath').addEventListener('keydown', e => {
  if (e.key === 'Enter') { const p = $('#localPath').value.trim(); if (p) startLocal(p); }
});

function showProgress(titleText, busy) {
  const st = $('#status');
  st.replaceChildren();
  const meta = el('div', 'prog-meta');
  meta.append(el('span', '', titleText), el('span', '', ''));
  const bar = el('div', 'bar' + (busy ? ' busy' : '')), fill = el('i');
  bar.appendChild(fill);
  const cf = el('div', 'prog-file', '');
  st.append(meta, bar, cf);
  return { meta, bar, fill, cf };
}

function startUpload(file) {
  clearInterval(pollTimer);
  $('#results').replaceChildren();
  const ui = showProgress('Uploading ' + file.name + ' (' + (file.size / 1048576).toFixed(1) + ' MB)...', false);
  const xhr = new XMLHttpRequest();
  xhr.open('POST', '/scan-upload');
  xhr.setRequestHeader('X-Token', TOKEN);
  xhr.setRequestHeader('X-Terms', encodeURIComponent(JSON.stringify(getTerms())));
  xhr.setRequestHeader('X-Filename', encodeURIComponent(file.name));
  xhr.upload.onprogress = e => {
    if (e.lengthComputable) ui.fill.style.width = (e.loaded / e.total * 100) + '%';
    if (e.loaded === e.total) {
      ui.meta.firstChild.textContent = 'Deep scanning...';
      ui.bar.classList.add('busy');
    }
  };
  xhr.onerror = () => { $('#status').textContent = 'Could not reach local scanner.'; };
  xhr.onload = () => {
    let d = null;
    try { d = JSON.parse(xhr.responseText); } catch (e) {}
    if (xhr.status !== 200 || !d || !d.scan_id) {
      $('#status').textContent = (d && d.error) || 'Upload failed.';
      return;
    }
    pollScan(d.scan_id, ui);
  };
  xhr.send(file);
}

async function startLocal(pathStr) {
  clearInterval(pollTimer);
  $('#results').replaceChildren();
  const ui = showProgress('Starting fast local deep scan...', true);
  try {
    const res = await fetch('/scan-local', {
      method:'POST',
      headers:{'Content-Type':'application/json','X-Token':TOKEN},
      body:JSON.stringify({path:pathStr, terms:getTerms()})
    });
    const d = await res.json();
    if (!res.ok || !d.scan_id) {
      $('#status').textContent = d.error || 'Could not start scan.';
      return;
    }
    pollScan(d.scan_id, ui);
  } catch (e) {
    $('#status').textContent = 'Could not reach local scanner.';
  }
}

function pollScan(scanId, ui) {
  clearInterval(pollTimer);
  pollTimer = setInterval(async () => {
    try {
      const res = await fetch('/status/' + encodeURIComponent(scanId), { headers:{'X-Token':TOKEN} });
      const d = await res.json();
      if (d.status === 'scanning') {
        ui.meta.firstChild.textContent = 'Scanning: ' + d.files_scanned + ' files (' + d.mb_scanned + ' MB) • ' + d.speed_fps + ' files/s';
        ui.meta.lastChild.textContent = 'Findings: ' + d.findings_so_far;
        ui.cf.textContent = d.current_file || '';
      } else if (d.status === 'done') {
        clearInterval(pollTimer);
        $('#status').replaceChildren();
        report = d.report;
        activeSev = new Set(SEV);
        activeCat = 'all';
        render();
        $('#results').scrollIntoView({behavior:'smooth', block:'start'});
      } else if (d.status === 'error') {
        clearInterval(pollTimer);
        $('#status').textContent = d.error || 'Scan error.';
      }
    } catch (e) {
      clearInterval(pollTimer);
      $('#status').textContent = 'Connection lost.';
    }
  }, 220);
}

async function openTarget(relFile, action) {
  if (!report) return;
  try {
    const res = await fetch('/open', {
      method:'POST',
      headers:{'Content-Type':'application/json','X-Token':TOKEN},
      body:JSON.stringify({scan_id:report.scan_id, file:relFile, action})
    });
    const d = await res.json();
    if (d.ok) {
      toast(t('openedMsg'));
    } else {
      toast(d.error || 'Failed to open');
    }
  } catch (e) {
    toast('Failed to open file');
  }
}

async function inspectTarget(relFile, lineNum) {
  if (!report) return;
  modalCurrentFile = relFile;
  $('#modalPath').textContent = relFile + (lineNum ? ':' + lineNum : '');
  $('#modalBody').replaceChildren(el('div', 'empty', 'Loading preview...'));
  $('#modalBg').classList.add('open');
  try {
    const res = await fetch('/preview', {
      method:'POST',
      headers:{'Content-Type':'application/json','X-Token':TOKEN},
      body:JSON.stringify({scan_id:report.scan_id, file:relFile, line:lineNum})
    });
    const d = await res.json();
    if (!res.ok) {
      $('#modalBody').replaceChildren(el('div', 'empty', d.error || 'Preview unavailable'));
      return;
    }
    $('#modalPath').textContent = d.disk_path + (lineNum ? ' : Line ' + lineNum : '');
    const frag = document.createDocumentFragment();
    d.lines.forEach(item => {
      const row = el('div', 'code-ln' + (item.num === d.target_line ? ' hit' : ''));
      row.append(el('span', 'code-num', String(item.num)), el('span', 'code-txt', item.text));
      frag.appendChild(row);
    });
    $('#modalBody').replaceChildren(frag);
    const hit = $('#modalBody .hit');
    if (hit) hit.scrollIntoView({block:'center'});
  } catch (e) {
    $('#modalBody').replaceChildren(el('div', 'empty', 'Could not load preview'));
  }
}

$('#modalClose').addEventListener('click', () => $('#modalBg').classList.remove('open'));
$('#modalBg').addEventListener('click', e => { if (e.target === $('#modalBg')) $('#modalBg').classList.remove('open'); });
$('#modalReveal').addEventListener('click', () => { if (modalCurrentFile) openTarget(modalCurrentFile, 'reveal'); });

function copyText(txt) {
  navigator.clipboard.writeText(txt).then(() => toast(t('copiedMsg'))).catch(() => toast('Copy failed'));
}

function render() {
  const root = $('#results');
  root.replaceChildren();
  const s = report.summary, c = s.counts, cats = s.categories;
  const total = SEV.reduce((a, k) => a + c[k], 0);

  const v = el('div', 'verdict'), icon = el('div', 'vi'), body = el('div', 'vb');
  let kind, title, desc;
  if (c.critical || c.high) {
    kind = 'bad'; title = t('verdictBad');
    desc = c.critical + ' critical & ' + c.high + ' high issues across ' + s.files_flagged + ' files (' + s.pii_files + ' files contain personal info).';
  } else if (total) {
    kind = 'warn'; title = t('verdictWarn');
    desc = total + ' findings across ' + s.files_flagged + ' files (' + s.pii_files + ' files with personal info).';
  } else {
    kind = 'ok'; title = t('verdictOk');
    desc = 'No secrets, GitHub blockers, or personal info patterns detected across ' + s.files_scanned + ' scanned files.';
  }
  v.classList.add(kind);
  icon.innerHTML = ICON[kind];
  body.append(el('h2', '', title), el('p', '', desc));
  const st = el('div', 'stats');
  [
    s.files_scanned + ' files scanned',
    s.files_flagged + ' flagged files',
    s.pii_files + ' PII files',
    s.mb_scanned + ' MB',
    s.elapsed_sec + 's',
    report.root
  ].forEach(x => st.appendChild(el('span', '', x)));
  body.appendChild(st);
  v.append(icon, body);
  root.appendChild(v);

  if (total) {
    const tiles = el('div', 'tiles');
    SEV.forEach(k => {
      const b = el('button', 'tile ' + k);
      b.append(el('b', '', String(c[k])), el('span', '', sevLabel(k)));
      if (!c[k]) { b.disabled = true; tiles.appendChild(b); return; }
      b.setAttribute('aria-pressed', String(activeSev.has(k)));
      b.onclick = () => {
        activeSev.has(k) ? activeSev.delete(k) : activeSev.add(k);
        b.setAttribute('aria-pressed', String(activeSev.has(k)));
        renderList();
      };
      tiles.appendChild(b);
    });
    root.appendChild(tiles);

    const tabs = el('div', 'tabs');
    const tabDefs = [
      ['all', t('tabAll') + ' (' + total + ')', ''],
      ['pii', t('tabPii') + ' (' + (cats.pii || 0) + ')', 'pii'],
      ['secret', t('tabSecret') + ' (' + (cats.secret || 0) + ')', ''],
      ['github', t('tabGithub') + ' (' + (cats.github || 0) + ')', ''],
      ['file_meta', t('tabFile') + ' (' + ((cats.file || 0) + (cats.metadata || 0)) + ')', '']
    ];
    tabDefs.forEach(([key, lbl, extraCls]) => {
      const b = el('button', 'tab ' + extraCls + (activeCat === key ? ' active' : ''), lbl);
      b.onclick = () => { activeCat = key; render(); };
      tabs.appendChild(b);
    });
    root.appendChild(tabs);

    const tools = el('div', 'tools');
    const q = el('input');
    q.type = 'search'; q.id = 'q'; q.placeholder = t('filterPh');
    q.oninput = renderList;
    tools.appendChild(q);

    const vBtn = el('button', 'btn', viewMode === 'file' ? t('viewFlat') : t('viewFile'));
    vBtn.onclick = () => { viewMode = viewMode === 'file' ? 'flat' : 'file'; render(); };
    tools.appendChild(vBtn);

    const dj = el('button', 'btn', t('dlJson'));
    dj.onclick = downloadJson;
    tools.appendChild(dj);

    const dh = el('button', 'btn primary', t('dlHtml'));
    dh.onclick = downloadHtml;
    tools.appendChild(dh);
    root.appendChild(tools);

    const rows = el('div', 'rows');
    rows.id = 'rows';
    root.appendChild(rows);
    renderList();
  }

  if (report.gitignore) {
    const det = el('details');
    det.appendChild(el('summary', '', 'Recommended .gitignore additions for GitHub'));
    const pre = el('div', 'gi-box', report.gitignore);
    const cp = el('button', 'btn sm primary', t('copyGi'));
    cp.style.marginTop = '10px';
    cp.onclick = () => copyText(report.gitignore);
    det.append(pre, cp);
    root.appendChild(det);
  }

  if (report.notes && report.notes.length) {
    const det = el('details');
    det.appendChild(el('summary', '', 'Scan notes (' + report.notes.length + ')'));
    const box = el('div', 'skips');
    report.notes.slice(0, 600).forEach(x => box.appendChild(el('div', '', x.full_path + '  —  ' + x.reason)));
    det.appendChild(box);
    root.appendChild(det);
  }
}

function filteredFindings() {
  const q = ($('#q') ? $('#q').value : '').toLowerCase();
  return report.findings.filter(f => {
    if (!activeSev.has(f.severity)) return false;
    if (activeCat === 'pii' && f.category !== 'pii') return false;
    if (activeCat === 'secret' && f.category !== 'secret') return false;
    if (activeCat === 'github' && f.category !== 'github') return false;
    if (activeCat === 'file_meta' && f.category !== 'file' && f.category !== 'metadata') return false;
    if (q && !f.full_path.toLowerCase().includes(q) && !f.type.toLowerCase().includes(q) && !f.preview.toLowerCase().includes(q)) return false;
    return true;
  });
}

function renderList() {
  const box = $('#rows');
  if (!box) return;
  box.replaceChildren();
  const items = filteredFindings();
  if (!items.length) {
    box.appendChild(el('div', 'empty', 'No findings match this filter.'));
    return;
  }

  if (viewMode === 'file') {
    const groups = new Map();
    items.forEach(f => {
      if (!groups.has(f.file)) groups.set(f.file, { file:f.file, full_path:f.full_path, items:[], pii:0, secret:0, github:0, maxSev:f.severity });
      const g = groups.get(f.file);
      g.items.push(f);
      if (f.category === 'pii') g.pii++;
      if (f.category === 'secret') g.secret++;
      if (f.category === 'github') g.github++;
    });

    let shown = 0;
    for (const g of groups.values()) {
      if (++shown > 500) break;
      const card = el('div', 'file-group');
      const head = el('div', 'fg-head');
      head.appendChild(el('div', 'fg-path', g.full_path));
      const acts = el('div', 'actions');
      const goBtn = el('button', 'btn sm primary', t('goToFile'));
      goBtn.onclick = () => openTarget(g.file, 'reveal');
      const openBtn = el('button', 'btn sm', t('openFile'));
      openBtn.onclick = () => openTarget(g.file, 'open');
      const cpBtn = el('button', 'btn sm', t('copyPath'));
      cpBtn.onclick = () => copyText(g.full_path);
      acts.append(goBtn, openBtn, cpBtn);
      head.appendChild(acts);

      const badges = el('div', 'fg-badges');
      badges.appendChild(el('span', 'sev', g.items.length + ' findings'));
      if (g.pii) badges.appendChild(el('span', 'cat pii', 'Personal Info: ' + g.pii));
      if (g.secret) badges.appendChild(el('span', 'cat', 'Secrets: ' + g.secret));
      if (g.github) badges.appendChild(el('span', 'cat github', 'GitHub: ' + g.github));

      const flist = el('div', 'fg-list');
      g.items.slice(0, 12).forEach(f => {
        const it = el('div', 'fg-item');
        const sev = el('span', 'sev', sevLabel(f.severity));
        sev.style.setProperty('--c', 'var(--' + (f.severity === 'critical' ? 'crit' : f.severity === 'medium' ? 'med' : f.severity) + ')');
        it.append(sev, el('span', 'cat ' + f.category, f.category), el('strong', '', f.type + (f.line ? ' (L' + f.line + ')' : '')));
        const insp = el('button', 'btn sm', t('inspect'));
        insp.style.marginLeft = 'auto';
        insp.onclick = () => inspectTarget(f.file, f.line);
        it.appendChild(insp);
        flist.append(it, el('code', 'prev', f.preview));
      });
      if (g.items.length > 12) flist.appendChild(el('div', 'hint', '+' + (g.items.length - 12) + ' more findings in this file...'));

      card.append(head, badges, flist);
      box.appendChild(card);
    }
    return;
  }

  items.slice(0, 800).forEach(f => {
    const r = el('div', 'row ' + f.severity);
    const top = el('div', 'top');
    top.append(el('span', 'sev', sevLabel(f.severity)), el('span', 'cat ' + f.category, f.category), el('span', 'what', f.type));
    const acts = el('div', 'actions');
    const goBtn = el('button', 'btn sm primary', t('goToFile'));
    goBtn.onclick = () => openTarget(f.file, 'reveal');
    const inspBtn = el('button', 'btn sm', t('inspect'));
    inspBtn.onclick = () => inspectTarget(f.file, f.line);
    const cpBtn = el('button', 'btn sm', t('copyPath'));
    cpBtn.onclick = () => copyText(f.full_path + (f.line ? ':' + f.line : ''));
    acts.append(goBtn, inspBtn, cpBtn);
    top.appendChild(acts);
    r.append(top, el('div', 'where', f.full_path + (f.line ? ' : Line ' + f.line : '')), el('code', 'prev', f.preview));
    box.appendChild(r);
  });
  if (items.length > 800) box.appendChild(el('div', 'empty', 'Showing 800 of ' + items.length + '. Export JSON/HTML report for all.'));
}

function downloadJson() {
  const blob = new Blob([JSON.stringify(report, null, 2)], {type:'application/json'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'gitshield-report-khaled-2026.json';
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}

function escHtml(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function downloadHtml() {
  const rows = report.findings.map(f =>
    '<tr><td>' + escHtml(f.severity.toUpperCase()) + '</td><td>' + escHtml(f.category.toUpperCase()) +
    '</td><td>' + escHtml(f.type) + '</td><td><code>' + escHtml(f.full_path + (f.line ? ':' + f.line : '')) +
    '</code></td><td><code>' + escHtml(f.preview) + '</code></td></tr>'
  ).join('');
  const doc = '<!doctype html><html><head><meta charset="utf-8"><title>GitShield Report - ' + CREDIT +
    '</title><style>body{font-family:system-ui,sans-serif;background:#090c14;color:#f1f5f9;padding:24px}table{width:100%;border-collapse:collapse;margin-top:16px}th,td{border:1px solid #232c45;padding:8px;text-align:left;font-size:13px;word-break:break-all}th{background:#111625}code{font-family:monospace;color:#38bdf8}</style></head><body><h1>GitShield Scan Report</h1><p>Created by <strong>' +
    CREDIT + '</strong> | Target: ' + escHtml(report.root) + ' | Files scanned: ' + report.summary.files_scanned +
    ' | Flagged files: ' + report.summary.files_flagged + ' | PII files: ' + report.summary.pii_files +
    '</p><table><thead><tr><th>Severity</th><th>Category</th><th>Type</th><th>Full Path</th><th>Preview</th></tr></thead><tbody>' +
    rows + '</tbody></table></body></html>';
  const blob = new Blob([doc], {type:'text/html'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'gitshield-report-khaled-2026.html';
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
            server = ReusableThreadingHTTPServer((HOST, p), Handler)
            break
        except OSError:
            continue
    if server is None:
        sys.exit("No free port between %d and %d." % (PORTS[0], PORTS[-1]))
    url = "http://127.0.0.1:%d" % PORT
    print("%s (%s) running at %s  (Ctrl+C to stop)" % (APP_NAME, APP_CREDIT, url))
    threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()