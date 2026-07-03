#!/usr/bin/env python3
"""
Honeypot Observer — HTTP Honeypot
Mimics common vulnerable web surfaces to attract and log attacker behaviour.
Emits one JSON event per line to /var/log/honeypot/http.jsonl
which Filebeat tails and ships to Logstash -> honeypot-events index.
"""
import json, re, uuid, hashlib, threading
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import unquote_plus
from flask import Flask, request, Response, make_response

LOG_FILE   = Path("/var/log/honeypot/http.jsonl")
LISTEN_PORT = 8080
app  = Flask(__name__)
_lock = threading.Lock()

PATTERNS = {
    "sqli": [
        r"(?i)\bunion\b.{0,40}\bselect\b",
        r"(?i)'\s*or\s*'?1'?\s*=\s*'?1",
        r"(?i)\bsleep\s*\(\s*\d+\s*\)",
        r"(?i)information_schema",
        r"(?i)\bdrop\s+table\b",
    ],
    "xss": [
        r"(?i)<script[\s>]",
        r"(?i)javascript:",
        r"(?i)on(error|load|click|mouseover)\s*=",
    ],
    "path_traversal": [
        r"\.\./", r"\.\.\\",
        r"(?i)/etc/passwd",
        r"(?i)boot\.ini",
    ],
    "log4shell": [
        r"\$\{jndi:",
        r"(?i)\$\{lower:",
    ],
    "command_injection": [
        r";\s*(cat|ls|whoami|id|uname|wget|curl)\b",
        r"\|\s*(cat|ls|whoami|id|uname|wget|curl)\b",
        r"\$\([^)]+\)",
    ],
    "credential_scan": [
        r"(?i)\.env$",
        r"(?i)\.git/config$",
        r"(?i)wp-config\.php$",
        r"(?i)id_rsa$",
    ],
}

MITRE = {
    "sqli":              "T1190",
    "xss":               "T1190",
    "path_traversal":    "T1083",
    "log4shell":         "T1190",
    "command_injection": "T1059",
    "credential_scan":   "T1552",
    "brute_force":       "T1110",
    "file_upload":       "T1105",
}

def detect(text):
    hits = set()
    if not text:
        return []
    decoded = unquote_plus(text)
    for cat, regexes in PATTERNS.items():
        for rx in regexes:
            if re.search(rx, decoded):
                hits.add(cat)
                break
    return sorted(hits)

def log_event(ev):
    line = json.dumps(ev, default=str)
    with _lock:
        with open(LOG_FILE, "a") as f:
            f.write(line + "\n")

def build_event(subtype, extra_categories=None):
    src  = request.headers.get("X-Forwarded-For", request.remote_addr) or "unknown"
    path = request.path
    qs   = request.query_string.decode("utf-8", errors="replace")
    body = (request.get_data(as_text=True) or "")[:2048]
    hdrs = json.dumps(dict(request.headers))
    # Decode everything before running patterns
    cats = detect(path + ("?" + qs if qs else "") + body + hdrs)
    if extra_categories:
        cats = sorted(set(cats) | set(extra_categories))
    ts = datetime.now(timezone.utc).isoformat()
    return {
        "@timestamp":          ts,
        "timestamp":           ts,
        "protocol":            "http",
        "honeypot_type":       "http",
        "eventid":             f"http.{subtype}",
        "uuid":                str(uuid.uuid4()),
        "session":             str(uuid.uuid4()),
        "src_ip":              src,
        "method":              request.method,
        "path":                path,
        "query_string":        qs,
        "user_agent":          request.headers.get("User-Agent", ""),
        "body_excerpt":        body[:512],
        "detected_categories": cats,
        "mitre_attack":        sorted({MITRE[c] for c in cats if c in MITRE}),
        "severity":            "high" if cats else "info",
        "message":             f"HTTP {request.method} {path}",
        "sensor":              "http-honeypot",
    }

LOGIN_HTML = """<!DOCTYPE html><html><head><title>{t}</title></head>
<body style="font-family:sans-serif;max-width:340px;margin:120px auto">
<h2>{t}</h2><form method="POST">
<p><input name="username" placeholder="Username" style="width:100%"></p>
<p><input name="password" type="password" placeholder="Password" style="width:100%"></p>
<p><button type="submit">Log in</button></p>{msg}</form></body></html>"""

def login_trap(title):
    if request.method == "POST":
        ev = build_event("login.attempt", {"brute_force"})
        ev["username_attempted"] = request.form.get("username", "")[:128]
        log_event(ev)
        resp = make_response(LOGIN_HTML.format(
            t=title, msg="<p style='color:red'>Invalid credentials</p>"))
        return resp, 401
    log_event(build_event("page.view"))
    return LOGIN_HTML.format(t=title, msg=""), 200

@app.route("/admin",       methods=["GET","POST"])
@app.route("/admin/login", methods=["GET","POST"])
def admin(): return login_trap("Admin Login")

@app.route("/wp-admin",    methods=["GET","POST"])
@app.route("/wp-login.php",methods=["GET","POST"])
def wp():    return login_trap("WordPress &rsaquo; Log In")

@app.route("/phpmyadmin",  methods=["GET","POST"])
@app.route("/phpMyAdmin",  methods=["GET","POST"])
def pma():   return login_trap("phpMyAdmin")

FAKE = {
    "/.env":           "DB_HOST=127.0.0.1\nDB_USER=admin\nDB_PASS=changeme\nAPP_KEY=base64:placeholder\n",
    "/.git/config":    "[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n\turl = https://internal.local/app.git\n",
    "/wp-config.php":  "<?php\ndefine('DB_PASSWORD', 'placeholder');\n",
    "/config.php.bak": "<?php\n$db_pass = 'placeholder';\n",
}

@app.route("/healthz")
def health():
    return {"status": "ok", "service": "http-honeypot"}

@app.route("/upload",     methods=["POST"])
@app.route("/api/upload", methods=["POST"])
def upload():
    saved = []
    for _, f in request.files.items():
        raw = f.read()
        sha = hashlib.sha256(raw).hexdigest()
        saved.append({"filename": f.filename, "sha256": sha, "size": len(raw)})
    ev = build_event("file.upload", {"file_upload"})
    ev["uploaded_files"] = saved
    log_event(ev)
    return {"status": "ok", "files": len(saved)}

@app.route("/", defaults={"p": ""})
@app.route("/<path:p>")
def catchall(p):
    full = "/" + p
    if full in FAKE:
        ev = build_event("sensitive.file.access", {"credential_scan"})
        log_event(ev)
        return Response(FAKE[full], mimetype="text/plain")
    ev = build_event("probe")
    log_event(ev)
    return Response("Not Found", status=404)
