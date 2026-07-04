#!/usr/bin/env python3
"""
Honeypot Observer — FTP Honeypot
Mimics a real FTP server to harvest credentials and log attacker behaviour.
Emits one JSON event per line to /var/log/honeypot/ftp.jsonl
"""
import json, uuid, threading
from datetime import datetime, timezone
from pathlib import Path
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer
from pyftpdlib.authorizers import DummyAuthorizer

LOG_FILE   = Path("/var/log/honeypot/ftp.jsonl")
LISTEN_PORT = 21
_lock = threading.Lock()

def log_event(ev):
    line = json.dumps(ev, default=str)
    with _lock:
        with open(LOG_FILE, "a") as f:
            f.write(line + "\n")

def make_event(subtype, src_ip, extra=None):
    ts = datetime.now(timezone.utc).isoformat()
    ev = {
        "@timestamp":    ts,
        "timestamp":     ts,
        "protocol":      "ftp",
        "honeypot_type": "ftp",
        "eventid":       f"ftp.{subtype}",
        "uuid":          str(uuid.uuid4()),
        "session":       str(uuid.uuid4()),
        "src_ip":        src_ip,
        "severity":      "high" if "login" in subtype else "medium",
        "message":       f"FTP {subtype} from {src_ip}",
        "sensor":        "ftp-honeypot",
        "mitre_attack":  ["T1110"],
        "detected_categories": ["brute_force"],
    }
    if extra:
        ev.update(extra)
    return ev

class HoneypotHandler(FTPHandler):

    def on_connect(self):
        log_event(make_event("session.connect", self.remote_ip))

    def on_disconnect(self):
        log_event(make_event("session.closed", self.remote_ip))

    def on_login_failed(self, username, password):
        log_event(make_event("login.failed", self.remote_ip, {
            "username_attempted": username[:128],
            "password_attempted": password[:128],
            "severity": "high",
            "mitre_attack": ["T1110"],
            "detected_categories": ["brute_force"],
        }))

    def on_login(self, username):
        # Always fails — no real users — but log the attempt
        log_event(make_event("login.success", self.remote_ip, {
            "username_attempted": username[:128],
            "severity": "critical",
            "mitre_attack": ["T1110", "T1078"],
            "detected_categories": ["brute_force", "initial_access"],
        }))

    def on_file_retrieved(self, file):
        log_event(make_event("file.download", self.remote_ip, {
            "file_path": str(file),
            "mitre_attack": ["T1083"],
            "detected_categories": ["discovery"],
        }))

    def on_file_sent(self, file):
        log_event(make_event("file.upload", self.remote_ip, {
            "file_path": str(file),
            "mitre_attack": ["T1105"],
            "detected_categories": ["file_upload"],
        }))

def main():
    authorizer = DummyAuthorizer()
    # No real users — all logins will fail at the authorizer level
    # but on_login_failed still fires so we capture credentials

    handler = HoneypotHandler
    handler.authorizer = authorizer
    handler.banner = "220 FTP Server ready."
    handler.passive_ports = range(60000, 60100)
    handler.masquerade_address = None

    server = FTPServer(("0.0.0.0", LISTEN_PORT), handler)
    server.max_cons = 50
    server.max_cons_per_ip = 5

    print(f"[ftp-honeypot] listening on 0.0.0.0:{LISTEN_PORT}")
    print(f"[ftp-honeypot] logging to {LOG_FILE}")
    server.serve_forever()

if __name__ == "__main__":
    main()
