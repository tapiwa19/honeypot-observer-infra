#!/usr/bin/env python3
"""
Honeypot Observer — Telnet Honeypot
Mimics a network device/router telnet interface.
Emits one JSON event per line to /var/log/honeypot/telnet.jsonl
"""
import json, uuid, socket, threading
from datetime import datetime, timezone
from pathlib import Path

LOG_FILE    = Path("/var/log/honeypot/telnet.jsonl")
LISTEN_PORT = 23
_lock       = threading.Lock()

def log_event(ev):
    with _lock:
        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(ev, default=str) + "\n")

def make_event(subtype, src_ip, extra=None):
    ts = datetime.now(timezone.utc).isoformat()
    ev = {
        "@timestamp": ts, "timestamp": ts,
        "protocol": "telnet", "honeypot_type": "telnet",
        "eventid": f"telnet.{subtype}",
        "uuid": str(uuid.uuid4()), "session": str(uuid.uuid4()),
        "src_ip": src_ip, "sensor": "telnet-honeypot",
        "severity": "high" if "login" in subtype else "medium",
        "message": f"Telnet {subtype} from {src_ip}",
        "mitre_attack": ["T1110"],
        "detected_categories": ["brute_force"],
    }
    if extra:
        ev.update(extra)
    return ev

def handle_client(conn, addr):
    src_ip = addr[0]
    log_event(make_event("session.connect", src_ip))
    try:
        # Send router-style banner
        conn.sendall(b"\r\nCisco IOS Software\r\nUsername: ")
        conn.settimeout(30)

        # Collect username
        username = b""
        while b"\r" not in username and b"\n" not in username and len(username) < 128:
            chunk = conn.recv(1)
            if not chunk:
                break
            username += chunk
        username = username.strip().decode("utf-8", errors="replace")

        conn.sendall(b"Password: ")

        # Collect password
        password = b""
        while b"\r" not in password and b"\n" not in password and len(password) < 128:
            chunk = conn.recv(1)
            if not chunk:
                break
            password += chunk
        password = password.strip().decode("utf-8", errors="replace")

        log_event(make_event("login.attempt", src_ip, {
            "username_attempted": username,
            "password_attempted": password,
            "severity": "high",
            "mitre_attack": ["T1110", "T1021"],
            "detected_categories": ["brute_force", "lateral_movement"],
        }))

        conn.sendall(b"\r\n% Authentication failed.\r\n")
    except Exception:
        pass
    finally:
        conn.close()
        log_event(make_event("session.closed", src_ip))

def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", LISTEN_PORT))
    server.listen(50)
    print(f"[telnet-honeypot] listening on 0.0.0.0:{LISTEN_PORT}")
    print(f"[telnet-honeypot] logging to {LOG_FILE}")
    while True:
        try:
            conn, addr = server.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            t.start()
        except Exception:
            pass

if __name__ == "__main__":
    main()
