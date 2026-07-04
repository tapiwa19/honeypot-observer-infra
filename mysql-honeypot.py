#!/usr/bin/env python3
"""
Honeypot Observer — MySQL Honeypot
Mimics a MySQL server to detect database attack attempts.
Emits one JSON event per line to /var/log/honeypot/mysql.jsonl
"""
import json, uuid, socket, threading, struct
from datetime import datetime, timezone
from pathlib import Path

LOG_FILE    = Path("/var/log/honeypot/mysql.jsonl")
LISTEN_PORT = 3306
_lock       = threading.Lock()

def log_event(ev):
    with _lock:
        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(ev, default=str) + "\n")

def make_event(subtype, src_ip, extra=None):
    ts = datetime.now(timezone.utc).isoformat()
    ev = {
        "@timestamp": ts, "timestamp": ts,
        "protocol": "mysql", "honeypot_type": "mysql",
        "eventid": f"mysql.{subtype}",
        "uuid": str(uuid.uuid4()), "session": str(uuid.uuid4()),
        "src_ip": src_ip, "sensor": "mysql-honeypot",
        "severity": "high" if "login" in subtype else "medium",
        "message": f"MySQL {subtype} from {src_ip}",
        "mitre_attack": ["T1110"],
        "detected_categories": ["brute_force"],
    }
    if extra:
        ev.update(extra)
    return ev

def mysql_handshake():
    """Build a realistic MySQL 5.7 server greeting packet."""
    server_version = b"5.7.38-honeypot\x00"
    thread_id      = struct.pack("<I", 1)
    auth_plugin_data = b"AAAAAAAA"   # 8 bytes scramble
    filler         = b"\x00"
    capabilities   = struct.pack("<H", 0xF7FF)
    charset        = b"\x21"         # utf8
    status         = struct.pack("<H", 0x0002)
    cap_upper      = struct.pack("<H", 0x8000)
    auth_data_len  = struct.pack("<B", 21)
    reserved       = b"\x00" * 10
    auth_plugin_data2 = b"AAAAAAAAAAAAA"  # 13 bytes
    auth_plugin_name  = b"mysql_native_password\x00"

    payload = (b"\x0a" + server_version + thread_id +
               auth_plugin_data + filler + capabilities +
               charset + status + cap_upper + auth_data_len +
               reserved + auth_plugin_data2 + auth_plugin_name)

    length  = struct.pack("<I", len(payload))[:3]
    seq     = b"\x00"
    return length + seq + payload

def mysql_error():
    """Access denied error packet."""
    msg     = b"Access denied for user"
    payload = b"\xff" + struct.pack("<H", 1045) + b"#28000" + msg
    length  = struct.pack("<I", len(payload))[:3]
    return length + b"\x02" + payload

def read_packet(conn):
    """Read one MySQL packet, return payload bytes."""
    header = b""
    while len(header) < 4:
        chunk = conn.recv(4 - len(header))
        if not chunk:
            return None
        header += chunk
    pkt_len = struct.unpack("<I", header[:3] + b"\x00")[0]
    data = b""
    while len(data) < pkt_len:
        chunk = conn.recv(pkt_len - len(data))
        if not chunk:
            return None
        data += chunk
    return data

def parse_login(data):
    """Extract username from MySQL HandshakeResponse41."""
    try:
        if len(data) < 36:
            return "unknown", "unknown"
        # Skip capabilities(4) + max_packet(4) + charset(1) + reserved(23) = 32
        offset = 32
        username = b""
        while offset < len(data) and data[offset:offset+1] != b"\x00":
            username += data[offset:offset+1]
            offset += 1
        return username.decode("utf-8", errors="replace"), "***"
    except Exception:
        return "unknown", "unknown"

def handle_client(conn, addr):
    src_ip = addr[0]
    log_event(make_event("session.connect", src_ip))
    try:
        conn.settimeout(15)
        conn.sendall(mysql_handshake())
        data = read_packet(conn)
        if data:
            username, password = parse_login(data)
            log_event(make_event("login.attempt", src_ip, {
                "username_attempted": username[:128],
                "severity": "high",
                "mitre_attack": ["T1110", "T1078"],
                "detected_categories": ["brute_force", "initial_access"],
            }))
            conn.sendall(mysql_error())
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
    print(f"[mysql-honeypot] listening on 0.0.0.0:{LISTEN_PORT}")
    print(f"[mysql-honeypot] logging to {LOG_FILE}")
    while True:
        try:
            conn, addr = server.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            t.start()
        except Exception:
            pass

if __name__ == "__main__":
    main()
