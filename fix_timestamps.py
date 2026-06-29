#!/usr/bin/env python3
"""
One-time fix: set @timestamp on all historical documents that are missing it.
Uses 'index' action (upsert) so existing docs get updated, not skipped.
"""
import json, glob, sys, urllib.request

ES_HOST  = "http://localhost:9200"
DEST     = "honeypot-ssh-events"
LOG_GLOB = "/opt/cowrie-docker/logs/cowrie.json*"
BATCH    = 500

def make_id(raw):
    return "{}-{}-{}".format(
        raw.get("uuid", ""),
        raw.get("eventid", ""),
        raw.get("timestamp", "")
    )

def parse_timestamp(ts):
    # Truncate microseconds to milliseconds for JS/ES compatibility
    if ts:
        return ts[:23] + "Z" if len(ts) > 24 else ts
    return None

def bulk_update(batch):
    lines = []
    for doc_id, doc in batch:
        lines.append(json.dumps({"index": {"_index": DEST, "_id": doc_id}}))
        lines.append(json.dumps(doc))
    body = "\n".join(lines) + "\n"
    req = urllib.request.Request(
        f"{ES_HOST}/_bulk",
        data=body.encode("utf-8"),
        headers={"Content-Type": "application/x-ndjson"},
        method="POST"
    )
    with urllib.request.urlopen(req) as resp:
        result = json.loads(resp.read())
    updated = sum(1 for i in result["items"] if i.get("index",{}).get("result") in ("created","updated"))
    errors  = [i["index"] for i in result["items"] if i.get("index",{}).get("status") not in (200,201)]
    return updated, errors

def main():
    files = sorted(glob.glob(LOG_GLOB))
    print(f"Found {len(files)} log file(s)")
    seen  = set()
    batch = []
    total = updated_total = error_total = 0

    for fpath in files:
        with open(fpath, "r", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    raw = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not raw.get("uuid") or not raw.get("eventid"):
                    continue
                total += 1
                doc_id = make_id(raw)
                if doc_id in seen:
                    continue
                seen.add(doc_id)

                # Build doc with @timestamp set
                doc = dict(raw)
                inp = doc.get("input")
                if doc.get("eventid") == "cowrie.command.input" and isinstance(inp, str):
                    doc["command_input"] = inp
                doc.pop("input", None)
                ts = parse_timestamp(raw.get("timestamp", ""))
                if ts:
                    doc["@timestamp"] = ts

                batch.append((doc_id, doc))
                if len(batch) >= BATCH:
                    u, e = bulk_update(batch)
                    updated_total += u
                    error_total   += len(e)
                    if e:
                        print(f"  ERRORS: {e[:2]}", file=sys.stderr)
                    batch = []

    if batch:
        u, e = bulk_update(batch)
        updated_total += u
        error_total   += len(e)

    print(f"\n{'='*50}")
    print(f"Raw lines read  : {total}")
    print(f"Unique events   : {len(seen)}")
    print(f"Updated in ES   : {updated_total}")
    print(f"Errors          : {error_total}")
    print(f"{'='*50}")
    if error_total > 0:
        print("ERRORS EXIST — check stderr", file=sys.stderr)
        sys.exit(1)
    else:
        print("SUCCESS")

main()
