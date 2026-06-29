#!/usr/bin/env python3
"""
Re-ingest all Cowrie raw log files into honeypot-ssh-events.
- Reads from raw JSON log files (authoritative source, never corrupted)
- Deduplicates by uuid+eventid+timestamp in memory before sending
- Recovers real command_input only on genuine cowrie.command.input events
- Bulk-indexes via Elasticsearch REST API with deterministic _id
- Safe to rerun: create action skips existing documents
"""
import json, glob, sys, urllib.request

ES_HOST  = "http://localhost:9200"
DEST     = "honeypot-ssh-events"
LOG_GLOB = "/opt/cowrie-docker/logs/cowrie.json*"
BATCH    = 500

def build_doc(raw):
    doc = dict(raw)
    inp = doc.get("input")
    if doc.get("eventid") == "cowrie.command.input" and isinstance(inp, str):
        doc["command_input"] = inp
    doc.pop("input", None)
    return doc

def make_id(doc):
    return "{}-{}-{}".format(
        doc.get("uuid", ""),
        doc.get("eventid", ""),
        doc.get("timestamp", "")
    )

def bulk_index(batch):
    lines = []
    for doc_id, doc in batch:
        lines.append(json.dumps({"create": {"_index": DEST, "_id": doc_id}}))
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
    created  = sum(1 for i in result["items"] if i.get("create",{}).get("result") == "created")
    conflict = sum(1 for i in result["items"] if i.get("create",{}).get("status") == 409)
    errors   = [i["create"] for i in result["items"]
                if i.get("create",{}).get("status") not in (201, 409)]
    return created, conflict, errors

def main():
    files = sorted(glob.glob(LOG_GLOB))
    print(f"Found {len(files)} log file(s)")
    seen = set()
    batch = []
    total = created_total = conflict_total = error_total = 0

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
                total += 1
                if not raw.get("uuid") or not raw.get("eventid"):
                    continue
                doc    = build_doc(raw)
                doc_id = make_id(doc)
                if doc_id in seen:
                    conflict_total += 1
                    continue
                seen.add(doc_id)
                batch.append((doc_id, doc))
                if len(batch) >= BATCH:
                    c, k, e = bulk_index(batch)
                    created_total  += c
                    conflict_total += k
                    error_total    += len(e)
                    if e:
                        print(f"  ERRORS: {e[:2]}", file=sys.stderr)
                    batch = []

    if batch:
        c, k, e = bulk_index(batch)
        created_total  += c
        conflict_total += k
        error_total    += len(e)
        if e:
            print(f"  ERRORS in final batch: {e[:2]}", file=sys.stderr)

    print(f"\n{'='*50}")
    print(f"Raw lines read      : {total}")
    print(f"Unique events found : {len(seen)}")
    print(f"Created in ES       : {created_total}")
    print(f"Conflicts (skipped) : {conflict_total}")
    print(f"Errors              : {error_total}")
    print(f"{'='*50}")
    if error_total > 0:
        print("ERRORS EXIST — check stderr above", file=sys.stderr)
        sys.exit(1)
    else:
        print("SUCCESS")

main()
