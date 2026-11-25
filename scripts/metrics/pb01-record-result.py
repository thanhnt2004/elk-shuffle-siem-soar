#!/usr/bin/env python3
"""Store the terminal outcome produced by the PB01 Telegram action."""

import argparse
import base64
import ipaddress
import json
import re
import ssl
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID


KEY_FILE = Path("/opt/datn/secrets/api-keys.env")
CA_FILE = "/opt/datn/elk/certs/ca/ca.crt"
ELASTIC = "https://localhost:9200"
RULE_ID = "datn-pb01-r01"


def utc_stamp(epoch):
    if type(epoch) is not int or epoch <= 0:
        raise ValueError("missing or invalid timestamp from Shuffle")
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()


def request(context, key, path, body, method="POST"):
    req = urllib.request.Request(
        ELASTIC + path, data=json.dumps(body).encode(), method=method,
        headers={"Authorization": f"ApiKey {key}", "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, context=context, timeout=12) as response:
        return response.status, json.load(response)


def make_result(data, alert, now):
    started = utc_stamp(data["execution_started_at"])
    receipt = data.get("telegram", {})
    code = receipt.get("status")
    notified_at = None
    message_id = receipt.get("message_id")
    receipt_time = receipt.get("date")
    if (code == 200 and receipt.get("ok") is True and type(message_id) is int and message_id > 0
            and type(receipt_time) is int and receipt_time > 0):
        sent = utc_stamp(receipt_time)
        if started <= sent <= now:
            notified_at = sent
    verified = notified_at is not None
    doc = {
        "@timestamp": now, "execution_id": str(UUID(data["execution_id"])),
        "alert_id": data["alert_id"], "playbook_id": "PB01", "rule_id": RULE_ID,
        "source_ip": data["source_ip"], "decision": "notify", "response_mode": "notify",
        "phase": "terminal", "result": "success" if verified else "failed", "verified": verified,
        "execution_started_at": started, "detected_time": alert["kibana.alert.start"],
        "reason": "telegram_accepted" if verified else "telegram_not_confirmed",
    }
    if type(code) is int:
        doc["telegram_status"] = code
    if verified:
        doc.update(notified_at=notified_at, telegram_message_id=message_id)
    return doc


def record(data):
    if not re.fullmatch(r"[a-f0-9]{64}", data["alert_id"]):
        raise ValueError("invalid Elastic alert ID")
    addr = str(ipaddress.ip_address(data["source_ip"]))
    keys = dict(line.split("=", 1) for line in KEY_FILE.read_text().splitlines() if "=" in line)
    context = ssl.create_default_context(cafile=CA_FILE)
    _, response = request(context, keys["FORWARDER_ES_API_KEY"], "/.alerts-security.alerts-default/_search", {
        "size": 2,
        "_source": ["kibana.alert.start"],
        "query": {"bool": {"filter": [
            {"term": {"kibana.alert.uuid": data["alert_id"]}},
            {"term": {"kibana.alert.rule.rule_id": RULE_ID}},
            {"term": {"source.ip": addr}},
        ]}},
    })
    hits = response["hits"]["hits"]
    if response.get("timed_out") or response["_shards"]["failed"] or len(hits) != 1:
        raise ValueError("PB01 alert and source IP could not be verified")
    doc = make_result(data, hits[0]["_source"], datetime.now(timezone.utc).isoformat())
    document_id = f"pb01-{doc['execution_id']}-terminal"
    try:
        status, ack = request(context, keys["SOAR_RESULTS_API_KEY"],
                              f"/datn-soar-results/_create/{document_id}?refresh=wait_for", doc, "PUT")
    except urllib.error.HTTPError as error:
        if error.code != 409:
            raise
        return {"stored": True, "document_id": document_id, "already_exists": True}
    if status != 201 or ack.get("result") != "created":
        raise ValueError("Elasticsearch did not confirm document creation")
    return {"stored": True, "document_id": document_id, "verified": doc["verified"], "result": doc["result"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("context_b64", help="Encoded PB01 execution and Telegram receipt fields")
    args = parser.parse_args()
    try:
        context = json.loads(base64.b64decode(args.context_b64, validate=True))
        print(json.dumps(record(context)))
    except urllib.error.HTTPError as error:
        sys.exit(f"PB01 result not stored: Elasticsearch HTTP {error.code}")
    except (OSError, ValueError, TypeError, KeyError, AttributeError, OverflowError) as error:
        sys.exit(f"PB01 result not stored: {type(error).__name__}: {error}")


if __name__ == "__main__":
    main()
