#!/usr/bin/env python3
"""Ghi ket qua terminal cua mot playbook SOAR vao datn-soar-results (dung chung moi PB).

Shuffle goi qua SSH (ubuntu@10.99.0.1, KHONG sudo):
    python3 -I /opt/datn/src/metrics/datn-record-result.py <context_base64>

Hop dong du lieu: huong-dan/goi-a/record-result-tong-quat.md (muc 1-2). Ban trien khai 24/11/2026
bo sung so voi ban mau trong tai lieu:
  - rule_id phai la ID day du dang datn-pbNN-rNN (alert duoc xac thuc theo ID nay + thuc the);
  - outcome cuong buc (skipped/no_action/denied/expired) ghi kem `reason` do workflow truyen;
  - `enrichment` (tom tat lam giau, khong index) va `action` de doi soat Chuong 4;
  - ghi idempotent theo execution_id (_create, 409 = da co).
"""

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

ALERT_INDEX = ".alerts-security.alerts-default"
ENTITY_FIELDS = {"source.ip", "host.name", "host.id", "user.name", "http.request.id"}
MODES = {"notify", "approval", "automatic"}
FORCED = {"denied", "expired", "skipped", "no_action"}


def utc_stamp(epoch):
    if type(epoch) is not int or epoch <= 0:
        raise ValueError("thieu hoac sai moc thoi gian (epoch giay) tu Shuffle")
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()


def opt_stamp(epoch):
    return utc_stamp(epoch) if epoch not in (None, 0) else None


def request(context, key, path, body, method="POST"):
    req = urllib.request.Request(
        ELASTIC + path, data=json.dumps(body).encode(), method=method,
        headers={"Authorization": f"ApiKey {key}", "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, context=context, timeout=12) as response:
        return response.status, json.load(response)


def clean_entity(field, value):
    if field not in ENTITY_FIELDS:
        raise ValueError(f"entity_field khong hop le: {field}")
    if field == "source.ip":
        return str(ipaddress.ip_address(value))
    if not isinstance(value, str) or not value or len(value) > 255:
        raise ValueError("entity_value rong hoac qua dai")
    return value


def in_window(stamp, started, now):
    return stamp is not None and started <= stamp <= now


def decide(data, started, now):
    """Tra ve (result, verified, extra) theo response_mode."""
    mode = data["response_mode"]
    if mode not in MODES:
        raise ValueError("response_mode phai la notify/approval/automatic")

    forced = data.get("outcome")
    if forced in FORCED:
        default = {"denied": "approval_denied", "expired": "approval_expired",
                   "skipped": "skipped", "no_action": "no_action"}[forced]
        reason = data.get("reason") if isinstance(data.get("reason"), str) else default
        return forced, False, {"decision": forced, "reason": reason[:200]}

    extra = {}
    if mode == "notify":
        receipt = data.get("telegram") or {}
        notified_at = None
        code = receipt.get("status")
        if type(code) is int:
            extra["telegram_status"] = code
        mid, when = receipt.get("message_id"), receipt.get("date")
        if (code == 200 and receipt.get("ok") is True and type(mid) is int and mid > 0
                and type(when) is int and when > 0):
            sent = utc_stamp(when)
            if in_window(sent, started, now):
                notified_at = sent
                extra["telegram_message_id"] = mid
        verified = notified_at is not None
        if verified:
            extra["notified_at"] = notified_at
        extra["decision"] = "notify"
        extra["reason"] = "telegram_accepted" if verified else "telegram_not_confirmed"
        return ("success" if verified else "failed"), verified, extra

    # approval / automatic: responder da chay roi hau kiem
    verify = data.get("verify") or {}
    ok = verify.get("ok") is True
    verified_at = opt_stamp(data.get("verified_at"))
    if not in_window(verified_at, started, now):
        verified_at = None
    verified = ok and verified_at is not None

    if mode == "approval":
        requested_at = opt_stamp(data.get("approval_requested_at"))
        approved_at = opt_stamp(data.get("approved_at"))
        if in_window(requested_at, started, now):
            extra["approval_requested_at"] = requested_at
        if in_window(approved_at, started, now):
            extra["approved_at"] = approved_at
        extra["decision"] = "approved" if extra.get("approved_at") else "manual"
    else:
        extra["decision"] = "automatic"

    if verified:
        extra["verified_at"] = verified_at
    if isinstance(verify.get("output"), str):
        extra["verify_output"] = verify["output"][:2000]
    receipt = data.get("telegram") or {}
    if isinstance(receipt, dict) and type(receipt.get("message_id")) is int:
        extra["telegram_message_id"] = receipt["message_id"]
        extra["telegram_ok"] = receipt.get("ok") is True
    extra["reason"] = "remediation_verified" if verified else "remediation_unverified"
    return ("success" if verified else "failed"), verified, extra


def make_result(data, alert, now):
    started = utc_stamp(data["execution_started_at"])
    result, verified, extra = decide(data, started, now)
    doc = {
        "@timestamp": now,
        "execution_id": str(UUID(data["execution_id"])),
        "alert_id": data["alert_id"],
        "playbook_id": data["playbook_id"],
        "rule_id": data["rule_id"],
        "entity_field": data["_entity_field"],
        "entity_value": data["_entity_value"],
        "response_mode": data["response_mode"],
        "phase": "terminal",
        "result": result,
        "verified": verified,
        "execution_started_at": started,
        "detected_time": alert["kibana.alert.start"],
    }
    if data["_entity_field"] == "source.ip":
        doc["source_ip"] = data["_entity_value"]
    if isinstance(data.get("action"), str):
        doc["action"] = data["action"][:500]
    if isinstance(data.get("test_id"), str):
        doc["test_id"] = data["test_id"]
    if isinstance(data.get("enrichment"), dict):
        doc["enrichment"] = data["enrichment"]
    doc.update(extra)
    return doc


def record(data):
    if not re.fullmatch(r"[a-f0-9]{64}", str(data.get("alert_id", ""))):
        raise ValueError("alert_id khong phai UUID canh bao Elastic (64 hex)")
    pb = data.get("playbook_id")
    if not re.fullmatch(r"PB\d{2}", str(pb)):
        raise ValueError("playbook_id phai dang PBxx")
    rule_id = data.get("rule_id")
    if not re.fullmatch(rf"datn-{str(pb).lower()}-r\d{{2}}", str(rule_id)):
        raise ValueError("rule_id phai la ID day du datn-pbNN-rNN cua dung playbook")
    data["_entity_field"] = data["entity_field"]
    data["_entity_value"] = clean_entity(data["entity_field"], data["entity_value"])

    keys = dict(line.split("=", 1) for line in KEY_FILE.read_text().splitlines() if "=" in line)
    context = ssl.create_default_context(cafile=CA_FILE)
    _, response = request(context, keys["FORWARDER_ES_API_KEY"], f"/{ALERT_INDEX}/_search", {
        "size": 2,
        "_source": ["kibana.alert.start"],
        "query": {"bool": {"filter": [
            {"term": {"kibana.alert.uuid": data["alert_id"]}},
            {"term": {"kibana.alert.rule.rule_id": rule_id}},
            {"term": {data["_entity_field"]: data["_entity_value"]}},
        ]}},
    })
    hits = response["hits"]["hits"]
    if response.get("timed_out") or response["_shards"]["failed"] or len(hits) != 1:
        raise ValueError("khong xac thuc duoc canh bao + thuc the trong Elastic")
    doc = make_result(data, hits[0]["_source"], datetime.now(timezone.utc).isoformat())
    document_id = f"{pb.lower()}-{doc['execution_id']}-terminal"
    try:
        status, ack = request(context, keys["SOAR_RESULTS_API_KEY"],
                              f"/datn-soar-results/_create/{document_id}?refresh=wait_for", doc, "PUT")
    except urllib.error.HTTPError as error:
        if error.code != 409:
            raise
        return {"stored": True, "document_id": document_id, "already_exists": True}
    if status != 201 or ack.get("result") != "created":
        raise ValueError("Elasticsearch khong xac nhan tao tai lieu")
    return {"stored": True, "document_id": document_id,
            "verified": doc["verified"], "result": doc["result"], "decision": doc["decision"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("context_b64", help="JSON context (execution + verify) da base64")
    args = parser.parse_args()
    try:
        context = json.loads(base64.b64decode(args.context_b64, validate=True))
        print(json.dumps(record(context)), end="")
    except urllib.error.HTTPError as error:
        sys.exit(f"result not stored: Elasticsearch HTTP {error.code}")
    except (OSError, ValueError, TypeError, KeyError, AttributeError, OverflowError) as error:
        sys.exit(f"result not stored: {type(error).__name__}: {error}")


if __name__ == "__main__":
    main()
