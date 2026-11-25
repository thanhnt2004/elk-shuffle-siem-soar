#!/usr/bin/env python3
"""DATN alert-forwarder — ban Goi A (thay cho ec2/forwarder/forwarder.py cu).

Khac ban cu 2 diem, con lai giu nguyen:
  1. WEBHOOKS doc dong moi bien moi truong dang WEBHOOK_PB<nn> (PB01..PB99),
     khong gioi han PB01..PB06 nhu truoc. Nho vay them playbook chi can them
     bien trong .env, khong sua code.
  2. response_mode lay tu tag "mode:notify|approval|automatic" tren rule Kibana.
     Khong co tag mode thi mac dinh "notify". Khong con bang RESPONSE_MODE ghi cung
     theo R01..R17, nen doi che do phan ung chi can sua tag rule.

Van giu: hop dong du lieu schema 2.0, loc building_block, checkpoint search_after,
retry 2 lan, cac truong *_vn theo gio Viet Nam.
"""
import json
import logging
import os
import re
import ssl
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

ES_URL = os.environ["ES_URL"].rstrip("/")
ES_API_KEY = os.environ["ES_API_KEY"]
ES_CA = os.environ.get("ES_CA", "/certs/ca.crt")
ALERT_INDEX = os.environ.get("ALERT_INDEX", ".alerts-security.alerts-default")
POLL_SECONDS = int(os.environ.get("POLL_SECONDS", "15"))
SETTLE_SECONDS = int(os.environ.get("SETTLE_SECONDS", "10"))
WEBHOOK_SECRET = os.environ["WEBHOOK_SECRET"]
STATE_FILE = os.environ.get("STATE_FILE", "/data/checkpoint.json")

# Doc dong: moi WEBHOOK_PB<nn> khac rong deu duoc nap.
WEBHOOKS = {}
for _k, _v in os.environ.items():
    _m = re.fullmatch(r"WEBHOOK_(PB\d{2})", _k)
    if _m and _v.strip():
        WEBHOOKS[_m.group(1)] = _v.strip()

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("forwarder")
ES_TLS = ssl.create_default_context(cafile=ES_CA)
VALID_MODES = {"notify", "approval", "automatic"}


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


VN = timezone(timedelta(hours=7), "GMT+7")


def vn_text(iso):
    if not iso:
        return None
    try:
        t = datetime.fromisoformat(str(iso).replace("Z", "+00:00"))
    except ValueError:
        return None
    if t.tzinfo is None:
        t = t.replace(tzinfo=timezone.utc)
    return t.astimezone(VN).strftime("%d/%m/%Y %H:%M:%S (GMT+7)")


def get(obj, path, default=None):
    if not isinstance(obj, dict):
        return default
    if path in obj:
        return obj[path]
    parts = path.split(".")
    for i in range(len(parts) - 1, 0, -1):
        head = ".".join(parts[:i])
        if head in obj:
            value = get(obj[head], ".".join(parts[i:]))
            if value is not None:
                return value
    return default


def first(value):
    if isinstance(value, list):
        return value[0] if value else None
    return value


def field(src, name):
    value = first(get(src, name))
    if value is not None:
        return value
    for term in get(src, "kibana.alert.threshold_result.terms", []) or []:
        if term.get("field") == name:
            return term.get("value")
    return None


def techniques(src):
    found = set()
    for threat in get(src, "kibana.alert.rule.threat", []) or []:
        for tech in threat.get("technique", []) or []:
            subs = [s.get("id") for s in tech.get("subtechnique", []) or [] if s.get("id")]
            found.update(subs or ([tech["id"]] if tech.get("id") else []))
    return sorted(found)


def mode_from_tags(tags):
    for t in tags:
        if t.startswith("mode:") and t[5:] in VALID_MODES:
            return t[5:]
    return "notify"


def build_payload(src):
    tags = get(src, "kibana.alert.rule.tags", []) or []
    rule_id = next((t for t in tags if re.fullmatch(r"R\d{2}", t)), None)
    playbook_id = next((t for t in tags if re.fullmatch(r"PB\d{2}", t)), None)
    cardinality = get(src, "kibana.alert.threshold_result.cardinality", []) or []
    return {
        "schema_version": "2.0",
        "playbook_id": playbook_id,
        "rule_id": rule_id,
        "rule_name": get(src, "kibana.alert.rule.name"),
        "alert_id": get(src, "kibana.alert.uuid"),
        "alert_time": (get(src, "kibana.alert.original_time")
                       or get(src, "kibana.alert.threshold_result.from")
                       or get(src, "@timestamp")),
        "detected_time": get(src, "@timestamp"),
        "forwarded_time": None,
        "test_id": None,
        "host_name": field(src, "host.name"),
        "source_ip": field(src, "source.ip"),
        "destination_ip": field(src, "destination.ip"),
        "user_name": field(src, "user.name"),
        "event_count": get(src, "kibana.alert.threshold_result.count"),
        "distinct_user_count": cardinality[0].get("value") if cardinality else None,
        "severity": get(src, "kibana.alert.severity"),
        "risk_score": get(src, "kibana.alert.risk_score"),
        "mitre_techniques": techniques(src),
        "evidence_query": get(src, "kibana.alert.rule.parameters.query"),
        "response_mode": mode_from_tags(tags),
    }


def post_json(url, body, headers, context=None):
    req = urllib.request.Request(
        url, data=json.dumps(body).encode("utf-8"), method="POST",
        headers={"Content-Type": "application/json", **headers})
    with urllib.request.urlopen(req, context=context, timeout=15) as resp:
        raw = resp.read()
    return json.loads(raw) if raw else {}


def load_state():
    try:
        with open(STATE_FILE, encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        since = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()
        return {"since": since, "search_after": None}


def save_state(state):
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(state, f)
    os.replace(tmp, STATE_FILE)


def search(state):
    body = {
        "size": 50,
        "sort": [{"@timestamp": "asc"}, {"kibana.alert.uuid": "asc"}],
        "query": {"bool": {
            "filter": [{"range": {"@timestamp": {"gt": state["since"],
                                                 "lte": f"now-{SETTLE_SECONDS}s"}}}],
            "must_not": [{"exists": {"field": "kibana.alert.building_block_type"}}],
        }},
    }
    if state.get("search_after"):
        body["search_after"] = state["search_after"]
    url = f"{ES_URL}/{ALERT_INDEX}/_search?ignore_unavailable=true"
    result = post_json(url, body, {"Authorization": f"ApiKey {ES_API_KEY}"}, ES_TLS)
    return result.get("hits", {}).get("hits", [])


def forward(src):
    payload = build_payload(src)
    url = WEBHOOKS.get(payload["playbook_id"] or "")
    if not payload["rule_id"] or not url:
        log.warning("bo qua alert %s: thieu tag Rxx/PBxx hoac chua khai webhook (rule=%s, pb=%s)",
                    payload["alert_id"], payload["rule_id"], payload["playbook_id"])
        return
    payload["forwarded_time"] = now_iso()
    payload["alert_time_vn"] = vn_text(payload["alert_time"])
    payload["detected_time_vn"] = vn_text(payload["detected_time"])
    payload["forwarded_time_vn"] = vn_text(payload["forwarded_time"])
    for attempt in range(3):
        try:
            post_json(url, payload, {"X-DATN-Secret": WEBHOOK_SECRET})
            log.info("da gui %s %s mode=%s alert=%s", payload["playbook_id"], payload["rule_id"],
                     payload["response_mode"], payload["alert_id"])
            return
        except (urllib.error.URLError, TimeoutError) as exc:
            log.warning("gui loi lan %d: %s", attempt + 1, exc)
            time.sleep(2 ** attempt)
    raise RuntimeError(f"Shuffle khong nhan alert {payload['alert_id']}")


def main():
    state = load_state()
    log.info("khoi dong, %d webhook: %s", len(WEBHOOKS), ", ".join(sorted(WEBHOOKS)))
    log.info("checkpoint=%s", state)
    while True:
        try:
            for hit in search(state):
                forward(hit["_source"])
                state["search_after"] = hit["sort"]
                save_state(state)
        except Exception as exc:
            log.error("vong poll loi: %s", exc)
        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()
