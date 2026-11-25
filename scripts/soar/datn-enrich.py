#!/usr/bin/env python3
"""Lam giau alert cho 6 playbook SOAR (DATN): PB02, PB03, PB05, PB15, PB18, PB23.

Shuffle goi qua SSH (ubuntu@10.99.0.1), tham so la payload forwarder da base64:
    python3 -I /opt/datn/src/soar/datn-enrich.py <PBnn> <payload_base64>

In ra MOT dong JSON, KHONG xuong dong (de Shuffle doc $enrich.output.<truong>):
    ok, reason, playbook_id, rule_tag, rule_full_id, alert_start, entity_field, entity_value,
    summary (van ban cho Telegram), cooldown, + truong rieng tung PB (file_path, dest_ip, task_name, host_ip...).
Chi DOC Elasticsearch (khoa harness-write chi co quyen read tren datn-* va alert). Khong thay doi gi.
"""
import base64
import ipaddress
import json
import re
import ssl
import sys
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

KEY_FILE = Path("/opt/datn/secrets/api-keys.env")
CA_FILE = "/opt/datn/elk/certs/ca/ca.crt"
ELASTIC = "https://localhost:9200"
ALERTS = ".alerts-security.alerts-default"
LAB_NET = ipaddress.ip_network("192.168.100.0/24")
PRIVATE_SKIP = [ipaddress.ip_network(n) for n in ("192.168.100.0/24", "10.99.0.0/24", "127.0.0.0/8")]
PROTECTED = {"192.168.100.1", "192.168.100.103", "192.168.173.1", "192.168.173.2", "192.168.173.10"}
EXEC_EXT = (".exe", ".dll", ".ps1", ".bat", ".vbs", ".hta", ".scr", ".cmd")
# Cua so gop (giay) theo PB + thuc the: cac alert gan nhu dong thoi cua CUNG mot dot tan cong
# (R02+R03, R04+R05, R07+R08/R09) chi xu ly mot lan. Khong dung cua so dai bang TTL chan vi enrich
# khong biet IP da duoc go chan som (chan lai IP dang bi chan van idempotent: chi gia han TTL).
# PB15/PB18/PB23 = 0: moi file/task/lan xoa log la mot su co rieng; R68 chi khop thay doi "removed"
# nen buoc khoi phuc cua SOAR khong tu kich hoat lai.
COOLDOWN = {"PB02": 120, "PB03": 120, "PB05": 120, "PB15": 0, "PB18": 0, "PB23": 0,
            "PB16": 60, "PB31": 60}
VN = timezone(timedelta(hours=7))


def pick_dest_ip(text):
    """Lay IP dich dau tien KHONG thuoc ha tang/lab-LAN tu mot chuoi (proctitle/script block/URL)."""
    for d in re.findall(r"(\d{1,3}(?:\.\d{1,3}){3})", str(text or "")):
        try:
            a = ipaddress.ip_address(d)
        except ValueError:
            continue
        if not any(a in n for n in PRIVATE_SKIP) and str(a) not in PROTECTED:
            return str(a)
    return None


class ES:
    def __init__(self):
        keys = dict(l.split("=", 1) for l in KEY_FILE.read_text().splitlines() if "=" in l)
        self.key = keys["HARNESS_API_KEY"]
        self.ctx = ssl.create_default_context(cafile=CA_FILE)

    def search(self, index, body):
        req = urllib.request.Request(
            f"{ELASTIC}/{index}/_search?ignore_unavailable=true", data=json.dumps(body).encode(),
            method="POST", headers={"Authorization": f"ApiKey {self.key}", "Content-Type": "application/json"})
        with urllib.request.urlopen(req, context=self.ctx, timeout=15) as resp:
            return json.load(resp)


def get(doc, path, default=None):
    """Doc truong ca dang phang ("a.b.c") lan long nhau."""
    if not isinstance(doc, dict):
        return default
    if path in doc:
        return doc[path]
    parts = path.split(".")
    for i in range(len(parts) - 1, 0, -1):
        head = ".".join(parts[:i])
        if head in doc:
            v = get(doc[head], ".".join(parts[i:]))
            if v is not None:
                return v
    return default


def first(v):
    return v[0] if isinstance(v, list) and v else (None if isinstance(v, list) else v)


def iso(s):
    try:
        return datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    except ValueError:
        return None


def vn(dt):
    return dt.astimezone(VN).strftime("%d/%m/%Y %H:%M:%S") if dt else "?"


def rng(start, before, after):
    return {"range": {"@timestamp": {"gte": (start - before).isoformat(), "lte": (start + after).isoformat()}}}


def short(s, n=120):
    s = str(s or "")
    return s if len(s) <= n else s[: n - 1] + "…"


def buckets(resp, name):
    return [(b["key"], b["doc_count"]) for b in resp.get("aggregations", {}).get(name, {}).get("buckets", [])]


def recent_success(es, pb, field, value, seconds, alert_id):
    """Da co ket qua terminal thanh cong cho cung PB + thuc the trong khoang `seconds` -> cooldown."""
    since = (datetime.now(timezone.utc) - timedelta(seconds=seconds)).isoformat()
    r = es.search("datn-soar-results", {"size": 1, "_source": ["alert_id", "@timestamp"], "query": {"bool": {
        "filter": [{"term": {"playbook_id": pb}}, {"term": {"entity_value": value}},
                   {"term": {"result": "success"}}, {"range": {"@timestamp": {"gte": since}}}],
        "must_not": [{"term": {"alert_id": alert_id}}]}}})
    hits = r["hits"]["hits"]
    return hits[0]["_source"]["alert_id"] if hits else None


# ---------------------------------------------------------------- tung playbook
def web_ip(payload):
    ip = str(ipaddress.ip_address(payload.get("source_ip") or ""))
    return ip


def pb02(es, alert, start, payload):
    ip = web_ip(payload)
    r = es.search("datn-web-*", {"size": 0, "query": {"bool": {"filter": [
        {"term": {"source.ip": ip}}, {"term": {"event.dataset": "nginx.access"}}, rng(start, timedelta(minutes=10), timedelta(minutes=1))]}},
        "aggs": {"codes": {"terms": {"field": "http.response.status_code", "size": 6}},
                 "paths": {"terms": {"field": "url.original", "size": 5}},
                 "ua": {"terms": {"field": "user_agent.original", "size": 2}}}})
    total = r["hits"]["total"]["value"]
    codes = ", ".join(f"{k}×{n}" for k, n in buckets(r, "codes"))
    paths = ", ".join(short(k, 40) for k, _ in buckets(r, "paths"))
    ua = "; ".join(short(k, 60) for k, _ in buckets(r, "ua"))
    return {"entity_field": "source.ip", "entity_value": ip, "requests_10m": total,
            "summary": f"Request 10′: {total} | Mã: {codes}\nUA: {ua}\nURL nhiều nhất: {paths}"}


def pb03(es, alert, start, payload):
    ip = web_ip(payload)
    r = es.search("datn-web-*", {"size": 0, "query": {"bool": {"filter": [
        {"term": {"source.ip": ip}}, {"term": {"event.category": "authentication"}},
        rng(start, timedelta(minutes=15), timedelta(minutes=1))]}},
        "aggs": {"users": {"cardinality": {"field": "user.name"}},
                 "out": {"terms": {"field": "event.outcome"}},
                 "ok_users": {"filter": {"term": {"event.outcome": "success"}},
                              "aggs": {"u": {"terms": {"field": "user.name", "size": 3}}}}}})
    users = r["aggregations"]["users"]["value"]
    out = dict(buckets(r, "out"))
    ok_users = [k for k, _ in r["aggregations"]["ok_users"]["u"]["buckets"]]
    tag = payload.get("rule_id")
    kind = {"R04": "Password spraying", "R05": "Credential stuffing (bot)", "R06": "Password guessing"}.get(tag, tag)
    summary = (f"Kiểu: {kind} | Tài khoản bị thử: {users} | Thất bại: {out.get('failure', 0)} | "
               f"Thành công: {out.get('success', 0)}")
    data = {"entity_field": "source.ip", "entity_value": ip, "users_tried": users,
            "failures": out.get("failure", 0), "successes": out.get("success", 0), "summary": summary}
    if tag == "R06":
        data["compromised_user"] = ok_users[0] if ok_users else None   # chi luu noi bo, khong gui Telegram
        data["summary"] += ("\n⚠️ CÓ ĐĂNG NHẬP THÀNH CÔNG sau chuỗi thất bại — cần đổi mật khẩu / "
                            "khoá tài khoản liên quan (tên tài khoản xem trong datn-soar-results).")
    return data


def pb05(es, alert, start, payload):
    ip = web_ip(payload)
    r = es.search("datn-web-*", {"size": 5, "sort": [{"@timestamp": "desc"}],
                                 "_source": ["url.original", "http.response.status_code", "http.request.id", "@timestamp"],
                                 "query": {"bool": {"filter": [
                                     {"term": {"source.ip": ip}}, {"term": {"event.dataset": "nginx.access"}},
                                     rng(start, timedelta(minutes=10), timedelta(minutes=1))],
                                     "should": [{"wildcard": {"url.original": {"value": p, "case_insensitive": True}}}
                                                for p in ("*union*", "*select*", "*%27*", "*sleep*", "*..*", "*%2e%2e*", "*passwd*")],
                                     "minimum_should_match": 1}}})
    rows = [h["_source"] for h in r["hits"]["hits"]]
    ids = [get(x, "http.request.id") for x in rows if get(x, "http.request.id")]
    lines = [f"{get(x, 'http.response.status_code')} {short(get(x, 'url.original'), 110)}" for x in rows]
    return {"entity_field": "source.ip", "entity_value": ip, "request_ids": ids,
            "matched_requests": r["hits"]["total"]["value"],
            "summary": "Mẫu/URL gần nhất:\n" + "\n".join(lines) + f"\nrequest_id: {', '.join(ids[:3])}"}


# Kiem ke tai san lab (khop static mapping DHCP tren pfSense, vm-01). Winlogbeat cua lab khong gui
# host.ip (khong bat add_host_metadata), nen cac PB can IP cua host Windows tra bang nay.
LAB_ASSETS = {"win10-elk": "192.168.100.101", "ubuntu-server-elk": "192.168.100.103"}


def host_ipv4(alert):
    name = str(first(get(alert, "host.name")) or "").lower()
    ips = get(alert, "host.ip") or []
    ips = [ips] if isinstance(ips, str) else list(ips)
    for v in ips + ([LAB_ASSETS[name]] if name in LAB_ASSETS else []):
        try:
            a = ipaddress.ip_address(v)
        except ValueError:
            continue
        if a.version == 4 and a in LAB_NET:
            return str(a)
    return None


def pb15(es, alert, start, payload):
    host = payload.get("host_name") or first(get(alert, "host.name"))
    eid = first(get(alert, "process.entity_id"))
    win = rng(start, timedelta(minutes=10), timedelta(minutes=2))
    base = [{"term": {"host.name": host}}, win]
    files, dests, cmd = [], [], first(get(alert, "process.command_line"))
    if eid:
        r = es.search("datn-windows-*", {"size": 20, "sort": [{"@timestamp": "desc"}],
                                         "_source": ["event.code", "file.path", "destination.ip", "process.command_line", "process.name"],
                                         "query": {"bool": {"filter": base + [{"term": {"process.entity_id": eid}},
                                                                              {"terms": {"event.code": ["1", "3", "11"]}}]}}})
        for h in r["hits"]["hits"]:
            s = h["_source"]
            code = str(get(s, "event.code"))
            if code == "11" and get(s, "file.path"):
                files.append(get(s, "file.path"))
            elif code == "3" and get(s, "destination.ip"):
                dests.append(get(s, "destination.ip"))
            elif code == "1" and not cmd:
                cmd = get(s, "process.command_line")
    if not files:   # bitsadmin: file do svchost (BITS) tao -> tim theo host + thu muc lab
        r = es.search("datn-windows-*", {"size": 10, "sort": [{"@timestamp": "desc"}], "_source": ["file.path"],
                                         "query": {"bool": {"filter": base + [{"term": {"event.code": "11"}},
                                                                              {"prefix": {"file.path": "C:\\DATN\\"}}]}}})
        files = [get(h["_source"], "file.path") for h in r["hits"]["hits"]]
    files = [f for f in files if f and f.lower().startswith("c:\\datn\\") and f.lower().endswith(EXEC_EXT)]
    if not dests and cmd:
        dests = re.findall(r"https?://(\d{1,3}(?:\.\d{1,3}){3})", cmd)
    dest = None
    for d in dests:
        try:
            a = ipaddress.ip_address(d)
        except ValueError:
            continue
        if not any(a in n for n in PRIVATE_SKIP) and str(a) not in PROTECTED:
            dest = str(a)
            break
    if not files:
        return {"ok": False, "reason": "khong tim thay file thuc thi trong C:\\DATN\\ lien quan alert",
                "entity_field": "host.name", "entity_value": host}
    return {"entity_field": "host.name", "entity_value": host, "file_path": files[0], "dest_ip": dest or "",
            "process_command_line": short(cmd, 200),
            "summary": f"Host: {host}\nFile: {files[0]}\nNguồn tải: {dest or 'không xác định'}\nLệnh: {short(cmd, 160)}"}


def pb18(es, alert, start, payload):
    host = payload.get("host_name") or first(get(alert, "host.name"))
    task = first(get(alert, "winlog.event_data.TaskName"))
    content = first(get(alert, "winlog.event_data.TaskContent")) or ""
    subject = first(get(alert, "winlog.event_data.SubjectUserName"))
    cmd = " ".join(x.strip() for x in re.findall(r"<(?:Command|Arguments)>(.*?)</(?:Command|Arguments)>", content, re.S))
    risky = re.search(r"(-enc|-encodedcommand|\\temp\\|\\appdata\\|users\\public|frombase64|downloadstring|iex)",
                      cmd, re.I)
    if not task:
        return {"ok": False, "reason": "alert khong co TaskName", "entity_field": "host.name", "entity_value": host}
    name = task.lstrip("\\")
    in_scope = bool(re.fullmatch(r"DATN-[A-Za-z0-9_.-]{1,60}", name))
    return {"entity_field": "host.name", "entity_value": host, "task_name": name, "task_action": short(cmd, 200),
            "in_lab_scope": in_scope, "risk_level": "high" if risky else "normal", "created_by": subject,
            "summary": (f"Host: {host} | Tạo bởi: {subject}\nTask: \\{name}\nAction: {short(cmd, 160)}\n"
                        f"Mức rủi ro nội dung: {'CAO (lệnh mã hoá/thư mục tạm)' if risky else 'bình thường'}"
                        + ("" if in_scope else "\nTask ngoài phạm vi lab (không phải DATN-*): responder sẽ từ chối tắt."))}


def pb23(es, alert, start, payload):
    host = payload.get("host_name") or first(get(alert, "host.name"))
    hip = host_ipv4(alert)
    if not hip:   # threshold alert chi co host.name -> lay host.ip tu su kien goc gan nhat
        r = es.search("datn-windows-*", {"size": 1, "sort": [{"@timestamp": "desc"}], "_source": ["host.ip"],
                                         "query": {"bool": {"filter": [{"term": {"host.name": host}}, rng(start, timedelta(minutes=30), timedelta(minutes=1))]}}})
        hits = r["hits"]["hits"]
        hip = host_ipv4(hits[0]["_source"]) if hits else None
    ev = es.search("datn-windows-*", {"size": 0, "query": {"bool": {"filter": [
        {"term": {"host.name": host}}, {"range": {"@timestamp": {"gte": (start - timedelta(minutes=60)).isoformat(),
                                                                "lt": start.isoformat()}}}]}},
        "aggs": {"ch": {"terms": {"field": "winlog.channel", "size": 6}}}})
    kept = ev["hits"]["total"]["value"]
    chans = ", ".join(f"{k.split('/')[0].replace('Microsoft-Windows-', '')}:{n}" for k, n in buckets(ev, "ch"))
    who = first(get(alert, "winlog.user_data.SubjectUserName")) or first(get(alert, "winlog.event_data.SubjectUserName")) \
        or first(get(alert, "user.name"))
    tag = payload.get("rule_id")
    what = {"R67": "Xoá event log Windows", "R68": "Tắt/đổi audit policy"}.get(tag, tag)
    return {"entity_field": "host.name", "entity_value": host, "host_ip": hip or "", "evidence_events_60m": kept,
            "summary": (f"{what} trên {host} ({hip or '?'}) — bởi: {who or '?'}\n"
                        f"Bằng chứng đã nằm ở ELK trước thời điểm xoá: {kept} sự kiện/60′ ({chans})")}


def pf_dest_from_lan(es, host_ip, start):
    """Dich ngoai lab tu pfSense LAN pass quanh thoi diem alert (du phong khi proctitle thieu IP)."""
    if not host_ip:
        return None, None
    r = es.search("datn-pfsense-fw-*", {"size": 20, "sort": [{"@timestamp": "desc"}],
                                        "_source": ["destination.ip", "destination.port"],
                                        "query": {"bool": {"filter": [
                                            {"term": {"observer.ingress.zone": "lan"}}, {"term": {"event.action": "pass"}},
                                            {"term": {"source.ip": host_ip}}, rng(start, timedelta(minutes=2), timedelta(minutes=2))]}}})
    for h in r["hits"]["hits"]:
        d = get(h["_source"], "destination.ip")
        if d and not any(ipaddress.ip_address(d) in n for n in PRIVATE_SKIP) and d not in PROTECTED:
            return d, get(h["_source"], "destination.port")
    return None, None


def pb16(es, alert, start, payload):
    """Reverse shell Linux: tim proctitle mau reverse shell, lay IP C2 de chan egress (cat state = kill shell song)."""
    host = payload.get("host_name") or first(get(alert, "host.name"))
    hip = host_ipv4(alert)
    r = es.search("datn-ubuntu-audit-*", {"size": 20, "sort": [{"@timestamp": "desc"}],
                                          "_source": ["auditd.log.proctitle", "process.name", "process.pid"],
                                          "query": {"bool": {"filter": [{"term": {"host.name": host}},
                                                                        {"term": {"event.action": "proctitle"}},
                                                                        rng(start, timedelta(minutes=3), timedelta(minutes=1))],
                                                             "should": [{"wildcard": {"auditd.log.proctitle": p}} for p in
                                                                        ("*dev/tcp/*", "*dev/udp/*", "*mkfifo*", "*socat*", "*ncat*", "*nc *-e*", "*pty.spawn*")],
                                                             "minimum_should_match": 1}}})
    pts = [get(h["_source"], "auditd.log.proctitle") for h in r["hits"]["hits"]]
    pts = [p for p in pts if p]
    dest = next((pick_dest_ip(p) for p in pts if pick_dest_ip(p)), None)
    port = None
    if not dest:
        dest, port = pf_dest_from_lan(es, hip, start)
    cmd = pts[0].replace("\x00", " ") if pts else ""
    if not dest:
        return {"ok": False, "reason": "khong xac dinh duoc IP C2 cua reverse shell",
                "entity_field": "host.name", "entity_value": host, "host_ip": hip or ""}
    return {"entity_field": "host.name", "entity_value": host, "host_ip": hip or "", "dest_ip": dest,
            "reverse_shell_cmd": short(cmd, 200),
            "summary": (f"Reverse shell trên {host} ({hip or '?'})\nLệnh: {short(cmd, 160)}\n"
                        f"C2: {dest}" + (f":{port}" if port else "") +
                        "\nChặn egress (cắt state → shell đang sống bị ngắt). Lưu ý: kill tiến trình cần responder gói B.")}


def pb31(es, alert, start, payload):
    """Dong goi + tuon du lieu. R43 Ubuntu (proctitle tar + nc), R44 Windows (4104 Compress + WebRequest)."""
    host = payload.get("host_name") or first(get(alert, "host.name"))
    hip = host_ipv4(alert)
    tag = payload.get("rule_id")
    archive, dest = None, None
    if tag == "R44":   # Windows
        r = es.search("datn-windows-*", {"size": 30, "sort": [{"@timestamp": "desc"}],
                                         "_source": ["powershell.file.script_block_text"],
                                         "query": {"bool": {"filter": [{"term": {"host.name": host}}, {"term": {"event.code": "4104"}},
                                                                       rng(start, timedelta(minutes=12), timedelta(minutes=1))]}}})
        for h in r["hits"]["hits"]:
            t = get(h["_source"], "powershell.file.script_block_text") or ""
            if not archive:
                m = re.search(r"-DestinationPath\s+['\"]?([A-Za-z]:\\[^\s'\"]+\.zip)", t, re.I)
                if m:
                    archive = m.group(1)
            if not dest:
                m = re.search(r"https?://([^/\s:'\"]+)", t, re.I)
                if m:
                    dest = pick_dest_ip(m.group(1)) or (m.group(1) if not any(c.isalpha() for c in m.group(1)) else None)
        if dest and any(c.isalpha() for c in str(dest)):
            dest = pick_dest_ip(dest)
        qpath = archive
    else:   # R43 Ubuntu
        r = es.search("datn-ubuntu-audit-*", {"size": 30, "sort": [{"@timestamp": "desc"}],
                                              "_source": ["auditd.log.proctitle"],
                                              "query": {"bool": {"filter": [{"term": {"host.name": host}}, {"term": {"event.action": "proctitle"}},
                                                                            rng(start, timedelta(minutes=12), timedelta(minutes=1))]}}})
        pts = [get(h["_source"], "auditd.log.proctitle") or "" for h in r["hits"]["hits"]]
        for p in pts:
            low = p.lower()
            if not archive and any(k in low for k in ("tar", "zip", "gzip")):
                m = re.search(r"(/tmp/[^\x00]+|/var/tmp/[^\x00]+|/dev/shm/[^\x00]+)", p)
                if m:
                    archive = m.group(1).split("\x00")[0]
            if not dest and any(k in low for k in ("nc\x00", "ncat", "scp", "socat", "curl", "wget")):
                dest = pick_dest_ip(p)
        if not dest:
            dest, _ = pf_dest_from_lan(es, hip, start)
        qpath = archive if archive and archive.startswith(("/tmp/", "/var/tmp/", "/dev/shm/")) else None
    if not dest:
        return {"ok": False, "reason": "khong xac dinh duoc IP dich tuon du lieu",
                "entity_field": "host.name", "entity_value": host, "host_ip": hip or ""}
    os_name = "Windows" if tag == "R44" else "Ubuntu"
    return {"entity_field": "host.name", "entity_value": host, "host_ip": hip or "", "dest_ip": dest,
            "archive_path": qpath or "", "exfil_os": os_name,
            "summary": (f"Đóng gói & tuồn dữ liệu ({os_name}) trên {host} ({hip or '?'})\n"
                        f"File nén: {qpath or 'không xác định được đường dẫn trong phạm vi cách ly'}\n"
                        f"Đích tuồn: {dest} → chặn egress" +
                        ("; cách ly file nén." if qpath else "; không cách ly (ngoài phạm vi lab).")) }


HANDLERS = {"PB02": pb02, "PB03": pb03, "PB05": pb05, "PB15": pb15, "PB18": pb18, "PB23": pb23,
            "PB16": pb16, "PB31": pb31}


def main():
    pb = sys.argv[1] if len(sys.argv) > 1 else ""
    out = {"ok": False, "playbook_id": pb}
    try:
        if pb not in HANDLERS or len(sys.argv) != 3:
            raise ValueError("dung: datn-enrich.py <PB02|PB03|PB05|PB15|PB18|PB23> <payload_base64>")
        payload = json.loads(base64.b64decode(sys.argv[2], validate=True))
        if payload.get("playbook_id") != pb:
            raise ValueError("playbook_id trong payload khong khop")
        alert_id = str(payload.get("alert_id") or "")
        if not re.fullmatch(r"[a-f0-9]{64}", alert_id):
            raise ValueError("alert_id khong hop le")
        es = ES()
        r = es.search(ALERTS, {"size": 1, "query": {"term": {"kibana.alert.uuid": alert_id}}})
        hits = r["hits"]["hits"]
        if not hits:
            raise ValueError("khong tim thay alert trong Elastic")
        alert = hits[0]["_source"]
        start = iso(get(alert, "kibana.alert.start")) or datetime.now(timezone.utc)
        out.update({"rule_tag": payload.get("rule_id"), "rule_full_id": get(alert, "kibana.alert.rule.rule_id"),
                    "rule_name": get(alert, "kibana.alert.rule.name"), "alert_start": start.isoformat(),
                    "alert_start_vn": vn(start), "risk_score": get(alert, "kibana.alert.risk_score")})
        data = HANDLERS[pb](es, alert, start, payload)
        ok = data.pop("ok", True)
        out.update(data)
        if out.get("entity_value") in PROTECTED:
            ok, out["reason"] = False, "thuc the thuoc ha tang duoc bao ve"
        prev = None
        if ok and out.get("entity_value") and COOLDOWN[pb] > 0:
            prev = recent_success(es, pb, out["entity_field"], out["entity_value"], COOLDOWN[pb], alert_id)
        out["cooldown"] = bool(prev)
        if prev:
            out["cooldown_alert"] = prev
        out["ok"] = bool(ok)
        out.setdefault("reason", "ok" if ok else "enrich_failed")
    except (ValueError, KeyError, TypeError, OSError, urllib.error.URLError) as err:
        out["ok"] = False
        out["reason"] = f"{type(err).__name__}: {err}"[:300]
    print(json.dumps(out, ensure_ascii=True), end="")


if __name__ == "__main__":
    main()
