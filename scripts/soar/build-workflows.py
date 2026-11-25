#!/usr/bin/env python3
"""Dung (hoac cap nhat) 6 workflow Shuffle cho PB02, PB03, PB05, PB15, PB18, PB23.

Chay tren EC2 (user ubuntu):  python3 /opt/datn/src/soar/build-workflows.py [PB02 PB03 ...]
In ra JSON {PBnn: {workflow, hook, webhook_internal}} de dien WEBHOOK_PBnn trong forwarder.

Khung chung moi workflow (giong PB01, them phan ung + hau kiem + ghi ket qua):
  Webhook -> input_check -> dedup_get -[found=false]-> dedup_set -[success=true]-> (allowlist) -> enrich
  enrich -[ok=false]-> record_noaction
  enrich -[ok=true]-> gate -[cooldown=true]-> record_cooldown
                           -[cooldown=false]-> (theo mode)
     automatic: respond_a -> verify_a -> notify_a -> record_a
     approval : notify_req_m -> approve_m (User Input) -> respond_m -> verify_m -> notify_m -> record_m
Hanh dong tren lab di THANG tu Shuffle qua SSH (khoa shuffle_soar); enrich/notify/record chay
tren EC2 (doc khoa ES/Telegram tu /opt/datn/secrets, khong de lo trong Shuffle).
"""
import base64
import json
import os
import sys

sys.path.insert(0, "/opt/datn/src/soar")
from shuffle_lib import Builder, KEY_EC2, KEY_SOAR, Shuffle, deploy  # noqa: E402

UBU = ("192.168.100.103", "soar")
PF = ("10.99.0.2", "admin")
WIN = ("192.168.100.101", "soar-responder")
RESP = r"powershell -NoProfile -NonInteractive -File C:\SOAR\responder.ps1"
ALLOW = '["10.99.0.0/24","192.168.100.1/32","192.168.100.103/32","192.168.173.1/32","192.168.173.2/32","192.168.173.10/32"]'
FRONT = os.environ.get("SHUFFLE_FRONTEND_URL", "http://127.0.0.1:3001").rstrip("/")

# ---------------------------------------------------------------- liquid python dung chung
PREFIX = r'''import json, base64
def _o(v):
    if isinstance(v, str):
        try:
            v = json.loads(v.strip())
        except ValueError:
            return {}
    return v if isinstance(v, dict) else {}
_X = self.full_execution
_R = {}
for _r in (_X.get("results") or []):
    _R[(_r.get("action") or {}).get("label")] = _r
def res(label):
    return _R.get(label) or {}
def out(label):
    return str(_o(res(label).get("result")).get("output") or "")
def outj(label):
    return _o(out(label))
ev = _o(_X.get("execution_argument"))
enr = outj("enrich")
'''

CHECK = r'''def checks(spec):
    ok, outs, done = True, [], 0
    for label, expects in spec:
        r = res(label)
        o = out(label).strip()
        outs.append(label + ": " + o[:300])
        good = r.get("status") == "SUCCESS"
        for e in expects:
            good = good and ((e[1:] not in o) if e.startswith("!") else (e in o))
        ok = ok and good
        done = max(done, int(r.get("completed_at") or 0) // 1000)
    return ok, " | ".join(outs), done
def vals():
    h = outj(CFG.get("hash_label") or "")
    return {"ip": ev.get("source_ip") or "", "host": ev.get("host_name") or "",
            "file": enr.get("file_path") or "", "dest": enr.get("dest_ip") or "-",
            "task": enr.get("task_name") or "", "host_ip": enr.get("host_ip") or "",
            "archive": enr.get("archive_path") or "", "sha": (h.get("sha256") or "")[:16]}
'''


def cfg_line(cfg):
    """Nhung cau hinh dang base64 JSON: tranh moi van de quoting/emoji trong ma liquid."""
    enc = base64.b64encode(json.dumps(cfg, ensure_ascii=False).encode("utf-8")).decode("ascii")
    return f'CFG = json.loads(base64.b64decode("{enc}").decode("utf-8"))\n'


def liquid(body):
    return "{% python %}\n" + body + "\n{% endpython %}"


def enrich_cmd(pb):
    code = 'print(base64.b64encode(str(self.full_execution.get("execution_argument") or "").encode("utf-8")).decode("ascii"), end="")'
    return f'python3 -I /opt/datn/src/soar/datn-enrich.py {pb} "' + liquid("import base64\n" + code) + '"'


def notify_cmd(cfg, stage):
    """stage: 'request' (xin duyet) hoac 'result' (sau hau kiem)."""
    body = PREFIX + CHECK + cfg_line(cfg) + r'''
v = vals()
act = CFG["action"].format(**v)
head = CFG["icon"] + " " + CFG["pb"] + " " + CFG["title"] + " — " + str(ev.get("rule_id")) + " (risk " + str(ev.get("risk_score")) + ")"
ent = "Thực thể: " + str(enr.get("entity_field")) + " = " + str(enr.get("entity_value"))
lines = [head, "Alert: " + str(ev.get("alert_id"))[:16] + "… | phát hiện " + str(enr.get("alert_start_vn")) + " (GMT+7)", ent, str(enr.get("summary") or "")]
if STAGE == "request":
    link = FRONT + "/forms/" + str((_X.get("workflow") or {}).get("id")) + "?authorization=" + str(_X.get("authorization")) + "&reference_execution=" + str(_X.get("execution_id")) + "&source_node=" + UI + "&backend_url=" + FRONT
    lines += ["✋ CẦN DUYỆT — hành động đề xuất: " + act, "Duyệt/từ chối (mở từ máy quản trị có IP trong Security Group):", link]
else:
    ok, outs, done = checks(CFG["verify"])
    mode = str(ev.get("response_mode"))
    lines += ["Chế độ: " + mode + (" (đã được duyệt)" if mode == "approval" else ""), "Hành động: " + act,
              "Hậu kiểm: " + ("ĐẠT ✅" if ok else "KHÔNG ĐẠT ❌") + " — " + outs[:600]]
print(base64.b64encode("\n".join(lines).encode("utf-8")).decode("ascii"), end="")
'''
    body = body.replace("STAGE ==", repr(stage) + " ==").replace("FRONT +", repr(FRONT) + " +").replace(
        "+ FRONT", "+ " + repr(FRONT)).replace("+ UI +", "+ " + repr(cfg.get("ui_id", "")) + " +")
    return 'python3 -I /opt/datn/src/soar/datn-notify.py "' + liquid(body) + '"'


def record_cmd(cfg, forced=None, reason_expr='""'):
    body = PREFIX + CHECK + cfg_line(cfg) + r'''
mode =str(ev.get("response_mode") or "notify")
rid = enr.get("rule_full_id") or ("datn-" + CFG["pb"].lower() + "-" + str(ev.get("rule_id") or "").lower())
ef = enr.get("entity_field") or CFG["entity_field"]
evv = enr.get("entity_value") or (ev.get("source_ip") if ef == "source.ip" else ev.get("host_name"))
ctx = {"playbook_id": CFG["pb"], "rule_id": rid, "alert_id": ev.get("alert_id"),
       "execution_id": _X.get("execution_id"), "execution_started_at": int(_X.get("started_at") or 0),
       "entity_field": ef, "entity_value": evv, "response_mode": mode,
       "enrichment": {k: enr.get(k) for k in ("summary", "rule_name", "cooldown_alert", "file_path", "dest_ip",
                                              "task_name", "task_action", "host_ip", "evidence_events_60m",
                                              "compromised_user", "request_ids", "users_tried", "reason",
                                              "reverse_shell_cmd", "archive_path", "exfil_os") if enr.get(k) is not None}}
if ev.get("test_id"):
    ctx["test_id"] = ev.get("test_id")
if FORCED:
    ctx["outcome"] = FORCED
    ctx["reason"] = REASON
else:
    v = vals()
    ctx["action"] = CFG["action"].format(**v)
    ok, outs, done = checks(CFG["verify"])
    ctx["verify"] = {"ok": ok, "output": outs}
    ctx["verified_at"] = done
    t = outj(CFG["notify_label"])
    if t:
        ctx["telegram"] = {"status": t.get("status"), "ok": t.get("ok"), "message_id": t.get("message_id"), "date": t.get("date")}
    if mode == "approval":
        ui = res(CFG["approve_label"])
        ctx["approval_requested_at"] = int(ui.get("started_at") or 0) // 1000
        click = _o(ui.get("result")).get("click_info") or {}
        ctx["approved_at"] = int(click.get("time") or 0) or int(ui.get("completed_at") or 0) // 1000
print(base64.b64encode(json.dumps(ctx).encode("utf-8")).decode("ascii"), end="")
'''
    body = body.replace("if FORCED:", "if " + repr(forced) + ":").replace(
        '"outcome"] = FORCED', '"outcome"] = ' + repr(forced)).replace("= REASON", "= " + reason_expr)
    return 'python3 -I /opt/datn/src/metrics/datn-record-result.py "' + liquid(body) + '"'


# ---------------------------------------------------------------- dac ta 6 playbook
def pf_verify(table, var):
    return (f'echo "$(/usr/local/sbin/soar-pf.sh test {table} {var}) rules=$(pfctl -sr | grep -c \'<{table}>\')"',
            [f"PRESENT {table}", "!rules=0"])


SPECS = {
    "PB02": {
        "title": "Quét lỗ hổng / dò thư mục web", "icon": "🕸️", "entity_field": "source.ip", "allowlist": True,
        "chains": {"automatic": {
            "action": "Nginx deny {ip} ttl=1800s (Ubuntu .103, lớp 7)",
            "respond": [("respond", UBU, "sudo /usr/local/sbin/soar-nginx-deny add $exec.source_ip 1800")],
            "verify": [("verify", UBU, "sudo /usr/local/sbin/soar-nginx-deny test $exec.source_ip", ["PRESENT nginx"])]}}},
    "PB03": {
        "title": "Tấn công đăng nhập web", "icon": "🔐", "entity_field": "source.ip", "allowlist": True,
        "chains": {"automatic": {
            "action": "Nginx deny {ip} ttl=1800s (Ubuntu .103, lớp 7)",
            "respond": [("respond", UBU, "sudo /usr/local/sbin/soar-nginx-deny add $exec.source_ip 1800")],
            "verify": [("verify", UBU, "sudo /usr/local/sbin/soar-nginx-deny test $exec.source_ip", ["PRESENT nginx"])]}}},
    "PB05": {
        "title": "Khai thác web (SQLi / path traversal)", "icon": "💥", "entity_field": "source.ip", "allowlist": True,
        "chains": {
            "automatic": {
                "action": "pfSense soar_block {ip} ttl=7200s (chặn WAN lớp 3)",
                "respond": [("respond", PF, "/usr/local/sbin/soar-pf.sh add soar_block $exec.source_ip 7200")],
                "verify": [("verify", PF) + pf_verify("soar_block", "$exec.source_ip")]},
            "approval": {
                "action": "pfSense soar_block {ip} ttl=7200s (chặn WAN lớp 3)",
                "respond": [("respond", PF, "/usr/local/sbin/soar-pf.sh add soar_block $exec.source_ip 7200")],
                "verify": [("verify", PF) + pf_verify("soar_block", "$exec.source_ip")]}}},
    "PB15": {
        "title": "Tải công cụ vào máy (T1105)", "icon": "📥", "entity_field": "host.name", "allowlist": False,
        "pre": [("hash", WIN, RESP + ' -Action Hash -Path "$enrich.output.file_path"')],
        "chains": {"approval": {
            "action": "Cách ly {file} (sha256 {sha}…) + pfSense soar_egress {dest} ttl=7200s",
            "respond": [("respond_file", WIN, RESP + ' -Action Quarantine -Path "$enrich.output.file_path"'),
                        ("respond_egress", PF, "/usr/local/sbin/soar-pf.sh add soar_egress $enrich.output.dest_ip 7200")],
            "verify": [("verify_file", WIN, RESP + ' -Action TestPath -Path "$enrich.output.file_path"', ['"result":"ABSENT"']),
                       ("verify_egress", PF) + pf_verify("soar_egress", "$enrich.output.dest_ip")]}}},
    "PB18": {
        "title": "Scheduled task (T1053.005)", "icon": "🗓️", "entity_field": "host.name", "allowlist": False,
        "chains": {"approval": {
            "action": "DisableTask \\{task} (xuất XML bằng chứng vào C:\\SOAR\\backup)",
            "respond": [("respond", WIN, RESP + ' -Action DisableTask -TaskName "$enrich.output.task_name"')],
            "verify": [("verify", WIN, RESP + ' -Action TaskState -TaskName "$enrich.output.task_name"', ['"state":"Disabled"'])]}}},
    "PB23": {
        "title": "Xoá log / tắt audit Windows", "icon": "🧹", "entity_field": "host.name", "allowlist": False,
        "chains": {
            "automatic": {
                "action": "RestoreAuditPolicy từ baseline C:\\SOAR\\baseline\\audit.csv",
                "respond": [("respond", WIN, RESP + " -Action RestoreAuditPolicy")],
                "verify": [("verify", WIN, RESP + " -Action AuditStatus", ['"match":true'])]},
            "approval": {
                "action": "Cô lập {host_ip} bằng pfSense soar_isolate ttl=1800s (chỉ giữ telemetry 5044)",
                "respond": [("respond", PF, "/usr/local/sbin/soar-pf.sh add soar_isolate $enrich.output.host_ip 1800")],
                "verify": [("verify", PF) + pf_verify("soar_isolate", "$enrich.output.host_ip")]}}},
    "PB16": {
        "title": "Reverse shell Linux (T1059.004)", "icon": "🐚", "entity_field": "host.name", "allowlist": False,
        "chains": {"automatic": {
            "action": "pfSense soar_egress {dest} ttl=7200s (cắt state → shell đang sống bị ngắt)",
            "respond": [("respond", PF, "/usr/local/sbin/soar-pf.sh add soar_egress $enrich.output.dest_ip 7200")],
            "verify": [("verify", PF) + pf_verify("soar_egress", "$enrich.output.dest_ip")]}}},
    "PB31": {
        "title": "Đóng gói & tuồn dữ liệu", "icon": "📦", "entity_field": "host.name", "allowlist": False,
        "chain_field": "$enrich.output.exfil_os",
        "chains": {
            "Ubuntu": {"mode": "approval", "sfx": "_u",
                "action": "Cách ly {archive} (Ubuntu) + pfSense soar_egress {dest} ttl=7200s",
                "respond": [("respond_file", UBU, "sudo /usr/local/sbin/soar-ubuntu.sh quarantine $enrich.output.archive_path"),
                            ("respond_egress", PF, "/usr/local/sbin/soar-pf.sh add soar_egress $enrich.output.dest_ip 7200")],
                "verify": [("verify_file", UBU, "sudo /usr/local/sbin/soar-ubuntu.sh test-path $enrich.output.archive_path", ['"result":"ABSENT"']),
                           ("verify_egress", PF) + pf_verify("soar_egress", "$enrich.output.dest_ip")]},
            "Windows": {"mode": "approval", "sfx": "_w",
                "action": "Cách ly {archive} (Windows) + pfSense soar_egress {dest} ttl=7200s",
                "respond": [("respond_file", WIN, RESP + ' -Action Quarantine -Path "$enrich.output.archive_path"'),
                            ("respond_egress", PF, "/usr/local/sbin/soar-pf.sh add soar_egress $enrich.output.dest_ip 7200")],
                "verify": [("verify_file", WIN, RESP + ' -Action TestPath -Path "$enrich.output.archive_path"', ['"result":"ABSENT"']),
                           ("verify_egress", PF) + pf_verify("soar_egress", "$enrich.output.dest_ip")]}}},
}


def build(api, b, pb, spec):
    X = 300
    gate_field = spec.get("chain_field", "$exec.response_mode")
    acts, trigs, br = [], [], []
    wh = b.webhook(f"Webhook_{pb}", 0, 300)
    trigs.append(wh)

    def add(node, *parents_conds):
        acts.append(node)
        return node

    inp = add(b.action("repeat_back_to_me", "input_check", {"call": "$exec"}, X, 300))
    br.append(b.branch(wh, inp))
    dget = add(b.action("get_datastore_value", "dedup_get", {"key": "$exec.alert_id", "category": f"{pb.lower()}_seen_alerts"}, 2 * X, 300))
    dset = add(b.action("set_datastore_value", "dedup_set", {"key": "$exec.alert_id", "value": "1", "category": f"{pb.lower()}_seen_alerts"}, 3 * X, 300))
    br += [b.branch(inp, dget), b.branch(dget, dset, [("$dedup_get.found", "equals", "false")])]
    prev, col = dset, 4
    cond = [("$dedup_set.success", "equals", "true")]
    base_cfg = {"pb": pb, "entity_field": spec["entity_field"], "title": spec["title"], "icon": spec["icon"]}
    if spec["allowlist"]:
        al = add(b.action("cidr_ip_match", "allowlist", {"ip": "$exec.source_ip", "networks": ALLOW}, col * X, 300))
        br.append(b.branch(prev, al, cond))
        skip = add(b.ssh("record_allowlist", "10.99.0.1", "ubuntu", KEY_EC2,
                         record_cmd(dict(base_cfg, verify=[], action=""), "skipped", '"allowlist: IP ha tang/duoc phep"'), col * X, 520))
        br.append(b.branch(al, skip, [("$allowlist.is_contained", "equals", "true")]))
        prev, cond, col = al, [("$allowlist.is_contained", "equals", "false")], col + 1
    enrich = add(b.ssh("enrich", "10.99.0.1", "ubuntu", KEY_EC2, enrich_cmd(pb), col * X, 300))
    br.append(b.branch(prev, enrich, cond))
    noact = add(b.ssh("record_noaction", "10.99.0.1", "ubuntu", KEY_EC2,
                      record_cmd(dict(base_cfg, verify=[], action=""), "no_action", 'str(enr.get("reason") or "enrich_failed")'), col * X, 520))
    br.append(b.branch(enrich, noact, [("$enrich.output.ok", "equals", "false")]))
    col += 1
    gate = add(b.action("repeat_back_to_me", "gate", {"call": "mode=$exec.response_mode cooldown=$enrich.output.cooldown"}, col * X, 300))
    br.append(b.branch(enrich, gate, [("$enrich.output.ok", "equals", "true")]))
    cd = add(b.ssh("record_cooldown", "10.99.0.1", "ubuntu", KEY_EC2,
                   record_cmd(dict(base_cfg, verify=[], action=""), "skipped", '"cooldown: da xu ly alert " + str(enr.get("cooldown_alert"))'), col * X, 520))
    br.append(b.branch(gate, cd, [("$enrich.output.cooldown", "equals", "true")]))
    col += 1
    head, hcond = gate, [("$enrich.output.cooldown", "equals", "false")]
    for label, (host, user), cmd in spec.get("pre", []):
        n = add(b.ssh(label, host, user, KEY_SOAR, cmd, col * X, 300))
        br.append(b.branch(head, n, hcond))
        head, hcond, col = n, [], col + 1

    if len(spec["chains"]) > 1:
        # Moi nhanh chi mot dieu kien. Chon nhanh theo chain_field: mac dinh la che do phan ung,
        # nhung PB co the re theo truong enrich khac (PB31 re theo HDH: $enrich.output.exfil_os).
        mg = add(b.action("repeat_back_to_me", "mode_gate", {"call": gate_field}, col * X, 300))
        br.append(b.branch(head, mg, hcond))
        head, hcond, col = mg, [], col + 1

    ui_ids = {}
    for row, (key, ch) in enumerate(spec["chains"].items()):
        y = 300 + row * 260 - (130 if len(spec["chains"]) > 1 else 0)
        mode = ch.get("mode", key)
        sfx = ch.get("sfx", "_a" if mode == "automatic" else "_m")
        c = col
        mcond = list(hcond)
        if len(spec["chains"]) > 1:
            mcond = [(gate_field, "equals", key)]
        cfg = dict(base_cfg, action=ch["action"],
                   verify=[[lbl + sfx, exp] for lbl, _h, _c, exp in ch["verify"]],
                   notify_label="notify" + sfx, approve_label="approve" + sfx,
                   hash_label="hash" if spec.get("pre") else "")
        last = head
        first_cond = mcond
        if mode == "approval":
            ent = "$exec.source_ip" if spec["entity_field"] == "source.ip" else "$exec.host_name"
            ui = b.user_input("approve" + sfx, f"{pb} {spec['title']}: duyet hanh dong cho alert $exec.alert_id ($exec.rule_id, {ent})?", (c + 1) * X, y)
            cfg["ui_id"] = ui["id"]
            ui_ids[key] = ui["id"]
            req = add(b.ssh("notify_req" + sfx, "10.99.0.1", "ubuntu", KEY_EC2, notify_cmd(cfg, "request"), c * X, y))
            if len(spec["chains"]) > 1:
                # Shuffle 2.3.0: neu nhanh automatic bi SKIPPED con dang lan truyen khi User Input dung,
                # execution bi ghi de WAITING -> EXECUTING va link duyet bi bo qua (da gap o PB23 24/11).
                # Tre 6 s de chuoi SKIPPED xong truoc.
                req["execution_delay"] = 6
            br.append(b.branch(last, req, first_cond))
            trigs.append(ui)
            br.append(b.branch(req, ui))
            last, first_cond, c = ui, [], c + 2
        for lbl, (host, user), cmd in ch["respond"]:
            n = add(b.ssh(lbl + sfx, host, user, KEY_SOAR, cmd, c * X, y))
            br.append(b.branch(last, n, first_cond))
            last, first_cond, c = n, [], c + 1
        for lbl, (host, user), cmd, _exp in ch["verify"]:
            n = add(b.ssh(lbl + sfx, host, user, KEY_SOAR, cmd, c * X, y))
            br.append(b.branch(last, n))
            last, c = n, c + 1
        nt = add(b.ssh("notify" + sfx, "10.99.0.1", "ubuntu", KEY_EC2, notify_cmd(cfg, "result"), c * X, y))
        br.append(b.branch(last, nt))
        rc = add(b.ssh("record" + sfx, "10.99.0.1", "ubuntu", KEY_EC2, record_cmd(cfg), (c + 1) * X, y))
        br.append(b.branch(nt, rc))

    name = {"PB02": "PB02-quet-web", "PB03": "PB03-dang-nhap-web", "PB05": "PB05-sqli-traversal",
            "PB15": "PB15-tai-cong-cu", "PB18": "PB18-scheduled-task", "PB23": "PB23-xoa-log",
            "PB16": "PB16-reverse-shell", "PB31": "PB31-exfil"}[pb]
    desc = f"DATN {pb} - {spec['title']}. Sinh boi build-workflows.py; sua o repo roi chay lai, khong sua tay."
    wf, hook = deploy(api, b, name, desc, acts, trigs, br, inp)
    return {"workflow": wf, "name": name, "hook": hook,
            "webhook_internal": f"http://shuffle-backend:5001/api/v1/hooks/webhook_{hook}", "user_input": ui_ids}


def main():
    want = sys.argv[1:] or list(SPECS)
    api = Shuffle()
    b = Builder(api)
    out = {}
    for pb in want:
        out[pb] = build(api, b, pb, SPECS[pb])
    print(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
