#!/usr/bin/env python3
"""Sinh file JSON rule Kibana cho 6 playbook da chot (PB02, PB03, PB05, PB15, PB18, PB23).

Chay: python3 make-rules.py <thu_muc_ra>   -> ghi pbNN-rNN.json (rule_id on dinh datn-pbNN-rNN)
Nap: source /opt/datn/datn-env.sh; source /opt/datn/detections/rule-helpers.sh; mkrule <file>

Ghi chu thiet ke (license Basic, da kiem 24/11/2026):
- Basic KHONG ho tro alert_suppression -> cac rule "moi su kien mot alert" doi thanh threshold
  gom theo thuc the (value 1) de mot dot tan cong ra mot alert, tranh hang tram execution.
- KQL wildcard tren keyword/wildcard phan biet hoa thuong -> liet ke bien the; EQL dung ':' (khong phan biet).
- KQL khong cho escape khoang trang trong gia tri wildcard (backslash + dau cach) -> dung '?' thay dau cach.
- url.original la URL tho (da ma hoa %), nen mau SQLi/traversal gom ca dang %27, %20, %2f, %2e.
- Tag PBnn / Rnn / mode:* la hop dong voi alert-forwarder.
"""
import json
import sys
from pathlib import Path

T = {
    "TA0043": "Reconnaissance", "TA0006": "Credential Access", "TA0001": "Initial Access",
    "TA0011": "Command and Control", "TA0003": "Persistence", "TA0002": "Execution",
    "TA0112": "Defense Impairment", "TA0009": "Collection", "TA0010": "Exfiltration",
}


def tactic(tid):
    return {"id": tid, "name": T[tid], "reference": f"https://attack.mitre.org/tactics/{tid}/"}


def tech(tid, name, sub=None):
    t = {"id": tid, "name": name, "reference": f"https://attack.mitre.org/techniques/{tid}/"}
    if sub:
        sid, sname = sub
        t["subtechnique"] = [{"id": sid, "name": sname,
                              "reference": f"https://attack.mitre.org/techniques/{sid.replace('.', '/')}/"}]
    return t


def rule(pb, r, name, desc, rtype, index, query, sev, risk, mode, threat, *, language="kuery",
         threshold=None, frm="now-360s", interval="1m"):
    d = {
        "rule_id": f"datn-{pb.lower()}-{r.lower()}",
        "name": f"{pb} {r} - {name}",
        "description": desc,
        "type": rtype,
        "index": index,
        "language": "eql" if rtype == "eql" else language,
        "query": query,
        "severity": sev,
        "risk_score": risk,
        "from": frm,
        "interval": interval,
        "max_signals": 100,
        "tags": ["DATN", pb, r, f"mode:{mode}"],
        "threat": threat,
        "enabled": False,
    }
    if threshold:
        d["threshold"] = threshold
    return d


WEB = ["datn-web-*"]
WIN = ["datn-windows-*"]
UBU = ["datn-ubuntu-audit-*"]

# Reverse shell: khop tren auditd.log.proctitle (truong keyword DA GIAI MA; process.args bi mang hoa hex
# khi co dau cach nen khong dung duoc). Dau cach giua cac arg la ky tu NULL -> wildcard * khop qua.
# KQL khong escape duoc '-'/'>' trong gia tri wildcard nen chi dung cac mau khong co ky tu dac biet:
# /dev/tcp va /dev/udp (thiet bi gia cua bash, gan nhu chi dung cho reverse shell) la tin hieu manh nhat.
REVSHELL = ("*dev/tcp/* or *dev/udp/* or *mkfifo* or (*socat* and *exec*) or "
            "(*python* and *socket* and *connect*) or (*python* and *pty* and *spawn*) or "
            "(*perl* and *socket* and *exec*) or (*ruby* and *socket* and *exec*) or "
            "(*ncat* and *lua* and *exec*)")

SCANNER_UA = ("*Nikto* or *nikto* or *sqlmap* or *Fuzz?Faster?U?Fool* or *gobuster* or "
              "*Nmap?Scripting?Engine* or *Nuclei* or *nuclei* or *WPScan* or *feroxbuster* or "
              "*DirBuster* or *dirbuster* or *masscan* or *zgrab*")
SQLI = ("*union*select* or *UNION*SELECT* or *Union*Select* or *%27%20or%20* or *%27%20OR%20* or "
        "*%27+or+* or *%27+OR+* or *%20or%201%3D1* or *%20OR%201%3D1* or *or%201=1* or *OR%201=1* or "
        "*sleep\\(* or *SLEEP\\(* or *sleep%28* or *SLEEP%28* or *information_schema* or *INFORMATION_SCHEMA* or "
        "*benchmark%28* or *%27--* or *%27%23*")
TRAV = ("*../..* or *..%2f* or *..%2F* or *%2e%2e* or *%2E%2E* or *etc/passwd* or *etc%2fpasswd* or "
        "*etc%2Fpasswd* or *win.ini* or *boot.ini*")

RULES = [
    # ---------------- PB02 quet lo hong / do thu muc web ----------------
    rule("PB02", "R02", "Do thu muc web (404 flood)",
         "Mot source.ip tao >= 30 phan hoi 404 trong cua so 6 phut (wordlist scanning). T1595.003.",
         "threshold", WEB, "event.dataset:nginx.access and http.response.status_code:404",
         "medium", 47, "automatic",
         [{"framework": "MITRE ATT&CK", "tactic": tactic("TA0043"),
           "technique": [tech("T1595", "Active Scanning", ("T1595.003", "Wordlist Scanning"))]}],
         threshold={"field": ["source.ip"], "value": 30}),
    rule("PB02", "R03", "User-Agent cong cu quet web",
         "Request co User-Agent cua cong cu quet (Nikto, sqlmap, ffuf, gobuster, Nmap NSE, Nuclei...). "
         "Gom theo source.ip (threshold value 1) thay cho alert_suppression. T1595.002.",
         "threshold", WEB, f"event.dataset:nginx.access and user_agent.original:({SCANNER_UA})",
         "high", 60, "automatic",
         [{"framework": "MITRE ATT&CK", "tactic": tactic("TA0043"),
           "technique": [tech("T1595", "Active Scanning", ("T1595.002", "Vulnerability Scanning"))]}],
         threshold={"field": ["source.ip"], "value": 1}),

    # ---------------- PB03 tan cong dang nhap web ----------------
    rule("PB03", "R04", "Password spraying web",
         ">= 5 user.name khac nhau dang nhap that bai tu 1 source.ip trong 6 phut. T1110.003.",
         "threshold", WEB, "event.category:authentication and event.outcome:failure",
         "high", 63, "automatic",
         [{"framework": "MITRE ATT&CK", "tactic": tactic("TA0006"),
           "technique": [tech("T1110", "Brute Force", ("T1110.003", "Password Spraying"))]}],
         threshold={"field": ["source.ip"], "value": 1, "cardinality": [{"field": "user.name", "value": 5}]}),
    rule("PB03", "R05", "Credential stuffing web (dau hieu tu dong)",
         "That bai co dau hieu tu dong (khong cookie phien hoac UA script), >= 10 user.name khac nhau "
         "tu 1 source.ip trong 6 phut. T1110.004.",
         "threshold", WEB,
         "event.category:authentication and event.outcome:failure and (labels.cookie_present:false or "
         "user_agent.original:(*python-requests* or *curl/* or *Go-http-client* or *okhttp* or *libwww* or *Hydra* or *hydra*))",
         "high", 70, "automatic",
         [{"framework": "MITRE ATT&CK", "tactic": tactic("TA0006"),
           "technique": [tech("T1110", "Brute Force", ("T1110.004", "Credential Stuffing"))]}],
         threshold={"field": ["source.ip"], "value": 1, "cardinality": [{"field": "user.name", "value": 10}]}),
    rule("PB03", "R06", "Dang nhap duoc sau nhieu lan sai",
         "Theo source.ip: 5 lan dang nhap that bai roi 1 lan thanh cong trong 10 phut. T1110.001.",
         "eql", WEB,
         'sequence by source.ip with maxspan=10m '
         '[authentication where event.outcome == "failure"] with runs=5 '
         '[authentication where event.outcome == "success"]',
         "critical", 85, "automatic",
         [{"framework": "MITRE ATT&CK", "tactic": tactic("TA0006"),
           "technique": [tech("T1110", "Brute Force", ("T1110.001", "Password Guessing"))]}],
         frm="now-900s"),

    # ---------------- PB05 SQLi / path traversal ----------------
    rule("PB05", "R07", "Mau SQLi / path traversal trong URL",
         "url.original chua mau SQLi hoac traversal (ke ca dang ma hoa %). Gom theo source.ip. T1190. "
         "Chi la dau hieu THU -> can nguoi duyet truoc khi chan.",
         "threshold", WEB, f"event.dataset:nginx.access and url.original:({SQLI} or {TRAV})",
         "high", 65, "approval",
         [{"framework": "MITRE ATT&CK", "tactic": tactic("TA0001"),
           "technique": [tech("T1190", "Exploit Public-Facing Application")]}],
         threshold={"field": ["source.ip"], "value": 1}),
    rule("PB05", "R08", "SQLi gay loi 500 (dau hieu thanh cong)",
         "Theo source.ip: request khop mau SQLi roi phan hoi 500 trong 2 phut. T1190.",
         "eql", WEB,
         'sequence by source.ip with maxspan=2m '
         '[any where event.dataset == "nginx.access" and url.original : ("*union*select*", "*%27%20or%20*", '
         '"*%27+or+*", "*or%201%3D1*", "*or%201=1*", "*sleep(*", "*sleep%28*", "*information_schema*")] '
         '[any where event.dataset == "nginx.access" and http.response.status_code == 500]',
         "critical", 82, "automatic",
         [{"framework": "MITRE ATT&CK", "tactic": tactic("TA0001"),
           "technique": [tech("T1190", "Exploit Public-Facing Application")]}]),
    rule("PB05", "R09", "Path traversal doc duoc file",
         "url.original co mau traversal, status 200 va than phan hoi > 1000 byte (co the da doc duoc file). "
         "Gom theo source.ip. T1190.",
         "threshold", WEB,
         f"event.dataset:nginx.access and http.response.status_code:200 and http.response.body.bytes > 1000 and url.original:({TRAV})",
         "critical", 85, "automatic",
         [{"framework": "MITRE ATT&CK", "tactic": tactic("TA0001"),
           "technique": [tech("T1190", "Exploit Public-Facing Application")]}],
         threshold={"field": ["source.ip"], "value": 1}),

    # ---------------- PB15 tai cong cu (Windows) ----------------
    rule("PB15", "R13", "Tai cong cu: ket noi ra roi tao file thuc thi",
         "Theo process.entity_id: Sysmon 3 (LOLBin ket noi ra ngoai LAN/VPN) roi Sysmon 11 tao file thuc thi trong 60s. T1105.",
         "eql", WIN,
         'sequence by process.entity_id with maxspan=60s '
         '[any where event.code == "3" and process.name : ("powershell.exe", "pwsh.exe", "certutil.exe", '
         '"bitsadmin.exe", "curl.exe", "cmd.exe", "mshta.exe", "rundll32.exe") and '
         'not cidrmatch(destination.ip, "192.168.100.0/24", "10.99.0.0/24", "127.0.0.0/8")] '
         '[any where event.code == "11" and file.extension : ("exe", "dll", "ps1", "bat", "vbs", "hta", "scr")]',
         "high", 70, "approval",
         [{"framework": "MITRE ATT&CK", "tactic": tactic("TA0011"),
           "technique": [tech("T1105", "Ingress Tool Transfer")]}]),
    rule("PB15", "R14", "LOLBin tai file thuc thi (certutil/bitsadmin/IWR)",
         "Sysmon 1: certutil -urlcache, bitsadmin /transfer, Invoke-WebRequest/curl -OutFile toi file thuc thi. T1105.",
         "query", WIN,
         "event.code:1 and ("
         "(process.name:certutil.exe and process.command_line:(*urlcache* or *URLCache* or *-split* or *verifyctl*)) or "
         "(process.name:bitsadmin.exe and process.command_line:(*transfer* or *TRANSFER* or *addfile*)) or "
         "(process.name:(powershell.exe or pwsh.exe) and process.command_line:(*Invoke-WebRequest* or *invoke-webrequest* or *iwr?* or *wget?* or *curl?* or *Start-BitsTransfer*) "
         "and process.command_line:(*-OutFile* or *-outfile* or *-o?* or *-Destination*))"
         ") and process.command_line:(*.exe* or *.dll* or *.ps1* or *.bat* or *.hta* or *.vbs* or *.scr*)",
         "high", 65, "approval",
         [{"framework": "MITRE ATT&CK", "tactic": tactic("TA0011"),
           "technique": [tech("T1105", "Ingress Tool Transfer")]}]),

    # ---------------- PB18 scheduled task ----------------
    rule("PB18", "R16", "Tao scheduled task",
         "Security 4698 (task moi), loai task he thong \\Microsoft\\* va task cap nhat OneDrive. "
         "Bo nhanh Sysmon 1 schtasks de mot task chi sinh mot alert (license Basic khong co suppression). T1053.005.",
         "query", WIN,
         "event.code:4698 and winlog.channel:Security and not winlog.event_data.TaskName:(\\\\Microsoft\\\\* or *OneDrive*Update*)",
         "medium", 47, "approval",
         [{"framework": "MITRE ATT&CK", "tactic": tactic("TA0003"),
           "technique": [tech("T1053", "Scheduled Task/Job", ("T1053.005", "Scheduled Task"))]},
          {"framework": "MITRE ATT&CK", "tactic": tactic("TA0002"),
           "technique": [tech("T1053", "Scheduled Task/Job", ("T1053.005", "Scheduled Task"))]}]),

    # ---------------- PB23 xoa log / tat audit (Windows) ----------------
    rule("PB23", "R67", "Xoa log Windows",
         "Security 1102 (xoa Security log) hoac System 104 (xoa log khac). Log da ve ELK truoc khi bi xoa. T1685.005.",
         "query", WIN,
         "(event.code:1102 and winlog.channel:Security) or (event.code:104 and winlog.channel:System)",
         "high", 73, "approval",
         [{"framework": "MITRE ATT&CK", "tactic": tactic("TA0112"),
           "technique": [tech("T1685", "Disable or Modify Tools", ("T1685.005", "Clear Windows Event Logs"))]}]),
    rule("PB23", "R68", "Tat/doi audit policy Windows",
         "Security 4719 co thay doi loai bo (removed) hoac auditpol /clear|/remove|disable. Gom theo host.name. "
         "4719 do chinh SOAR khoi phuc (chi them lai) khong khop. T1685.001.",
         "threshold", WIN,
         "(event.code:4719 and winlog.channel:Security and winlog.event_data.AuditPolicyChanges:(*8448* or *8450* or *removed* or *Removed*)) or "
         "(event.code:1 and process.name:auditpol.exe and process.command_line:(*/clear* or */CLEAR* or */remove* or */REMOVE* or *disable*))",
         "high", 70, "automatic",
         [{"framework": "MITRE ATT&CK", "tactic": tactic("TA0112"),
           "technique": [tech("T1685", "Disable or Modify Tools", ("T1685.001", "Disable or Modify Windows Event Log"))]}],
         threshold={"field": ["host.name"], "value": 1}),

    # ---------------- PB16 reverse shell (Linux) ----------------
    rule("PB16", "R37", "Reverse shell Linux (mau lenh)",
         "auditd.log.proctitle chua mau reverse shell: /dev/tcp, /dev/udp, mkfifo, socat exec, nc/ncat -e, "
         "python socket connect, pty.spawn. Gom theo host.name. T1059.004.",
         "threshold", UBU,
         f"event.action:proctitle and auditd.log.proctitle:({REVSHELL})",
         "critical", 85, "automatic",
         [{"framework": "MITRE ATT&CK", "tactic": tactic("TA0002"),
           "technique": [tech("T1059", "Command and Scripting Interpreter", ("T1059.004", "Unix Shell"))]},
          {"framework": "MITRE ATT&CK", "tactic": tactic("TA0011"),
           "technique": [tech("T1571", "Non-Standard Port")]}],
         threshold={"field": ["host.name"], "value": 1}),

    # ---------------- PB31 dong goi + tuon du lieu ----------------
    rule("PB31", "R43", "Nen roi tuon du lieu (Ubuntu)",
         "Theo host.name: SYSCALL execve tar/zip/gzip roi SYSCALL execve nc/scp/socat/curl... trong 10 phut. "
         "process.name lay tu ban ghi SYSCALL (EXECVE bi mang hoa hex). T1560.001 + T1048.003.",
         "eql", UBU,
         'sequence by host.name with maxspan=10m '
         '[process where event.action == "syscall" and process.name in ("tar","zip","gzip","7z","7za","bzip2","xz","zstd")] '
         '[process where event.action == "syscall" and process.name in ("nc","ncat","scp","sftp","socat","curl","wget")]',
         "critical", 82, "approval",
         [{"framework": "MITRE ATT&CK", "tactic": tactic("TA0010"),
           "technique": [tech("T1048", "Exfiltration Over Alternative Protocol", ("T1048.003", "Exfiltration Over Unencrypted Non-C2 Protocol"))]},
          {"framework": "MITRE ATT&CK", "tactic": tactic("TA0009"),
           "technique": [tech("T1560", "Archive Collected Data", ("T1560.001", "Archive via Utility"))]}]),
    rule("PB31", "R44", "Nen roi tuon du lieu (Windows)",
         "Theo host.name: 4104 Compress-Archive roi 4104 Invoke-WebRequest/RestMethod hoac Net.WebClient trong 10 phut. "
         "Chay rieng tung lenh thi moi lenh la mot script block. T1560.001 + T1041.",
         "eql", WIN,
         'sequence by host.name with maxspan=10m '
         '[any where event.code == "4104" and powershell.file.script_block_text like~ "*compress-archive*"] '
         '[any where event.code == "4104" and (powershell.file.script_block_text like~ "*invoke-webrequest*" or '
         'powershell.file.script_block_text like~ "*invoke-restmethod*" or powershell.file.script_block_text like~ "*net.webclient*" or '
         'powershell.file.script_block_text like~ "*uploadfile*")]',
         "critical", 82, "approval",
         [{"framework": "MITRE ATT&CK", "tactic": tactic("TA0010"),
           "technique": [tech("T1041", "Exfiltration Over C2 Channel")]},
          {"framework": "MITRE ATT&CK", "tactic": tactic("TA0009"),
           "technique": [tech("T1560", "Archive Collected Data", ("T1560.001", "Archive via Utility"))]}]),
]


def main():
    out = Path(sys.argv[1] if len(sys.argv) > 1 else ".")
    out.mkdir(parents=True, exist_ok=True)
    for r in RULES:
        p = out / (r["rule_id"].removeprefix("datn-") + ".json")
        p.write_text(json.dumps(r, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(p)


if __name__ == "__main__":
    main()
