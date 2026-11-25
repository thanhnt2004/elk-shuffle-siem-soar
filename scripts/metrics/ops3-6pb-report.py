#!/usr/bin/env python3
"""Chay OPS3 (datn-metrics.py) cho tung dot E2E cua 6 playbook va in bang tong hop Markdown.

  source /opt/datn/datn-env.sh
  python3 -I /opt/datn/src/metrics/ops3-6pb-report.py e2e-pb02-20261125 e2e-pb03-20261125 ... [--no-write]

Moi dot duoc chot vao datn-metrics (schema_version 2, id batch-<sha256>) giong OPS3 hien co,
roi in: TP/FN/FP/TN, detection rate, FPR, MTTD, threshold delay, SOAR latency, approval wait,
MTTR, result coverage, playbook success rate, automation rate. Kem JSON chi tiet o stdout --json.
"""
import json
import subprocess
import sys

METRICS = "/opt/datn/src/metrics/datn-metrics.py"


def run(batch, write):
    cmd = ["python3", "-I", METRICS, "--batch-id", batch, "--details"]
    if not write:
        cmd.append("--no-write")
    out = subprocess.run(cmd, capture_output=True, text=True, check=True).stdout
    return json.loads(out)


def f(v, pct=False, unit=""):
    if v is None:
        return "—"
    return f"{v * 100:.0f}%" if pct else f"{v:.1f}{unit}"


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    write = "--no-write" not in sys.argv
    rows, full = [], {}
    for b in args:
        m = run(b, write)
        full[b] = m
        lat = m["latency"]
        rows.append([
            b, f"{m['tp_detected']}/{m['tp_total']}", f"{m['fp_fired']}/{m['fp_total']}",
            f(m["detection_rate"], True), f(m["false_positive_rate"], True),
            f(lat["mttd"]["mean"], unit="s"), f(lat["threshold_delay"]["mean"], unit="s"),
            f(lat["soar_latency"]["mean"], unit="s"), f(lat["approval_wait"]["mean"], unit="s"),
            f(lat["mttr"]["mean"], unit="s"), f(lat["mttr_after_approve"]["mean"], unit="s"),
            f(m["result_coverage"], True), f(m["playbook_success_rate"], True), f(m["automation_rate"], True),
            str(m["trials_with_extra_alerts"]),
        ])
    head = ["Dot", "TP", "FP", "DR", "FPR", "MTTD", "Tre nguong", "Tre SOAR", "Cho duyet", "MTTR",
            "MTTR sau duyet", "Du ket qua", "PB thanh cong", "Tu dong hoa", "Luot co alert thua"]
    print("| " + " | ".join(head) + " |")
    print("|" + "---|" * len(head))
    for r in rows:
        print("| " + " | ".join(r) + " |")
    if "--json" in sys.argv:
        print(json.dumps(full, ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()
