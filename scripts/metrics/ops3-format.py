#!/usr/bin/env python3
"""Render an OPS3 report for Telegram without changing the Shuffle JSON contract."""

import argparse
import json
import sys
from datetime import datetime, timedelta, timezone


VIETNAM_TZ = timezone(timedelta(hours=7))


def local_time(value):
    if not value:
        return None
    try:
        stamp = datetime.fromisoformat(value)
    except (ValueError, TypeError):
        return None
    if stamp.tzinfo is None:
        return None
    return stamp.astimezone(VIETNAM_TZ).strftime("%d/%m/%Y %H:%M")


def fraction(numerator, denominator):
    if not denominator:
        return "chưa có dữ liệu"
    return f"{numerator}/{denominator} ({numerator / denominator:.1%})"


def duration(report, name):
    stats = report.get("latency", {}).get(name, {})
    mean = stats.get("mean", report.get(f"{name}_sec"))
    if mean is None:
        return "chưa có dữ liệu"
    if not stats:
        return f"{mean:g} s"
    return f"{mean:g} s (n={stats['n']}, trung vị {stats['median']:g} s, max {stats['max']:g} s)"


def format_report(m):
    window = m.get("window") or "không rõ khoảng đo"
    batch = m.get("batch_id")
    start = local_time(m.get("window_start"))
    end = local_time(m.get("window_end"))
    expected = m.get("executions_expected", m.get("executions", 0))
    observed = m.get("executions_observed", m.get("executions", 0))
    recorded = m.get("results_recorded", m.get("executions", 0))
    success = m.get("verified_success", m.get("success", 0))
    eligible = m.get("automation_eligible")
    misses = m.get("workflow_outcomes", {})
    lines = [f"📊 Báo cáo DATN · {f'đợt {batch}' if batch else window}"]
    if start and end:
        lines.append(f"{start} → {end} (GMT+7)")
    if m.get("synthetic_firewall_trials"):
        lines.append(f"Dữ liệu firewall giả lập: {m['synthetic_firewall_trials']} lượt")
    lines.extend([
        f"Phát hiện: {fraction(m.get('tp_detected', 0), m.get('tp_total', 0))}",
        f"Cảnh báo sai: {fraction(m.get('fp_fired', 0), m.get('fp_total', 0))}",
        f"Workflow kỳ vọng {expected} · đã thấy chạy {observed} · có kết quả {recorded}",
        f"Thành công đã xác minh: {fraction(success, expected)}",
        f"MTTD: {duration(m, 'mttd')}",
        f"Độ trễ điều phối: {duration(m, 'soar_latency')}",
        f"Độ trễ thông báo: {duration(m, 'notification_latency')}",
    ])
    if m.get("latency", {}).get("threshold_delay", {}).get("n"):
        lines.append(f"Từ khi đủ ngưỡng đến alert: {duration(m, 'threshold_delay')}")
    if m.get("latency", {}).get("observed_notification_latency", {}).get("n"):
        lines.append("Alert → Telegram (đối chiếu lịch sử Shuffle): "
                     + duration(m, "observed_notification_latency"))
    if m.get("latency", {}).get("observed_threshold_to_notification", {}).get("n"):
        lines.append("Đủ ngưỡng → Telegram (đối chiếu lịch sử Shuffle): "
                     + duration(m, "observed_threshold_to_notification"))
    modes = m.get("response_modes", {})
    if expected and modes.get("notify") == expected:
        lines.append("MTTR và tự động hóa ứng phó: không áp dụng cho chế độ thông báo")
    else:
        lines.extend([
            f"MTTR: {duration(m, 'mttr')}",
            f"Tự động hóa: {fraction(m.get('automated_executions', 0), eligible)}",
        ])
        if modes.get("approval"):
            lines.append(f"Chờ duyệt: {duration(m, 'approval_wait')}")
            lines.append(f"Sau duyệt: {duration(m, 'mttr_after_approve')}")
    if expected:
        lines.append(
            f"Đang chờ {misses.get('pending_result', 0)} · "
            f"thiếu execution {misses.get('missing_execution', 0)} · "
            f"thiếu kết quả {misses.get('missing_result', 0)}"
        )
        unresolved = misses.get("ambiguous_execution", 0) + misses.get("conflicting_result", 0)
        if unresolved:
            lines.append(f"Kết quả cần đối chiếu: {unresolved}")
    invalid = m.get("invalid_trials", 0)
    ambiguous = m.get("ambiguous_trials", 0)
    pending = m.get("pending_trials", 0)
    if invalid or ambiguous or pending:
        lines.append(f"Lượt ngoại lệ: thiếu dữ liệu {invalid} · ghép mơ hồ {ambiguous} · đang chờ {pending}")
    duplicate = m.get("trials_with_extra_alerts", 0)
    if duplicate:
        lines.append(f"Lượt có cảnh báo bổ sung: {duplicate}")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plain", action="store_true", help="Xem truoc tin nhan de doc")
    args = parser.parse_args()
    text = format_report(json.load(sys.stdin))
    if args.plain:
        print(text)
    else:
        # The existing Shuffle action inserts the result inside a JSON string.
        print(json.dumps(text, ensure_ascii=False)[1:-1], end="")


if __name__ == "__main__":
    main()
