"""Regression tests for the OPS3 reducer and its Shuffle text output."""

import base64
import importlib.util
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("datn_metrics", ROOT / "datn-metrics.py")
METRICS = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = METRICS
SPEC.loader.exec_module(METRICS)


def stamp(time):
    return f"2026-11-22T{time}Z"


def trial(identifier, entity="192.0.2.10", **values):
    return {
        "test_id": identifier, "batch_id": "lab", "rule_id": "datn-pb01-r01", "kind": "positive",
        "t0": stamp("07:00:00"), "t1": stamp("07:00:15"), "alert_deadline": stamp("07:06:00"),
        "entity_field": "source.ip", "entity_value": entity, "response_mode": "automatic", **values,
    }


def alert(identifier, entity="192.0.2.10", **values):
    return {
        METRICS.ALERT_ID_FIELD: identifier, METRICS.RULE_FIELD: "datn-pb01-r01",
        METRICS.ALERT_START_FIELD: stamp("07:01:15"),
        "kibana.alert.original_time": stamp("07:00:15"),
        "@timestamp": stamp("08:00:00"), "source": {"ip": entity}, **values,
    }


def report(tests, alerts, results=(), at="07:30:00"):
    return METRICS.measure(tests, alerts, results, lambda _: True, METRICS.iso(stamp(at)))


class MetricsTests(unittest.TestCase):
    def test_stable_creation_time_and_verified_action(self):
        row = {
            "@timestamp": stamp("07:01:35"), "alert_id": "a", "execution_id": "e",
            "execution_started_at": stamp("07:01:20"), "verified_at": stamp("07:01:35"),
            "decision": "automatic", "result": "success", "verified": True,
        }
        summary, details = report([trial("t")], [alert("a")], [row])
        self.assertEqual(summary["mttd_sec"], 60)
        self.assertEqual(summary["soar_latency_sec"], 5)
        self.assertEqual(summary["mttr_sec"], 20)
        self.assertEqual(summary["verified_success"], 1)
        self.assertEqual(details[0]["execution_id"], "e")

    def test_unique_attribution_and_smoke_rule(self):
        tests = [trial("t1"), trial("t2", "192.0.2.11"), trial("t3", "192.0.2.12", kind="control")]
        smoke = alert("smoke", "192.0.2.12", **{METRICS.RULE_FIELD: "datn-smoke-forwarder"})
        summary, _ = report(tests, [alert("a"), smoke])
        self.assertEqual((summary["tp_detected"], summary["fn"], summary["tn"], summary["fp_fired"]), (1, 1, 1, 0))

    def test_overlapping_trials_are_ambiguous(self):
        summary, details = report([trial("a"), trial("b", kind="control")], [alert("one")])
        self.assertEqual(summary["ambiguous_trials"], 2)
        self.assertEqual(summary["tp_total"] + summary["fp_total"], 0)
        self.assertTrue(all(x["status"] == "ambiguous_alert" for x in details))

    def test_alert_earlier_than_threshold_completion_is_not_attributed(self):
        summary, _ = report([trial("t", t_ready=stamp("07:01:20"))], [alert("early")])
        self.assertEqual((summary["tp_detected"], summary["fn"]), (0, 1))

    def test_explicit_alert_resolves_overlap_and_duplicate_alerts_count_once(self):
        tests = [trial("t1", alert_id="a"), trial("t2", kind="control"), trial("t3", "192.0.2.11")]
        summary, _ = report(tests, [alert("a"), alert("b", "192.0.2.11"), alert("c", "192.0.2.11")])
        self.assertEqual((summary["tp_detected"], summary["tn"], summary["trials_with_extra_alerts"]), (2, 1, 1))

    def test_missing_execution_result_stays_in_denominator(self):
        tests = [trial("t1"), trial("t2", "192.0.2.11"), trial("t3", "192.0.2.12")]
        rows = [
            {
                "@timestamp": stamp("07:01:30"), "alert_id": "a", "execution_id": "e1",
                "result": "success", "verified": True, "verified_at": stamp("07:01:30"),
            },
            {"@timestamp": stamp("07:01:25"), "alert_id": "b", "execution_id": "e2", "phase": "started"},
            {"@timestamp": stamp("07:01:25"), "alert_id": "c", "execution_id": "probe", "is_test": True},
        ]
        summary, _ = report(tests, [alert("a"), alert("b", "192.0.2.11"), alert("c", "192.0.2.12")], rows)
        self.assertEqual([summary[k] for k in
                          ("executions_expected", "executions_observed", "results_recorded", "verified_success")],
                         [3, 2, 1, 1])
        self.assertEqual(summary["playbook_success_rate"], 0.333333)
        self.assertEqual(summary["workflow_outcomes"]["missing_result"], 1)
        self.assertEqual(summary["workflow_outcomes"]["missing_execution"], 1)

    def test_notify_and_absent_evidence(self):
        docs = [trial("t", response_mode="notify", t1=None)]
        receipt = {
            "@timestamp": stamp("07:01:40"), "alert_id": "a", "execution_id": "e",
            "result": "success", "verified": True, "notified_at": stamp("07:01:40"),
        }
        summary, _ = report(docs, [alert("a")], [receipt])
        self.assertEqual(summary["notification_latency_sec"], 25)
        self.assertEqual(summary["verified_success"], 1)
        self.assertIsNone(summary["mttd_sec"])
        self.assertIsNone(summary["mttr_sec"])
        self.assertIsNone(summary["automation_rate"])
        receipt.pop("notified_at")
        missing, _ = report(docs, [alert("a")], [receipt])
        self.assertEqual((missing["results_recorded"], missing["verified_success"]), (1, 0))

    def test_shuffle_runtime_argument_selects_batch_and_preserves_default(self):
        for argument, expected in (("batch:pb01-dot01", "pb01-dot01"), ("", None), ("{}", None)):
            with self.subTest(argument=argument):
                self.assertEqual(METRICS.shuffle_batch_id(base64.b64encode(argument.encode())), expected)
        for invalid in ("not base64!", base64.b64encode(b"batch:too many words")):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                METRICS.shuffle_batch_id(invalid)

    def test_observed_telegram_delivery_keeps_missing_workflow_result(self):
        row = trial("t", response_mode="notify", alert_id="a", execution_id="e",
                    t_ready=stamp("07:00:20"), execution_started_at=stamp("07:01:20"),
                    observed_notified_at=stamp("07:01:40"), observed_notification_accepted=True,
                    input_origin="synthetic_firewall_fixture")
        summary, details = report([row], [alert("a")])
        self.assertEqual(summary["workflow_outcomes"], {"missing_result": 1})
        self.assertEqual(summary["synthetic_firewall_trials"], 1)
        self.assertEqual((summary["results_recorded"], summary["verified_success"]), (0, 0))
        self.assertEqual(summary["observed_notification_latency_sec"], 25)
        self.assertEqual(summary["observed_threshold_to_notification_sec"], 80)
        self.assertIsNone(summary["notification_latency_sec"])
        self.assertIsNotNone(details[0]["observed_notified_at"])

    def test_legacy_unidentified_and_unclosed_trials_do_not_enter_denominator(self):
        docs = [trial("legacy", rule_id="R01"), trial("pending"), trial("bad-id", alert_id="wrong")]
        summary, _ = report(docs, [], at="07:04:00")
        self.assertEqual((summary["invalid_trials"], summary["pending_trials"], summary["tp_total"]), (1, 2, 0))
        closed, _ = report(docs, [])
        self.assertEqual((closed["invalid_trials"], closed["tp_total"], closed["fn"]), (2, 1, 1))

    def test_formatter_carries_window_dates_and_escapes_json(self):
        m = {"window": "7d", "window_start": stamp("07:00:00"), "window_end": stamp("08:00:00"),
             "tp_total": 3, "tp_detected": 2}
        command = [sys.executable, ROOT / "ops3-format.py"]
        result = subprocess.run(command, input=json.dumps(m), encoding="utf-8", check=True,
                                capture_output=True, env={**os.environ, "PYTHONIOENCODING": "utf-8"})
        text = json.loads('"' + result.stdout + '"')
        self.assertIn("7d", text)
        self.assertIn("22/11/2026 14:00 → 22/11/2026 15:00 (GMT+7)", text)
        self.assertIn("2/3 (66.7%)", text)
        self.assertIn("chưa có dữ liệu", text)
        self.assertNotIn("24h", text)


if __name__ == "__main__":
    unittest.main()
