#!/usr/bin/env python3
"""Summarize labelled Elastic/Shuffle measurements for OPS3."""

import argparse
import base64
import binascii
import hashlib
import json
import os
import re
import ssl
import sys
import urllib.request
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from statistics import fmean, median


ALERT_INDEX = ".alerts-security.alerts-default"
RULE_FIELD = "kibana.alert.rule.rule_id"
ALERT_ID_FIELD = "kibana.alert.uuid"
ALERT_START_FIELD = "kibana.alert.start"
ENTITY_FIELDS = ("source.ip", "host.name", "host.id", "user.name", "http.request.id")
MODES = {"notify", "approval", "automatic"}
TERMINAL = {"success", "failed", "denied", "expired", "skipped", "no_action"}
STAT_NAMES = (
    "mttd", "threshold_delay", "soar_latency", "notification_latency",
    "observed_notification_latency", "observed_threshold_to_notification",
    "mttr", "approval_wait", "mttr_after_approve",
)


def shuffle_batch_id(encoded):
    try:
        argument = base64.b64decode(encoded, validate=True).decode("utf-8").strip()
    except (binascii.Error, UnicodeDecodeError) as error:
        raise ValueError("Runtime Argument cua Shuffle khong giai ma duoc") from error
    if not argument.startswith("batch:"):
        return None
    batch_id = argument.removeprefix("batch:")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", batch_id):
        raise ValueError("Runtime Argument can co dang batch:<ma-dot>")
    return batch_id


def iso(value):
    if not isinstance(value, str):
        return None
    try:
        stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return stamp.astimezone(timezone.utc) if stamp.tzinfo is not None else None
    except ValueError:
        return None


def timestamp(stamp):
    return stamp.isoformat() if stamp is not None else None


def field(doc, path):
    if path in doc:
        return doc[path]
    value = doc
    for part in path.split("."):
        value = value.get(part) if isinstance(value, dict) else None
    return value


def ratio(numerator, denominator):
    return round(numerator / denominator, 6) if denominator else None


def exclude_check(doc):
    return doc.get("is_test") is True or doc.get("result") == "integration_check"


def stable_rule_id(doc):
    value = doc.get("source_rule_id") or doc.get("rule_id")
    return value if isinstance(value, str) and value and not re.fullmatch(r"[Rr]\d+", value) else None


@dataclass(frozen=True)
class Trial:
    identifier: str
    rule_id: str
    kind: str
    start: datetime
    end: datetime
    entity_field: str
    entity_value: str
    alert_id: str
    doc: dict

    @classmethod
    def parse(cls, doc):
        identifier, rule_id = doc.get("test_id"), stable_rule_id(doc)
        kind = doc.get("kind")
        if not isinstance(kind, str):
            return None
        kind = {"tp": "positive", "fp": "control"}.get(kind, kind)
        start = iso(doc.get("t0"))
        end = iso(doc.get("alert_deadline")) if "alert_deadline" in doc else (
            start + timedelta(minutes=15) if start else None
        )
        entity_field, entity_value = doc.get("entity_field"), doc.get("entity_value")
        if not entity_field:
            if doc.get("source_ip"):
                entity_field, entity_value = "source.ip", doc["source_ip"]
            elif doc.get("host_name"):
                entity_field, entity_value = "host.name", doc["host_name"]
        alert_id = doc.get("alert_id")
        if not (
            isinstance(identifier, str) and identifier and rule_id
            and kind in {"positive", "control"} and start and end and end >= start
            and (
                (entity_field in ENTITY_FIELDS and isinstance(entity_value, str) and entity_value)
                or (not entity_field and isinstance(alert_id, str) and alert_id)
            )
        ):
            return None
        return cls(identifier, rule_id, kind, start, end, entity_field, entity_value, alert_id, doc)

    def matches(self, alert):
        if self.rule_id != field(alert, RULE_FIELD):
            return False
        when = iso(field(alert, ALERT_START_FIELD))
        earliest = self.start
        if self.kind == "positive":
            earliest = max(self.start, iso(self.doc.get("t1")) or self.start,
                           iso(self.doc.get("t_ready")) or self.start)
        if when is None or not earliest <= when <= self.end:
            return False
        if self.alert_id and self.alert_id != field(alert, ALERT_ID_FIELD):
            return False
        if self.entity_field:
            value = field(alert, self.entity_field)
            return self.entity_value in value if isinstance(value, list) else self.entity_value == value
        return bool(self.alert_id)


def correlate(trials, alerts):
    by_rule = defaultdict(list)
    for trial in trials:
        by_rule[trial.rule_id].append(trial)
    candidates = defaultdict(list)
    ambiguous = set()
    duplicate_ids = set()
    seen = set()
    for alert in sorted(alerts, key=lambda a: iso(field(a, ALERT_START_FIELD)) or datetime.max.replace(tzinfo=timezone.utc)):
        alert_id = field(alert, ALERT_ID_FIELD)
        if not alert_id or alert_id in seen:
            continue
        seen.add(alert_id)
        matching = [t for t in by_rule[field(alert, RULE_FIELD)] if t.matches(alert)]
        explicit = [t for t in matching if t.alert_id]
        owners = explicit or matching
        if len(owners) > 1:
            ambiguous.update(t.identifier for t in owners)
        elif owners:
            identifier = owners[0].identifier
            if candidates[identifier]:
                duplicate_ids.add(identifier)
            candidates[identifier].append(alert)
    return candidates, ambiguous, duplicate_ids


def execution_for(trial, alert, records, mode, as_of):
    alert_time = iso(field(alert, ALERT_START_FIELD))
    requested = trial.doc.get("execution_id")
    by_id = defaultdict(list)
    for record in records:
        execution_id = record.get("execution_id")
        test_id = record.get("test_id")
        if execution_id and iso(record.get("@timestamp")) >= alert_time and (not test_id or test_id == trial.identifier):
            by_id[execution_id].append(record)
    if requested:
        selected = by_id[requested]
    elif len(by_id) == 1:
        requested, selected = next(iter(by_id.items()))
    else:
        return {"observed": bool(by_id), "outcome": "ambiguous_execution" if by_id else "missing_execution"}
    terminal = [r for r in selected if r.get("result") in TERMINAL and r.get("phase") != "started"]
    statuses = {
        (r.get("result"), r.get("verified") is True, r.get("decision"))
        for r in terminal
    }
    if len(statuses) > 1:
        return {"observed": True, "execution_id": requested, "recorded": True, "outcome": "conflicting_result"}
    report = max(terminal, key=lambda r: iso(r.get("@timestamp")) or alert_time, default={})

    def in_range(value):
        stamp = iso(value)
        return stamp if stamp and alert_time <= stamp <= as_of else None

    starts = [
        t for r in selected
        if (t := in_range(r.get("execution_started_at") or r.get("started_at")
                          or (r.get("@timestamp") if r.get("phase") == "started" else None)))
    ]
    if trial.doc.get("execution_id") == requested:
        manual = in_range(trial.doc.get("execution_started_at"))
        if manual:
            starts.append(manual)
    started = min(starts, default=None)
    result = report.get("result")
    notified = in_range(report.get("notified_at"))
    verified_at = in_range(report.get("verified_at") or report.get("t6"))
    checked_at = notified if mode == "notify" else verified_at
    verified = result == "success" and report.get("verified") is True and checked_at is not None
    return {
        "observed": bool(selected or started),
        "execution_id": requested,
        "recorded": bool(report),
        "outcome": ("verified_success" if verified else result or
                    ("missing_result" if selected or started else "missing_execution")),
        "verified": verified,
        "decision": report.get("decision"),
        "started": started,
        "notified": notified,
        "approval_requested": in_range(report.get("approval_requested_at")),
        "approved": in_range(report.get("approved_at") or report.get("t5")),
        "verified_at": verified_at,
    }


def add_duration(samples, name, start, end):
    if start is not None and end is not None and end >= start:
        samples[name].append((end - start).total_seconds())


def statistics(samples):
    if not samples:
        return {"n": 0, "mean": None, "median": None, "max": None}
    return {
        "n": len(samples),
        "mean": round(fmean(samples), 3),
        "median": round(median(samples), 3),
        "max": round(max(samples), 3),
    }


def measure(test_docs, alerts, records, include, as_of):
    parsed = [(doc, Trial.parse(doc)) for doc in test_docs if not exclude_check(doc)]
    identifiers = Counter(trial.identifier for _, trial in parsed if trial)
    valid = [t for _, t in parsed if t and identifiers[t.identifier] == 1]
    received = [a for a in alerts if (stamp := iso(field(a, ALERT_START_FIELD))) and stamp <= as_of]
    candidates, ambiguous, duplicates = correlate(valid, received)
    records_by_alert = defaultdict(list)
    for record in records:
        stamp = iso(record.get("@timestamp"))
        if not exclude_check(record) and stamp and stamp <= as_of:
            records_by_alert[record.get("alert_id")].append(record)
    counts, modes, outcomes = Counter(), Counter(), Counter()
    samples = defaultdict(list)
    details = []
    for doc, trial in parsed:
        if not include(doc):
            continue
        if not trial or identifiers[trial.identifier] != 1:
            counts["invalid_trials"] += 1
            details.append({"test_id": doc.get("test_id"), "status": "invalid_trial"})
            continue
        if trial.identifier in ambiguous:
            counts["ambiguous_trials"] += 1
            details.append({"test_id": trial.identifier, "status": "ambiguous_alert"})
            continue
        if trial.end > as_of:
            counts["pending_trials"] += 1
            details.append({"test_id": trial.identifier, "status": "pending_alert_window"})
            continue
        found = candidates[trial.identifier]
        if trial.alert_id and not found:
            counts["invalid_trials"] += 1
            details.append({"test_id": trial.identifier, "status": "unmatched_alert_reference"})
            continue
        status = ("true_positive" if found else "false_negative") if trial.kind == "positive" else (
            "false_positive" if found else "true_negative"
        )
        counts[status] += 1
        if doc.get("input_origin") == "synthetic_firewall_fixture":
            counts["synthetic_firewall_trials"] += 1
        counts["trials_with_extra_alerts"] += int(trial.identifier in duplicates)
        detail = {
            "test_id": trial.identifier, "rule_id": trial.rule_id, "status": status,
            "t0": timestamp(trial.start), "alert_deadline": timestamp(trial.end),
        }
        details.append(detail)
        if not found:
            continue

        alert = found[0]
        alert_id = field(alert, ALERT_ID_FIELD)
        alert_time = iso(field(alert, ALERT_START_FIELD))
        detail.update(alert_id=alert_id, t_alert=timestamp(alert_time), extra_alerts=len(found) - 1)
        if status != "true_positive":
            continue
        event_time = iso(doc.get("t1"))
        if event_time and event_time >= trial.start:
            add_duration(samples, "mttd", event_time, alert_time)
        ready = iso(doc.get("t_ready"))
        detail.update(t1=timestamp(event_time), t_ready=timestamp(ready))
        if event_time and ready and event_time <= ready:
            add_duration(samples, "threshold_delay", ready, alert_time)
        if doc.get("expect_workflow") is False:
            continue

        counts["executions_expected"] += 1
        mode = doc.get("response_mode")
        if mode not in MODES:
            mode = next((tag[5:] for tag in field(alert, "kibana.alert.rule.tags") or []
                         if isinstance(tag, str) and tag.startswith("mode:") and tag[5:] in MODES), None)
        modes[mode or "unknown"] += 1
        result = execution_for(trial, alert, records_by_alert[alert_id], mode, as_of)
        counts["executions_observed"] += int(result["observed"])
        counts["results_recorded"] += int(result.get("recorded", False))
        counts["verified_success"] += int(result.get("verified", False))
        outcome = result["outcome"]
        if outcome in {"missing_execution", "missing_result"}:
            deadline = iso(doc.get("response_deadline")) or (alert_time + timedelta(minutes=15))
            if as_of < deadline:
                outcome = "pending_result"
        outcomes[outcome] += 1
        detail.update(
            execution_id=result.get("execution_id"), response_mode=mode, outcome=outcome,
            execution_started_at=timestamp(result.get("started")),
            notified_at=timestamp(result.get("notified")),
            approval_requested_at=timestamp(result.get("approval_requested")),
            approved_at=timestamp(result.get("approved")),
            verified_at=timestamp(result.get("verified_at")),
        )
        if mode in {"approval", "automatic"}:
            counts["automation_eligible"] += 1
            if result.get("decision") == "automatic" and outcome in {"verified_success", "failed", "success"}:
                counts["automated_executions"] += 1
        add_duration(samples, "soar_latency", alert_time, result.get("started"))
        add_duration(samples, "notification_latency", alert_time, result.get("notified"))
        if (mode == "notify" and not result.get("recorded") and result.get("started")
                and trial.alert_id == alert_id and doc.get("observed_notification_accepted") is True):
            observed_at = iso(doc.get("observed_notified_at"))
            if observed_at and result["started"] <= observed_at <= as_of:
                detail["observed_notified_at"] = timestamp(observed_at)
                add_duration(samples, "observed_notification_latency", alert_time, observed_at)
                if event_time and ready and event_time <= ready <= alert_time:
                    add_duration(samples, "observed_threshold_to_notification", ready, observed_at)
        if mode == "approval":
            add_duration(samples, "approval_wait", result.get("approval_requested"), result.get("approved"))
        if mode in {"approval", "automatic"} and result.get("verified"):
            add_duration(samples, "mttr", alert_time, result.get("verified_at"))
            if mode == "approval":
                add_duration(samples, "mttr_after_approve", result.get("approved"), result.get("verified_at"))

    tp_total = counts["true_positive"] + counts["false_negative"]
    fp_total = counts["false_positive"] + counts["true_negative"]
    report = {
        **{key: counts[key] for key in (
            "executions_expected", "executions_observed", "results_recorded", "verified_success",
            "automation_eligible", "automated_executions", "invalid_trials", "ambiguous_trials",
            "pending_trials", "trials_with_extra_alerts", "synthetic_firewall_trials",
        )},
        "tp_total": tp_total, "tp_detected": counts["true_positive"], "fn": counts["false_negative"],
        "fp_total": fp_total, "fp_fired": counts["false_positive"], "tn": counts["true_negative"],
        "detection_rate": ratio(counts["true_positive"], tp_total),
        "false_positive_rate": ratio(counts["false_positive"], fp_total),
        "executions": counts["executions_observed"], "success": counts["verified_success"],
        "playbook_success_rate": ratio(counts["verified_success"], counts["executions_expected"]),
        "result_coverage": ratio(counts["results_recorded"], counts["executions_expected"]),
        "automation_rate": ratio(counts["automated_executions"], counts["automation_eligible"]),
        "response_modes": dict(modes), "workflow_outcomes": dict(outcomes),
        "latency": {name: statistics(samples[name]) for name in STAT_NAMES},
    }
    report.update({name + "_sec": stats["mean"] for name, stats in report["latency"].items()})
    return report, details


class Elastic:
    def __init__(self):
        password = os.environ.get("ELASTIC_PASSWORD")
        if not password:
            raise ValueError("Thieu ELASTIC_PASSWORD trong moi truong")
        self.base = os.environ.get("ES_LOCAL", "https://localhost:9200")
        self.context = ssl.create_default_context(cafile=os.environ.get(
            "ES_CA_LOCAL", "/opt/datn/elk/certs/ca/ca.crt"
        ))
        self.headers = {
            "Content-Type": "application/json",
            "Authorization": "Basic " + base64.b64encode(f"elastic:{password}".encode()).decode(),
        }

    def request(self, path, body, method="POST"):
        request = urllib.request.Request(
            self.base + path, data=json.dumps(body).encode(), method=method, headers=self.headers
        )
        with urllib.request.urlopen(request, context=self.context, timeout=30) as response:
            return json.load(response)

    def search(self, index, query, fields=None):
        body = {"size": 500, "sort": ["_doc"], "query": query}
        if fields is not None:
            body["_source"] = fields
        page = self.request(f"/{index}/_search?scroll=1m&allow_partial_search_results=false", body)
        scroll = page.get("_scroll_id")
        try:
            while True:
                if page.get("timed_out") or page.get("_shards", {}).get("failed"):
                    raise RuntimeError(f"Ket qua tim kiem khong day du: {index}")
                hits = page["hits"]["hits"]
                if not hits:
                    break
                yield from (hit["_source"] for hit in hits)
                if not scroll:
                    raise RuntimeError(f"Thieu scroll ID cho index: {index}")
                page = self.request("/_search/scroll", {"scroll_id": scroll, "scroll": "1m"})
                scroll = page.get("_scroll_id", scroll)
        finally:
            if scroll:
                self.request("/_search/scroll", {"scroll_id": [scroll]}, method="DELETE")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    selection = parser.add_mutually_exclusive_group()
    selection.add_argument("--since", help="Cua so truot, vi du 24h hoac 7d")
    selection.add_argument("--batch-id", help="Tong hop cac luot thu cua mot dot")
    selection.add_argument("--shuffle-argument-b64", help="Runtime Argument do Shuffle ma hoa Base64")
    parser.add_argument("--no-write", action="store_true", help="Chi in JSON, khong ghi index")
    parser.add_argument("--details", action="store_true", help="Kem doi chieu tung luot trong stdout")
    args = parser.parse_args()
    shuffle_batch = args.shuffle_argument_b64 is not None
    if shuffle_batch:
        args.batch_id = shuffle_batch_id(args.shuffle_argument_b64)
    if args.batch_id is not None and not args.batch_id.strip():
        parser.error("--batch-id khong duoc de trong")
    now = datetime.now(timezone.utc).replace(microsecond=0)
    label = args.since or "24h"
    span = re.fullmatch(r"(\d{1,5})([mhd])", label)
    if not span or int(span[1]) == 0:
        parser.error("--since phai la so duong kem m, h hoac d")
    lower = now - timedelta(seconds=int(span[1]) * {"m": 60, "h": 3600, "d": 86400}[span[2]])

    def include(doc):
        if args.batch_id is not None:
            return doc.get("batch_id") == args.batch_id
        stamp = iso(doc.get("t0")) or iso(doc.get("@timestamp"))
        return stamp is not None and lower <= stamp <= now

    elastic = Elastic()
    # Keep neighbouring trials available so an alert cannot be reattributed across batches.
    tests = list(elastic.search("datn-tests", {"match_all": {}}))
    if shuffle_batch and args.batch_id and not any(include(doc) and not exclude_check(doc) for doc in tests):
        raise ValueError("Khong tim thay dot trong datn-tests")
    scoped = [trial for doc in tests if include(doc) and not exclude_check(doc) and (trial := Trial.parse(doc))]
    alerts, results = [], []
    if scoped:
        start = min(t.start for t in scoped)
        end = min(now, max(t.end for t in scoped))
        filters = [
            {"terms": {RULE_FIELD: sorted({t.rule_id for t in scoped})}},
            {"range": {ALERT_START_FIELD: {"gte": timestamp(start), "lte": timestamp(end)}}},
        ]
        fields = [RULE_FIELD, ALERT_ID_FIELD, ALERT_START_FIELD, "kibana.alert.rule.tags", *ENTITY_FIELDS]
        alerts = list(elastic.search(ALERT_INDEX, {"bool": {"filter": filters}}, fields))
        ids = sorted({value for a in alerts if (value := field(a, ALERT_ID_FIELD))})
        for pos in range(0, len(ids), 500):
            results.extend(elastic.search("datn-soar-results", {"terms": {"alert_id": ids[pos:pos + 500]}}))

    metrics, details = measure(tests, alerts, results, include, now)
    first = min((t.start for t in scoped), default=None)
    last = max((t.end for t in scoped), default=None)
    metrics.update({
        "schema_version": 2,
        "@timestamp": timestamp(now),
        "window": label if args.batch_id is None else "batch",
        "batch_id": args.batch_id,
        "window_start": timestamp(lower if args.batch_id is None else first),
        "window_end": timestamp(now if args.batch_id is None else last),
    })
    if not args.no_write:
        if args.batch_id is None:
            elastic.request("/datn-metrics/_doc", metrics)
        else:
            batch_hash = hashlib.sha256(args.batch_id.encode()).hexdigest()
            elastic.request(f"/datn-metrics/_doc/batch-{batch_hash}", metrics, method="PUT")
    if args.details:
        metrics["trials"] = details
    print(json.dumps(metrics, ensure_ascii=False))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, RuntimeError) as error:
        sys.exit(f"OPS3: {error}")
