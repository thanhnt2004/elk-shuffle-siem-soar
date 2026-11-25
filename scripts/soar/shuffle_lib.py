#!/usr/bin/env python3
"""Thu vien nho dung workflow Shuffle qua REST API (DATN, 6 playbook).

Chay tren EC2 bang user ubuntu. Doc:
  /opt/datn/secrets/shuffle-api.env   SHUFFLE_API_KEY, SHUFFLE_URL   (quyen 600, khong in ra)
  /opt/datn/forwarder/.env            WEBHOOK_SECRET  (header X-DATN-Secret cua webhook)

Metadata app (app_id, app_version, anh, ...) duoc sao tu workflow PB01 dang chay de
khong phai ghi cung; nho vay node moi giong het node dung bang giao dien.
"""
import copy
import json
import os
import urllib.error
import urllib.request
import uuid
from pathlib import Path

API_ENV = Path("/opt/datn/secrets/shuffle-api.env")
FWD_ENV = Path("/opt/datn/forwarder/.env")
PB01_WORKFLOW = os.environ["SHUFFLE_PB01_WORKFLOW_ID"]

# File khoa trong Shuffle Files (chi luu ID, khong luu noi dung)
KEY_EC2 = os.environ["SHUFFLE_EC2_KEY_FILE_ID"]
KEY_SOAR = os.environ["SHUFFLE_LAB_KEY_FILE_ID"]


def _env(path):
    out = {}
    for line in path.read_text().splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip().strip('"').strip("'")
    return out


class Shuffle:
    def __init__(self):
        env = _env(API_ENV)
        self.base = env.get("SHUFFLE_URL", "http://10.99.0.1:5001").rstrip("/")
        self._key = env["SHUFFLE_API_KEY"]
        self.secret = _env(FWD_ENV)["WEBHOOK_SECRET"]

    def call(self, method, path, body=None, org=None):
        data = None if body is None else json.dumps(body).encode()
        headers = {"Authorization": f"Bearer {self._key}", "Content-Type": "application/json"}
        if org:
            headers["Org-Id"] = org
        req = urllib.request.Request(self.base + path, data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                raw = resp.read()
        except urllib.error.HTTPError as err:
            raise RuntimeError(f"{method} {path} -> HTTP {err.code}: {err.read()[:400]!r}") from None
        return json.loads(raw) if raw else {}


class Builder:
    """Sinh action/trigger/branch dung metadata lay tu PB01."""

    def __init__(self, api):
        self.api = api
        pb01 = api.call("GET", f"/api/v1/workflows/{PB01_WORKFLOW}")
        self.org = pb01["org_id"]
        self.templates = {}
        for a in pb01["actions"]:
            self.templates.setdefault(a["name"], a)
        self.telegram_auth = self.templates["post_send_message"]["authentication_id"]
        self.webhook_tpl = next(t for t in pb01["triggers"] if t["trigger_type"] == "WEBHOOK")

    def action(self, name, label, params, x, y):
        a = copy.deepcopy(self.templates[name])
        a["id"] = str(uuid.uuid4())
        a["label"] = label
        a["position"] = {"x": x, "y": y}
        a["errors"] = []
        a["is_valid"] = True
        given = dict(params)
        new_params = []
        for p in a["parameters"]:
            p = copy.deepcopy(p)
            if p["name"] in given:
                p["value"] = given.pop(p["name"])
            elif name == "post_send_message" and p["name"] == "api_token":
                p["value"] = ""   # lay tu Authentication cua app (khong chep token vao workflow)
            new_params.append(p)
        if given:
            raise ValueError(f"tham so la cho {name}: {sorted(given)}")
        a["parameters"] = new_params
        if name != "post_send_message":
            a["authentication_id"] = ""
        return a

    def ssh(self, label, host, user, key, command, x, y):
        return self.action("run_ssh_command", label, {
            "host": host, "port": "22", "user_name": user,
            "private_key_file_id": key, "password": "", "command": command}, x, y)

    def telegram(self, label, chat_id, text, x, y):
        body = json.dumps({"chat_id": chat_id, "text": text}, ensure_ascii=False)
        return self.action("post_send_message", label, {"body": body}, x, y)

    def webhook(self, label, x, y):
        t = copy.deepcopy(self.webhook_tpl)
        hook_id = str(uuid.uuid4())
        t["id"] = hook_id
        t["label"] = label
        t["position"] = {"x": x, "y": y}
        t["status"] = "uninitialized"
        for p in t["parameters"]:
            if p["name"] == "url":
                p["value"] = f"{self.api.base}/api/v1/hooks/webhook_{hook_id}"
            elif p["name"] == "tmp":
                p["value"] = f"webhook_{hook_id}"
            elif p["name"] == "auth_headers":
                p["value"] = f"X-DATN-Secret={self.api.secret}"
        return t

    @staticmethod
    def user_input(label, info, x, y):
        params = [("alertinfo", info), ("options", "boolean"), ("type", "subflow"),
                  ("email", ""), ("sms", ""), ("subflow", ""), ("subflow_failure", "")]
        return {
            "name": "User Input", "app_name": "User Input", "app_version": "1.0.0", "type": "TRIGGER",
            "trigger_type": "USERINPUT", "status": "running", "is_valid": True, "errors": None,
            "id": str(uuid.uuid4()), "label": label, "environment": "onprem",
            "description": "Wait for user input trigger", "long_description": "Take user input to continue execution",
            "parameters": [{"name": n, "example": "", "value": v} for n, v in params],
            "position": {"x": x, "y": y},
        }

    @staticmethod
    def branch(src, dst, conditions=()):
        conds = []
        for left, op, right in conditions:
            conds.append({
                "id": str(uuid.uuid4()),
                "source": {"name": "source", "value": left, "variant": "STATIC_VALUE", "action_field": "", "id": str(uuid.uuid4())},
                "condition": {"name": "condition", "value": op, "id": str(uuid.uuid4())},
                "destination": {"name": "destination", "value": right, "variant": "STATIC_VALUE", "action_field": "", "id": str(uuid.uuid4())},
            })
        return {"id": str(uuid.uuid4()), "source_id": src["id"], "destination_id": dst["id"],
                "conditions": conds, "label": "", "has_errors": False, "decorator": False}


def find_workflow(api, name):
    for w in api.call("GET", "/api/v1/workflows"):
        if w.get("name") == name:
            return w
    return None


def deploy(api, builder, name, description, actions, triggers, branches, start, variables=()):
    """Tao moi (hoac thay noi dung) workflow theo ten, roi bat webhook. Tra ve (workflow_id, hook_id)."""
    old = find_workflow(api, name)
    if old is None:
        old = api.call("POST", "/api/v1/workflows", {"name": name, "description": description}, org=builder.org)
    wf_id = old["id"]
    full = api.call("GET", f"/api/v1/workflows/{wf_id}")
    # Giu nguyen id webhook cu (neu co) de URL trong forwarder khong doi
    old_hook = next((t for t in (full.get("triggers") or []) if t.get("trigger_type") == "WEBHOOK"), None)
    for t in triggers:
        if t["trigger_type"] == "WEBHOOK" and old_hook:
            new_id = t["id"]
            t["id"] = old_hook["id"]
            for b in branches:
                if b["source_id"] == new_id:
                    b["source_id"] = t["id"]
            for p in t["parameters"]:
                if p["name"] == "url":
                    p["value"] = f"{api.base}/api/v1/hooks/webhook_{t['id']}"
                elif p["name"] == "tmp":
                    p["value"] = f"webhook_{t['id']}"
    full.update({
        "name": name, "description": description, "actions": actions, "triggers": triggers,
        "branches": branches, "start": start["id"], "visual_branches": [],
        "workflow_variables": [{"id": str(uuid.uuid4()), "name": k, "value": v, "description": ""} for k, v in variables],
        "configuration": {"exit_on_error": False, "start_from_top": False, "skip_notifications": False},
        "org_id": builder.org, "previously_saved": True, "is_valid": True,
    })
    for a in full["actions"]:
        a["isStartNode"] = a["id"] == start["id"]
    api.call("PUT", f"/api/v1/workflows/{wf_id}", full, org=builder.org)
    hook = next((t for t in triggers if t["trigger_type"] == "WEBHOOK"), None)
    if hook:
        try:
            api.call("POST", "/api/v1/hooks/new", {
                "name": hook["label"], "type": "webhook", "id": hook["id"], "workflow": wf_id,
                "start": start["id"], "environment": "onprem",
                "auth": f"X-DATN-Secret={api.secret}", "custom_response": "",
                "version": "v1", "version_timeout": 15}, org=builder.org)
        except RuntimeError as err:
            if "exists" not in str(err).lower():
                raise
        full = api.call("GET", f"/api/v1/workflows/{wf_id}")
        for t in full["triggers"]:
            if t["id"] == hook["id"]:
                t["status"] = "running"
        api.call("PUT", f"/api/v1/workflows/{wf_id}", full, org=builder.org)
    return wf_id, (hook["id"] if hook else None)
