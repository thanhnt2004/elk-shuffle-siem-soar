#!/usr/bin/env python3
"""Gui tin Telegram cho playbook SOAR (DATN) ma khong de token trong Shuffle.

Shuffle goi qua SSH (ubuntu@10.99.0.1):
    python3 -I /opt/datn/src/soar/datn-notify.py <text_base64>

Token va chat ID doc tu /opt/datn/secrets/telegram.env (600, ubuntu):
    TELEGRAM_BOT_TOKEN=...
    TELEGRAM_CHAT_ID=...
In ra MOT dong JSON khong xuong dong: {"status":200,"ok":true,"message_id":N,"date":epoch}
(khong bao gio in token/URL). Ma thoat 0 ke ca khi Telegram tu choi, de workflow van
ghi duoc ket qua "telegram_not_confirmed".
"""
import base64
import binascii
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

ENV = Path("/opt/datn/secrets/telegram.env")
MAX_TEXT = 3900


def load_env():
    out = {}
    for line in ENV.read_text().splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def main():
    if len(sys.argv) != 2:
        sys.exit("dung: datn-notify.py <text_base64>")
    try:
        text = base64.b64decode(sys.argv[1], validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError):
        print(json.dumps({"status": 0, "ok": False, "error": "bad_base64"}), end="")
        return
    env = load_env()
    body = json.dumps({"chat_id": env["TELEGRAM_CHAT_ID"], "text": text[:MAX_TEXT],
                       "disable_web_page_preview": True}).encode()
    req = urllib.request.Request(
        f"https://api.telegram.org/bot{env['TELEGRAM_BOT_TOKEN']}/sendMessage",
        data=body, method="POST", headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            status, data = resp.status, json.load(resp)
    except urllib.error.HTTPError as err:
        status, data = err.code, {"ok": False}
    except (urllib.error.URLError, TimeoutError, OSError) as err:
        print(json.dumps({"status": 0, "ok": False, "error": type(err).__name__}), end="")
        return
    msg = data.get("result") or {}
    print(json.dumps({"status": status, "ok": data.get("ok") is True,
                      "message_id": msg.get("message_id"), "date": msg.get("date")}), end="")


if __name__ == "__main__":
    main()
