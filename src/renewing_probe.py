#!/usr/bin/env python3
"""Probe an endpoint whose access token is short lived.

Everything specific lives in environment secrets. The flow:
  1. exchange a durable cookie for a short-lived token at AUTH_URL
  2. call TARGET_URL with that token
  3. count the list at COUNT_PATH
  4. notify on a rising edge, dedup through a committed state file

Requests go through the curl binary: the target sits behind an edge that rejects
python's default client signature.
"""
import json
import os
import re
import smtplib
import subprocess
import sys
import time
import urllib.request
from email.message import EmailMessage

STATE = os.path.join(os.path.dirname(__file__), "state2.json")
UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36")


def env(name, default=None, required=False):
    v = os.environ.get(name, default)
    if required and not v:
        print(f"missing {name}", file=sys.stderr)
        sys.exit(0)
    return v


def call(url, method="GET", headers=None, body=None, timeout=25):
    cmd = ["curl", "-sS", "--max-time", str(timeout), "-w", "\n__C__%{http_code}",
           "--url", url, "-X", method, "-H", f"user-agent: {UA}"]
    for k, v in (headers or {}).items():
        cmd += ["-H", f"{k}: {v}"]
    if body is not None:
        cmd += ["--data-raw", body]
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 10)
    out = p.stdout
    if "__C__" in out:
        text, _, code = out.rpartition("\n__C__")
        try:
            return int(code.strip()), text
        except ValueError:
            pass
    return 0, out + p.stderr


def load_state():
    try:
        return json.load(open(STATE))
    except Exception:
        return {}


def save_state(s):
    json.dump(s, open(STATE, "w"))


def get_token():
    status, text = call(env("AUTH_URL", required=True), "POST",
                        {"accept": "*/*",
                         "content-type": "application/x-www-form-urlencoded",
                         "origin": env("AUTH_ORIGIN", ""),
                         "referer": env("AUTH_ORIGIN", "") + "/",
                         "cookie": env("AUTH_COOKIE", required=True)}, "")
    if status != 200:
        raise RuntimeError(f"auth {status}: {text[:160]}")
    tok = json.loads(text).get("jwt")
    if not tok:
        raise RuntimeError(f"no token in auth reply: {text[:160]}")
    return tok


def dig(d, path):
    for part in path.split("."):
        if isinstance(d, dict):
            d = d.get(part)
        else:
            return None
    return d


def push(title, body):
    topic = env("NTFY_TOPIC")
    if not topic:
        return
    try:
        urllib.request.urlopen(urllib.request.Request(
            f"https://ntfy.sh/{topic}", data=body.encode(),
            headers={"Title": title, "Priority": "max", "Tags": "rotating_light"}),
            timeout=10).read()
    except Exception as e:
        print(f"push failed: {e}", file=sys.stderr)


def mail(subject, body):
    user, pw = env("EMAIL_FROM"), env("EMAIL_APP_PASSWORD")
    if not user or not pw:
        return
    m = EmailMessage()
    m["Subject"], m["From"], m["To"] = subject, user, env("EMAIL_TO", user)
    m.set_content(body)
    try:
        with smtplib.SMTP("smtp.gmail.com", 587, timeout=20) as s:
            s.starttls()
            s.login(user, pw)
            s.send_message(m)
    except Exception as e:
        print(f"mail failed: {e}", file=sys.stderr)


def main():
    st = load_state()
    now = int(time.time())
    try:
        token = get_token()
    except Exception as e:
        print(f"auth failed: {e}", file=sys.stderr)
        if now - st.get("auth_alert", 0) > 21600:
            st["auth_alert"] = now
            save_state(st)
            push(env("AUTH_FAIL_SUBJECT", "[update] credential needs a refresh"),
                 env("AUTH_FAIL_BODY", "The stored credential no longer works."))
        return

    headers = json.loads(env("TARGET_HEADERS", "{}"))
    headers["authorization"] = f"Bearer {token}"
    headers.setdefault("accept", "*/*")
    status, text = call(env("TARGET_URL", required=True), "GET", headers)
    if status != 200:
        print(f"target {status}: {text[:160]}", file=sys.stderr)
        return

    rows = dig(json.loads(text), env("COUNT_PATH", "worlds")) or []
    n = len(rows) if isinstance(rows, list) else int(rows or 0)
    prev = st.get("count", 0)
    st["count"], st["at"] = n, now
    print(f"count={n} prev={prev}")

    if n > 0 and (n > prev or now - st.get("alerted", 0) > int(env("REALERT", "900"))):
        st["alerted"] = now
        subject = env("ALERT_SUBJECT2", "[update] {n} new item(s)").format(n=n)
        body = env("ALERT_BODY2", "{n} item(s) available.\n{link}").format(
            n=n, link=env("TARGET_LINK2", ""))
        push(subject, body)
        mail(subject, body)
    if n == 0:
        st.pop("alerted", None)
    save_state(st)


if __name__ == "__main__":
    main()
