#!/usr/bin/env python3
"""Small scheduled probe: POST a configured endpoint, count items at a JSON path,
notify (email + ntfy) when the count rises. All endpoint-specific config is supplied
via environment (repo secrets); nothing identifying is hard-coded."""
import json, os, ssl, smtplib, sys, time, urllib.request, urllib.error
from email.mime.text import MIMEText
from pathlib import Path

ROOT = Path(__file__).resolve().parent
STATE = ROOT / "state.json"
REALERT = int(os.environ.get("REALERT_SECONDS", "600"))
FAIL_ALERT_AT = 4          # quiet for a few blips, then one "looks down" note
FAIL_REALERT_EVERY = 24

def log(m): print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {m}", flush=True)

def load_state():
    try: return json.loads(STATE.read_text())
    except Exception: return {}

def save_state(st): STATE.write_text(json.dumps(st, indent=2))

def dig(obj, path):
    """Walk a dotted path; integer segments index into lists."""
    cur = obj
    for seg in path.split("."):
        if isinstance(cur, list):
            cur = cur[int(seg)]
        else:
            cur = cur[seg]
    return cur

def fetch_count():
    url = os.environ["PROBE_URL"]
    body = os.environ.get("PROBE_BODY", "")
    if body:
        body = (body + f"&requestId=r{int(time.time())}").encode()
    headers = json.loads(os.environ.get("PROBE_HEADERS", "{}"))
    cookie = os.environ.get("PROBE_COOKIE", "")
    if cookie: headers["cookie"] = cookie
    req = urllib.request.Request(url, data=body or None,
                                 method="POST" if body else "GET", headers=headers)
    with urllib.request.urlopen(req, timeout=30) as r:
        data = json.loads(r.read().decode("utf-8", "replace"))
    arr = dig(data, os.environ["COUNT_PATH"])
    return len(arr) if isinstance(arr, list) else int(arr)

def send_email(subject, msgbody):
    to, frm, pw = os.environ.get("EMAIL_TO",""), os.environ.get("EMAIL_FROM",""), os.environ.get("EMAIL_APP_PASSWORD","")
    if not (to and frm and pw): return False
    m = MIMEText(msgbody); m["Subject"]=subject; m["From"]=frm; m["To"]=to
    with smtplib.SMTP_SSL("smtp.gmail.com", 465, timeout=20, context=ssl.create_default_context()) as s:
        s.login(frm, pw); s.send_message(m)
    return True

def send_push(title, msgbody, priority="max"):
    topic = os.environ.get("NTFY_TOPIC","").strip()
    if not topic: return False
    req = urllib.request.Request(f"https://ntfy.sh/{topic}", data=msgbody.encode("utf-8"),
        headers={"Title": title.encode("ascii","replace").decode(), "Priority": priority,
                 "Tags": "rotating_light", "Click": os.environ.get("TARGET_LINK","")})
    urllib.request.urlopen(req, timeout=15).read(); return True

def notify(subject, msgbody):
    ok=[]
    for name, fn in (("email", lambda: send_email(subject, msgbody)), ("ntfy", lambda: send_push(subject, msgbody))):
        try:
            if fn(): ok.append(name)
        except Exception as e: log(f"{name} failed: {e}")
    return ok

def main():
    st = load_state(); now = int(time.time())
    try:
        count = fetch_count()
    except urllib.error.HTTPError as e:
        code = e.code; snippet = ""
        try: snippet = e.read().decode("utf-8","replace")[:200]
        except Exception: pass
        log(f"HTTP {code}: {snippet}")
        if code in (401, 403):
            if not st.get("auth_alerted"):
                notify("[probe] session expired", "the probe endpoint returned auth error; refresh PROBE_COOKIE / PROBE_BODY secret.")
                st["auth_alerted"]=True; save_state(st)
            sys.exit(0)
        # other non-200: transient
        st["fails"]=st.get("fails",0)+1
        if st["fails"]==FAIL_ALERT_AT or (st["fails"]>FAIL_ALERT_AT and (st["fails"]-FAIL_ALERT_AT)%FAIL_REALERT_EVERY==0):
            notify("[probe] looks down", f"{st['fails']} failed polls; status={code}")
        save_state(st); sys.exit(0)
    except Exception as e:
        st["fails"]=st.get("fails",0)+1; log(f"error: {e}"); save_state(st); sys.exit(0)

    prev = st.get("count", 0); last_alert = st.get("last_alert_ts", 0)
    st["fails"]=0; st["auth_alerted"]=False
    rising = (count > 0 and prev <= 0) or (count > prev and count > 0)
    realert = count > 0 and (now - last_alert) >= REALERT
    log(f"count={count} prev={prev} rising={rising} realert={realert}")
    if rising or realert:
        link = os.environ.get("TARGET_LINK", "")
        reason = "new since last check" if rising else "still pending"
        subj = os.environ.get("ALERT_SUBJECT", "[update] {n} new item(s)").format(n=count)
        msg = os.environ.get("ALERT_BODY", "{n} item(s) detected.\n\n{link}\n\n({reason})").format(n=count, link=link, reason=reason)
        sent = notify(subj, msg)
        if sent: st["last_alert_ts"]=now; log(f"alert via {'+'.join(sent)}")
    st["count"]=count; st["last_poll_ts"]=now; save_state(st)

if __name__ == "__main__":
    main()
