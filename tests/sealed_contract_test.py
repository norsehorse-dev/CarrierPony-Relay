# Sealed-sender relay contract test. Walks all five /v1/sealed/* endpoints and
# checks the capability, no-oracle, anti-hijack, and flood-cap behavior.
#
# Point it at a running relay:
#   BASE=https://your-relay python3 tests/sealed_contract_test.py
# Default is http://127.0.0.1:8080 (a local php -S over a test DB). The device VM
# has no php or mysql, so validate in a throwaway server, not on real infra.
import urllib.request, urllib.error, json, hmac, hashlib, os, base64, time, sys

BASE = os.environ.get("BASE", "http://127.0.0.1:8080").rstrip("/")

def post(path, body):
    req = urllib.request.Request(BASE + path, data=json.dumps(body).encode(),
                                 headers={'content-type': 'application/json'}, method='POST')
    try:
        r = urllib.request.urlopen(req, timeout=10)
        return r.status, json.loads(r.read().decode() or '{}')
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode() or '{}')
        except Exception:
            return e.code, {}

def auth(device_key, action, device_id, ts):
    return hmac.new(device_key.encode(), f"{action}:{device_id}:{ts}".encode(), hashlib.sha256).hexdigest()

fails = 0
def check(name, cond, extra=""):
    global fails
    print(("PASS  " if cond else "FAIL  ") + name + (("  ::  " + str(extra)) if extra else ""))
    if not cond:
        fails += 1

device_id = os.urandom(16).hex()
device_key = os.urandom(32).hex()
mailbox = os.urandom(32).hex()
other_mailbox = os.urandom(32).hex()
env = base64.b64encode(b"hello sealed world").decode()

s, b = post("/v1/sealed/register-device", {"device_id": device_id, "device_key": device_key, "wake_token": ""})
check("register-device", s == 200 and b.get("ok"), f"{s} {b}")

ts = int(time.time())
s, b = post("/v1/sealed/register-mailboxes", {"device_id": device_id, "ts": ts,
            "auth": auth(device_key, "mbx", device_id, ts),
            "mailboxes": [{"mailbox": mailbox, "expires_at": ts + 3600}]})
check("register-mailboxes registered=1", s == 200 and b.get("registered") == 1, f"{s} {b}")

s, b = post("/v1/sealed/register-mailboxes", {"device_id": device_id, "ts": ts, "auth": "0" * 64,
            "mailboxes": [{"mailbox": mailbox}]})
check("register-mailboxes bad auth -> 401", s == 401, f"{s} {b}")

s, b = post("/v1/sealed/send", {"mailbox": mailbox, "envelope": env})
check("send to registered mailbox", s == 200 and b.get("ok"), f"{s} {b}")

s, b = post("/v1/sealed/send", {"mailbox": other_mailbox, "envelope": env})
check("send unregistered -> ok, no oracle", s == 200 and b.get("ok") and "throttled" not in b, f"{s} {b}")

ts = int(time.time())
s, b = post("/v1/sealed/inbox", {"device_id": device_id, "ts": ts, "auth": auth(device_key, "inbox", device_id, ts)})
msgs = b.get("messages", [])
check("inbox returns 1 msg", s == 200 and len(msgs) == 1, f"{s} count={len(msgs)}")
check("envelope round-trips", bool(msgs) and msgs[0]["envelope"] == env)
check("message on right mailbox", bool(msgs) and msgs[0]["mailbox"] == mailbox)
mid = msgs[0]["message_id"] if msgs else "0" * 32

s, b = post("/v1/sealed/inbox", {"device_id": device_id, "ts": int(time.time()), "auth": "0" * 64})
check("inbox bad auth -> 401", s == 401, f"{s}")

ts = int(time.time())
s, b = post("/v1/sealed/ack", {"device_id": device_id, "ts": ts, "auth": auth(device_key, "ack", device_id, ts),
            "message_ids": [mid]})
check("ack deletes 1", s == 200 and b.get("deleted") == 1, f"{s} {b}")

ts = int(time.time())
s, b = post("/v1/sealed/inbox", {"device_id": device_id, "ts": ts, "auth": auth(device_key, "inbox", device_id, ts)})
check("inbox empty after ack", s == 200 and len(b.get("messages", [])) == 0, f"{b}")

d2, k2 = os.urandom(16).hex(), os.urandom(32).hex()
post("/v1/sealed/register-device", {"device_id": d2, "device_key": k2})
ts = int(time.time())
s, b = post("/v1/sealed/register-mailboxes", {"device_id": d2, "ts": ts, "auth": auth(k2, "mbx", d2, ts),
            "mailboxes": [{"mailbox": mailbox, "expires_at": ts + 3600}]})
check("hijack blocked (registered=0)", b.get("registered") == 0, f"{b}")
post("/v1/sealed/send", {"mailbox": mailbox, "envelope": env})
ts = int(time.time())
s, b = post("/v1/sealed/inbox", {"device_id": d2, "ts": ts, "auth": auth(k2, "inbox", d2, ts)})
check("hijacker sees nothing", len(b.get("messages", [])) == 0, f"{b}")

flood = os.urandom(32).hex()
ts = int(time.time())
post("/v1/sealed/register-mailboxes", {"device_id": device_id, "ts": ts, "auth": auth(device_key, "mbx", device_id, ts),
     "mailboxes": [{"mailbox": flood, "expires_at": ts + 3600}]})
throttled = False
for _ in range(25):
    s, b = post("/v1/sealed/send", {"mailbox": flood, "envelope": env})
    if b.get("throttled"):
        throttled = True
check("flood cap engages", throttled)

print("\n" + ("ALL PASS" if fails == 0 else f"{fails} CHECK(S) FAILED"))
sys.exit(1 if fails else 0)
