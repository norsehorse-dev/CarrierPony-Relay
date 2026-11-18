# Relay parity test. Pins down what every endpoint answers, status code and JSON
# body alike, including every refusal, so a second implementation of the relay
# can be held to the first. The two contract tests check that the relay works;
# this one checks that two relays cannot be told apart by a client.
#
# Run it against a throwaway relay and database, never a live one. It changes
# rows directly to move time forward.
#
#   BASE=http://127.0.0.1:8080 TESTKEY=/path/to/cp-testkey \
#   MYSQL="mariadb -N -B carrierpony" REAPER="php src/reaper.php" \
#   python3 tests/parity_test.py
#
# The relay under test needs these settings, which differ from the defaults so
# the limits can be reached with small requests:
#
#   max_envelope_bytes  30000
#   inbox_bytes_budget  25000
#   pair_max_open       3
#   pair_offer_ttl      600
#   device_stale_days   30
#   push_gateway url    http://127.0.0.1:<GATEWAY_PORT>   (default port 8097)
#
# The test starts a stand-in push gateway on GATEWAY_PORT and records the wakes
# the relay sends it. MYSQL and REAPER are optional; the checks that need them
# are reported as SKIP when they are not set.
import urllib.request, urllib.error, json, os, base64, subprocess, sys, re, time, hmac, hashlib, threading, shlex
from http.server import BaseHTTPRequestHandler, HTTPServer

BASE = os.environ.get("BASE", "http://127.0.0.1:8080").rstrip("/")
TESTKEY = os.environ.get("TESTKEY", "cp-testkey")
MYSQL = os.environ.get("MYSQL", "")
REAPER = os.environ.get("REAPER", "")
GATEWAY_PORT = int(os.environ.get("GATEWAY_PORT", "8097"))
MAX_ENVELOPE = 30000
MAX_TTL = 30 * 86400

fails = 0
skips = 0

def check(name, cond, extra=""):
    global fails
    print(("PASS  " if cond else "FAIL  ") + name + (("  ::  " + str(extra)[:300]) if (extra != "" and not cond) else ""))
    if not cond:
        fails += 1

def skip(name):
    global skips
    skips += 1
    print("SKIP  " + name)

def raw(path, data=None, method="POST", ctype="application/json"):
    req = urllib.request.Request(BASE + path, data=data, headers={"content-type": ctype}, method=method)
    try:
        r = urllib.request.urlopen(req, timeout=20)
        return r.status, r.headers.get("content-type", ""), r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.headers.get("content-type", ""), e.read().decode()

def post(path, body):
    s, _, text = raw(path, json.dumps(body).encode())
    try:
        return s, json.loads(text or "{}")
    except Exception:
        return s, {"_unparsed": text[:200]}

def is_err(res, status, error):
    return res[0] == status and res[1] == {"error": error}

def sql(q):
    out = subprocess.run(shlex.split(MYSQL) + ["-e", q], capture_output=True, text=True, check=True).stdout
    return [line.split("\t") for line in out.splitlines()]

def one(q):
    rows = sql(q)
    return rows[0][0] if rows else None

# ---- stand-in push gateway ------------------------------------------------

wakes = []

class Gateway(BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("content-length", "0") or 0))
        try:
            wakes.append((self.path, json.loads(body.decode())))
        except Exception:
            wakes.append((self.path, None))
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"ok":true}')

    def log_message(self, *a):
        pass

gateway = HTTPServer(("127.0.0.1", GATEWAY_PORT), Gateway)
threading.Thread(target=gateway.serve_forever, daemon=True).start()

def wakes_since(mark):
    time.sleep(0.2)
    return wakes[mark:]

# ---- identities -----------------------------------------------------------

class Identity:
    def __init__(self, kind):
        k = json.loads(subprocess.run([TESTKEY, "gen", kind], capture_output=True, text=True, check=True).stdout)
        self.kind, self.fpr, self.pubkey, self.secret = kind, k["fpr"], k["pubkey"], k["secret"]
        self.device_id = os.urandom(16).hex()

    def sign(self, data):
        out = subprocess.run([TESTKEY, "sign"], input=json.dumps({"secret": self.secret, "data": data}),
                             capture_output=True, text=True, check=True).stdout
        return json.loads(out)["sig"]

    def auth(self):
        s, b = post("/v1/challenge", {"fpr": self.fpr})
        return {"fpr": self.fpr, "nonce": b["nonce"], "sig": self.sign(b["nonce"])}

    def call(self, path, extra=None, drop=()):
        body = self.auth()
        body.update(extra or {})
        for k in drop:
            body.pop(k, None)
        return post(path, body)

    def register(self, device_id=None, label="test"):
        return self.call("/v1/register-device",
                         {"pubkey": self.pubkey, "device_id": device_id or self.device_id, "label": label})

def b64(n, fill=b"x"):
    return base64.b64encode(fill * n).decode()

HEX32 = re.compile(r"^[0-9a-f]{32}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
STAMP = re.compile(r"^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d$")

# ---- routing and request parsing -------------------------------------------

s, ct, text = raw("/v1/nope", b"{}")
check("unknown path is 404 not_found", s == 404 and json.loads(text) == {"error": "not_found"}, (s, text))
check("errors are sent as application/json", ct.split(";")[0].strip() == "application/json", ct)
s, ct, text = raw("/v1/challenge", None, method="GET")
check("GET on an endpoint is 404 not_found", s == 404 and json.loads(text) == {"error": "not_found"}, (s, text))
s, ct, text = raw("/", b"{}")
check("the root path is 404 not_found", s == 404 and json.loads(text) == {"error": "not_found"}, (s, text))
s, ct, text = raw("/v1/challenge/", json.dumps({"fpr": "A" * 40}).encode())
check("a trailing slash is accepted", s == 200 and "nonce" in json.loads(text), (s, text))
check("answers are sent as application/json", ct.split(";")[0].strip() == "application/json", ct)
s, ct, text = raw("/v1/challenge", json.dumps({"fpr": "A" * 40}).encode(), ctype="text/plain")
check("the request content type does not matter", s == 200, (s, text))

for label, data in [("an empty body", b""), ("a body that is not JSON", b"not json"),
                    ("a JSON string", b'"hello"'), ("a JSON list", b"[1,2]"),
                    ("a null field", b'{"fpr":null}'), ("an empty field", b'{"fpr":""}')]:
    s, ct, text = raw("/v1/challenge", data)
    check("challenge with %s is 400 missing:fpr" % label, s == 400 and json.loads(text) == {"error": "missing:fpr"}, (s, text))

# ---- challenge -------------------------------------------------------------

for bad in ["A" * 39, "A" * 41, "A" * 63, "A" * 65, "G" * 40, "A" * 39 + " "]:
    check("challenge refuses %r" % bad[-3:] + " (%d)" % len(bad), is_err(post("/v1/challenge", {"fpr": bad}), 400, "bad_fpr"))
s, b = post("/v1/challenge", {"fpr": "ab" * 20})
check("challenge answers exactly a 64-hex nonce", s == 200 and list(b) == ["nonce"] and HEX64.match(b["nonce"]) is not None, (s, b))
s, b2 = post("/v1/challenge", {"fpr": "ab" * 20})
check("each challenge is a new nonce", b2.get("nonce") != b.get("nonce"))

# ---- login refusals, in the order the relay checks them ---------------------

a, bob = Identity("v4"), Identity("v6")
stranger = Identity("v4")

for path in ["/v1/send", "/v1/inbox", "/v1/ack", "/v1/register-push", "/v1/register-wake", "/v1/report",
             "/v1/pair/offer", "/v1/pair/accept", "/v1/pair/status"]:
    check(path + " without a login is 400 missing:fpr", is_err(post(path, {}), 400, "missing:fpr"))
check("login without a nonce is 400 missing:nonce", is_err(post("/v1/inbox", {"fpr": a.fpr}), 400, "missing:nonce"))
check("login without a signature is 400 missing:sig", is_err(post("/v1/inbox", {"fpr": a.fpr, "nonce": "x"}), 400, "missing:sig"))
check("login with a malformed fingerprint is 400 bad_fpr",
      is_err(post("/v1/inbox", {"fpr": "nothex", "nonce": "x", "sig": "y"}), 400, "bad_fpr"))
check("login with an unknown nonce is 401 bad_challenge",
      is_err(post("/v1/inbox", {"fpr": a.fpr, "nonce": "0" * 64, "sig": "y"}), 401, "bad_challenge"))
check("login before registering is 401 bad_signature", is_err(a.call("/v1/inbox", {"device_id": a.device_id}), 401, "bad_signature"))
body = a.auth(); body["sig"] = "not a signature"
check("login with a broken signature is 401 bad_signature", is_err(post("/v1/inbox", body), 401, "bad_signature"))

# ---- register-device -------------------------------------------------------

order = ["fpr", "pubkey", "device_id", "nonce", "sig"]
full = {"fpr": a.fpr, "pubkey": a.pubkey, "device_id": a.device_id, "nonce": "0" * 64, "sig": "x"}
for k in order:
    body = {x: full[x] for x in order if x != k}
    check("register-device without %s is 400 missing:%s" % (k, k), is_err(post("/v1/register-device", body), 400, "missing:" + k))
check("the first missing field is the one reported", is_err(post("/v1/register-device", {"fpr": a.fpr, "sig": "x"}), 400, "missing:pubkey"))
check("register-device refuses a malformed fingerprint", is_err(post("/v1/register-device", dict(full, fpr="xyz")), 400, "bad_fpr"))
check("register-device refuses a malformed device id", is_err(post("/v1/register-device", dict(full, device_id="ABC")), 400, "bad_device_id"))
check("register-device refuses an uppercase device id", is_err(post("/v1/register-device", dict(full, device_id="A" * 32)), 400, "bad_device_id"))
check("register-device refuses a key over 100000 characters",
      is_err(post("/v1/register-device", dict(full, pubkey="k" * 100001)), 400, "bad_pubkey"))
check("register-device with an unknown nonce is 401 bad_challenge", is_err(post("/v1/register-device", full), 401, "bad_challenge"))
body = a.auth(); body.update({"pubkey": stranger.pubkey, "device_id": a.device_id})
check("register-device with someone else's key is 401 bad_signature", is_err(post("/v1/register-device", body), 401, "bad_signature"))

res = a.register(label="L" * 80)
check("register-device answers exactly ok", res == (200, {"ok": True}), res)
check("register-device again answers ok", a.register(label="second") == (200, {"ok": True}))
check("register-device without a label answers ok",
      a.call("/v1/register-device", {"pubkey": a.pubkey, "device_id": a.device_id}) == (200, {"ok": True}))
check("the second identity registers", bob.register() == (200, {"ok": True}))
bob_dev2 = os.urandom(16).hex()
check("a second device registers under the same identity", bob.register(device_id=bob_dev2) == (200, {"ok": True}))
if MYSQL:
    a.register(label="L" * 80)
    check("a label is cut to 64 characters", one("SELECT CHAR_LENGTH(label) FROM devices WHERE device_id='%s'" % a.device_id) == "64")
    check("registering twice keeps one device row", one("SELECT COUNT(*) FROM devices WHERE fpr='%s'" % a.fpr) == "1")
    check("the fingerprint is stored in uppercase", one("SELECT BINARY fpr = BINARY UPPER(fpr) FROM identities WHERE fpr='%s'" % a.fpr) == "1")
else:
    skip("stored label, device and fingerprint (needs MYSQL)")

check("login from an identity that never registered is 401 bad_signature",
      is_err(stranger.call("/v1/inbox", {"device_id": stranger.device_id}), 401, "bad_signature"))
body = a.auth(); first = post("/v1/inbox", dict(body, device_id=a.device_id))
check("a nonce works once", first[0] == 200 and is_err(post("/v1/inbox", dict(body, device_id=a.device_id)), 401, "bad_challenge"), first)
body = a.auth(); body["fpr"] = a.fpr.lower()
check("login accepts a lowercase fingerprint", post("/v1/inbox", dict(body, device_id=a.device_id))[0] == 200)

# ---- send ------------------------------------------------------------------

env = b64(11)
check("send without a recipient is 400 missing:to_fpr", is_err(a.call("/v1/send", {"envelope": env}), 400, "missing:to_fpr"))
check("send without an envelope is 400 missing:envelope", is_err(a.call("/v1/send", {"to_fpr": bob.fpr}), 400, "missing:envelope"))
check("send to a malformed fingerprint is 400 bad_to_fpr", is_err(a.call("/v1/send", {"to_fpr": "A" * 41, "envelope": env}), 400, "bad_to_fpr"))
for label, bad in [("not base64", "!!!!"), ("the wrong length", "abc"), ("padding in the middle", "ab=cdefg"), ("url-safe base64", "ab-_")]:
    check("send refuses an envelope that is " + label, is_err(a.call("/v1/send", {"to_fpr": bob.fpr, "envelope": bad}), 400, "bad_envelope"))
check("send refuses an envelope one byte over the limit",
      is_err(a.call("/v1/send", {"to_fpr": bob.fpr, "envelope": b64(MAX_ENVELOPE + 1)}), 413, "too_large"))
s, ct, text = raw("/v1/send", b'{"pad":"' + b"x" * (MAX_ENVELOPE * 4 // 3 + 70000) + b'"}')
check("an oversized body is 413 before the login is looked at", s == 413 and json.loads(text) == {"error": "too_large"}, (s, text[:80]))
check("send to an unregistered fingerprint is 404 unknown_recipient",
      is_err(a.call("/v1/send", {"to_fpr": stranger.fpr, "envelope": env}), 404, "unknown_recipient"))
check("send from an unregistered identity is 401", is_err(stranger.call("/v1/send", {"to_fpr": bob.fpr, "envelope": env}), 401, "bad_signature"))

now = int(time.time())
s, b = a.call("/v1/send", {"to_fpr": bob.fpr, "envelope": b64(MAX_ENVELOPE)})
check("send at exactly the limit is stored", s == 200, (s, b))
check("send answers exactly message_id and expires_at", s == 200 and sorted(b) == ["expires_at", "message_id"]
      and HEX32.match(b["message_id"]) is not None and isinstance(b["expires_at"], int), (s, b))
check("with no expiry the message lives the maximum time", abs(b.get("expires_at", 0) - (now + MAX_TTL)) <= 5, b)
m_big = b.get("message_id")
want = int(time.time()) + 3600
s, b = a.call("/v1/send", {"to_fpr": bob.fpr.lower(), "envelope": env, "expires_at": want})
check("a valid expiry is kept as sent", s == 200 and b.get("expires_at") == want, (s, b))
m_small = b.get("message_id")
s, b = a.call("/v1/send", {"to_fpr": bob.fpr, "envelope": env, "expires_at": int(time.time()) - 10, "silent": True})
check("an expiry in the past becomes the maximum", s == 200 and abs(b.get("expires_at", 0) - (int(time.time()) + MAX_TTL)) <= 5, (s, b))
m_silent = b.get("message_id")
s, b = a.call("/v1/send", {"to_fpr": bob.fpr, "envelope": env, "expires_at": int(time.time()) + MAX_TTL + 1000})
check("an expiry beyond the maximum becomes the maximum", s == 200 and abs(b.get("expires_at", 0) - (int(time.time()) + MAX_TTL)) <= 5, (s, b))
m_far = b.get("message_id")

# ---- inbox -----------------------------------------------------------------

check("inbox without a device is 400 missing:device_id", is_err(bob.call("/v1/inbox"), 400, "missing:device_id"))
check("inbox with a malformed device is 400 bad_device_id", is_err(bob.call("/v1/inbox", {"device_id": "zz"}), 400, "bad_device_id"))
check("inbox for a device that is not registered is 403 unknown_device",
      is_err(bob.call("/v1/inbox", {"device_id": os.urandom(16).hex()}), 403, "unknown_device"))
check("inbox for another identity's device is 403 unknown_device",
      is_err(bob.call("/v1/inbox", {"device_id": a.device_id}), 403, "unknown_device"))

s, b = bob.call("/v1/inbox", {"device_id": bob.device_id})
got = b.get("messages", [])
check("inbox answers exactly a messages list", s == 200 and list(b) == ["messages"], (s, list(b)))
check("a message over the byte budget goes out alone", [m["message_id"] for m in got] == [m_big], [m["message_id"] for m in got])
if got:
    m = got[0]
    check("a message has exactly five fields",
          sorted(m) == ["alert", "envelope", "expires_at", "message_id", "received_at"], sorted(m))
    check("alert is a JSON number", m["alert"] == 1 and isinstance(m["alert"], int), m["alert"])
    check("received_at and expires_at are UTC 'YYYY-MM-DD HH:MM:SS'",
          STAMP.match(str(m["received_at"])) is not None and STAMP.match(str(m["expires_at"])) is not None, (m["received_at"], m["expires_at"]))
    check("the envelope comes back unchanged", m["envelope"] == b64(MAX_ENVELOPE))
check("polling again returns the same message until it is acked",
      [m["message_id"] for m in bob.call("/v1/inbox", {"device_id": bob.device_id})[1].get("messages", [])] == [m_big])

# ---- ack -------------------------------------------------------------------

check("ack without ids is 400 missing:message_ids", is_err(bob.call("/v1/ack", {"device_id": bob.device_id}), 400, "missing:message_ids"))
check("ack with ids that are not a list is 400 bad_message_ids",
      is_err(bob.call("/v1/ack", {"device_id": bob.device_id, "message_ids": "abc"}), 400, "bad_message_ids"))
check("ack with a malformed device is 400 bad_device_id",
      is_err(bob.call("/v1/ack", {"device_id": "zz", "message_ids": [m_big]}), 400, "bad_device_id"))
check("ack for a device that is not registered is 403 unknown_device",
      is_err(bob.call("/v1/ack", {"device_id": os.urandom(16).hex(), "message_ids": [m_big]}), 403, "unknown_device"))
check("ack with an empty list answers acked 0", bob.call("/v1/ack", {"device_id": bob.device_id, "message_ids": []}) == (200, {"acked": 0}))
check("ack skips ids that are malformed or unknown",
      bob.call("/v1/ack", {"device_id": bob.device_id, "message_ids": ["zz", 7, None, "0" * 32]}) == (200, {"acked": 0}))
check("the sender cannot ack the recipient's message",
      a.call("/v1/ack", {"device_id": a.device_id, "message_ids": [m_big]}) == (200, {"acked": 0}))
check("ack answers the number acked", bob.call("/v1/ack", {"device_id": bob.device_id, "message_ids": [m_big, m_big]}) == (200, {"acked": 1}))
check("acking again answers 0", bob.call("/v1/ack", {"device_id": bob.device_id, "message_ids": [m_big]}) == (200, {"acked": 0}))

s, b = bob.call("/v1/inbox", {"device_id": bob.device_id})
got = b.get("messages", [])
check("the rest arrive oldest first", [m["message_id"] for m in got] == [m_small, m_silent, m_far], [m["message_id"] for m in got])
check("alert follows silent", [m["alert"] for m in got] == [1, 0, 1], [m["alert"] for m in got])
s, b = bob.call("/v1/inbox", {"device_id": bob_dev2})
check("the second device has its own copy of every message",
      [m["message_id"] for m in b.get("messages", [])] == [m_big], [m["message_id"] for m in b.get("messages", [])])
if MYSQL:
    check("a message stays stored until every device has acked it", one("SELECT COUNT(*) FROM messages WHERE message_id='%s'" % m_big) == "1")
    bob.call("/v1/ack", {"device_id": bob_dev2, "message_ids": [m_big]})
    check("and is deleted once they all have", one("SELECT COUNT(*) FROM messages WHERE message_id='%s'" % m_big) == "0")
    sql("UPDATE messages SET expires_at = DATE_SUB(UTC_TIMESTAMP(), INTERVAL 1 SECOND) WHERE message_id='%s'" % m_small)
    s, b = bob.call("/v1/inbox", {"device_id": bob.device_id})
    check("an expired message is not returned", m_small not in [m["message_id"] for m in b.get("messages", [])])
    bob.call("/v1/ack", {"device_id": bob.device_id, "message_ids": []})
    check("any ack clears expired messages", one("SELECT COUNT(*) FROM messages WHERE message_id='%s'" % m_small) == "0")
    body = bob.auth()
    sql("UPDATE challenges SET expires_at = DATE_SUB(UTC_TIMESTAMP(), INTERVAL 1 SECOND) WHERE nonce='%s'" % body["nonce"])
    check("an expired nonce is 401 bad_challenge", is_err(post("/v1/inbox", dict(body, device_id=bob.device_id)), 401, "bad_challenge"))
    sql("UPDATE devices SET last_seen = DATE_SUB(UTC_TIMESTAMP(), INTERVAL 1 DAY) WHERE device_id='%s'" % bob.device_id)
    bob.call("/v1/inbox", {"device_id": bob.device_id})
    age = int(one("SELECT TIMESTAMPDIFF(SECOND, last_seen, UTC_TIMESTAMP()) FROM devices WHERE device_id='%s'" % bob.device_id))
    check("inbox updates the device's last_seen", 0 <= age < 30, age)
else:
    skip("message deletion, expiry and nonce expiry (needs MYSQL)")
for dev in (bob.device_id, bob_dev2):
    ids = [m["message_id"] for m in bob.call("/v1/inbox", {"device_id": dev})[1].get("messages", [])]
    bob.call("/v1/ack", {"device_id": dev, "message_ids": ids})

sizes = [9000, 9000, 9000, 9000]
ids = [a.call("/v1/send", {"to_fpr": bob.fpr, "envelope": b64(n)})[1].get("message_id") for n in sizes]
got = [m["message_id"] for m in bob.call("/v1/inbox", {"device_id": bob.device_id})[1].get("messages", [])]
check("a poll stops at the byte budget", got == ids[:2], (got, ids))
bob.call("/v1/ack", {"device_id": bob.device_id, "message_ids": got})
got = [m["message_id"] for m in bob.call("/v1/inbox", {"device_id": bob.device_id})[1].get("messages", [])]
check("the next poll brings the rest", got == ids[2:], (got, ids))
bob.call("/v1/ack", {"device_id": bob.device_id, "message_ids": ids})
bob.call("/v1/ack", {"device_id": bob_dev2, "message_ids": ids})

# ---- register-push ---------------------------------------------------------

check("register-push without a device is 400 missing:device_id", is_err(a.call("/v1/register-push", {"push_token": "t"}), 400, "missing:device_id"))
check("register-push without a token is 400 missing:push_token", is_err(a.call("/v1/register-push", {"device_id": a.device_id}), 400, "missing:push_token"))
check("register-push with a malformed device is 400 bad_device_id",
      is_err(a.call("/v1/register-push", {"device_id": "zz", "push_token": "t"}), 400, "bad_device_id"))
check("register-push with an unknown platform is 400 bad_platform",
      is_err(a.call("/v1/register-push", {"device_id": a.device_id, "push_token": "t", "platform": "wns"}), 400, "bad_platform"))
check("register-push for a device that is not registered is 403 unknown_device",
      is_err(a.call("/v1/register-push", {"device_id": os.urandom(16).hex(), "push_token": "t"}), 403, "unknown_device"))
check("register-push answers exactly ok", a.call("/v1/register-push", {"device_id": a.device_id, "push_token": "T" * 300}) == (200, {"ok": True}))
if MYSQL:
    row = sql("SELECT CHAR_LENGTH(push_token), platform FROM devices WHERE device_id='%s'" % a.device_id)[0]
    check("the token is cut to 255 characters and the platform defaults to apns", row == ["255", "apns"], row)
check("register-push with the same values again answers ok",
      a.call("/v1/register-push", {"device_id": a.device_id, "push_token": "T" * 300}) == (200, {"ok": True}))
check("register-push accepts FCM in any case",
      a.call("/v1/register-push", {"device_id": a.device_id, "push_token": "tok", "platform": "FCM"}) == (200, {"ok": True}))
if MYSQL:
    check("the platform is stored in lowercase", one("SELECT platform FROM devices WHERE device_id='%s'" % a.device_id) == "fcm")
    sql("UPDATE devices SET push_token = NULL WHERE device_id='%s'" % a.device_id)
else:
    skip("stored push token and platform (needs MYSQL)")

# ---- register-wake and the gateway -----------------------------------------

check("register-wake without a device is 400 missing:device_id", is_err(bob.call("/v1/register-wake", {}), 400, "missing:device_id"))
check("register-wake with a malformed device is 400 bad_device_id", is_err(bob.call("/v1/register-wake", {"device_id": "zz"}), 400, "bad_device_id"))
check("register-wake with a malformed token is 400 bad_wake_token",
      is_err(bob.call("/v1/register-wake", {"device_id": bob.device_id, "wake_token": "A" * 64}), 400, "bad_wake_token"))
check("register-wake for a device that is not registered is 403 unknown_device",
      is_err(bob.call("/v1/register-wake", {"device_id": os.urandom(16).hex(), "wake_token": "a" * 64}), 403, "unknown_device"))
tok = os.urandom(32).hex()
check("register-wake answers exactly ok", bob.call("/v1/register-wake", {"device_id": bob.device_id, "wake_token": tok}) == (200, {"ok": True}))

mark = len(wakes)
a.call("/v1/send", {"to_fpr": bob.fpr, "envelope": env})
check("a send wakes the opted-in device through the gateway, and only it",
      wakes_since(mark) == [("/v1/wake", {"wake_token": tok, "silent": False})], wakes_since(mark))
mark = len(wakes)
a.call("/v1/send", {"to_fpr": bob.fpr, "envelope": env, "silent": True})
check("a silent send is passed on as silent", wakes_since(mark) == [("/v1/wake", {"wake_token": tok, "silent": True})], wakes_since(mark))
mark = len(wakes)
a.call("/v1/send", {"to_fpr": bob.fpr, "envelope": env, "kind": "request"})
check("a contact request reaches the gateway as an ordinary wake",
      wakes_since(mark) == [("/v1/wake", {"wake_token": tok, "silent": False})], wakes_since(mark))
check("register-wake with an empty token clears it", bob.call("/v1/register-wake", {"device_id": bob.device_id, "wake_token": ""}) == (200, {"ok": True}))
check("register-wake with no token clears it too", bob.call("/v1/register-wake", {"device_id": bob.device_id}) == (200, {"ok": True}))
mark = len(wakes)
a.call("/v1/send", {"to_fpr": bob.fpr, "envelope": env})
check("no wake once the token is cleared", wakes_since(mark) == [], wakes_since(mark))
for dev in (bob.device_id, bob_dev2):
    ids = [m["message_id"] for m in bob.call("/v1/inbox", {"device_id": dev})[1].get("messages", [])]
    bob.call("/v1/ack", {"device_id": dev, "message_ids": ids})

# ---- report ----------------------------------------------------------------

check("report without a fingerprint is 400 missing:reported_fpr", is_err(a.call("/v1/report", {"category": "spam"}), 400, "missing:reported_fpr"))
check("report without a category is 400 missing:category", is_err(a.call("/v1/report", {"reported_fpr": bob.fpr}), 400, "missing:category"))
check("report with a malformed fingerprint is 400 bad_reported_fpr",
      is_err(a.call("/v1/report", {"reported_fpr": "zz", "category": "spam"}), 400, "bad_reported_fpr"))
check("report with an unknown category is 400 bad_category",
      is_err(a.call("/v1/report", {"reported_fpr": bob.fpr, "category": "boring"}), 400, "bad_category"))
for cat in ["spam", "harassment", "illegal", "csam", "other", "SPAM"]:
    check("report accepts the category " + cat, a.call("/v1/report", {"reported_fpr": bob.fpr.lower(), "category": cat}) == (200, {"ok": True}))
unseen = os.urandom(32).hex().upper()
res = a.call("/v1/report", {"reported_fpr": unseen, "category": "other", "description": "d" * 5000,
                            "content": "c" * 21000, "attachment_meta": "m" * 5000})
check("report about a fingerprint the relay has never seen answers ok", res == (200, {"ok": True}), res)
if MYSQL:
    row = sql("SELECT reporter_fpr, category, CHAR_LENGTH(description), CHAR_LENGTH(content), CHAR_LENGTH(attachment_meta), status "
              "FROM reports WHERE reported_fpr='%s'" % unseen)[0]
    check("a report is stored trimmed to 4000, 20000 and 4000 characters, status open",
          row == [a.fpr, "other", "4000", "20000", "4000", "open"], row)
    check("the reported fingerprint is stored in uppercase and the category in lowercase",
          one("SELECT COUNT(*) FROM reports WHERE BINARY reported_fpr='%s' AND BINARY category='spam' AND reporter_fpr='%s'" % (bob.fpr, a.fpr)) == "2")
else:
    skip("stored report (needs MYSQL)")

# ---- pairing ---------------------------------------------------------------

check("pair offer without a key is 400 missing:pubkey", is_err(a.call("/v1/pair/offer"), 400, "missing:pubkey"))
check("pair offer with a key over 100000 characters is 400 bad_pubkey", is_err(a.call("/v1/pair/offer", {"pubkey": "k" * 100001}), 400, "bad_pubkey"))
s, b = a.call("/v1/pair/offer", {"pubkey": a.pubkey})
check("pair offer answers exactly token and expires_in", s == 200 and sorted(b) == ["expires_in", "token"]
      and HEX32.match(b["token"]) is not None and b["expires_in"] == 600, (s, b))
token = b.get("token")

check("pair status without a token is 400 missing:token", is_err(a.call("/v1/pair/status"), 400, "missing:token"))
check("pair status with a malformed token is 400 bad_token", is_err(a.call("/v1/pair/status", {"token": "zz"}), 400, "bad_token"))
check("pair status for an unknown token is 404 no_such_offer", is_err(a.call("/v1/pair/status", {"token": "0" * 32}), 404, "no_such_offer"))
check("pair status for someone else's offer is 403 not_your_offer", is_err(bob.call("/v1/pair/status", {"token": token}), 403, "not_your_offer"))
check("pair status of an open offer answers exactly state open", a.call("/v1/pair/status", {"token": token}) == (200, {"state": "open"}))

check("pair accept without a token is 400 missing:token", is_err(bob.call("/v1/pair/accept", {"pubkey": bob.pubkey}), 400, "missing:token"))
check("pair accept without a key is 400 missing:pubkey", is_err(bob.call("/v1/pair/accept", {"token": token}), 400, "missing:pubkey"))
check("pair accept with a malformed token is 400 bad_token", is_err(bob.call("/v1/pair/accept", {"token": "ZZ", "pubkey": bob.pubkey}), 400, "bad_token"))
check("pair accept with a key over 100000 characters is 400 bad_pubkey",
      is_err(bob.call("/v1/pair/accept", {"token": token, "pubkey": "k" * 100001}), 400, "bad_pubkey"))
check("pair accept for an unknown token is 404 no_such_offer",
      is_err(bob.call("/v1/pair/accept", {"token": "0" * 32, "pubkey": bob.pubkey}), 404, "no_such_offer"))
res = bob.call("/v1/pair/accept", {"token": token, "pubkey": bob.pubkey})
check("pair accept answers exactly the offerer's fingerprint and key",
      res == (200, {"offerer_fpr": a.fpr, "offerer_pubkey": a.pubkey}), res)
check("pair accept a second time is 410 offer_closed", is_err(bob.call("/v1/pair/accept", {"token": token, "pubkey": bob.pubkey}), 410, "offer_closed"))
res = a.call("/v1/pair/status", {"token": token})
check("pair status of an accepted offer answers the responder",
      res == (200, {"state": "accepted", "responder_fpr": bob.fpr, "responder_pubkey": bob.pubkey}), res)

tokens = [a.call("/v1/pair/offer", {"pubkey": a.pubkey})[1].get("token") for _ in range(3)]
check("three open offers are allowed", all(t and HEX32.match(t) for t in tokens), tokens)
check("a fourth open offer is 429 too_many_offers", is_err(a.call("/v1/pair/offer", {"pubkey": a.pubkey}), 429, "too_many_offers"))
check("an identity may accept its own offer", a.call("/v1/pair/accept", {"token": tokens[0], "pubkey": a.pubkey})[0] == 200)
check("an accepted offer no longer counts against the limit", a.call("/v1/pair/offer", {"pubkey": a.pubkey})[0] == 200)
if MYSQL:
    sql("UPDATE pairing_offers SET expires_at = DATE_SUB(UTC_TIMESTAMP(), INTERVAL 1 SECOND) WHERE token='%s'" % tokens[1])
    check("pair status of an open offer past its time answers state expired", a.call("/v1/pair/status", {"token": tokens[1]}) == (200, {"state": "expired"}))
    check("pair accept of an offer past its time is 410 offer_closed",
          is_err(bob.call("/v1/pair/accept", {"token": tokens[1], "pubkey": bob.pubkey}), 410, "offer_closed"))
    check("an expired offer no longer counts against the limit", a.call("/v1/pair/offer", {"pubkey": a.pubkey})[0] == 200)
    sql("UPDATE pairing_offers SET expires_at = DATE_SUB(UTC_TIMESTAMP(), INTERVAL 1 SECOND) WHERE token='%s'" % token)
    check("an accepted offer past its time is still collectable", a.call("/v1/pair/status", {"token": token})[1].get("state") == "accepted")
else:
    skip("expired pairing offers (needs MYSQL)")

# ---- sealed path -----------------------------------------------------------

def mac(key, action, dev, ts):
    return hmac.new(key.encode(), ("%s:%s:%s" % (action, dev, ts)).encode(), hashlib.sha256).hexdigest()

class Sealed:
    def __init__(self):
        self.dev, self.key = os.urandom(16).hex(), os.urandom(32).hex()

    def signed(self, action, extra=None, ts=None, auth=None):
        ts = int(time.time()) if ts is None else ts
        body = {"device_id": self.dev, "ts": ts, "auth": auth or mac(self.key, action, self.dev, ts)}
        body.update(extra or {})
        return body

P = "/v1/sealed/"
x, y = Sealed(), Sealed()
check("sealed register-device without a device is 400 missing:device_id", is_err(post(P + "register-device", {"device_key": x.key}), 400, "missing:device_id"))
check("sealed register-device without a key is 400 missing:device_key", is_err(post(P + "register-device", {"device_id": x.dev}), 400, "missing:device_key"))
check("sealed register-device with a malformed device is 400 bad_device_id",
      is_err(post(P + "register-device", {"device_id": "zz", "device_key": x.key}), 400, "bad_device_id"))
check("sealed register-device with a malformed key is 400 bad_device_key",
      is_err(post(P + "register-device", {"device_id": x.dev, "device_key": "K" * 64}), 400, "bad_device_key"))
check("sealed register-device answers exactly ok", post(P + "register-device", {"device_id": x.dev, "device_key": x.key}) == (200, {"ok": True}))
check("sealed register-device with a different key and no proof is 401 bad_auth",
      is_err(post(P + "register-device", {"device_id": x.dev, "device_key": os.urandom(32).hex()}), 401, "bad_auth"))
check("sealed register-device again with the same key and no proof is 401 bad_auth",
      is_err(post(P + "register-device", {"device_id": x.dev, "device_key": x.key}), 401, "bad_auth"))
xtok = os.urandom(32).hex()
check("sealed register-device with proof updates the wake token",
      post(P + "register-device", x.signed("register", {"device_key": x.key, "wake_token": xtok})) == (200, {"ok": True}))
check("the proof is tied to the action", is_err(post(P + "register-device", x.signed("inbox", {"device_key": x.key})), 401, "bad_auth"))
post(P + "register-device", {"device_id": y.dev, "device_key": y.key})

box = [os.urandom(32).hex() for _ in range(4)]
for k in ["device_id", "ts", "auth", "mailboxes"]:
    body = x.signed("mbx", {"mailboxes": box}); del body[k]
    check("sealed register-mailboxes without %s is 400 missing:%s" % (k, k), is_err(post(P + "register-mailboxes", body), 400, "missing:" + k))
ghost = Sealed()
check("sealed register-mailboxes for an unknown device is 404 unknown_device",
      is_err(post(P + "register-mailboxes", ghost.signed("mbx", {"mailboxes": box})), 404, "unknown_device"))
check("sealed register-mailboxes with a malformed device is 404 unknown_device",
      is_err(post(P + "register-mailboxes", dict(x.signed("mbx", {"mailboxes": box}), device_id="zz")), 404, "unknown_device"))
check("a wrong proof is 401 bad_auth", is_err(post(P + "register-mailboxes", x.signed("mbx", {"mailboxes": box}, auth="0" * 64)), 401, "bad_auth"))
check("a proof that is not 64 hex characters is 401 bad_auth", is_err(post(P + "register-mailboxes", x.signed("mbx", {"mailboxes": box}, auth="zz")), 401, "bad_auth"))
check("a proof 301 seconds old is 401 bad_auth",
      is_err(post(P + "register-mailboxes", x.signed("mbx", {"mailboxes": box}, ts=int(time.time()) - 301)), 401, "bad_auth"))
check("a proof 301 seconds ahead is 401 bad_auth",
      is_err(post(P + "register-mailboxes", x.signed("mbx", {"mailboxes": box}, ts=int(time.time()) + 301)), 401, "bad_auth"))
check("a proof 200 seconds old is accepted",
      post(P + "register-mailboxes", x.signed("mbx", {"mailboxes": box[:1]}, ts=int(time.time()) - 200))[0] == 200)
ts = int(time.time())
check("a proof in uppercase is 401 bad_auth",
      is_err(post(P + "register-mailboxes", x.signed("mbx", {"mailboxes": box[:1]}, ts=ts, auth=mac(x.key, "mbx", x.dev, ts).upper())), 401, "bad_auth"))
check("the timestamp may be sent as a string",
      post(P + "register-mailboxes", dict(x.signed("mbx", {"mailboxes": box[:1]}, ts=ts), ts=str(ts)))[0] == 200)
check("an empty mailbox list is 400 no_mailboxes", is_err(post(P + "register-mailboxes", x.signed("mbx", {"mailboxes": []})), 400, "no_mailboxes"))
check("a mailbox list that is not a list is 400 no_mailboxes", is_err(post(P + "register-mailboxes", x.signed("mbx", {"mailboxes": "abc"})), 400, "no_mailboxes"))
check("513 mailboxes is 400 too_many",
      is_err(post(P + "register-mailboxes", x.signed("mbx", {"mailboxes": [os.urandom(32).hex() for _ in range(513)]})), 400, "too_many"))
check("a list with nothing valid in it answers registered 0",
      post(P + "register-mailboxes", x.signed("mbx", {"mailboxes": ["zz", 5, {"mailbox": "A" * 64}]})) == (200, {"ok": True, "registered": 0}))
res = post(P + "register-mailboxes", x.signed("mbx", {"mailboxes": [box[0], {"mailbox": box[1]},
           {"mailbox": box[2], "expires_at": int(time.time()) + 3600}, box[0], "junk"]}))
check("mailboxes register as strings or objects, duplicates counted once", res == (200, {"ok": True, "registered": 3}), res)
check("registering the same mailboxes again answers the same count",
      post(P + "register-mailboxes", x.signed("mbx", {"mailboxes": box[:3]})) == (200, {"ok": True, "registered": 3}))
check("512 mailboxes in one call are accepted",
      post(P + "register-mailboxes", y.signed("mbx", {"mailboxes": [os.urandom(32).hex() for _ in range(512)]})) == (200, {"ok": True, "registered": 512}))
check("another device cannot claim a mailbox that is taken",
      post(P + "register-mailboxes", y.signed("mbx", {"mailboxes": [box[0], box[3]]})) == (200, {"ok": True, "registered": 1}))

check("sealed send without a mailbox is 400 missing:mailbox", is_err(post(P + "send", {"envelope": env}), 400, "missing:mailbox"))
check("sealed send without an envelope is 400 missing:envelope", is_err(post(P + "send", {"mailbox": box[0]}), 400, "missing:envelope"))
check("sealed send to a malformed mailbox is 400 bad_mailbox", is_err(post(P + "send", {"mailbox": "A" * 64, "envelope": env}), 400, "bad_mailbox"))
check("sealed send refuses an envelope that is not base64", is_err(post(P + "send", {"mailbox": box[0], "envelope": "!!!!"}), 400, "bad_envelope"))
check("sealed send refuses an envelope over the limit", is_err(post(P + "send", {"mailbox": box[0], "envelope": b64(MAX_ENVELOPE + 1)}), 413, "too_large"))
s, ct, text = raw(P + "send", b'{"pad":"' + b"x" * (MAX_ENVELOPE * 4 // 3 + 70000) + b'"}')
check("an oversized sealed body is 413 too_large", s == 413 and json.loads(text) == {"error": "too_large"}, (s, text[:80]))
check("sealed send to an unregistered mailbox answers exactly ok", post(P + "send", {"mailbox": os.urandom(32).hex(), "envelope": env}) == (200, {"ok": True}))

mark = len(wakes)
check("sealed send answers exactly ok", post(P + "send", {"mailbox": box[0], "envelope": b64(MAX_ENVELOPE)}) == (200, {"ok": True}))
check("a sealed send wakes the owning device", wakes_since(mark) == [("/v1/wake", {"wake_token": xtok, "silent": False})], wakes_since(mark))
mark = len(wakes)
post(P + "send", {"mailbox": box[1], "envelope": env, "silent": True})
check("a silent sealed send is passed on as silent", wakes_since(mark) == [("/v1/wake", {"wake_token": xtok, "silent": True})], wakes_since(mark))
mark = len(wakes)
post(P + "send", {"mailbox": box[3], "envelope": env})
check("a device with no wake token is not woken", wakes_since(mark) == [], wakes_since(mark))
post(P + "send", {"mailbox": box[2], "envelope": env, "expires_at": int(time.time()) + 3600})

for k in ["device_id", "ts", "auth"]:
    body = x.signed("inbox"); del body[k]
    check("sealed inbox without %s is 400 missing:%s" % (k, k), is_err(post(P + "inbox", body), 400, "missing:" + k))
check("sealed inbox for an unknown device is 404 unknown_device", is_err(post(P + "inbox", ghost.signed("inbox")), 404, "unknown_device"))
check("sealed inbox with a wrong proof is 401 bad_auth", is_err(post(P + "inbox", x.signed("mbx")), 401, "bad_auth"))
check("sealed inbox with a zero timestamp is 401 bad_auth", is_err(post(P + "inbox", x.signed("inbox", ts=0)), 401, "bad_auth"))
s, b = post(P + "inbox", x.signed("inbox"))
got = b.get("messages", [])
check("sealed inbox answers exactly a messages list", s == 200 and list(b) == ["messages"], (s, list(b)))
check("a sealed message over the byte budget goes out alone", [m["mailbox"] for m in got] == [box[0]], [m.get("mailbox") for m in got])
if got:
    m = got[0]
    check("a sealed message has exactly six fields",
          sorted(m) == ["alert", "envelope", "expires_at", "mailbox", "message_id", "received_at"], sorted(m))
    check("its alert is a JSON number and its times are 'YYYY-MM-DD HH:MM:SS'",
          m["alert"] == 1 and isinstance(m["alert"], int) and STAMP.match(str(m["received_at"])) is not None
          and STAMP.match(str(m["expires_at"])) is not None and HEX32.match(m["message_id"]) is not None, m)
big_id = got[0]["message_id"] if got else "0" * 32
s, b = post(P + "inbox", x.signed("inbox", {"skip": [big_id, "junk", 9]}))
got = b.get("messages", [])
check("the skip list lets the messages behind through, oldest first", [m["mailbox"] for m in got] == [box[1], box[2]], [m.get("mailbox") for m in got])
check("sealed alert follows silent", [m["alert"] for m in got] == [0, 1], [m.get("alert") for m in got])
small_ids = [m["message_id"] for m in got]
check("a skip list that is not a list is ignored",
      [m["message_id"] for m in post(P + "inbox", x.signed("inbox", {"skip": "abc"}))[1].get("messages", [])] == [big_id])
check("the other device sees only its own mailbox",
      [m["mailbox"] for m in post(P + "inbox", y.signed("inbox"))[1].get("messages", [])] == [box[3]])

for k in ["device_id", "ts", "auth", "message_ids"]:
    body = x.signed("ack", {"message_ids": [big_id]}); del body[k]
    check("sealed ack without %s is 400 missing:%s" % (k, k), is_err(post(P + "ack", body), 400, "missing:" + k))
check("sealed ack for an unknown device is 404 unknown_device", is_err(post(P + "ack", ghost.signed("ack", {"message_ids": [big_id]})), 404, "unknown_device"))
check("sealed ack with a wrong proof is 401 bad_auth", is_err(post(P + "ack", x.signed("inbox", {"message_ids": [big_id]})), 401, "bad_auth"))
check("sealed ack with an empty list is 400 no_ids", is_err(post(P + "ack", x.signed("ack", {"message_ids": []})), 400, "no_ids"))
check("sealed ack with ids that are not a list is 400 no_ids", is_err(post(P + "ack", x.signed("ack", {"message_ids": "abc"})), 400, "no_ids"))
check("sealed ack with nothing valid answers deleted 0", post(P + "ack", x.signed("ack", {"message_ids": ["zz", 4]})) == (200, {"ok": True, "deleted": 0}))
check("another device cannot ack these messages", post(P + "ack", y.signed("ack", {"message_ids": [big_id]})) == (200, {"ok": True, "deleted": 0}))
check("sealed ack answers the number deleted",
      post(P + "ack", x.signed("ack", {"message_ids": [big_id, big_id, "0" * 32]})) == (200, {"ok": True, "deleted": 1}))
check("sealed ack deletes the rest", post(P + "ack", x.signed("ack", {"message_ids": small_ids})) == (200, {"ok": True, "deleted": 2}))
check("sealed inbox is empty afterwards", post(P + "inbox", x.signed("inbox")) == (200, {"messages": []}))

flood = os.urandom(32).hex()
post(P + "register-mailboxes", y.signed("mbx", {"mailboxes": [flood]}))
answers = [post(P + "send", {"mailbox": flood, "envelope": env}) for _ in range(22)]
check("the first twenty deposits to one mailbox answer ok", all(r == (200, {"ok": True}) for r in answers[:20]), answers[:20])
check("the next ones answer ok and throttled", all(r == (200, {"ok": True, "throttled": True}) for r in answers[20:]), answers[20:])

if MYSQL:
    sql("UPDATE mailboxes SET expires_at = DATE_SUB(UTC_TIMESTAMP(), INTERVAL 1 SECOND) WHERE mailbox='%s'" % box[1])
    post(P + "send", {"mailbox": box[1], "envelope": env})
    check("a deposit to an expired mailbox answers ok and stores nothing", one("SELECT COUNT(*) FROM sealed_messages WHERE mailbox='%s'" % box[1]) == "0")
    check("registering an expired mailbox again renews it",
          post(P + "register-mailboxes", x.signed("mbx", {"mailboxes": [box[1]]})) == (200, {"ok": True, "registered": 1})
          and one("SELECT expires_at > UTC_TIMESTAMP() FROM mailboxes WHERE mailbox='%s'" % box[1]) == "1")
    check("the wake token of a sealed device is stored", one("SELECT wake_token FROM sealed_devices WHERE device_id='%s'" % x.dev) == xtok)
    post(P + "register-device", x.signed("register", {"device_key": x.key}))
    check("registering again without a wake token clears it", one("SELECT wake_token IS NULL FROM sealed_devices WHERE device_id='%s'" % x.dev) == "1")
else:
    skip("expired mailboxes and stored wake token (needs MYSQL)")

# ---- reaper ----------------------------------------------------------------

if MYSQL and REAPER:
    def count(table, where="1"):
        return int(one("SELECT COUNT(*) FROM %s WHERE %s" % (table, where)))

    keep = a.call("/v1/send", {"to_fpr": bob.fpr, "envelope": env})[1]["message_id"]
    gone = a.call("/v1/send", {"to_fpr": bob.fpr, "envelope": env})[1]["message_id"]
    acked = a.call("/v1/send", {"to_fpr": a.fpr, "envelope": env})[1]["message_id"]
    sql("UPDATE messages SET expires_at = DATE_SUB(UTC_TIMESTAMP(), INTERVAL 1 SECOND) WHERE message_id='%s'" % gone)
    sql("UPDATE deliveries d JOIN messages m ON m.id = d.message_pk SET d.acked_at = UTC_TIMESTAMP() WHERE m.message_id='%s'" % acked)
    f_old, f_new = os.urandom(20).hex().upper(), os.urandom(20).hex().upper()
    post("/v1/challenge", {"fpr": f_old}); post("/v1/challenge", {"fpr": f_new})
    sql("UPDATE challenges SET expires_at = DATE_SUB(UTC_TIMESTAMP(), INTERVAL 1 SECOND) WHERE fpr='%s'" % f_old)

    r_live, r_dead, r_held = [os.urandom(32).hex() for _ in range(3)]
    post(P + "register-mailboxes", x.signed("mbx", {"mailboxes": [r_live, r_dead, r_held]}))
    post(P + "send", {"mailbox": r_held, "envelope": env})
    post(P + "send", {"mailbox": r_live, "envelope": env})
    sql("UPDATE mailboxes SET expires_at = DATE_SUB(UTC_TIMESTAMP(), INTERVAL 1 SECOND) WHERE mailbox IN ('%s','%s')" % (r_dead, r_held))
    sql("UPDATE sealed_messages SET expires_at = DATE_SUB(UTC_TIMESTAMP(), INTERVAL 1 SECOND) WHERE mailbox='%s'" % r_live)

    old_dev = Sealed(); post(P + "register-device", {"device_id": old_dev.dev, "device_key": old_dev.key})
    sql("UPDATE sealed_devices SET last_seen = DATE_SUB(UTC_TIMESTAMP(), INTERVAL 61 DAY) WHERE device_id='%s'" % old_dev.dev)
    idle = Identity("v4"); idle.register()
    sql("UPDATE devices SET last_seen = DATE_SUB(UTC_TIMESTAMP(), INTERVAL 31 DAY) WHERE device_id='%s'" % idle.device_id)

    o_open = a.call("/v1/pair/offer", {"pubkey": a.pubkey})[1].get("token")
    if not o_open:
        sql("DELETE FROM pairing_offers WHERE offerer_fpr='%s' AND state='open'" % a.fpr)
        o_open = a.call("/v1/pair/offer", {"pubkey": a.pubkey})[1]["token"]
    sql("UPDATE pairing_offers SET expires_at = DATE_SUB(UTC_TIMESTAMP(), INTERVAL 1 SECOND) WHERE token='%s'" % o_open)
    sql("UPDATE pairing_offers SET accepted_at = DATE_SUB(UTC_TIMESTAMP(), INTERVAL 31 DAY) WHERE token='%s'" % tokens[0])

    out = subprocess.run(shlex.split(REAPER), capture_output=True, text=True)
    line = out.stdout.strip().splitlines()[-1] if out.stdout.strip() else ""
    check("the reaper runs and reports one line of counts", out.returncode == 0 and re.search(
        r"^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d reaper: expired_messages=\d+ acked_messages=\d+ stale_challenges=\d+ stale_devices=\d+ "
        r"stale_offers=\d+ expired_sealed=\d+ stale_mailboxes=\d+ stale_sealed_devices=\d+$", line) is not None, (out.returncode, line, out.stderr[:200]))
    check("reaper: an expired message is deleted", count("messages", "message_id='%s'" % gone) == 0)
    check("reaper: a fully acked message is deleted", count("messages", "message_id='%s'" % acked) == 0)
    check("reaper: a live message is kept with its deliveries", count("messages", "message_id='%s'" % keep) == 1
          and count("deliveries d JOIN messages m ON m.id=d.message_pk", "m.message_id='%s'" % keep) == 2)
    check("reaper: an expired nonce is deleted and a live one kept",
          count("challenges", "fpr='%s'" % f_old) == 0 and count("challenges", "fpr='%s'" % f_new) == 1)
    check("reaper: an expired sealed message is deleted", count("sealed_messages", "mailbox='%s'" % r_live) == 0)
    check("reaper: an expired empty mailbox is deleted", count("mailboxes", "mailbox='%s'" % r_dead) == 0)
    check("reaper: an expired mailbox that still holds a message is kept", count("mailboxes", "mailbox='%s'" % r_held) == 1)
    check("reaper: a sealed device idle for 61 days is deleted", count("sealed_devices", "device_id='%s'" % old_dev.dev) == 0)
    check("reaper: a device idle past device_stale_days is deleted, its identity kept",
          count("devices", "device_id='%s'" % idle.device_id) == 0 and count("identities", "fpr='%s'" % idle.fpr) == 1)
    check("reaper: an open offer past its time is deleted", count("pairing_offers", "token='%s'" % o_open) == 0)
    check("reaper: an offer accepted 31 days ago is deleted", count("pairing_offers", "token='%s'" % tokens[0]) == 0)
    check("reaper: a recently accepted offer is kept even past its time", count("pairing_offers", "token='%s'" % token) == 1)
else:
    skip("reaper (needs MYSQL and REAPER)")

gateway.shutdown()
print()
print(("ALL PASS" if fails == 0 else "%d FAILED" % fails) + ((", %d skipped" % skips) if skips else ""))
sys.exit(1 if fails else 0)
