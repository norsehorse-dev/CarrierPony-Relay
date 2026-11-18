# Fingerprint-path relay contract test. Walks challenge, register-device, send,
# inbox, ack, register-wake, pair offer/accept/status and report with v4 and v6
# identities, and checks that a login can only ever speak for its own fingerprint.
#
# Point it at a running relay:
#   BASE=http://127.0.0.1:8080 TESTKEY=/path/to/cp-testkey python3 tests/identity_contract_test.py
#
# KINDS picks the identity types (default "v4,v6,v6pq"). A relay still verifying
# with gpg only accepts v4, so run it there with KINDS=v4. Set EXPECT_V6_REFUSED=1
# to also check that such a relay turns a v6 login away cleanly.
# TESTKEY is the cp-testkey helper built from verifier/cmd/cp-testkey.
# Validate against a throwaway server and database, never a live relay.
import urllib.request, urllib.error, json, os, base64, subprocess, sys

BASE = os.environ.get("BASE", "http://127.0.0.1:8080").rstrip("/")
TESTKEY = os.environ.get("TESTKEY", "cp-testkey")
KINDS = [k for k in os.environ.get("KINDS", "v4,v6,v6pq").split(",") if k]
EXPECT_V6_REFUSED = os.environ.get("EXPECT_V6_REFUSED") == "1"
FPR_LEN = {"v4": 40, "v6": 64, "v6pq": 64}

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

fails = 0
def check(name, cond, extra=""):
    global fails
    print(("PASS  " if cond else "FAIL  ") + name + (("  ::  " + str(extra)) if (extra and not cond) else ""))
    if not cond:
        fails += 1

class Identity:
    def __init__(self, kind):
        out = subprocess.run([TESTKEY, "gen", kind], capture_output=True, text=True, check=True).stdout
        k = json.loads(out)
        self.kind, self.fpr, self.pubkey, self.secret = kind, k["fpr"], k["pubkey"], k["secret"]
        self.device_id = os.urandom(16).hex()

    def sign(self, data):
        out = subprocess.run([TESTKEY, "sign"], input=json.dumps({"secret": self.secret, "data": data}),
                             capture_output=True, text=True, check=True).stdout
        return json.loads(out)["sig"]

    def auth(self, fpr=None):
        fpr = fpr or self.fpr
        s, b = post("/v1/challenge", {"fpr": fpr})
        if s != 200:
            return {"fpr": fpr, "nonce": "0" * 64, "sig": "x"}
        return {"fpr": fpr, "nonce": b["nonce"], "sig": self.sign(b["nonce"])}

    def call(self, path, extra=None, fpr=None):
        body = self.auth(fpr)
        body.update(extra or {})
        return post(path, body)

    def register(self, pubkey=None, fpr=None):
        return self.call("/v1/register-device",
                         {"pubkey": pubkey or self.pubkey, "device_id": self.device_id, "label": "test"}, fpr)

env = base64.b64encode(b"hello relay").decode()

for bad in ["A" * 39, "A" * 41, "A" * 50, "A" * 63, "A" * 65, "G" * 40, "G" * 64, ""]:
    s, b = post("/v1/challenge", {"fpr": bad})
    check("challenge refuses a %d-character fingerprint" % len(bad), s == 400, (s, b))
for n in (40, 64):
    s, b = post("/v1/challenge", {"fpr": "a" * n})
    check("challenge accepts %d hex characters, any case" % n, s == 200 and len(b.get("nonce", "")) == 64, (s, b))

ids = {}
for kind in KINDS:
    a = Identity(kind)
    ids[kind] = a
    tag = "[%s] " % kind
    check(tag + "fingerprint is %d characters" % FPR_LEN[kind], len(a.fpr) == FPR_LEN[kind])

    s, b = a.call("/v1/inbox", {"device_id": a.device_id})
    check(tag + "login before registering is refused", s in (401, 403), (s, b))

    other = Identity(kind)
    s, b = a.register(pubkey=other.pubkey)
    check(tag + "register with a key that is not this fingerprint's is refused", s == 401, (s, b))
    s, b = other.register(fpr=a.fpr)
    check(tag + "register under someone else's fingerprint is refused", s == 401, (s, b))

    s, b = a.register()
    check(tag + "register-device", s == 200 and b.get("ok") is True, (s, b))
    s, b = a.register()
    check(tag + "register-device again is fine", s == 200, (s, b))

    body = a.auth()
    body["device_id"] = a.device_id
    s, b = post("/v1/inbox", body)
    check(tag + "inbox with a fresh login", s == 200 and b.get("messages") == [], (s, b))
    s, b = post("/v1/inbox", body)
    check(tag + "the same challenge cannot be used twice", s == 401 and b.get("error") == "bad_challenge", (s, b))

    s, b = other.register()
    s, b = other.call("/v1/inbox", {"device_id": a.device_id}, fpr=a.fpr)
    check(tag + "another identity cannot log in as this one", s == 401 and b.get("error") == "bad_signature", (s, b))

    s, b = other.call("/v1/send", {"to_fpr": a.fpr, "envelope": env})
    check(tag + "send to this identity", s == 200 and len(b.get("message_id", "")) == 32, (s, b))
    mid = b.get("message_id")
    s, b = other.call("/v1/send", {"to_fpr": a.fpr.lower(), "envelope": env, "silent": True})
    check(tag + "send accepts a lowercase fingerprint", s == 200, (s, b))
    s, b = other.call("/v1/send", {"to_fpr": a.fpr[:-1], "envelope": env})
    check(tag + "send refuses a short fingerprint", s == 400 and b.get("error") == "bad_to_fpr", (s, b))
    s, b = other.call("/v1/send", {"to_fpr": ("0" * len(a.fpr)), "envelope": env})
    check(tag + "send to an unknown fingerprint is 404", s == 404, (s, b))

    s, b = a.call("/v1/inbox", {"device_id": a.device_id})
    got = b.get("messages", [])
    check(tag + "inbox returns both messages", s == 200 and len(got) == 2 and got[0]["envelope"] == env, (s, b))
    check(tag + "alert flag follows silent", [int(m["alert"]) for m in got] == [1, 0], got)
    s, b = other.call("/v1/inbox", {"device_id": other.device_id})
    check(tag + "the sender's inbox stays empty", s == 200 and b.get("messages") == [], (s, b))
    s, b = a.call("/v1/ack", {"device_id": a.device_id, "message_ids": [m["message_id"] for m in got]})
    check(tag + "ack", s == 200 and b.get("acked") == 2, (s, b))
    s, b = a.call("/v1/inbox", {"device_id": a.device_id})
    check(tag + "inbox empty after ack", s == 200 and b.get("messages") == [], (s, b))

    s, b = a.call("/v1/register-wake", {"device_id": a.device_id, "wake_token": os.urandom(32).hex()})
    check(tag + "register-wake", s == 200, (s, b))

    s, b = a.call("/v1/pair/offer", {"pubkey": a.pubkey})
    token = b.get("token", "")
    check(tag + "pair offer", s == 200 and len(token) == 32, (s, b))
    s, b = a.call("/v1/pair/status", {"token": token})
    check(tag + "pair status open", s == 200 and b.get("state") == "open", (s, b))
    s, b = other.call("/v1/pair/status", {"token": token})
    check(tag + "pair status is only for the offerer", s == 403, (s, b))
    s, b = other.call("/v1/pair/accept", {"token": token, "pubkey": other.pubkey})
    check(tag + "pair accept returns the offerer", s == 200 and b.get("offerer_fpr") == a.fpr and b.get("offerer_pubkey") == a.pubkey, (s, b))
    s, b = a.call("/v1/pair/status", {"token": token})
    check(tag + "pair status returns the responder", s == 200 and b.get("state") == "accepted"
          and b.get("responder_fpr") == other.fpr and b.get("responder_pubkey") == other.pubkey, (s, b))
    s, b = other.call("/v1/pair/accept", {"token": token, "pubkey": other.pubkey})
    check(tag + "an accepted offer cannot be accepted again", s == 410, (s, b))

    s, b = a.call("/v1/report", {"reported_fpr": other.fpr, "category": "spam"})
    check(tag + "report", s == 200, (s, b))
    s, b = a.call("/v1/report", {"reported_fpr": other.fpr + "0", "category": "spam"})
    check(tag + "report refuses a bad fingerprint", s == 400, (s, b))

if "v4" in ids and "v6pq" in ids:
    v4, v6 = ids["v4"], ids["v6pq"]
    for src, dst, name in ((v4, v6, "v4 to v6"), (v6, v4, "v6 to v4")):
        s, b = src.call("/v1/send", {"to_fpr": dst.fpr, "envelope": env})
        check("[mixed] send " + name, s == 200, (s, b))
        s, b = dst.call("/v1/inbox", {"device_id": dst.device_id})
        got = b.get("messages", [])
        check("[mixed] delivered " + name, s == 200 and len(got) == 1, (s, b))
        dst.call("/v1/ack", {"device_id": dst.device_id, "message_ids": [m["message_id"] for m in got]})
    s, b = v4.call("/v1/pair/offer", {"pubkey": v4.pubkey})
    token = b.get("token", "")
    s, b = v6.call("/v1/pair/accept", {"token": token, "pubkey": v6.pubkey})
    check("[mixed] v6 accepts a v4 offer", s == 200 and b.get("offerer_fpr") == v4.fpr, (s, b))
    s, b = v4.call("/v1/pair/status", {"token": token})
    check("[mixed] v4 offerer sees the v6 responder", s == 200 and b.get("responder_fpr") == v6.fpr, (s, b))

if EXPECT_V6_REFUSED:
    v6 = Identity("v6")
    s, b = v6.register()
    check("[gpg relay] a v6 login is refused with 401", s == 401 and b.get("error") == "bad_signature", (s, b))

print()
print("ALL PASS" if fails == 0 else "%d FAILED" % fails)
sys.exit(1 if fails else 0)
