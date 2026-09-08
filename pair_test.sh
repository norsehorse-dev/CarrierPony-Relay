#!/usr/bin/env bash
set -u

BASE="${1:-https://api.carrierpony.com}"

GH="$(mktemp -d)"
export GNUPGHOME="$GH"
chmod 700 "$GH"

PASS=0
FAIL=0
FPRS=""

cleanup() { rm -rf "$GH"; }
trap cleanup EXIT

ok() {
  if [ "$1" = "$2" ]; then
    echo "PASS $3"
    PASS=$((PASS + 1))
  else
    echo "FAIL $3 (got '$2' want '$1')"
    FAIL=$((FAIL + 1))
  fi
}

jstr() { php -r 'echo json_encode(file_get_contents("php://stdin"));'; }

devid() { head -c16 /dev/urandom | od -An -tx1 | tr -d ' \n'; }

genkey() {
  local uid="$1" params
  params="$(mktemp)"
  cat >"$params" <<EOF
%no-protection
Key-Type: EDDSA
Key-Curve: ed25519
Key-Usage: sign
Name-Real: $uid
Expire-Date: 0
%commit
EOF
  gpg --batch --gen-key "$params" >/dev/null 2>&1
  rm -f "$params"
  gpg --batch --with-colons --list-keys "$uid" | awk -F: '/^fpr:/{print $10; exit}'
}

challenge() {
  curl -s "$BASE/v1/challenge" -H 'Content-Type: application/json' \
    -d "{\"fpr\":\"$1\"}" | grep -oE '"nonce":"[0-9a-f]+"' | head -1 | cut -d'"' -f4
}

sig_for() {
  local fpr="$1" nonce="$2"
  printf '%s' "$nonce" | gpg --batch --yes --detach-sign --armor -u "$fpr" -o - 2>/dev/null | jstr
}

register() {
  local fpr="$1" nonce sig pub
  nonce="$(challenge "$fpr")"
  sig="$(sig_for "$fpr" "$nonce")"
  pub="$(gpg --armor --export "$fpr" | jstr)"
  curl -s -o /dev/null -w '%{http_code}' "$BASE/v1/register-device" \
    -H 'Content-Type: application/json' \
    -d "{\"fpr\":\"$fpr\",\"pubkey\":$pub,\"device_id\":\"$(devid)\",\"nonce\":\"$nonce\",\"sig\":$sig}"
}

call() {
  local fpr="$1" path="$2" extra="$3" nonce sig
  nonce="$(challenge "$fpr")"
  sig="$(sig_for "$fpr" "$nonce")"
  [ -n "$extra" ] && extra=",$extra"
  curl -s -w $'\n%{http_code}' "$BASE$path" -H 'Content-Type: application/json' \
    -d "{\"fpr\":\"$fpr\",\"nonce\":\"$nonce\",\"sig\":$sig$extra}"
}

field() { grep -oE "\"$1\":\"[^\"]*\"" | head -1 | cut -d'"' -f4; }
code() { tail -1; }
bodyof() { sed '$d'; }

echo "relay: $BASE"
echo "generating two throwaway test identities..."
ALICE="$(genkey "cp-test-alice-$$")"
BOB="$(genkey "cp-test-bob-$$")"
FPRS="$ALICE $BOB"
echo "alice=$ALICE"
echo "bob=$BOB"
echo "test identities (delete these after): $FPRS"
echo

ok "200" "$(register "$ALICE")" "register alice"
ok "200" "$(register "$BOB")"   "register bob"

R="$(call "$ALICE" /v1/pair/offer "\"pubkey\":$(gpg --armor --export "$ALICE" | jstr)")"
ok "200" "$(printf '%s' "$R" | code)" "offer returns 200"
TOKEN="$(printf '%s' "$R" | bodyof | field token)"
echo "token=$TOKEN"

R="$(call "$BOB" /v1/pair/accept "\"token\":\"$TOKEN\",\"pubkey\":$(gpg --armor --export "$BOB" | jstr)")"
ok "200" "$(printf '%s' "$R" | code)" "accept returns 200"
ok "$ALICE" "$(printf '%s' "$R" | bodyof | field offerer_fpr)" "accept returns alice fpr"

R="$(call "$ALICE" /v1/pair/status "\"token\":\"$TOKEN\"")"
ok "200" "$(printf '%s' "$R" | code)" "status returns 200"
ok "accepted" "$(printf '%s' "$R" | bodyof | field state)" "status state accepted"
ok "$BOB" "$(printf '%s' "$R" | bodyof | field responder_fpr)" "status returns bob fpr"

R="$(call "$BOB" /v1/pair/accept "\"token\":\"$TOKEN\",\"pubkey\":$(gpg --armor --export "$BOB" | jstr)")"
ok "410" "$(printf '%s' "$R" | code)" "second accept closed (single-use)"

R="$(call "$BOB" /v1/pair/status "\"token\":\"$TOKEN\"")"
ok "403" "$(printf '%s' "$R" | code)" "wrong party cannot poll offer"

R="$(call "$ALICE" /v1/pair/status "\"token\":\"nothex\"")"
ok "400" "$(printf '%s' "$R" | code)" "bad token rejected"

R="$(call "$BOB" /v1/pair/accept "\"token\":\"ffffffffffffffffffffffffffffffff\",\"pubkey\":$(gpg --armor --export "$BOB" | jstr)")"
ok "404" "$(printf '%s' "$R" | code)" "unknown token 404"

NONCE="$(challenge "$ALICE")"
BADSIG='"-----BEGIN PGP SIGNATURE-----\nbogus\n-----END PGP SIGNATURE-----\n"'
C="$(curl -s -o /dev/null -w '%{http_code}' "$BASE/v1/pair/offer" -H 'Content-Type: application/json' \
  -d "{\"fpr\":\"$ALICE\",\"nonce\":\"$NONCE\",\"sig\":$BADSIG,\"pubkey\":$(gpg --armor --export "$ALICE" | jstr)}")"
ok "401" "$C" "bad signature rejected"

echo
echo "$PASS passed, $FAIL failed"
echo "remember to remove test identities: $FPRS"
[ "$FAIL" -eq 0 ]
