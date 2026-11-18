// cp-verify reads one JSON request on stdin and answers on stdout.
//
//	{"pubkey": "<armored key>", "fpr": "<hex>", "data": "<nonce>", "sig": "<armored sig>"}
//
// Exit status 0 and {"ok":true} when the signature is valid, otherwise exit
// status 1 and {"ok":false,"error":"...","detail":"..."}. "detail" is the
// library's own reason, for logs only. The PHP relay calls it in place of gpg.
package main

import (
	"encoding/json"
	"io"
	"os"

	verifier "github.com/norsehorse-dev/CarrierPony-Relay/verifier"
)

type request struct {
	Pubkey string `json:"pubkey"`
	Fpr    string `json:"fpr"`
	Data   string `json:"data"`
	Sig    string `json:"sig"`
}

func fail(msg string) {
	json.NewEncoder(os.Stdout).Encode(map[string]any{"ok": false, "error": msg})
	os.Exit(1)
}

func main() {
	raw, err := io.ReadAll(io.LimitReader(os.Stdin, 1<<20))
	if err != nil {
		fail("bad_request")
	}
	var req request
	if err := json.Unmarshal(raw, &req); err != nil {
		fail("bad_request")
	}
	if err, detail := verifier.VerifyDetail(req.Pubkey, req.Fpr, []byte(req.Data), req.Sig); err != nil {
		json.NewEncoder(os.Stdout).Encode(map[string]any{"ok": false, "error": err.Error(), "detail": detail})
		os.Exit(1)
	}
	json.NewEncoder(os.Stdout).Encode(map[string]any{"ok": true})
}
