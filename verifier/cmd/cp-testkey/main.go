// cp-testkey makes throwaway identities and signs with them. It exists only so
// the relay contract test can exercise v4 and v6 logins; the relay never runs it.
//
//	cp-testkey gen v4|v6|v6pq    -> {"fpr","pubkey","secret"}
//	cp-testkey sign              <- {"secret","data"} on stdin -> {"sig"}
package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	openpgp "github.com/ProtonMail/go-crypto/openpgp/v2"
)

func die(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

func armored(blockType string, write func(*bytes.Buffer) error) string {
	var raw, out bytes.Buffer
	if err := write(&raw); err != nil {
		die(err)
	}
	w, err := armor.Encode(&out, blockType, nil)
	if err != nil {
		die(err)
	}
	w.Write(raw.Bytes())
	w.Close()
	return out.String()
}

func gen(kind string) {
	v6 := kind != "v4"
	algo := packet.PubKeyAlgoEdDSA
	if v6 {
		algo = packet.PubKeyAlgoEd25519
	}
	cfg := &packet.Config{Algorithm: algo, V6Keys: v6}
	e, err := openpgp.NewEntity("CarrierPony", "", "", cfg)
	if err != nil {
		die(err)
	}
	if v6 {
		if err := e.AddSigningSubkey(cfg); err != nil {
			die(err)
		}
	}
	if kind == "v6pq" {
		if err := e.AddEncryptionSubkey(&packet.Config{Algorithm: packet.PubKeyAlgoMlkem768X25519, V6Keys: true}); err != nil {
			die(err)
		}
	}
	json.NewEncoder(os.Stdout).Encode(map[string]string{
		"fpr":    strings.ToUpper(hex.EncodeToString(e.PrimaryKey.Fingerprint)),
		"pubkey": armored("PGP PUBLIC KEY BLOCK", func(b *bytes.Buffer) error { return e.Serialize(b) }),
		"secret": armored("PGP PRIVATE KEY BLOCK", func(b *bytes.Buffer) error { return e.SerializePrivate(b, nil) }),
	})
}

func sign() {
	var req struct{ Secret, Data string }
	if err := json.NewDecoder(os.Stdin).Decode(&req); err != nil {
		die(err)
	}
	list, err := openpgp.ReadArmoredKeyRing(strings.NewReader(req.Secret))
	if err != nil || len(list) != 1 {
		die(fmt.Errorf("bad secret key"))
	}
	var out bytes.Buffer
	if err := openpgp.ArmoredDetachSign(&out, list, strings.NewReader(req.Data), &openpgp.SignParams{}); err != nil {
		die(err)
	}
	json.NewEncoder(os.Stdout).Encode(map[string]string{"sig": out.String()})
}

func main() {
	if len(os.Args) == 3 && os.Args[1] == "gen" {
		gen(os.Args[2])
		return
	}
	if len(os.Args) == 2 && os.Args[1] == "sign" {
		sign()
		return
	}
	die(fmt.Errorf("usage: cp-testkey gen v4|v6|v6pq | cp-testkey sign"))
}
