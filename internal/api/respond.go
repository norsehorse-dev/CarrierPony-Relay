package api

import (
	"bytes"
	"encoding/json"
	"net/http"
)

// field is one name and value of a JSON answer. Answers are written as ordered
// lists of fields so the names come out in the same order every time, the order
// the PHP relay used.
type field struct {
	name  string
	value any
}

type object []field

func (o object) MarshalJSON() ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, f := range o {
		if i > 0 {
			buf.WriteByte(',')
		}
		name, err := marshal(f.name)
		if err != nil {
			return nil, err
		}
		value, err := marshal(f.value)
		if err != nil {
			return nil, err
		}
		buf.Write(name)
		buf.WriteByte(':')
		buf.Write(value)
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

// marshal encodes one value without the HTML escaping encoding/json applies by
// default, which would turn the + and / of an armored key into \u sequences.
func marshal(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// result is what a handler answers: a status and a JSON body.
type result struct {
	status int
	body   object
}

func ok(fields ...field) result {
	return result{http.StatusOK, object(fields)}
}

func fail(status int, code string) result {
	return result{status, object{{"error", code}}}
}

func missing(name string) result {
	return fail(http.StatusBadRequest, "missing:"+name)
}

func write(w http.ResponseWriter, res result) {
	body, err := res.body.MarshalJSON()
	if err != nil {
		res.status, body = http.StatusInternalServerError, []byte(`{"error":"server_error"}`)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(res.status)
	w.Write(body)
}
