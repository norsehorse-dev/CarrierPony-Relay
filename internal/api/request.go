package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
)

// input is the decoded request body. The PHP relay read every request as a JSON
// object and treated anything else as an empty one, whatever the content type,
// and the apps in the field were written against that.
type input map[string]any

// errTooLarge is returned when a body is over the limit for its endpoint.
var errTooLarge = errors.New("request body too large")

// readInput reads and decodes a body of at most limit bytes. A body that is not
// a JSON object decodes to an empty input, never to an error.
func readInput(r *http.Request, limit int64) (input, error) {
	if r.ContentLength > limit {
		return nil, errTooLarge
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
	if err != nil {
		return input{}, nil
	}
	if int64(len(raw)) > limit {
		return nil, errTooLarge
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	// Numbers keep their digits, so a timestamp is used exactly as sent.
	dec.UseNumber()
	var in input
	if err := dec.Decode(&in); err != nil {
		return input{}, nil
	}
	if _, err := dec.Token(); err != io.EOF {
		return input{}, nil
	}
	if in == nil {
		return input{}, nil
	}
	return in, nil
}

// has reports whether a field counts as sent: present, not null and not the
// empty string. A zero, a false or an empty list still counts.
func (in input) has(name string) bool {
	v, found := in[name]
	if !found || v == nil {
		return false
	}
	s, isString := v.(string)
	return !isString || s != ""
}

// firstMissing returns the first of the names that was not sent, or "".
func (in input) firstMissing(names ...string) string {
	for _, name := range names {
		if !in.has(name) {
			return name
		}
	}
	return ""
}

// text returns a field as the string a handler validates. Strings come back as
// they are and numbers as their digits. Anything else comes back as a value no
// check accepts, so a list or an object where a string belongs is refused as
// malformed instead of crashing the request the way it did in PHP.
func (in input) text(name string) string {
	switch v := in[name].(type) {
	case string:
		return v
	case json.Number:
		return v.String()
	case nil:
		return ""
	}
	return "\x00"
}

var (
	reFingerprint = regexp.MustCompile(`^(?:[0-9A-F]{40}|[0-9A-F]{64})$`)
	reHex32       = regexp.MustCompile(`^[0-9a-f]{32}$`)
	reHex64       = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// fingerprint returns a field with its ASCII letters uppercased, and whether it
// is a v4 (40 hex) or v6 (64 hex) fingerprint.
func (in input) fingerprint(name string) (string, bool) {
	fpr := upperASCII(in.text(name))
	return fpr, reFingerprint.MatchString(fpr)
}

// upperASCII uppercases a to z and leaves every other byte alone, as PHP's
// strtoupper does. strings.ToUpper would also fold a few non-ASCII letters.
func upperASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'a' && c <= 'z' {
			b[i] = c - 32
		}
	}
	return string(b)
}
