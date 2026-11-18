package api

import (
	"encoding/json"
	"math"
	"strconv"
	"strings"
	"unicode/utf8"
)

// The apps were written against a PHP relay, and a few of its loose rules are
// part of the interface: what counts as "set", how a number arrives. They are
// kept here, in one place, so the handlers read plainly.

// truthy is PHP's !empty(): false for a missing field, null, false, 0, "", "0"
// and an empty list or object.
func truthy(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case bool:
		return x
	case string:
		return x != "" && x != "0"
	case json.Number:
		f, err := x.Float64()
		return err != nil || f != 0
	case []any:
		return len(x) > 0
	case map[string]any:
		return len(x) > 0
	}
	return true
}

// integer is PHP's (int) cast of a decoded JSON value: a number is truncated, a
// string gives its leading number or 0, true is 1 and everything else is 0.
func integer(v any) int64 {
	switch x := v.(type) {
	case json.Number:
		return numberToInt(x.String())
	case string:
		return numberToInt(leadingNumber(x))
	case bool:
		if x {
			return 1
		}
	case []any:
		if len(x) > 0 {
			return 1
		}
	case map[string]any:
		if len(x) > 0 {
			return 1
		}
	}
	return 0
}

func numberToInt(s string) int64 {
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		return n
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil || math.IsNaN(f) || math.IsInf(f, 0) || f >= math.MaxInt64 || f <= math.MinInt64 {
		return 0
	}
	return int64(f)
}

// leadingNumber returns the numeric prefix of a string the way PHP reads one:
// optional whitespace and sign, digits, an optional fraction and exponent.
func leadingNumber(s string) string {
	s = strings.TrimLeft(s, " \t\n\r\v\f")
	i := 0
	if i < len(s) && (s[i] == '+' || s[i] == '-') {
		i++
	}
	digits := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
		digits++
	}
	if i < len(s) && s[i] == '.' {
		j := i + 1
		for j < len(s) && s[j] >= '0' && s[j] <= '9' {
			j++
			digits++
		}
		if j > i+1 || digits > 0 {
			i = j
		}
	}
	if digits == 0 {
		return "0"
	}
	if i < len(s) && (s[i] == 'e' || s[i] == 'E') {
		j := i + 1
		if j < len(s) && (s[j] == '+' || s[j] == '-') {
			j++
		}
		k := j
		for k < len(s) && s[k] >= '0' && s[k] <= '9' {
			k++
		}
		if k > j {
			i = k
		}
	}
	return s[:i]
}

// cutBytes shortens a string to at most n bytes without splitting a character.
// PHP cut at the byte and could leave half a character behind, which the
// database then refused.
func cutBytes(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// cutChars shortens a string to at most n characters.
func cutChars(s string, n int) string {
	if len(s) <= n {
		return s
	}
	count := 0
	for i := range s {
		if count == n {
			return s[:i]
		}
		count++
	}
	return s
}

// values returns the items of a JSON list, or of a JSON object, which PHP also
// read as an array. The second result is false for anything else.
func values(v any) ([]any, bool) {
	switch x := v.(type) {
	case []any:
		return x, true
	case map[string]any:
		out := make([]any, 0, len(x))
		for _, item := range x {
			out = append(out, item)
		}
		return out, true
	}
	return nil, false
}
