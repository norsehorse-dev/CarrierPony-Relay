package api

import (
	"encoding/json"
	"strings"
	"testing"
)

func decode(t *testing.T, s string) any {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(s))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		t.Fatalf("%s: %v", s, err)
	}
	return v
}

func TestTruthy(t *testing.T) {
	for in, want := range map[string]bool{
		`null`: false, `false`: false, `0`: false, `0.0`: false, `""`: false, `"0"`: false, `[]`: false, `{}`: false,
		`true`: true, `1`: true, `-1`: true, `0.5`: true, `"1"`: true, `"false"`: true, `"00"`: true, `" "`: true, `[0]`: true, `{"a":0}`: true,
	} {
		if got := truthy(decode(t, in)); got != want {
			t.Errorf("truthy(%s) = %v, want %v", in, got, want)
		}
	}
}

func TestInteger(t *testing.T) {
	for in, want := range map[string]int64{
		`null`: 0, `false`: 0, `true`: 1, `0`: 0, `1763420000`: 1763420000, `-5`: -5, `12.9`: 12, `-12.9`: -12, `1e3`: 1000,
		`"1763420000"`: 1763420000, `" 42"`: 42, `"42abc"`: 42, `"abc"`: 0, `""`: 0, `"1e3"`: 1000, `"12.9"`: 12, `"-7"`: -7,
		`"+7"`: 7, `"."`: 0, `"1e"`: 1, `[]`: 0, `[1]`: 1, `{}`: 0, `1e400`: 0, `99999999999999999999`: 0,
	} {
		if got := integer(decode(t, in)); got != want {
			t.Errorf("integer(%s) = %d, want %d", in, got, want)
		}
	}
}

func TestCutBytesKeepsWholeCharacters(t *testing.T) {
	if got := cutBytes(strings.Repeat("a", 70), 64); len(got) != 64 {
		t.Errorf("ascii cut to %d bytes", len(got))
	}
	// 63 one-byte characters, then a three-byte one that would straddle the cut.
	in := strings.Repeat("a", 63) + "€" + "tail"
	if got := cutBytes(in, 64); got != strings.Repeat("a", 63) {
		t.Errorf("cut left %q", got[60:])
	}
	if got := cutBytes("short", 64); got != "short" {
		t.Errorf("a short string was changed: %q", got)
	}
}

func TestCutChars(t *testing.T) {
	if got := cutChars(strings.Repeat("€", 10), 4); got != strings.Repeat("€", 4) {
		t.Errorf("got %q", got)
	}
	if got := cutChars("abc", 4); got != "abc" {
		t.Errorf("got %q", got)
	}
}

func TestEnvelopeSize(t *testing.T) {
	for in, want := range map[string]int64{"QUJD": 3, "QUI=": 2, "QQ==": 1, "QUJDREVG": 6, "ab+/": 3} {
		if got, ok := envelopeSize(in); !ok || got != want {
			t.Errorf("envelopeSize(%q) = %d, %v, want %d", in, got, ok, want)
		}
	}
	for _, in := range []string{"", "abc", "abcde", "!!!!", "ab-_", "ab=c", "a=bc", "=abc", "abc=defg", "ab==cdef", "QUJD\n", "QQ=="[:3] + " ", "===="} {
		if _, ok := envelopeSize(in); ok {
			t.Errorf("envelopeSize(%q) was accepted", in)
		}
	}
}

func TestPickWithinBudget(t *testing.T) {
	c := func(sizes ...int64) []candidate {
		out := make([]candidate, len(sizes))
		for i, s := range sizes {
			out[i] = candidate{id: int64(i + 1), size: s}
		}
		return out
	}
	for _, tc := range []struct {
		name    string
		waiting []candidate
		budget  int64
		want    []int64
	}{
		{"nothing waiting", nil, 100, nil},
		{"everything fits", c(10, 20, 30), 100, []int64{1, 2, 3}},
		{"stops when the budget is reached", c(50, 50, 10), 100, []int64{1, 2}},
		{"one over the budget goes alone", c(150, 10), 100, []int64{1}},
		{"a later one over the budget waits, smaller ones behind it go", c(40, 150, 30), 100, []int64{1, 3}},
		{"skips what does not fit and keeps looking", c(60, 60, 30), 100, []int64{1, 3}},
	} {
		got := pickWithinBudget(tc.waiting, tc.budget)
		if len(got) != len(tc.want) {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
				break
			}
		}
	}
}
