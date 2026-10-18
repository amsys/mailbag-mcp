// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package mail

import "testing"

// TestCursor_RoundTrip checks that DecodeCursor reads back exactly
// what EncodeCursor wrote (§3.9).
//
// arch: T3.1, §3.7, §3.8, §3.9, C6
func TestCursor_RoundTrip(t *testing.T) {
	cases := []Cursor{
		{Position: "4211", QueryHash: "abc123"},
		{Position: "", QueryHash: ""},
		{Position: "pageToken-xyz", QueryHash: "deadbeef"},
	}
	for _, c := range cases {
		enc := EncodeCursor(c)
		got, err := DecodeCursor(enc)
		if err != nil {
			t.Fatalf("DecodeCursor(%q): %v", enc, err)
		}
		if got != c {
			t.Fatalf("round trip mismatch: got %+v, want %+v", got, c)
		}
	}
}

// TestCursor_DecodeRejectsGarbage checks that a string EncodeCursor did
// not produce fails cleanly. The cursor argument comes from a tool
// call, so it is attacker-controlled (§3.9, §3.15).
//
// arch: T3.1, §3.7, §3.8, §3.9, C6
func TestCursor_DecodeRejectsGarbage(t *testing.T) {
	cases := []string{
		"",
		"not base64!!!",
		"aGVsbG8", // valid base64url, but not JSON ("hello")
	}
	for _, s := range cases {
		if _, err := DecodeCursor(s); err == nil {
			t.Fatalf("DecodeCursor(%q): want an error, got none", s)
		}
	}
}

// TestCursor_ValidateRefusesQueryMismatch checks that a cursor built
// for one query is refused for a different one, so a caller cannot
// reuse a page position across an unrelated search (§3.9).
//
// arch: T3.1, §3.7, §3.8, §3.9, C6
func TestCursor_ValidateRefusesQueryMismatch(t *testing.T) {
	q1 := Query{Raw: "from:a@example.com", Folder: "INBOX"}
	q2 := Query{Raw: "from:b@example.com", Folder: "INBOX"}

	cur := EncodeCursor(Cursor{Position: "100", QueryHash: HashQuery(q1)})

	if _, err := ValidateCursor(cur, q1); err != nil {
		t.Fatalf("ValidateCursor with the matching query: %v", err)
	}
	if _, err := ValidateCursor(cur, q2); err == nil {
		t.Fatalf("ValidateCursor with a different query: want an error, got none")
	}
}

// TestCursor_EmptyIsFirstPage checks that an empty cursor string is
// always valid, because it means "the first page", with no query to
// mismatch against (§3.9).
//
// arch: T3.1, §3.7, §3.8, §3.9, C6
func TestCursor_EmptyIsFirstPage(t *testing.T) {
	c, err := ValidateCursor("", Query{Raw: "anything"})
	if err != nil {
		t.Fatalf("ValidateCursor(\"\", ...): %v", err)
	}
	if c != (Cursor{}) {
		t.Fatalf("ValidateCursor(\"\", ...) = %+v, want the zero Cursor", c)
	}
}

// TestCursor_RoundTripUIDValidity checks that UIDValidity, added for
// DRV.12, survives the same round trip as Position and QueryHash.
//
// arch: DRV.12
func TestCursor_RoundTripUIDValidity(t *testing.T) {
	c := Cursor{Position: "42", QueryHash: "abc123", UIDValidity: 778899}
	enc := EncodeCursor(c)
	got, err := DecodeCursor(enc)
	if err != nil {
		t.Fatalf("DecodeCursor(%q): %v", enc, err)
	}
	if got != c {
		t.Fatalf("round trip mismatch: got %+v, want %+v", got, c)
	}
}

// TestHashQuery_NoSeparatorCollision checks that a NUL byte inside
// Folder or Raw cannot shift the field boundary that HashQuery hashes
// on. Before this fix, {Folder:"A", Raw:"\x00B"} and
// {Folder:"A\x00", Raw:"B"} hashed to the same value, so a cursor
// built for one query was accepted for the other (§3.9).
//
// arch: T3.1, §3.7, §3.8, §3.9, C6
func TestHashQuery_NoSeparatorCollision(t *testing.T) {
	q1 := Query{Folder: "A", Raw: "\x00B"}
	q2 := Query{Folder: "A\x00", Raw: "B"}
	if HashQuery(q1) == HashQuery(q2) {
		t.Fatalf("HashQuery(%+v) == HashQuery(%+v): NUL byte shifts the field boundary", q1, q2)
	}
}

// FuzzCursor checks that DecodeCursor never fails to decode a string
// EncodeCursor produced, and that a cursor that decoded once decodes
// again after one more encode/decode round trip, for arbitrary
// Position and QueryHash content (§3.9).
//
// arch: T3.1, §3.7, §3.8, §3.9, C6
func FuzzCursor(f *testing.F) {
	f.Add("4211", "abc123")
	f.Add("", "")
	f.Add("page\x00token", "hash\nwith\nnewlines")
	f.Fuzz(func(t *testing.T, position, hash string) {
		want := Cursor{Position: position, QueryHash: hash}
		enc := EncodeCursor(want)
		got, err := DecodeCursor(enc)
		if err != nil {
			t.Fatalf("DecodeCursor(EncodeCursor(%+v)) failed: %v", want, err)
		}
		if got != want {
			t.Fatalf("round trip mismatch: got %+v, want %+v", got, want)
		}
	})
}
