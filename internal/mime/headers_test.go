// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package mime

import "testing"

// arch: T3.3, §3.14, §3.10, C20, C21, C22, M15
func TestParse_BadAddressList(t *testing.T) {
	if _, err := ParseAddressList("not an address <<<"); err == nil {
		t.Fatal("ParseAddressList: want an error for malformed input, got nil")
	}
}

// TestHeaders_AddressListQuotedComma is M15: "Smith, John" <j@x> must
// not be cut at the comma inside the quoted display name. Parsing
// through the library (net/mail, via go-message/mail), not a
// hand-written pattern, is what makes this safe.
//
// arch: T3.3, §3.14, §3.10, C20, C21, C22, M15
func TestHeaders_AddressListQuotedComma(t *testing.T) {
	got, err := ParseAddressList(`"Smith, John" <j@example.com>, second@example.com`)
	if err != nil {
		t.Fatalf("ParseAddressList: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("ParseAddressList: got %d addresses, want 2: %+v", len(got), got)
	}
	if got[0].Address != "j@example.com" {
		t.Errorf("address[0] = %q, want j@example.com", got[0].Address)
	}
	if got[0].Name != "Smith, John" {
		t.Errorf("name[0] = %q, want %q", got[0].Name, "Smith, John")
	}
	if got[1].Address != "second@example.com" {
		t.Errorf("address[1] = %q, want second@example.com", got[1].Address)
	}
}

// arch: T3.3, §3.14, §3.10, C20, C21, C22, M15
func TestParse_AddressListEmpty(t *testing.T) {
	got, err := ParseAddressList("  ")
	if err != nil {
		t.Fatalf("ParseAddressList: %v", err)
	}
	if got != nil {
		t.Errorf("ParseAddressList(blank) = %+v, want nil", got)
	}
}

// arch: T3.3, §3.14, §3.10, C20, C21, C22, M15
func TestDecodeHeaderText_Plain(t *testing.T) {
	got := DecodeHeaderText("plain subject, no encoded words")
	want := "plain subject, no encoded words"
	if got != want {
		t.Errorf("DecodeHeaderText = %q, want %q", got, want)
	}
}

// arch: T3.3, §3.14, §3.10, C20, C21, C22, M15
func TestDecodeHeaderText_EncodedWord(t *testing.T) {
	// "Café" as an RFC 2047 UTF-8 Q-encoded word.
	got := DecodeHeaderText("=?UTF-8?Q?Caf=C3=A9?=")
	if got != "Café" {
		t.Errorf("DecodeHeaderText = %q, want %q", got, "Café")
	}
}
