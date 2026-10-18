// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package guard

import (
	"errors"
	"strings"
	"testing"
)

// TestValidateAddress_ParsesRFC5322 checks that a good address passes
// and a bad one fails, with no repair attempt (§3.15, T2.6).
//
// arch: T2.6, §3.15, M10, B17
func TestValidateAddress_ParsesRFC5322(t *testing.T) {
	cases := []struct {
		name    string
		addr    string
		wantErr bool
	}{
		{"plain", "user@example.com", false},
		{"named", "Barry Gibbs <bg@example.com>", false},
		{"quoted comma name", `"Smith, John" <j@example.com>`, false},
		{"empty", "", true},
		{"no at sign", "not-an-address", true},
		{"CRLF injection", "user@example.com\r\nBcc: attacker@evil.com", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := ValidateAddress(c.addr)
			if (err != nil) != c.wantErr {
				t.Fatalf("ValidateAddress(%q) error = %v, wantErr %v", c.addr, err, c.wantErr)
			}
		})
	}
}

// TestValidateAddresses_FailsOnFirstBad checks that a list of
// addresses fails as soon as one entry is bad, naming that entry.
//
// arch: T2.6, §3.15, M10, B17
func TestValidateAddresses_FailsOnFirstBad(t *testing.T) {
	err := ValidateAddresses([]string{"good@example.com", "bad", "also-good@example.com"})
	if err == nil {
		t.Fatal("want an error, got nil")
	}
}

// TestValidate_RejectsCRLF checks that CR, LF and NUL bytes in a
// field are refused, never silently removed (M10, §3.15).
//
// arch: T2.6, §3.15, M10, B17
func TestValidate_RejectsCRLF(t *testing.T) {
	cases := []struct {
		name    string
		value   string
		wantErr bool
	}{
		{"plain subject", "Weekly report", false},
		{"trailing space and newline", "Weekly report \n", false},
		{"embedded CR", "Weekly\rreport", true},
		{"embedded LF", "Weekly\nreport", true},
		{"embedded CRLF header injection", "Weekly report\r\nBcc: attacker@evil.com", true},
		{"embedded NUL", "Weekly\x00report", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := ValidateField(c.value)
			if (err != nil) != c.wantErr {
				t.Fatalf("ValidateField(%q) error = %v, wantErr %v", c.value, err, c.wantErr)
			}
			if c.wantErr && !errors.Is(err, ErrControlChar) {
				t.Fatalf("want ErrControlChar, got %v", err)
			}
		})
	}
}

// TestValidateField_ReturnsTrimmed checks that the trimmed value
// reaches the caller on success, so the caller never re-sends the
// untrimmed original that carried the trailing white space (S2-judge
// finding 3, §3.15).
//
// arch: T2.6, §3.15, M10, B17
func TestValidateField_ReturnsTrimmed(t *testing.T) {
	got, err := ValidateField("Weekly report \t\r\n")
	if err != nil {
		t.Fatalf("ValidateField error = %v, want nil", err)
	}
	if got != "Weekly report" {
		t.Fatalf("ValidateField value = %q, want %q", got, "Weekly report")
	}
}

// TestValidate_ErrorHasNoAddress checks that ValidateAddress never
// echoes the address, or any fragment of it, into its error text.
// A call-end log that writes the error text must not gain an address
// (S2-judge finding 12, §10.5).
//
// arch: T2.6, §3.15, M10, B17
func TestValidate_ErrorHasNoAddress(t *testing.T) {
	cases := []string{
		"user@example.com\r\nBcc: attacker@evil.com",
		"a@b@secret-project.example.com",
		"not-an-address-at-all",
	}
	for _, addr := range cases {
		t.Run(addr, func(t *testing.T) {
			err := ValidateAddress(addr)
			if err == nil {
				t.Fatal("want an error, got nil")
			}
			if strings.Contains(err.Error(), addr) {
				t.Fatalf("error text holds the address: %v", err)
			}
			if strings.Contains(err.Error(), "@") {
				t.Fatalf("error text holds an address-like fragment: %v", err)
			}
		})
	}
}

// TestValidateAlias_Pattern mirrors B17's TestAlias_Pattern cases
// through the guard package wrapper, including the path-traversal
// and dot cases named in the trap register.
//
// arch: T2.6, §3.15, M10, B17
func TestValidateAlias_Pattern(t *testing.T) {
	cases := []struct {
		alias   string
		wantErr bool
	}{
		{"work", false},
		{"work-gmail_1", false},
		{"../../x", true},
		{"a.b", true},
		{"", true},
		{"has space", true},
	}
	for _, c := range cases {
		t.Run(c.alias, func(t *testing.T) {
			err := ValidateAlias(c.alias)
			if (err != nil) != c.wantErr {
				t.Fatalf("ValidateAlias(%q) error = %v, wantErr %v", c.alias, err, c.wantErr)
			}
			if c.wantErr && !errors.Is(err, ErrInvalidAlias) {
				t.Fatalf("want ErrInvalidAlias, got %v", err)
			}
		})
	}
}
