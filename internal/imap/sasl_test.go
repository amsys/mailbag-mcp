// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package imap

import (
	"encoding/base64"
	"testing"
)

// TestXOAUTH2_InitialResponse checks the exact bytes of the initial
// response and its base64 form.
// arch: T4.1, §3.6, §3.10, §3.11, B12
func TestXOAUTH2_InitialResponse(t *testing.T) {
	// Arrange
	c := NewXOAUTH2("bob@example.com", "tok123")

	// Act
	mech, ir, err := c.Start()

	// Assert
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if mech != "XOAUTH2" {
		t.Errorf("mech = %q, want XOAUTH2", mech)
	}
	want := "user=bob@example.com\x01auth=Bearer tok123\x01\x01"
	if string(ir) != want {
		t.Errorf("ir = %q, want %q", ir, want)
	}
	const wantB64 = "dXNlcj1ib2JAZXhhbXBsZS5jb20BYXV0aD1CZWFyZXIgdG9rMTIzAQE="
	if got := base64.StdEncoding.EncodeToString(ir); got != wantB64 {
		t.Errorf("base64 = %q, want %q", got, wantB64)
	}
}

// TestXOAUTH2_EmptyReplyToChallenge checks that a server challenge gets an
// empty, not nil, response, and that a second challenge is an error.
// arch: T4.1, §3.6, §3.10, §3.11, B12
func TestXOAUTH2_EmptyReplyToChallenge(t *testing.T) {
	// Arrange
	c := NewXOAUTH2("bob@example.com", "tok123")
	if _, _, err := c.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	challenge := []byte(`{"status":"400","schemes":"Bearer"}`)

	// Act
	resp, err := c.Next(challenge)

	// Assert
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	if resp == nil {
		t.Fatal("response is nil, want an empty but not nil response")
	}
	if len(resp) != 0 {
		t.Errorf("response = %q, want empty", resp)
	}
	if _, err := c.Next(challenge); err == nil {
		t.Error("second challenge: got no error, want one")
	}
}

// TestLOGIN_Steps checks the two steps of the LOGIN mechanism.
// arch: T4.1, §3.6, §3.10, §3.11, B12
func TestLOGIN_Steps(t *testing.T) {
	// Arrange
	c := NewLOGIN("bob", "s3cret")

	// Act
	mech, ir, err := c.Start()

	// Assert
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if mech != "LOGIN" {
		t.Errorf("mech = %q, want LOGIN", mech)
	}
	if string(ir) != "bob" {
		t.Errorf("ir = %q, want %q", ir, "bob")
	}
	resp, err := c.Next([]byte("Password:"))
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	if string(resp) != "s3cret" {
		t.Errorf("response = %q, want %q", resp, "s3cret")
	}
	if _, err := c.Next([]byte("Nonsense:")); err == nil {
		t.Error("bad challenge: got no error, want one")
	}
}
