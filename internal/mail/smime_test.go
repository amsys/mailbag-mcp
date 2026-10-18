// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// This file tests the S/MIME kind predicate SMIMEKindOf and
// SMIMEKindOfValue (DR1G.2, DR1G.18.1).

package mail

import "testing"

// TestSMIMEKindOf_Table checks each kind that SMIMEKindOf gives from a
// media type and a parameter map, including the fail-closed cases: no
// smime-type, an other smime-type and two differing values.
//
// arch: DR1G.2, DR1G.18, IR1G.2
func TestSMIMEKindOf_Table(t *testing.T) {
	cases := []struct {
		name   string
		mt     string
		params map[string]string
		want   SMIMEKind
	}{
		{"signed", "application/pkcs7-mime", map[string]string{"smime-type": "signed-data"}, SMIMESigned},
		{"enveloped", "application/pkcs7-mime", map[string]string{"smime-type": "enveloped-data"}, SMIMEEnveloped},
		{"authenveloped", "application/pkcs7-mime", map[string]string{"smime-type": "authenveloped-data"}, SMIMEEnveloped},
		{"old name signed", "application/x-pkcs7-mime", map[string]string{"smime-type": "signed-data"}, SMIMESigned},
		{"old name enveloped", "application/x-pkcs7-mime", map[string]string{"smime-type": "enveloped-data"}, SMIMEEnveloped},
		{"no param", "application/pkcs7-mime", nil, SMIMEUnknown},
		{"other param only", "application/pkcs7-mime", map[string]string{"name": "smime.p7m"}, SMIMEUnknown},
		{"certs-only", "application/pkcs7-mime", map[string]string{"smime-type": "certs-only"}, SMIMEUnknown},
		{"compressed", "application/pkcs7-mime", map[string]string{"smime-type": "compressed-data"}, SMIMEUnknown},
		{"empty value", "application/pkcs7-mime", map[string]string{"smime-type": ""}, SMIMEUnknown},
		{"two values differ", "application/pkcs7-mime", map[string]string{"smime-type": "signed-data", "SMIME-TYPE": "enveloped-data"}, SMIMEUnknown},
		{"two values same", "application/pkcs7-mime", map[string]string{"smime-type": "signed-data", "Smime-Type": "Signed-Data"}, SMIMESigned},
		{"signature part", "application/pkcs7-signature", map[string]string{"smime-type": "signed-data"}, SMIMENone},
		{"multipart signed", "multipart/signed", map[string]string{"protocol": "application/pkcs7-signature"}, SMIMENone},
		{"text", "text/plain", map[string]string{"smime-type": "enveloped-data"}, SMIMENone},
		{"empty type", "", nil, SMIMENone},
	}
	for _, c := range cases {
		if got := SMIMEKindOf(c.mt, c.params); got != c.want {
			t.Errorf("%s: SMIMEKindOf(%q, %v) = %d, want %d", c.name, c.mt, c.params, got, c.want)
		}
	}
}

// TestSMIMEKindOf_RFC2231KeyUnknown checks that an RFC 2231 form of
// the smime-type key gives SMIMEUnknown for a pkcs7-mime type, alone or
// beside a plain key, in any case. The fetch gate and the verifier walk
// then fail closed. A type that is not pkcs7-mime still gives
// SMIMENone.
//
// arch: DR1G.2, DR1G.18.1, IR1G.2, IR1G.3
func TestSMIMEKindOf_RFC2231KeyUnknown(t *testing.T) {
	cases := []struct {
		name   string
		mt     string
		params map[string]string
		want   SMIMEKind
	}{
		{"continued key alone", "application/pkcs7-mime", map[string]string{"smime-type*0": "enveloped-data"}, SMIMEUnknown},
		{"continued key beside enveloped", "application/pkcs7-mime", map[string]string{"smime-type": "enveloped-data", "smime-type*0": "enveloped-data"}, SMIMEUnknown},
		{"second segment beside enveloped", "application/x-pkcs7-mime", map[string]string{"smime-type": "enveloped-data", "smime-type*1": "x"}, SMIMEUnknown},
		{"extended key mixed case", "application/pkcs7-mime", map[string]string{"smime-type": "enveloped-data", "SMIME-Type*": "us-ascii''enveloped-data"}, SMIMEUnknown},
		{"extended key beside signed", "application/pkcs7-mime", map[string]string{"smime-type": "signed-data", "smime-type*": "us-ascii''signed-data"}, SMIMEUnknown},
		{"text type with key", "text/plain", map[string]string{"smime-type*0": "enveloped-data"}, SMIMENone},
		{"signature type with key", "application/pkcs7-signature", map[string]string{"smime-type": "signed-data", "smime-type*": "signed-data"}, SMIMENone},
		{"similar key is not a form", "application/pkcs7-mime", map[string]string{"smime-type": "enveloped-data", "smime-types": "x"}, SMIMEEnveloped},
	}
	for _, c := range cases {
		if got := SMIMEKindOf(c.mt, c.params); got != c.want {
			t.Errorf("%s: SMIMEKindOf(%q, %v) = %d, want %d", c.name, c.mt, c.params, got, c.want)
		}
	}
}

// TestSMIMEKindOf_IgnoresCase checks that the case of the media type,
// of the parameter key and of the value does not change the kind, and
// that outer white space does not either.
//
// arch: DR1G.2, DR1G.18, IR1G.2
func TestSMIMEKindOf_IgnoresCase(t *testing.T) {
	cases := []struct {
		mt     string
		params map[string]string
		want   SMIMEKind
	}{
		{"Application/PKCS7-MIME", map[string]string{"smime-type": "signed-data"}, SMIMESigned},
		{"application/pkcs7-mime", map[string]string{"SMIME-Type": "signed-data"}, SMIMESigned},
		{"application/pkcs7-mime", map[string]string{"smime-type": "Signed-Data"}, SMIMESigned},
		{"APPLICATION/X-PKCS7-MIME", map[string]string{"Smime-Type": "ENVELOPED-DATA"}, SMIMEEnveloped},
		{"application/pkcs7-mime", map[string]string{"smime-type": "AuthEnveloped-Data"}, SMIMEEnveloped},
		{" application/pkcs7-mime ", map[string]string{"smime-type": " enveloped-data "}, SMIMEEnveloped},
	}
	for _, c := range cases {
		if got := SMIMEKindOf(c.mt, c.params); got != c.want {
			t.Errorf("SMIMEKindOf(%q, %v) = %d, want %d", c.mt, c.params, got, c.want)
		}
	}
}

// TestSMIMEKindOfValue_Table checks the string form that callers with
// a stored smime-type value use, and that SMIMEKindOf agrees with it
// for the same input.
//
// arch: DR1G.2, DR1G.18, IR1G.2
func TestSMIMEKindOfValue_Table(t *testing.T) {
	cases := []struct {
		mt, st string
		want   SMIMEKind
	}{
		{"application/pkcs7-mime", "signed-data", SMIMESigned},
		{"application/pkcs7-mime", "enveloped-data", SMIMEEnveloped},
		{"application/pkcs7-mime", "authenveloped-data", SMIMEEnveloped},
		{"application/x-pkcs7-mime", "ENVELOPED-DATA", SMIMEEnveloped},
		{"application/pkcs7-mime", "", SMIMEUnknown},
		{"application/pkcs7-mime", "certs-only", SMIMEUnknown},
		{"application/pkcs7-mime", "signed-data; x=y", SMIMEUnknown},
		{"application/pkcs7-signature", "", SMIMENone},
		{"multipart/encrypted", "", SMIMENone},
		{"text/plain", "signed-data", SMIMENone},
		{"", "", SMIMENone},
	}
	for _, c := range cases {
		if got := SMIMEKindOfValue(c.mt, c.st); got != c.want {
			t.Errorf("SMIMEKindOfValue(%q, %q) = %d, want %d", c.mt, c.st, got, c.want)
		}
		if got := SMIMEKindOf(c.mt, map[string]string{"smime-type": c.st}); got != c.want {
			t.Errorf("SMIMEKindOf(%q, smime-type %q) = %d, want %d (same as SMIMEKindOfValue)", c.mt, c.st, got, c.want)
		}
	}
}
