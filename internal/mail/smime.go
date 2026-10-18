// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// This file holds the one S/MIME kind predicate. The fetch gate, the
// D7.3 encrypted note, the verifier walk, the decrypt input switch and
// the attachment kind all call it, so no other code compares
// smime-type values (DR1G.2, DR1G.18.1, IR1G.2).

package mail

import "strings"

// SMIMEKind is what an application/(x-)pkcs7-mime part says it holds.
//
// arch: DR1G.2, IR1G.2
type SMIMEKind int

const (
	// SMIMEUnknown is a pkcs7-mime part with no smime-type, with an
	// other smime-type, or with two smime-type values that differ.
	// It is the zero value. A caller that must fail closed treats it
	// as "can be signed" and as "not enveloped".
	SMIMEUnknown SMIMEKind = iota
	// SMIMESigned is smime-type=signed-data.
	SMIMESigned
	// SMIMEEnveloped is smime-type=enveloped-data or
	// authenveloped-data.
	SMIMEEnveloped
	// SMIMENone is a media type that is not a pkcs7-mime type.
	SMIMENone
)

// smimeTypeKey is the Content-Type parameter that names the kind
// (RFC 8551 section 3.2.2).
const smimeTypeKey = "smime-type"

// smimeTypeRFC2231Prefix starts each RFC 2231 form of the smime-type
// key: "smime-type*", "smime-type*0", "smime-type*1" and so on.
const smimeTypeRFC2231Prefix = smimeTypeKey + "*"

// SMIMEKindOf classifies one part from its media type and its
// Content-Type parameters. The comparison of the type, the key and
// the value ignores case. When two keys that differ only in case hold
// different values, the kind is SMIMEUnknown: the predicate does not
// pick one of them.
//
// A parameter map that holds an RFC 2231 form of the key
// ("smime-type*", "smime-type*0", ...) also gives SMIMEUnknown for a
// pkcs7-mime type. The predicate does not decode such a key, so the
// plain key and the encoded key could disagree. go-imap BODYSTRUCTURE
// params keep these keys; mime.ParseMediaType and go-message fold
// them into the plain key first. A media type that is not a
// pkcs7-mime type gives SMIMENone, as before.
//
// arch: DR1G.2, DR1G.18.1, IR1G.2, IR1G.3
func SMIMEKindOf(mediaType string, params map[string]string) SMIMEKind {
	var value string
	seen := false
	for k, v := range params {
		if strings.HasPrefix(strings.ToLower(k), smimeTypeRFC2231Prefix) {
			return SMIMEKindOfValue(mediaType, "")
		}
		if !strings.EqualFold(k, smimeTypeKey) {
			continue
		}
		v = strings.ToLower(strings.TrimSpace(v))
		if seen && v != value {
			return SMIMEKindOfValue(mediaType, "")
		}
		value, seen = v, true
	}
	return SMIMEKindOfValue(mediaType, value)
}

// SMIMEKindOfValue classifies one part from its media type and the
// value of its smime-type parameter. A caller that holds the value as
// a string, such as Message.SMIMEType or Attachment.SMIMEType, calls
// it. The comparison ignores case and outer white space.
//
// arch: DR1G.18.1, IR1G.2
func SMIMEKindOfValue(mediaType, smimeType string) SMIMEKind {
	switch strings.ToLower(strings.TrimSpace(mediaType)) {
	case "application/pkcs7-mime", "application/x-pkcs7-mime":
	default:
		return SMIMENone
	}
	switch strings.ToLower(strings.TrimSpace(smimeType)) {
	case "signed-data":
		return SMIMESigned
	case "enveloped-data", "authenveloped-data":
		return SMIMEEnveloped
	}
	return SMIMEUnknown
}
