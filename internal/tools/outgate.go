// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// Output gate: the run-time check of the two zones of a tool result.
// Each string under a key named "untrusted" must be one fence of the
// nonce of this response. Each other string must match the closed
// grammar that its `strict` tag names. A result that fails does not
// leave the server.
//
// arch: DU4.1, DU0.1, DU9.1
package tools

import (
	"encoding"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"

	"github.com/amsys/mailbag-mcp/internal/guard"
)

// untrustedKey is the JSON name that starts the untrusted zone.
const untrustedKey = "untrusted"

// gateMaxDepth is the deepest nesting that the gate walks. A result is
// a shallow tree; a deeper value is refused, so a cycle cannot make the
// walk run without end.
const gateMaxDepth = 32

// headType is the type that every Out embeds as its first field.
var headType = reflect.TypeOf(Head{})

// The marshaler types. A value of such a type has a JSON form that
// the walk cannot see, so the gate refuses it.
var (
	jsonMarshalerType = reflect.TypeOf((*json.Marshaler)(nil)).Elem()
	textMarshalerType = reflect.TypeOf((*encoding.TextMarshaler)(nil)).Elem()
)

// checkOut checks the result out of one call against the two zones of
// DU4.1, for the response of f. It returns nil when out can leave the
// server. Else it returns an error whose text is the path of the first
// field that fails and a fixed reason. The path holds only Go names
// and indexes, never a field value, so the error text is server text.
//
// Rules:
//   - out is a struct, or a pointer to one, with [Head] as its first,
//     embedded field with no json tag. Head.Fence must equal
//     f.Nonce().
//   - A field with the JSON name "untrusted" holds a struct or a
//     pointer to one (DU5.1).
//   - Under a field with the JSON name "untrusted", each string, and
//     each element of a string slice, must satisfy f.Holds. Numbers
//     and bools are refused there.
//   - Outside that zone, each string must have a `strict` tag and pass
//     guard.Strict for its kind, or the note registry for kind "note".
//   - An empty string passes only for a field with omitempty.
//   - A map, an interface, a []byte, a marshaler type, a channel, a
//     func and a complex number are refused, also when empty.
//   - Fields that encoding/json does not write are not walked.
//
// arch: DU4.1, DU2.1, DU3.1, DU3.5, DU5.1
func checkOut(f guard.Fencer, out any) error {
	v := reflect.ValueOf(out)
	for v.IsValid() && v.Kind() == reflect.Pointer {
		if v.IsNil() {
			break
		}
		v = v.Elem()
	}
	if !v.IsValid() || v.Kind() != reflect.Struct {
		return errors.New("out: the result is not a struct")
	}
	tp := v.Type()
	root := tp.Name()
	if root == "" {
		root = "out"
	}
	if tp.NumField() == 0 || !tp.Field(0).Anonymous || tp.Field(0).Type != headType {
		return fmt.Errorf("%s: Head is not the first, embedded field", root)
	}
	// A JSON tag on Head would hide "fence" or move it under another
	// key, so it would not be the first key of the result (INV-4).
	if _, tagged := tp.Field(0).Tag.Lookup("json"); tagged {
		return fmt.Errorf("%s: Head has a json tag; encoding/json must promote its fields", root)
	}
	g := gate{f: f}
	return g.walk(v, root, zoneCtx{}, 0)
}

// zoneCtx is what the gate knows about the field that holds a value.
type zoneCtx struct {
	// untrusted is true under a field with the JSON name "untrusted".
	untrusted bool
	// kind is the `strict` tag of the field; empty when it has none.
	kind string
	// omit is true when the field has omitempty and the value is the
	// field itself, not an element or a pointer target.
	omit bool
}

// gate holds the Fencer of one check.
type gate struct {
	f guard.Fencer
}

// refuse gives the error of a failed field.
func refuse(path, reason string) error {
	return fmt.Errorf("%s: %s", path, reason)
}

// walk checks v, found at path, in the zone c.
func (g gate) walk(v reflect.Value, path string, c zoneCtx, depth int) error {
	if depth > gateMaxDepth {
		return refuse(path, "the value is nested too deep")
	}
	tp := v.Type()
	if tp.Implements(jsonMarshalerType) || reflect.PointerTo(tp).Implements(jsonMarshalerType) ||
		tp.Implements(textMarshalerType) || reflect.PointerTo(tp).Implements(textMarshalerType) {
		return refuse(path, "a marshaler type is not allowed")
	}
	switch v.Kind() {
	case reflect.String:
		return g.str(v.String(), path, c)
	case reflect.Bool,
		reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr,
		reflect.Float32, reflect.Float64:
		if c.untrusted {
			return refuse(path, "a number or a bool is not allowed under untrusted")
		}
		return nil
	case reflect.Pointer:
		if v.IsNil() {
			return nil
		}
		c.omit = false
		return g.walk(v.Elem(), path, c, depth+1)
	case reflect.Slice, reflect.Array:
		if v.Kind() == reflect.Slice && tp.Elem().Kind() == reflect.Uint8 {
			return refuse(path, "a byte slice is not allowed")
		}
		c.omit = false
		for i := 0; i < v.Len(); i++ {
			if err := g.walk(v.Index(i), fmt.Sprintf("%s[%d]", path, i), c, depth+1); err != nil {
				return err
			}
		}
		return nil
	case reflect.Struct:
		return g.fields(v, path, c, depth)
	default:
		// Map, Interface, Chan, Func, Complex64, Complex128 and
		// UnsafePointer.
		return refuse(path, "a "+v.Kind().String()+" is not allowed")
	}
}

// fields checks each field of the struct v that encoding/json writes.
func (g gate) fields(v reflect.Value, path string, c zoneCtx, depth int) error {
	tp := v.Type()
	for i := 0; i < tp.NumField(); i++ {
		sf := tp.Field(i)
		name, opts, skip := jsonField(sf)
		if skip {
			continue
		}
		fc := zoneCtx{untrusted: c.untrusted || name == untrustedKey, kind: sf.Tag.Get("strict")}
		fc.omit = hasOpt(opts, "omitempty")
		fp := path + "." + sf.Name
		if name == untrustedKey && !isObject(sf.Type) {
			// One joined string would let a line break in a subject
			// make a second "from" line inside the fence (DU5.1).
			return refuse(fp, "the untrusted key must hold an object of named fields")
		}
		if name == "" {
			// An embedded struct with no JSON name: encoding/json
			// writes its fields at this level. omitempty does not
			// apply to it.
			fc.kind, fc.omit = "", false
		}
		if err := g.walk(v.Field(i), fp, fc, depth+1); err != nil {
			return err
		}
	}
	return nil
}

// jsonField gives the JSON name and the options of sf, as
// encoding/json reads them. The name is empty for an embedded struct
// whose fields encoding/json promotes. skip is true for a field that
// encoding/json does not write.
func jsonField(sf reflect.StructField) (name, opts string, skip bool) {
	tag := sf.Tag.Get("json")
	if tag == "-" {
		return "", "", true
	}
	name, opts, _ = strings.Cut(tag, ",")
	if sf.Anonymous {
		t := sf.Type
		if t.Kind() == reflect.Pointer {
			t = t.Elem()
		}
		if !sf.IsExported() && t.Kind() != reflect.Struct {
			return "", "", true
		}
		if name == "" && t.Kind() == reflect.Struct {
			return "", opts, false
		}
	} else if !sf.IsExported() {
		return "", "", true
	}
	if name == "" {
		name = sf.Name
	}
	return name, opts, false
}

// isObject reports whether encoding/json writes a value of type t as a
// JSON object: a struct, or a pointer to one.
func isObject(t reflect.Type) bool {
	if t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	return t.Kind() == reflect.Struct
}

// hasOpt reports whether the comma-separated options opts hold o.
func hasOpt(opts, o string) bool {
	for _, x := range strings.Split(opts, ",") {
		if x == o {
			return true
		}
	}
	return false
}

// str checks one string s in the zone c.
func (g gate) str(s, path string, c zoneCtx) error {
	if s == "" {
		if c.omit {
			return nil
		}
		return refuse(path, "the value is empty and the field has no omitempty")
	}
	if c.untrusted {
		if !g.f.Holds(s) {
			return refuse(path, "the value is not one fence of this response")
		}
		return nil
	}
	switch c.kind {
	case "":
		return refuse(path, "the field has no strict tag")
	case "note":
		if _, ok := strictNote(s); !ok {
			return refuse(path, "the note matches no form of the registry")
		}
		return nil
	case "nonce":
		// The fence must be the nonce of this response, not only a
		// value of the right form (INV-2, INV-4).
		if s != g.f.Nonce() || !guard.Strict("nonce", s) {
			return refuse(path, "the value is not the nonce of this response")
		}
		return nil
	}
	if !guard.Strict(c.kind, s) {
		return refuse(path, "the value does not match the strict kind "+c.kind)
	}
	return nil
}
