package mobileconfig

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
)

// A small reader of Apple XML property lists, used only by the tests. It is
// written separately from the writer on purpose: a test that read the file with
// the writer's own assumptions could not catch the writer's mistakes.

type pDict struct {
	keys  []string
	m     map[string]any
	elems int // elements in the whole document, set on the root only
}

func (d pDict) Has(k string) bool { _, ok := d.m[k]; return ok }
func (d pDict) Keys() []string    { return d.keys }
func (d pDict) String(k string) string {
	s, _ := d.m[k].(string)
	return s
}
func (d pDict) Bool(k string) (v, ok bool) { v, ok = d.m[k].(bool); return }
func (d pDict) Array(k string) []any {
	a, _ := d.m[k].([]any)
	return a
}
func (d pDict) Dict(k string) pDict {
	x, _ := d.m[k].(pDict)
	return x
}
func (d pDict) ElementCount() int { return d.elems }

func (d pDict) walk(f func(key string, v any)) {
	for _, k := range d.keys {
		f(k, d.m[k])
		walkValue(d.m[k], f)
	}
}

func walkValue(v any, f func(key string, v any)) {
	switch x := v.(type) {
	case pDict:
		x.walk(f)
	case []any:
		for _, e := range x {
			walkValue(e, f)
		}
	}
}

// AllKeys lists the key of every dict at every depth.
func (d pDict) AllKeys() []string {
	var out []string
	d.walk(func(k string, _ any) { out = append(out, k) })
	return out
}

// AllStrings lists the string values of every key called name at every depth.
func (d pDict) AllStrings(name string) []string {
	var out []string
	d.walk(func(k string, v any) {
		if s, ok := v.(string); ok && k == name {
			out = append(out, s)
		}
	})
	return out
}

func parsePlist(b []byte) (pDict, error) {
	dec := xml.NewDecoder(bytes.NewReader(b))
	dec.Strict = true
	elems := 0
	next := func() (xml.Token, error) {
		for {
			tok, err := dec.Token()
			if err != nil {
				return nil, err
			}
			switch t := tok.(type) {
			case xml.StartElement:
				elems++
				return tok, nil
			case xml.EndElement:
				return tok, nil
			case xml.CharData:
				if len(bytes.TrimSpace(t)) == 0 {
					continue
				}
				return tok, nil
			}
		}
	}
	var value func(start xml.StartElement) (any, error)
	text := func(name string) (string, error) {
		var s []byte
		for {
			tok, err := next()
			if err != nil {
				return "", err
			}
			switch t := tok.(type) {
			case xml.CharData:
				s = append(s, t...)
			case xml.EndElement:
				if t.Name.Local != name {
					return "", fmt.Errorf("</%s> closes <%s>", t.Name.Local, name)
				}
				return string(s), nil
			default:
				return "", fmt.Errorf("element inside <%s>", name)
			}
		}
	}
	value = func(start xml.StartElement) (any, error) {
		switch start.Name.Local {
		case "dict":
			d := pDict{m: map[string]any{}}
			for {
				tok, err := next()
				if err != nil {
					return nil, err
				}
				if _, ok := tok.(xml.EndElement); ok {
					return d, nil
				}
				ks, ok := tok.(xml.StartElement)
				if !ok || ks.Name.Local != "key" {
					return nil, errors.New("dict child is not a key")
				}
				k, err := text("key")
				if err != nil {
					return nil, err
				}
				if _, dup := d.m[k]; dup {
					return nil, fmt.Errorf("key %q twice", k)
				}
				vt, err := next()
				if err != nil {
					return nil, err
				}
				vs, ok := vt.(xml.StartElement)
				if !ok {
					return nil, errors.New("key without a value")
				}
				v, err := value(vs)
				if err != nil {
					return nil, err
				}
				d.keys = append(d.keys, k)
				d.m[k] = v
			}
		case "array":
			a := []any{}
			for {
				tok, err := next()
				if err != nil {
					return nil, err
				}
				if _, ok := tok.(xml.EndElement); ok {
					return a, nil
				}
				vs, ok := tok.(xml.StartElement)
				if !ok {
					return nil, errors.New("text in an array")
				}
				v, err := value(vs)
				if err != nil {
					return nil, err
				}
				a = append(a, v)
			}
		case "string", "data", "integer", "date", "real":
			return text(start.Name.Local)
		case "true", "false":
			tok, err := next()
			if err != nil {
				return nil, err
			}
			if e, ok := tok.(xml.EndElement); !ok || e.Name.Local != start.Name.Local {
				return nil, errors.New("a boolean with content")
			}
			return start.Name.Local == "true", nil
		}
		return nil, fmt.Errorf("unknown element <%s>", start.Name.Local)
	}

	for {
		tok, err := next()
		if errors.Is(err, io.EOF) {
			return pDict{}, errors.New("no plist element")
		}
		if err != nil {
			return pDict{}, err
		}
		start, ok := tok.(xml.StartElement)
		if !ok || start.Name.Local != "plist" {
			return pDict{}, errors.New("the document is not a plist")
		}
		tok, err = next()
		if err != nil {
			return pDict{}, err
		}
		root, ok := tok.(xml.StartElement)
		if !ok || root.Name.Local != "dict" {
			return pDict{}, errors.New("the root is not a dict")
		}
		v, err := value(root)
		if err != nil {
			return pDict{}, err
		}
		if tok, err = next(); err != nil {
			return pDict{}, err
		}
		if e, ok := tok.(xml.EndElement); !ok || e.Name.Local != "plist" {
			return pDict{}, errors.New("content after the root dict")
		}
		if tok, err = next(); !errors.Is(err, io.EOF) {
			return pDict{}, errors.New("content after the plist")
		}
		d := v.(pDict)
		d.elems = elems
		return d, nil
	}
}
