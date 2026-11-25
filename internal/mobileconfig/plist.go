package mobileconfig

import (
	"bytes"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"strconv"
	"unicode/utf8"
)

// plist writes an Apple XML property list. Every character that came from a
// person or from the database goes through encoding/xml's encoder, which
// escapes it; only fixed markup is written as text, so an SSID holding <, & or
// ]]> cannot change the structure of the file (P3 7.3).
//
// The encoder replaces a character XML cannot carry with U+FFFD and says
// nothing, which would turn one SSID into another network's name. leaf
// therefore refuses such text itself, before the encoder sees it.
type plist struct {
	buf   bytes.Buffer
	enc   *xml.Encoder
	depth int
	err   error
}

func newPlist() *plist {
	p := &plist{}
	p.enc = xml.NewEncoder(&p.buf)
	p.markup("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
		"<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n" +
		"<plist version=\"1.0\">\n")
	return p
}

func (p *plist) fail(err error) {
	if p.err == nil {
		p.err = err
	}
}

// markup writes fixed text. It is called with literals only.
func (p *plist) markup(s string) {
	if p.err != nil {
		return
	}
	if err := p.enc.Flush(); err != nil {
		p.fail(err)
		return
	}
	p.buf.WriteString(s)
}

func (p *plist) indent() {
	for i := 0; i < p.depth; i++ {
		p.markup("\t")
	}
}

// leaf writes <tag>text</tag> on its own line.
func (p *plist) leaf(tag, text string) {
	if p.err != nil {
		return
	}
	if !xmlSafe(text) {
		p.fail(errors.New("mobileconfig: text that XML cannot carry"))
		return
	}
	p.indent()
	start := xml.StartElement{Name: xml.Name{Local: tag}}
	for _, tok := range []xml.Token{start, xml.CharData(text), start.End()} {
		if err := p.enc.EncodeToken(tok); err != nil {
			p.fail(err)
			return
		}
	}
	p.markup("\n")
}

func (p *plist) open(tag string) {
	p.indent()
	p.markup("<" + tag + ">\n")
	p.depth++
}

func (p *plist) close(tag string) {
	p.depth--
	p.indent()
	p.markup("</" + tag + ">\n")
}

func (p *plist) openDict()   { p.open("dict") }
func (p *plist) closeDict()  { p.close("dict") }
func (p *plist) openArray()  { p.open("array") }
func (p *plist) closeArray() { p.close("array") }

func (p *plist) key(k string)  { p.leaf("key", k) }
func (p *plist) str(v string)  { p.leaf("string", v) }
func (p *plist) integer(n int) { p.leaf("integer", strconv.Itoa(n)) }
func (p *plist) data(b []byte) { p.leaf("data", base64.StdEncoding.EncodeToString(b)) }
func (p *plist) strs(v []string) {
	p.openArray()
	for _, s := range v {
		p.str(s)
	}
	p.closeArray()
}

// boolean writes <true/> or <false/> as the empty element Apple's own files
// use; the encoder would write <true></true>.
func (p *plist) boolean(v bool) {
	p.indent()
	if v {
		p.markup("<true/>\n")
	} else {
		p.markup("<false/>\n")
	}
}

// finish closes the document and returns it.
func (p *plist) finish() ([]byte, error) {
	p.markup("</plist>\n")
	if p.err != nil {
		return nil, p.err
	}
	if err := p.enc.Flush(); err != nil {
		return nil, err
	}
	return p.buf.Bytes(), nil
}

// xmlSafe reports whether every rune of s is an XML 1.0 Char that is not a
// control character: tab, line feed and carriage return are legal XML, but no
// profile value needs them, and refusing them keeps one rule for all text.
func xmlSafe(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 0x20 && r <= 0x7e, r >= 0xa0 && r <= 0xd7ff, r >= 0xe000 && r <= 0xfffd, r >= 0x10000 && r <= 0x10ffff:
		default:
			return false
		}
	}
	return true
}
