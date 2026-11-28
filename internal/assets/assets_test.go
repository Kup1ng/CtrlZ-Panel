package assets

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

func gradient(w, h int) *image.NRGBA {
	img := image.NewNRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			img.Set(x, y, color.NRGBA{R: uint8(x), G: uint8(y), B: uint8(x ^ y), A: 255})
		}
	}
	return img
}

func encodePNG(t *testing.T, img image.Image) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := png.Encode(&b, img); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// chunk is a PNG chunk with a correct CRC.
func chunk(kind string, data []byte) []byte {
	var b bytes.Buffer
	_ = binary.Write(&b, binary.BigEndian, uint32(len(data)))
	b.WriteString(kind)
	b.Write(data)
	_ = binary.Write(&b, binary.BigEndian, crc32.ChecksumIEEE(append([]byte(kind), data...)))
	return b.Bytes()
}

// withChunk puts an extra chunk right after the signature and IHDR of a PNG.
func withChunk(png []byte, kind string, data []byte) []byte {
	const afterIHDR = 8 + 12 + 13
	out := append([]byte{}, png[:afterIHDR]...)
	out = append(out, chunk(kind, data)...)
	return append(out, png[afterIHDR:]...)
}

func decodeDims(t *testing.T, b []byte) (int, int, string) {
	t.Helper()
	cfg, format, err := image.DecodeConfig(bytes.NewReader(b))
	if err != nil {
		t.Fatalf("the output is no image: %v", err)
	}
	return cfg.Width, cfg.Height, format
}

func TestNormalizeWritesAPNGAgain(t *testing.T) {
	src := encodePNG(t, gradient(64, 32))
	out, err := norm(src)
	if err != nil {
		t.Fatal(err)
	}
	if w, h, f := decodeDims(t, out); w != 64 || h != 32 || f != "png" {
		t.Errorf("output is %dx%d %s", w, h, f)
	}
	// The same pixels.
	a, _ := png.Decode(bytes.NewReader(src))
	b, _ := png.Decode(bytes.NewReader(out))
	for _, p := range [][2]int{{0, 0}, {63, 31}, {10, 20}} {
		ar, ag, ab, aa := a.At(p[0], p[1]).RGBA()
		br, bg, bb, ba := b.At(p[0], p[1]).RGBA()
		if ar != br || ag != bg || ab != bb || aa != ba {
			t.Errorf("pixel %v changed", p)
		}
	}
}

func TestNormalizeDropsMetadataAndTrailingBytes(t *testing.T) {
	src := withChunk(encodePNG(t, gradient(8, 8)), "tEXt", []byte("Comment\x00where I live"))
	src = append(src, []byte("TRAILING-SECRET")...)
	out, err := norm(src)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"tEXt", "where I live", "TRAILING-SECRET"} {
		if bytes.Contains(out, []byte(s)) {
			t.Errorf("the output still holds %q", s)
		}
	}
}

func TestNormalizeJPEGLosesItsExif(t *testing.T) {
	var j bytes.Buffer
	if err := jpeg.Encode(&j, gradient(40, 40), nil); err != nil {
		t.Fatal(err)
	}
	exif := append([]byte("Exif\x00\x00"), []byte("GPS 35.7N 51.4E")...)
	seg := append([]byte{0xFF, 0xE1, byte((len(exif) + 2) >> 8), byte(len(exif) + 2)}, exif...)
	src := append(append(append([]byte{}, j.Bytes()[:2]...), seg...), j.Bytes()[2:]...)
	out, err := norm(src)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(out, []byte("GPS")) || bytes.Contains(out, []byte("Exif")) {
		t.Error("the output holds the Exif segment")
	}
	if _, _, f := decodeDims(t, out); f != "png" {
		t.Errorf("the output is %s, want png", f)
	}
}

func TestNormalizeWebP(t *testing.T) {
	// A 1 by 1 lossless WebP, the smallest valid one.
	src, err := base64.StdEncoding.DecodeString("UklGRhoAAABXRUJQVlA4TA0AAAAvAAAAEAcQERGIiP4HAA==")
	if err != nil {
		t.Fatal(err)
	}
	out, err := norm(src)
	if err != nil {
		t.Fatal(err)
	}
	if w, h, f := decodeDims(t, out); w != 1 || h != 1 || f != "png" {
		t.Errorf("output is %dx%d %s", w, h, f)
	}
}

func TestNormalizeRefuses(t *testing.T) {
	big := make([]byte, MaxLogoBytes+1)
	copy(big, encodePNG(t, gradient(4, 4)))
	cases := map[string][]byte{
		"empty":               nil,
		"text":                []byte("not an image at all"),
		"a GIF":               []byte("GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00;"),
		"an SVG":              []byte(`<svg xmlns="http://www.w3.org/2000/svg" width="10" height="10"/>`),
		"over 256 KiB":        big,
		"wider than 1024":     encodePNG(t, image.NewNRGBA(image.Rect(0, 0, MaxLogoSide+1, 1))),
		"taller than 1024":    encodePNG(t, image.NewNRGBA(image.Rect(0, 0, 1, MaxLogoSide+1))),
		"a cut PNG":           encodePNG(t, gradient(64, 64))[:80],
		"a signature alone":   {0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a},
		"a JPEG header alone": {0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 'J', 'F', 'I', 'F'},
	}
	for name, b := range cases {
		if _, err := norm(b); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v, want ErrInvalid", name, err)
		}
	}
	// The edge itself is allowed, in height as in width.
	if _, err := norm(encodePNG(t, image.NewNRGBA(image.Rect(0, 0, MaxLogoSide, MaxLogoSide)))); err != nil {
		t.Errorf("1024 by 1024: %v", err)
	}
}

// A header that names a canvas of 60000 by 60000 is refused before a pixel is decoded: the file is a few dozen bytes and
// the decode would need more memory than the machine has.
func TestNormalizeReadsTheHeaderFirst(t *testing.T) {
	ihdr := make([]byte, 13)
	binary.BigEndian.PutUint32(ihdr[0:], 60000)
	binary.BigEndian.PutUint32(ihdr[4:], 60000)
	ihdr[8], ihdr[9] = 8, 6
	src := append([]byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a}, chunk("IHDR", ihdr)...)
	src = append(src, chunk("IDAT", []byte{0x78, 0x9c, 0x03, 0x00, 0x00, 0x00, 0x00, 0x01})...)
	src = append(src, chunk("IEND", nil)...)
	if _, err := norm(src); !errors.Is(err, ErrInvalid) {
		t.Errorf("a canvas of 60000 by 60000: %v", err)
	}
}

// fakeWriter can only lose: a store.Won that won is made inside package store, and the winning path is driven against
// the database by TestCapsRaceHarness (tenant_asset.create).
type fakeWriter struct {
	locked, inserted int
	lockErr          error
}

func (f *fakeWriter) QuotaLock() error { f.locked++; return f.lockErr }
func (f *fakeWriter) AssetInsert(sha256, png []byte) (uuid.UUID, store.Won, error) {
	f.inserted++
	return uuid.Nil, store.Won{}, nil
}

func TestStoreOrderAndRefusals(t *testing.T) {
	src := encodePNG(t, gradient(8, 8))
	good, err := Normalize(context.Background(), src)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeWriter{}
	// A zero Logo is what a caller gets from a Normalize it did not check: nothing is taken or written for it.
	if _, err := Store(f, Logo{}); !errors.Is(err, ErrInvalid) || f.locked != 0 || f.inserted != 0 {
		t.Errorf("no image: %v, lock %d, insert %d: nothing may be taken or written", err, f.locked, f.inserted)
	}
	if _, err := Store(f, good); !errors.Is(err, ErrLimit) || f.locked != 1 || f.inserted != 1 {
		t.Errorf("a tenant at its limit: %v, lock %d, insert %d", err, f.locked, f.inserted)
	}
	boom := errors.New("lock failed")
	g := &fakeWriter{lockErr: boom}
	if _, err := Store(g, good); !errors.Is(err, boom) || g.inserted != 0 {
		t.Errorf("a lock that failed: %v, insert %d", err, g.inserted)
	}
}

// A JPEG whose scans are counted by their markers: the decoder has no limit of its own, so the count is the only thing
// between a 256 KiB file of thousands of near-empty progressive scans and seconds of CPU (B2-r1-5). The file below decodes
// fine without the check, since a comment segment is ignored by the decoder; only the marker count refuses it.
func TestNormalizeRefusesAJPEGWithManyScans(t *testing.T) {
	var j bytes.Buffer
	if err := jpeg.Encode(&j, gradient(40, 40), nil); err != nil {
		t.Fatal(err)
	}
	withComment := func(pairs int) []byte {
		payload := bytes.Repeat([]byte{0xFF, 0xDA}, pairs)
		seg := append([]byte{0xFF, 0xFE, byte((len(payload) + 2) >> 8), byte(len(payload) + 2)}, payload...)
		return append(append(append([]byte{}, j.Bytes()[:2]...), seg...), j.Bytes()[2:]...)
	}
	if _, err := norm(withComment(MaxJPEGScans - 1)); err != nil {
		t.Errorf("a file at the limit: %v", err)
	}
	if _, err := norm(withComment(MaxJPEGScans)); !errors.Is(err, ErrInvalid) {
		t.Errorf("a file over the limit: err = %v, want ErrInvalid", err)
	}
	if got := jpegScans(j.Bytes()); got != 1 {
		t.Errorf("a baseline JPEG has %d scan markers, want 1", got)
	}
}

// norm is Normalize with a context that never ends, returning the PNG bytes.
func norm(raw []byte) ([]byte, error) {
	l, err := Normalize(context.Background(), raw)
	return l.PNG(), err
}

// A request whose client has gone leaves the queue for a decode slot, and a context that has ended is not judged as an
// image (B2-r2-2).
func TestNormalizeWaitEndsWithTheContext(t *testing.T) {
	good := encodePNG(t, gradient(8, 8))
	sem := decodeSem()
	for i := 0; i < decodeSlots; i++ {
		sem <- struct{}{}
	}
	defer func() {
		for i := 0; i < decodeSlots; i++ {
			<-sem
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := Normalize(ctx, good); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("a wait for a slot that never frees: err = %v, want the deadline", err)
	}
	done, stop := context.WithCancel(context.Background())
	stop()
	if _, err := Normalize(done, good); !errors.Is(err, context.Canceled) {
		t.Errorf("a context that ended already: err = %v, want Canceled", err)
	}
	// A bad image is refused before any slot is asked for, so a full queue does not turn it into a wait.
	if _, err := Normalize(ctx, []byte("junk")); !errors.Is(err, ErrInvalid) {
		t.Errorf("a bad image with the slots taken: err = %v, want ErrInvalid", err)
	}
	// Store decodes nothing: it finishes with every slot taken.
	f := &fakeWriter{}
	if _, err := Store(f, Logo{png: good}); !errors.Is(err, ErrLimit) || f.inserted != 1 {
		t.Errorf("Store with every slot taken: %v, insert %d", err, f.inserted)
	}
}
