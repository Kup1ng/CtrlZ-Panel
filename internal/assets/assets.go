// Package assets is the one writer of ctrlz.tenant_assets (P4b 10.5): the logo of a block page, for an upload and for an
// import alike. A route never writes the table itself, so no image reaches it that did not pass the checks below.
//
// Why decode and write again: an uploaded file is the sender's bytes, and a JPEG or a WebP can carry a location, a camera
// and a thumbnail, a PNG can carry text chunks and a second image after its end. The block page is served to the people of
// the tenant, so what is stored is what this package made: the pixels, as one PNG with no ancillary chunk.
package assets

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"image"
	"image/png"
	// The decoders of the three types a logo may arrive as. image.DecodeConfig and image.Decode find them by the magic
	// bytes, and nothing else is registered, so any other type (a GIF, a BMP, an SVG) is not an image here.
	_ "image/jpeg"

	"github.com/google/uuid"
	_ "golang.org/x/image/webp"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

const (
	// MaxLogoBytes is the size of what is sent and of what is stored: 256 KiB, the CHECK of tenant_assets.size.
	MaxLogoBytes = 262144
	// MaxLogoSide is the largest width or height the header may name. It is read before any pixel is decoded, so a small file
	// that claims a huge canvas never costs memory.
	MaxLogoSide = 1024
	// MaxJPEGScans bounds the scans of a JPEG. Go's decoder has no limit of its own, and for each scan of a progressive
	// image it walks every block of the component, so a file of 256 KiB holding thousands of near-empty scans costs
	// seconds of CPU under the size and dimension limits above. A real logo has about ten.
	MaxJPEGScans = 32
	// decodeSlots is how many decodes run at once: the work is CPU-bound and one tenant's burst must not take every core
	// of the API process from the others.
	decodeSlots = 2
)

// decodeSem holds one token for each decode in progress.
var decodeSem = make(chan struct{}, decodeSlots)

// jpegScans counts the start-of-scan markers of a JPEG. 0xFF 0xDA cannot appear in entropy-coded data (a 0xFF there is
// stuffed as 0xFF 0x00), so the count can only be too high, by a segment that holds the pair, never too low.
func jpegScans(raw []byte) int {
	return bytes.Count(raw, []byte{0xff, 0xda})
}

var (
	// ErrInvalid is asset_invalid: not an image of a type a logo may be, too large, too wide, or not decodable. The caller
	// says no more than that, since the reason may repeat what the sender sent.
	ErrInvalid = errors.New("assets: asset_invalid")
	// ErrLimit is asset_limit: the tenant holds MaxAssetsPerTenant assets already.
	ErrLimit = errors.New("assets: asset_limit")
)

// Writer is what Store needs of the database. store.Tx is the one implementation.
type Writer interface {
	QuotaLock() error
	AssetInsert(sha256, png []byte) (uuid.UUID, store.Won, error)
}

// Normalize checks the bytes of an uploaded logo and returns the PNG that is stored in their place. It takes no database:
// the checks are the same for an upload and for an import, and an import runs them on every logo before it writes any row.
func Normalize(raw []byte) ([]byte, error) {
	if len(raw) == 0 || len(raw) > MaxLogoBytes {
		return nil, ErrInvalid
	}
	// The header only: the dimensions are judged before a pixel is decoded.
	cfg, format, err := image.DecodeConfig(bytes.NewReader(raw))
	if err != nil || (format != "png" && format != "jpeg" && format != "webp") {
		return nil, ErrInvalid
	}
	if cfg.Width < 1 || cfg.Height < 1 || cfg.Width > MaxLogoSide || cfg.Height > MaxLogoSide {
		return nil, ErrInvalid
	}
	if format == "jpeg" && jpegScans(raw) > MaxJPEGScans {
		return nil, ErrInvalid
	}
	decodeSem <- struct{}{}
	defer func() { <-decodeSem }()
	img, _, err := image.Decode(bytes.NewReader(raw))
	if err != nil {
		return nil, ErrInvalid
	}
	// The decoded size must be the one the header named: a decoder that disagreed with its own header is not trusted.
	if b := img.Bounds(); b.Dx() != cfg.Width || b.Dy() != cfg.Height {
		return nil, ErrInvalid
	}
	var out bytes.Buffer
	enc := png.Encoder{CompressionLevel: png.BestCompression}
	if err := enc.Encode(&out, img); err != nil {
		return nil, ErrInvalid
	}
	if out.Len() > MaxLogoBytes {
		return nil, ErrInvalid
	}
	return out.Bytes(), nil
}

// Store normalizes raw and writes it as an asset of the tenant of w's transaction, under the tenant quota lock, and returns
// the id of the row. An image that fails is ErrInvalid and a tenant at its limit is ErrLimit; nothing is written then.
func Store(w Writer, raw []byte) (uuid.UUID, error) {
	data, err := Normalize(raw)
	if err != nil {
		return uuid.Nil, err
	}
	if err := w.QuotaLock(); err != nil {
		return uuid.Nil, err
	}
	sum := sha256.Sum256(data)
	id, won, err := w.AssetInsert(sum[:], data)
	if err != nil {
		return uuid.Nil, err
	}
	if !won.Yes() {
		return uuid.Nil, ErrLimit
	}
	return id, nil
}
