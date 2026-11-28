// Package assets is the one writer of ctrlz.tenant_assets (P4b 10.5): the logo of a block page, for an upload and for an
// import alike. A route never writes the table itself, so no image reaches it that did not pass the checks below.
//
// Why decode and write again: an uploaded file is the sender's bytes, and a JPEG or a WebP can carry a location, a camera
// and a thumbnail, a PNG can carry text chunks and a second image after its end. The block page is served to the people of
// the tenant, so what is stored is what this package made: the pixels, as one PNG with no ancillary chunk.
//
// Two steps, because the first one is CPU and may queue: Normalize runs before a transaction opens and gives a Logo, and
// Store, inside the transaction, writes a Logo and decodes nothing.
package assets

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"image"
	"image/png"
	// The decoders of the three types a logo may arrive as. image.DecodeConfig and image.Decode find them by the magic
	// bytes, and nothing else is registered, so any other type (a GIF, a BMP, an SVG) is not an image here.
	_ "image/jpeg"
	"sync"

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

// decodeSem holds one token for each decode in progress. It is process-wide on purpose: the limit is on the CPU of the API
// process, not on one request or one tenant. OnceValue keeps it a value that is computed once and never reassigned.
var decodeSem = sync.OnceValue(func() chan struct{} { return make(chan struct{}, decodeSlots) })

// acquireDecodeSlot waits for one of the decode slots and gives the caller up when its context ends, so a request whose
// client has gone does not stay in the queue. A context that has ended already is refused first: select picks at random
// when a slot is free and the context is done together.
func acquireDecodeSlot(ctx context.Context) (release func(), err error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sem := decodeSem()
	select {
	case sem <- struct{}{}:
		return func() { <-sem }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

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

// Logo is the PNG that Normalize made from a sender's bytes. Only Normalize makes one, so Store, which takes a Logo, can only
// write what passed the checks below; the zero Logo is refused.
type Logo struct{ png []byte }

// PNG returns the normalized bytes.
func (l Logo) PNG() []byte { return l.png }

// Normalize checks the bytes of an uploaded logo and returns the PNG that is stored in their place. It takes no database,
// and a caller runs it BEFORE it opens its transaction: the decode waits for one of decodeSlots slots, and a transaction that
// waited there would hold a pool connection and its locks for the whole queue (B2-r2-2). An import runs it on every logo
// before it writes any row, and the Logo it gets is what Store writes, so no logo is decoded twice. The wait ends with ctx,
// and the error is then ctx.Err(), not ErrInvalid: the image was not judged.
func Normalize(ctx context.Context, raw []byte) (Logo, error) {
	if len(raw) == 0 || len(raw) > MaxLogoBytes {
		return Logo{}, ErrInvalid
	}
	// The header only: the dimensions are judged before a pixel is decoded.
	cfg, format, err := image.DecodeConfig(bytes.NewReader(raw))
	if err != nil || (format != "png" && format != "jpeg" && format != "webp") {
		return Logo{}, ErrInvalid
	}
	if cfg.Width < 1 || cfg.Height < 1 || cfg.Width > MaxLogoSide || cfg.Height > MaxLogoSide {
		return Logo{}, ErrInvalid
	}
	if format == "jpeg" && jpegScans(raw) > MaxJPEGScans {
		return Logo{}, ErrInvalid
	}
	release, err := acquireDecodeSlot(ctx)
	if err != nil {
		return Logo{}, err
	}
	defer release()
	img, _, err := image.Decode(bytes.NewReader(raw))
	if err != nil {
		return Logo{}, ErrInvalid
	}
	// The decoded size must be the one the header named: a decoder that disagreed with its own header is not trusted.
	if b := img.Bounds(); b.Dx() != cfg.Width || b.Dy() != cfg.Height {
		return Logo{}, ErrInvalid
	}
	var out bytes.Buffer
	enc := png.Encoder{CompressionLevel: png.BestCompression}
	if err := enc.Encode(&out, img); err != nil {
		return Logo{}, ErrInvalid
	}
	if out.Len() > MaxLogoBytes {
		return Logo{}, ErrInvalid
	}
	return Logo{png: out.Bytes()}, nil
}

// Store writes a normalized logo as an asset of the tenant of w's transaction, under the tenant quota lock, and returns the
// id of the row. A tenant at its limit is ErrLimit and nothing is written then. It decodes nothing, so the transaction that
// calls it never waits for a decode slot.
func Store(w Writer, l Logo) (uuid.UUID, error) {
	if len(l.png) == 0 {
		return uuid.Nil, ErrInvalid
	}
	if err := w.QuotaLock(); err != nil {
		return uuid.Nil, err
	}
	sum := sha256.Sum256(l.png)
	id, won, err := w.AssetInsert(sum[:], l.png)
	if err != nil {
		return uuid.Nil, err
	}
	if !won.Yes() {
		return uuid.Nil, ErrLimit
	}
	return id, nil
}
