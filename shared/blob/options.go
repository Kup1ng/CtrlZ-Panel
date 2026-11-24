package blob

import "github.com/Kup1ng/CtrlZ-Shared/reason"

// Action is the decision type. The numbers equal ctrlz.common.v1.Action.
type Action uint8

const (
	ActNone     Action = 0
	ActBlock    Action = 1
	ActBypass   Action = 2
	ActRedirect Action = 3
)

// TargetKind equals ctrlz.common.v1.TargetKind.
type TargetKind uint8

const (
	TargetNone     TargetKind = 0
	TargetLocation TargetKind = 1
	TargetAuto     TargetKind = 2
	TargetRandom   TargetKind = 3
	TargetIP       TargetKind = 4
	TargetHost     TargetKind = 5
)

// Bits of Options.Present (contract 9.2). The boolean options 0 to 6 use the
// same bit positions in Options.Bools.
const (
	OptExfiltration      uint32 = 1 << 0
	OptRebind            uint32 = 1 << 1
	OptDisableDNSSEC     uint32 = 1 << 2
	OptDNS64             uint32 = 1 << 3
	OptFlatten           uint32 = 1 << 4
	OptSafeSearch        uint32 = 1 << 5
	OptRestrictedYouTube uint32 = 1 << 6
	OptBlockResponse     uint32 = 1 << 7
	OptECS               uint32 = 1 << 8
	OptBlockTTL          uint32 = 1 << 9
	OptRedirectTTL       uint32 = 1 << 10
	OptBypassTTL         uint32 = 1 << 11

	optKnown    uint32 = 1<<12 - 1
	optBoolMask uint32 = 1<<7 - 1
)

// Block Response values.
const (
	BlockZero     uint8 = 1
	BlockNXDomain uint8 = 2
	BlockRefused  uint8 = 3
	BlockCustom   uint8 = 4
	BlockBranded  uint8 = 5
)

// ECS modes.
const (
	ECSNone   uint8 = 1
	ECSAuto   uint8 = 2
	ECSCustom uint8 = 3
)

// OptsSize is the size of one OPTS record.
const OptsSize = 96

// Options is the nullable option set of one profile. A bit clear in Present
// means "not set": the other slot of a stack, or the default, decides.
type Options struct {
	Present       uint32
	Bools         uint8
	BlockResponse uint8
	ECSMode       uint8
	ECSV4Prefix   uint8
	ECSV6Prefix   uint8
	BlockTTL      uint32
	RedirectTTL   uint32
	BypassTTL     uint32
	BlockV4       [4]byte
	BlockV6       [16]byte
	ECSV4         [4]byte
	ECSV6         [16]byte
	BlockPageHash [32]byte
}

// Has reports whether the option is set (not null).
func (o *Options) Has(bit uint32) bool { return o.Present&bit != 0 }

// Bool returns a boolean option's value, false when null.
func (o *Options) Bool(bit uint32) bool { return o.Present&bit != 0 && uint32(o.Bools)&bit != 0 }

// Marshal encodes the 96-byte OPTS record.
func (o *Options) Marshal() [OptsSize]byte {
	var b [OptsSize]byte
	le.PutUint32(b[0:], o.Present)
	b[4] = o.Bools
	b[5] = o.BlockResponse
	b[6] = o.ECSMode
	b[7] = o.ECSV4Prefix
	b[8] = o.ECSV6Prefix
	le.PutUint32(b[12:], o.BlockTTL)
	le.PutUint32(b[16:], o.RedirectTTL)
	le.PutUint32(b[20:], o.BypassTTL)
	copy(b[24:], o.BlockV4[:])
	copy(b[28:], o.BlockV6[:])
	copy(b[44:], o.ECSV4[:])
	copy(b[48:], o.ECSV6[:])
	copy(b[64:], o.BlockPageHash[:])
	return b
}

// ParseOptions decodes and validates one OPTS record. It is strict: a field
// whose option is null must be zero, so one logical option set has exactly
// one encoding. That keeps blob hashes stable and rejects hand-built blobs
// that hide data in unused fields.
func ParseOptions(b []byte) (Options, error) {
	const sec = "OPTS"
	var o Options
	if len(b) != OptsSize {
		return o, reason.New(reason.BadSection, sec, 0, "record is %d bytes, want %d", len(b), OptsSize)
	}
	o.Present = le.Uint32(b[0:])
	o.Bools = b[4]
	o.BlockResponse = b[5]
	o.ECSMode = b[6]
	o.ECSV4Prefix = b[7]
	o.ECSV6Prefix = b[8]
	o.BlockTTL = le.Uint32(b[12:])
	o.RedirectTTL = le.Uint32(b[16:])
	o.BypassTTL = le.Uint32(b[20:])
	copy(o.BlockV4[:], b[24:])
	copy(o.BlockV6[:], b[28:])
	copy(o.ECSV4[:], b[44:])
	copy(o.ECSV6[:], b[48:])
	copy(o.BlockPageHash[:], b[64:])

	if o.Present&^optKnown != 0 {
		return o, reason.New(reason.BadEnum, sec, 0, "unknown present bits %#x", o.Present&^optKnown)
	}
	if uint32(o.Bools)&^o.Present != 0 || uint32(o.Bools)&^optBoolMask != 0 {
		return o, reason.New(reason.BadEnum, sec, 4, "boolean value set for a null option")
	}
	if !allZero(b[9:12]) {
		return o, reason.New(reason.BadSection, sec, 9, "pad bytes not zero")
	}
	if o.Has(OptBlockResponse) {
		if o.BlockResponse < BlockZero || o.BlockResponse > BlockBranded {
			return o, reason.New(reason.BadEnum, sec, 5, "block_response %d", o.BlockResponse)
		}
	} else if o.BlockResponse != 0 || o.BlockV4 != [4]byte{} || o.BlockV6 != [16]byte{} || o.BlockPageHash != [32]byte{} {
		return o, reason.New(reason.BadSection, sec, 5, "block response data without the option")
	}
	if o.Has(OptECS) {
		if o.ECSMode < ECSNone || o.ECSMode > ECSCustom {
			return o, reason.New(reason.BadEnum, sec, 6, "ecs_mode %d", o.ECSMode)
		}
		if o.ECSV4Prefix > 32 || o.ECSV6Prefix > 128 {
			return o, reason.New(reason.BadEnum, sec, 7, "ecs prefix out of range")
		}
	} else if o.ECSMode != 0 || o.ECSV4Prefix != 0 || o.ECSV6Prefix != 0 || o.ECSV4 != [4]byte{} || o.ECSV6 != [16]byte{} {
		return o, reason.New(reason.BadSection, sec, 6, "ecs data without the option")
	}
	if (!o.Has(OptBlockTTL) && o.BlockTTL != 0) || (!o.Has(OptRedirectTTL) && o.RedirectTTL != 0) || (!o.Has(OptBypassTTL) && o.BypassTTL != 0) {
		return o, reason.New(reason.BadSection, sec, 12, "ttl without the option")
	}
	return o, nil
}

// Merge combines two slots' options: the first non-null wins per option, and
// the block response and ECS settings travel as units (their custom IPs, page
// hash, mode and subnets come from the same slot). Order is (earlier, later).
func Merge(a, b *Options) Options {
	out := *a
	for bit := uint32(1); bit <= OptRestrictedYouTube; bit <<= 1 {
		if !a.Has(bit) && b.Has(bit) {
			out.Present |= bit
			if b.Bools&uint8(bit) != 0 {
				out.Bools |= uint8(bit)
			}
		}
	}
	if !a.Has(OptBlockResponse) && b.Has(OptBlockResponse) {
		out.Present |= OptBlockResponse
		out.BlockResponse, out.BlockV4, out.BlockV6, out.BlockPageHash = b.BlockResponse, b.BlockV4, b.BlockV6, b.BlockPageHash
	}
	if !a.Has(OptECS) && b.Has(OptECS) {
		out.Present |= OptECS
		out.ECSMode, out.ECSV4Prefix, out.ECSV6Prefix, out.ECSV4, out.ECSV6 = b.ECSMode, b.ECSV4Prefix, b.ECSV6Prefix, b.ECSV4, b.ECSV6
	}
	if !a.Has(OptBlockTTL) && b.Has(OptBlockTTL) {
		out.Present |= OptBlockTTL
		out.BlockTTL = b.BlockTTL
	}
	if !a.Has(OptRedirectTTL) && b.Has(OptRedirectTTL) {
		out.Present |= OptRedirectTTL
		out.RedirectTTL = b.RedirectTTL
	}
	if !a.Has(OptBypassTTL) && b.Has(OptBypassTTL) {
		out.Present |= OptBypassTTL
		out.BypassTTL = b.BypassTTL
	}
	return out
}

// Defaults of the contract (section 6). TTL values are provisional until the
// P4 load tests (D31), so they live in these two constants only.
const (
	DefaultBlockTTL    uint32 = 60
	DefaultRedirectTTL uint32 = 60
)

// Effective is Options with defaults applied. It is what the evaluator reads.
type Effective struct {
	Exfiltration      bool
	Rebind            bool
	DisableDNSSEC     bool
	DNS64             bool
	Flatten           bool
	SafeSearch        bool
	RestrictedYouTube bool

	BlockResponse uint8
	BlockV4       [4]byte
	BlockV6       [16]byte
	BlockPageHash [32]byte

	ECSMode     uint8
	ECSV4Prefix uint8
	ECSV6Prefix uint8
	ECSV4       [4]byte
	ECSV6       [16]byte

	BlockTTL    uint32
	RedirectTTL uint32
	BypassTTL   uint32 // meaningful only when HasBypassTTL
	// HasBypassTTL false means "keep the answer's own TTL".
	HasBypassTTL bool
}

// Effective applies the defaults to o.
func (o *Options) Effective() Effective {
	e := Effective{
		Exfiltration:      o.Bool(OptExfiltration),
		Rebind:            o.Bool(OptRebind),
		DisableDNSSEC:     o.Bool(OptDisableDNSSEC),
		DNS64:             o.Bool(OptDNS64),
		Flatten:           o.Bool(OptFlatten),
		SafeSearch:        o.Bool(OptSafeSearch),
		RestrictedYouTube: o.Bool(OptRestrictedYouTube),
		BlockResponse:     BlockZero,
		ECSMode:           ECSNone,
		BlockTTL:          DefaultBlockTTL,
		RedirectTTL:       DefaultRedirectTTL,
	}
	if o.Has(OptBlockResponse) {
		e.BlockResponse, e.BlockV4, e.BlockV6, e.BlockPageHash = o.BlockResponse, o.BlockV4, o.BlockV6, o.BlockPageHash
	}
	if o.Has(OptECS) {
		e.ECSMode, e.ECSV4Prefix, e.ECSV6Prefix, e.ECSV4, e.ECSV6 = o.ECSMode, o.ECSV4Prefix, o.ECSV6Prefix, o.ECSV4, o.ECSV6
	}
	if e.ECSMode == ECSAuto {
		// Auto means the client's own network at a fixed width: /24 and /56.
		if e.ECSV4Prefix == 0 {
			e.ECSV4Prefix = 24
		}
		if e.ECSV6Prefix == 0 {
			e.ECSV6Prefix = 56
		}
	}
	if o.Has(OptBlockTTL) {
		e.BlockTTL = o.BlockTTL
	}
	if o.Has(OptRedirectTTL) {
		e.RedirectTTL = o.RedirectTTL
	}
	if o.Has(OptBypassTTL) {
		e.BypassTTL, e.HasBypassTTL = o.BypassTTL, true
	}
	return e
}
