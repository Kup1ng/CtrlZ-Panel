package compiler

import (
	"bytes"
	"errors"
	"sort"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	commonv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/common/v1"
	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"
	"github.com/Kup1ng/CtrlZ-Shared/wire"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// Sizes the compiler plans an entry by. The node's validator refuses an entry above wire.MaxEntrySize bytes and above
// wire.MaxRecordsPerEntry puts, deletes and blob names together, and a refusal cannot be retried away: the same chunk is
// refused again. So a chunk is cut by both measures, with a margin for what an estimate cannot see.
const (
	// entryFrame is the tag and length a field costs on the wire, over the size of its message.
	entryFrame = 6
	// blobRefBytes and delBlobBytes are what naming a blob costs in put_blobs and in del_blobs.
	blobRefBytes = 48
	delBlobBytes = 40
	// entryReserve is the room kept for what a chunk does not weigh: the pair table, the free DNS value, the catalog
	// reference and the header of the entry.
	entryReserve = 1 << 20
)

// chunk is the records of one entry before they are chained: what a pass decided changes, cut to the size an entry
// may be. n and bytes are its weight, kept by the add methods and nowhere else: n counts the records, the blobs the entry
// names and, at worst, the blobs it frees (del_blobs are known only when the entry is built, so each delete and each
// replaced record counts the blobs its old record bound); bytes is an estimate of the encoded size.
type chunk struct {
	putE []*policyv1.EndpointRecord
	delE [][]byte
	putC []*policyv1.ClaimRecord
	delC [][]byte
	// blobs is the size of every blob the put records bind that was compiled, by hash. The bytes are not kept: a pass
	// compiles every owed tenant before it writes, and the bytes of the whole fleet's blobs at once would not fit in the
	// worker (W4-r3-1). The files are put in the store as each tenant compiles, and the entry only names them.
	blobs map[string]int

	v        *View
	n, bytes int

	// Carried by the first entry of a pass only.
	pair *policyv1.PairTable
	free *policyv1.FreeDns
	// A catalog entry carries the reference and nothing of a tenant's.
	catalog *policyv1.CatalogRef
	major   uint32 // set on a format bump
	class   commonv1.EntryClass
}

func newChunk(v *View) *chunk { return &chunk{blobs: map[string]int{}, v: v} }

func (c *chunk) records() int { return c.n }

func (c *chunk) empty() bool {
	return c.records() == 0 && c.pair == nil && c.free == nil && c.catalog == nil && c.major == 0
}

// freed is how many blobs a record that is deleted or replaced may leave unbound.
func (c *chunk) freed(id []byte) int {
	if c.v == nil {
		return 0
	}
	if old := c.v.Endpoints[string(id)]; old != nil {
		return len(bindings(old))
	}
	return 0
}

// costPutE is what a put of rec adds to the chunk: its blobs that are not in the chunk yet count with it.
func (c *chunk) costPutE(rec *policyv1.EndpointRecord, blobs map[string]int) (n, size int) {
	f := c.freed(rec.EndpointId)
	n, size = 1+f, proto.Size(rec)+entryFrame+f*delBlobBytes
	for _, h := range bindings(rec) {
		if _, ok := blobs[string(h)]; !ok {
			continue
		}
		if _, in := c.blobs[string(h)]; !in {
			n++
			size += blobRefBytes
		}
	}
	return n, size
}

func (c *chunk) addPutE(rec *policyv1.EndpointRecord, blobs map[string]int) {
	n, size := c.costPutE(rec, blobs)
	c.n, c.bytes = c.n+n, c.bytes+size
	c.putE = append(c.putE, rec)
	for _, h := range bindings(rec) {
		if sz, ok := blobs[string(h)]; ok {
			c.blobs[string(h)] = sz
		}
	}
}

// blobSizes is what a diff keeps of the compiled blobs of a tenant: the size, never the bytes.
func blobSizes(blobs map[string]*Profile) map[string]int {
	out := make(map[string]int, len(blobs))
	for h, p := range blobs {
		if p != nil {
			out[h] = p.Len()
		}
	}
	return out
}

func (c *chunk) costDelE(id []byte) (n, size int) {
	f := c.freed(id)
	return 1 + f, len(id) + entryFrame + f*delBlobBytes
}

func (c *chunk) addDelE(id []byte) {
	n, size := c.costDelE(id)
	c.n, c.bytes = c.n+n, c.bytes+size
	c.delE = append(c.delE, id)
}

func (c *chunk) costPutC(rec *policyv1.ClaimRecord) (n, size int) {
	return 1, proto.Size(rec) + entryFrame
}

func (c *chunk) addPutC(rec *policyv1.ClaimRecord) {
	n, size := c.costPutC(rec)
	c.n, c.bytes = c.n+n, c.bytes+size
	c.putC = append(c.putC, rec)
}

func (c *chunk) costDelC(id []byte) (n, size int) { return 1, len(id) + entryFrame }

func (c *chunk) addDelC(id []byte) {
	n, size := c.costDelC(id)
	c.n, c.bytes = c.n+n, c.bytes+size
	c.delC = append(c.delC, id)
}

// diff is one tenant's compile against the view: the records that differ.
type diff struct {
	chunk
	// tenants of this unit: a unit of one tenant, or of several that share a batch_id, which must go in one entry.
	tenants []uuid.UUID
}

// claimIndex lists the view's claims by the Endpoint that holds them, sorted, so one tenant's diff reads its own claims
// and not every claim of the fleet (a pass over T tenants was T sorts of all claims).
func claimIndex(v *View) map[string][]string {
	out := map[string][]string{}
	for _, k := range sortedKeys(v.Claims) {
		ep := string(v.Claims[k].EndpointId)
		out[ep] = append(out[ep], k)
	}
	return out
}

// diffTenant compares a tenant's output with the view. owned is the keys of the view's Endpoints that were last compiled for
// the tenant; a record the output no longer has and the tenant owned is deleted, unless the Endpoint was kept (it has no
// record in the view and none could be compiled, so the output says nothing about it).
//
// The tenant owns what it owned and what it compiles now: after a restart the view knows no owner, and a claim the tenant
// gave up in the meantime is found only through the Endpoints the tenant has today. Claims are always compared, for kept
// Endpoints too, so a claim that the database no longer holds never outlives its row because a profile did not compile.
func diffTenant(v *View, tenant uuid.UUID, out *Output, owned []string, claimsOf map[string][]string) *diff {
	d := &diff{tenants: []uuid.UUID{tenant}}
	d.chunk = *newChunk(v)
	sizes := blobSizes(out.Blobs)
	for _, k := range sortedKeys(out.Endpoints) {
		rec := out.Endpoints[k]
		v.owner[k] = tenant
		if old := v.Endpoints[k]; old != nil && proto.Equal(old, rec) {
			continue
		}
		if wire.ValidateEndpoint(rec) != nil {
			// A record the validator refuses would make the node quarantine the whole entry. It is left out and the
			// Endpoint keeps the record it had.
			out.Problems = append(out.Problems, ReasonRecordInvalid)
			continue
		}
		d.addPutE(rec, sizes)
	}
	for k := range out.Kept {
		v.owner[k] = tenant
	}
	mine := map[string]bool{}
	var dels [][]byte
	for _, k := range owned {
		mine[k] = true
		if _, ok := out.Endpoints[k]; !ok && !out.Kept[k] {
			dels = append(dels, []byte(k))
		}
	}
	sort.Slice(dels, func(i, j int) bool { return bytes.Compare(dels[i], dels[j]) < 0 })
	for _, id := range dels {
		d.addDelE(id)
	}
	for k := range out.Endpoints {
		mine[k] = true
	}
	for k := range out.Kept {
		mine[k] = true
	}
	for _, k := range sortedKeys(out.Claims) {
		rec := out.Claims[k]
		if old := v.Claims[k]; old != nil && proto.Equal(old, rec) {
			continue
		}
		if wire.ValidateClaim(rec) != nil {
			out.Problems = append(out.Problems, ReasonRecordInvalid)
			continue
		}
		d.addPutC(rec)
	}
	var gone []string
	for ep := range mine {
		for _, k := range claimsOf[ep] {
			if _, ok := out.Claims[k]; !ok {
				gone = append(gone, k)
			}
		}
	}
	sort.Strings(gone)
	for _, k := range gone {
		d.addDelC([]byte(k))
	}
	return d
}

// orphans are the records of the view that no tenant owns after a full pass: their tenant is gone, or their Endpoint
// was deleted without a mark (a tenant purge cascades past the outbox).
func orphans(v *View) *diff {
	d := &diff{}
	d.chunk = *newChunk(v)
	for _, k := range sortedKeys(v.Endpoints) {
		if _, ok := v.owner[k]; !ok {
			d.addDelE([]byte(k))
		}
	}
	for _, k := range sortedKeys(v.Claims) {
		if _, ok := v.owner[string(v.Claims[k].EndpointId)]; !ok {
			d.addDelC([]byte(k))
		}
	}
	return d
}

// merge joins the units of one batch_id group into one. The weights add up, which counts a blob two units share twice:
// the bound is safe, and cut weighs the records again.
func merge(v *View, ds []*diff) *diff {
	out := &diff{}
	out.chunk = *newChunk(v)
	for _, d := range ds {
		out.putE = append(out.putE, d.putE...)
		out.delE = append(out.delE, d.delE...)
		out.putC = append(out.putC, d.putC...)
		out.delC = append(out.delC, d.delC...)
		out.tenants = append(out.tenants, d.tenants...)
		out.n += d.n
		out.bytes += d.bytes
		for h, b := range d.blobs {
			out.blobs[h] = b
		}
	}
	return out
}

// limits are what one planned entry may hold: records (with the blobs it names and may free) and encoded bytes. hard is the
// record count of the validator, the most a unit that is larger than an entry is cut to.
type limits struct{ count, hard, bytes int }

// pack puts the units into entries of at most lim.count records and lim.bytes bytes, each unit whole: a Move between profiles
// is one batch and must reach a node in one entry (Plan, "ارتباط پنل و نود"). A unit larger than the validator allows
// cannot be whole in anything and is cut there; oversize says so.
func pack(v *View, units []*diff, lim limits) (out []*chunk, oversize bool) {
	cur := newChunk(v)
	flush := func() {
		if cur.records() != 0 {
			out = append(out, cur)
		}
		cur = newChunk(v)
	}
	for _, u := range units {
		if u.records() > lim.hard || u.bytes > lim.bytes {
			oversize = true
			flush()
			out = append(out, cut(v, u, lim.hard, lim.bytes)...)
			continue
		}
		if cur.records()+u.records() > lim.count || cur.bytes+u.bytes > lim.bytes {
			flush()
		}
		cur.putE = append(cur.putE, u.putE...)
		cur.delE = append(cur.delE, u.delE...)
		cur.putC = append(cur.putC, u.putC...)
		cur.delC = append(cur.delC, u.delC...)
		cur.n += u.n
		cur.bytes += u.bytes
		for h, b := range u.blobs {
			cur.blobs[h] = b
		}
	}
	flush()
	return out, oversize
}

// cut splits one unit into entries of at most n records and maxBytes bytes. The blobs of a put are counted with it, so an
// entry never holds a record whose blob went in the next one: the node fetches a bound blob in any case, but the entry
// stays honest about what it names. A single record always fits (it is far below the byte cap), so the cut ends.
func cut(v *View, u *diff, n, maxBytes int) []*chunk {
	var out []*chunk
	cur := newChunk(v)
	roll := func(wn, wb int) {
		if cur.n != 0 && (cur.n+wn > n || cur.bytes+wb > maxBytes) {
			out = append(out, cur)
			cur = newChunk(v)
		}
	}
	for _, rec := range u.putE {
		wn, wb := cur.costPutE(rec, u.blobs)
		roll(wn, wb)
		cur.addPutE(rec, u.blobs)
	}
	for _, id := range u.delE {
		wn, wb := cur.costDelE(id)
		roll(wn, wb)
		cur.addDelE(id)
	}
	for _, rec := range u.putC {
		wn, wb := cur.costPutC(rec)
		roll(wn, wb)
		cur.addPutC(rec)
	}
	for _, id := range u.delC {
		wn, wb := cur.costDelC(id)
		roll(wn, wb)
		cur.addDelC(id)
	}
	if cur.n != 0 {
		out = append(out, cur)
	}
	return out
}

// split halves a chunk the validator refused, at a record boundary, so one oversize entry does not stop the compiler for
// every tenant (the estimate is a bound, not a proof). The first half keeps what the entry carries besides records. ok is
// false for a chunk of one record or none, which no cut can help.
func split(ch *chunk) (a, b *chunk, ok bool) {
	total := len(ch.putE) + len(ch.delE) + len(ch.putC) + len(ch.delC)
	if total < 2 {
		return nil, nil, false
	}
	a, b = newChunk(ch.v), newChunk(ch.v)
	a.pair, a.free, a.class, a.major = ch.pair, ch.free, ch.class, ch.major
	b.class = ch.class
	i := 0
	pick := func() *chunk {
		i++
		if i <= total/2 {
			return a
		}
		return b
	}
	for _, rec := range ch.putE {
		pick().addPutE(rec, ch.blobs)
	}
	for _, id := range ch.delE {
		pick().addDelE(id)
	}
	for _, rec := range ch.putC {
		pick().addPutC(rec)
	}
	for _, id := range ch.delC {
		pick().addDelC(id)
	}
	return a, b, true
}

// built is an entry ready to write.
type built struct {
	entry   *policyv1.ConfigEntry
	payload []byte
	hash    []byte
	// files are the blobs this entry names in put_blobs, by hash with their size: the store must hold each before the entry is
	// committed. Their bytes were put as the tenant compiled.
	files map[string]int
	put   []artifactRow
	gc    [][]byte
}

// errEntry is a chunk whose entry the validator refuses.
var errEntry = errors.New("compiler: the entry does not validate")

// build makes the entry of a chunk on top of the view: the records, the blobs the nodes may not hold yet and the blobs
// that nothing binds any more (del_blobs, one shot, T-534), the carried values, the chain. It changes nothing.
//
// A hash is named in put_blobs when no row says the nodes hold it, or it waits for its collection (it is bound again,
// 6.5). It is named in del_blobs when this entry takes the last binding away; a hash a record of the same entry binds
// again is not, and one kept by another Endpoint is named in the entry that frees it, because the count is of the whole
// state and not of the entry.
func build(v *View, c *chunk, now time.Time, major uint32) (*built, error) {
	e := &policyv1.ConfigEntry{
		Seq: v.Seq + 1, Class: c.class, PrevHash: v.Head, CreatedAt: now.Unix(),
		PutEndpoints: c.putE, DelEndpoints: c.delE, PutClaims: c.putC, DelClaims: c.delC,
		PairTable: c.pair, FreeDns: c.free, Catalog: c.catalog, MinBlobMajor: major,
	}
	if e.Class == commonv1.EntryClass_ENTRY_CLASS_UNSPECIFIED {
		e.Class = commonv1.EntryClass_ENTRY_CLASS_POLICY
	}
	b := &built{entry: e, files: map[string]int{}}

	delta := map[string]int{}
	for _, id := range c.delE {
		if old := v.Endpoints[string(id)]; old != nil {
			for _, h := range bindings(old) {
				delta[string(h)]--
			}
		}
	}
	for _, rec := range c.putE {
		if old := v.Endpoints[string(rec.EndpointId)]; old != nil {
			for _, h := range bindings(old) {
				delta[string(h)]--
			}
		}
		for _, h := range bindings(rec) {
			delta[string(h)]++
		}
	}
	for _, h := range sortedKeys(delta) {
		bound := v.refs[h] + delta[h]
		bi := v.blobs[h]
		size, compiled := c.blobs[h]
		switch {
		case bound > 0 && delta[h] > 0 && compiled && (bi == nil || bi.gcAfter != 0):
			e.PutBlobs = append(e.PutBlobs, &policyv1.BlobRef{Hash: []byte(h), Size: uint64(size), Kind: policyv1.BlobKind_BLOB_KIND_PROFILE})
			b.files[h] = size
			first := v.Seq + 1
			if bi != nil {
				first = bi.firstSeq
			}
			b.put = append(b.put, artifactRow{Hash: []byte(h), Kind: kindProfile, Size: int64(size), StoreRef: hexOf([]byte(h)), FirstSeq: first})
		case bound == 0 && bi != nil && bi.gcAfter == 0:
			e.DelBlobs = append(e.DelBlobs, []byte(h))
			b.gc = append(b.gc, []byte(h))
		}
	}
	// A blob a record binds that is neither new nor waiting needs nothing here: the nodes hold it. One whose row exists but
	// whose file the store lost is written again by the full pass (Compiler.fire, Artifacts.Ensure), since the row says
	// it exists.

	payload, err := wire.MarshalEntry(e)
	if err != nil {
		return nil, errEntry
	}
	if _, err := wire.DecodeEntry(payload); err != nil {
		return nil, errEntry
	}
	var prev [32]byte
	copy(prev[:], v.Head)
	h := wire.EntryHash(prev, payload)
	b.payload, b.hash = payload, h[:]
	return b, nil
}

func hexOf(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 2*len(b))
	for i, x := range b {
		out[2*i], out[2*i+1] = digits[x>>4], digits[x&15]
	}
	return string(out)
}

// classOf is the config_log.class text of an entry.
func classOf(c commonv1.EntryClass) string {
	if c == commonv1.EntryClass_ENTRY_CLASS_CATALOG {
		return "catalog"
	}
	return "policy"
}

// outboxIDs collects the ids of marks.
func outboxIDs(marks []store.OutboxMark) []uuid.UUID {
	out := make([]uuid.UUID, len(marks))
	for i, m := range marks {
		out[i] = m.ID
	}
	return out
}
