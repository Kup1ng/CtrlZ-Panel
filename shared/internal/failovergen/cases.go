package failovergen

import (
	"fmt"
	"strings"
)

func ceilTo(x, tick int64) int64 { return (x + tick - 1) / tick * tick }

// world adds the healthy traffic of a pair (A, B) up to end: Heartbeats every
// hbEvery (A at phase 0, B half a period later, so their rounds are out of
// phase) and a passing round of each node every probeEvery. It returns the
// specs so a case can change one signal before it is laid out.
type world struct {
	c          *cs
	a, b       hbSpec
	ar, br     roundSpec
	end        int64
	skipLayout bool
}

func newWorld(c *cs, end int64) *world {
	w := &world{c: c, end: end}
	w.a = hbSpec{node: "A", peer: "B", to: end}
	w.b = hbSpec{node: "B", peer: "A", phase: c.th.hbEvery / 2, to: end}
	w.ar = roundSpec{node: "A", to: end}
	w.br = roundSpec{node: "B", to: end}
	return w
}

// lay writes the four signals. Heartbeats go first at a tied instant, so a
// node's Heartbeat that reports a round does not see that round yet.
func (w *world) lay() {
	w.c.heartbeats(w.a)
	w.c.heartbeats(w.b)
	w.c.rounds(w.ar)
	w.c.rounds(w.br)
}

func (T thresholds) wd() col { return col{Withdrawn: true} }

func downFrom(t0 int64) func(int64) int {
	return func(t int64) int {
		if t >= t0 {
			return 1
		}
		return 0
	}
}

// f1Cases are the generated cases of row F1 and of the inputs that only F1
// reads: hb, the probe state machine, the view age and the 15 s without a
// round.
func f1Cases(T thresholds) []Case {
	var out []Case
	const aLast = 20000
	flip := flipAt(aLast, T.hbStale, false, T.tick)
	fire := flip + T.f1For
	end := fire + 2*T.tick
	withdrawA := map[string]col{"A": {Withdrawn: true}}
	// The base: A heartbeats and is probed until aLast and then is silent, B
	// reports A down from 25 s on, B is healthy throughout.
	base := func(id, why string, end int64) (*cs, *world) {
		c := T.newCase(id, "F1", why, "A", "B")
		w := newWorld(c, end)
		w.a.to, w.ar.to = aLast, aLast
		w.b.view = downFrom(25000)
		return c, w
	}
	fires := func(c *cs, at int64) {
		c.event(at, "F1", withdrawA).alert(at, T.alertF1, "A", "")
	}

	c, w := base("f1-001", "F1: dead(A) and ready(B) hold for exactly 5 s: A's last Heartbeat at 20 s is 15 s old at 35 s, B reports A down, so F1 withdraws A at 40 s", end)
	w.lay()
	fires(c, fire)
	out = append(out, c.finish(end))

	c, w = base("f1-002", "F1: only the state false, A already withdrawn: dead(A) and ready(B) hold and nothing happens", end)
	c.start("A", T.wd())
	w.lay()
	out = append(out, c.finish(end))

	c, w = base("f1-003", "F1: only dead(A) false, A keeps its Heartbeats and rounds and B reports it up: no action", end)
	w.a.to, w.ar.to, w.b.view = end, end, up
	w.lay()
	out = append(out, c.finish(end))

	c, w = base("f1-004", "F1: only ready(B) false, B's rounds fail so its probe state is down: A is dead and nothing moves", end)
	w.br.pass = fail
	w.lay()
	out = append(out, c.finish(end))

	// One tick before the timer: view(A) turns up at 39 s, so the 5 s begin
	// again when it turns down at 43 s and F1 comes at 48 s.
	c, w = base("f1-005", "F1: the inputs break one tick before the timer (B's Heartbeat at 38.5 s says A is up): no action at 40 s, the timer starts again when B reports A down at 42.5 s and F1 comes 5 s after that tick", 49000)
	w.lay()
	c.hbOne(38500, hbSpec{node: "B", peer: "A", view: up})
	fires(c, 48000)
	out = append(out, c.finish(49000))

	// Input hb(X): the threshold tick and the tick before it.
	c, w = base("f1-010", "input hb: a Heartbeat arrives 0.5 s before the tick at which the last one would have passed 15 s, so the Heartbeat is still counted at 35 s and passes at 50 s, and F1 follows at 55 s", 56000)
	w.lay()
	c.hbOne(34500, hbSpec{node: "A", peer: "B"})
	fires(c, ceilTo(34500+T.hbStale, T.tick)+T.f1For)
	out = append(out, c.finish(56000))

	// Input probe(X), up in 3 rounds: A is dead from the start, B is probed.
	deadA := func(id, why string, end int64) (*cs, *world) {
		c := T.newCase(id, "F1", why, "A", "B")
		w := newWorld(c, end)
		w.a.to, w.ar.to = -1, -1
		w.b.view = down
		return c, w
	}
	third := T.probeRounds * T.probeEvery // the third round
	c, w = deadA("f1-011", "input probe: three passing rounds in a row make B up at the third round (15 s), the same tick on which hb(A) passes, so F1 comes at 20 s", third+T.f1For+2*T.tick)
	w.lay()
	fires(c, third+T.f1For)
	out = append(out, c.finish(third+T.f1For+2*T.tick))

	c, w = deadA("f1-012", "input probe: the third round fails after two passes, so B is not up (a lone failure changes nothing and two passes are not three): three more passes make it up at 30 s and F1 comes at 35 s", 37000)
	w.br.pass = func(t int64) bool { return t != third }
	w.lay()
	fires(c, third+T.probeRounds*T.probeEvery+T.f1For)
	out = append(out, c.finish(37000))

	// Input probe(X), down in 3 rounds: A heartbeats, its rounds pass and then fail.
	liveA := func(id, why string, end int64) (*cs, *world) {
		c := T.newCase(id, "F1", why, "A", "B")
		w := newWorld(c, end)
		w.b.view = downFrom(25000)
		return c, w
	}
	c, w = liveA("f1-013", "input probe: three failing rounds in a row (25, 30, 35 s) make A down at 35 s, with its Heartbeats still arriving and B reporting it down, so dead(A) holds from 35 s and F1 comes at 40 s", 42000)
	w.ar.pass = func(t int64) bool { return t < 25000 }
	w.lay()
	fires(c, 40000)
	out = append(out, c.finish(42000))

	c, w = liveA("f1-014", "input probe: two failing rounds and then a pass do not make A down: dead(A) never holds and nothing moves", 45000)
	w.ar.pass = func(t int64) bool { return t < 25000 || t >= 35000 }
	w.lay()
	out = append(out, c.finish(45000))

	c, w = liveA("f1-015", "input probe: a probe state that was never learned is unknown, not down: A has no round at all, its Heartbeats arrive and B reports it down, and nothing moves", 45000)
	w.ar.to = -1
	w.lay()
	out = append(out, c.finish(45000))

	// Input probe unknown after 15 s with no round.
	c, w = base("f1-016", "input probe: B's last round is at 25 s, so B is unknown from 40 s, the tick on which the 5 s would end: no F1, and B never becomes ready again", end)
	w.br.to = 25000
	w.lay()
	out = append(out, c.finish(end))

	c, w = base("f1-017", "input probe: B's last round is at 26 s, so B is still up at 40 s (14 s since its last round) and F1 comes at 40 s", end)
	w.br.to = 25000
	w.lay()
	c.roundAt(26000, "B", true)
	fires(c, fire)
	out = append(out, c.finish(end))

	// Input view(X): the age of the peer's Heartbeat, 10 s.
	viewAge := func(id, why string, lastB int64, fireF1 bool) {
		c, w := base(id, why, end)
		w.b.to = 27500
		w.lay()
		c.hbOne(lastB, hbSpec{node: "B", peer: "A", view: down})
		if fireF1 {
			fires(c, fire)
		}
		out = append(out, c.finish(end))
	}
	viewAge("f1-018", "input view: B's last Heartbeat is 10 s old at 40 s, so view(A) is none and the timer breaks on the tick it would have ended: no F1", fire-10*T.tick, false)
	viewAge("f1-019", "input view: B's last Heartbeat is 9 s old at 40 s, so view(A) is still down and F1 comes at 40 s", fire-9*T.tick, true)

	// Flap rule: the withdrawal time against the last failback.
	flapCase := func(id, why string, back int64, flaps bool) {
		c, w := base(id, why, end)
		c.start("A", col{LastFailbackAt: i64(back)})
		w.lay()
		got := col{Withdrawn: true, LastFailbackAt: i64(back)}
		if flaps {
			got.FlapUntil = i64(fire + T.flapFor)
		}
		c.event(fire, "F1", map[string]col{"A": got}).alert(fire, T.alertF1, "A", "")
		if flaps {
			c.alert(fire, T.alertFlap, "A", "")
		}
		out = append(out, c.finish(end))
	}
	flapCase("flap-001", "flap rule: a withdrawal 3599 s after the failback is a flap: flap_until is a day ahead, the flapping alert follows, S is 1800 s", fire-(T.flapWindow-1000), true)
	flapCase("flap-002", "flap rule: a withdrawal 3600 s after the failback is no flap: S stays 300 s", fire-T.flapWindow, false)
	return out
}

// f2Cases: row F2 and the age of the peer's Heartbeat in rd.
func f2Cases(T thresholds) []Case {
	var out []Case
	const badFrom = 20000
	fire := badFrom + T.f2For
	end := fire + 2*T.tick
	withdrawA := map[string]col{"A": {Withdrawn: true}}
	bad := func(t int64) []bool {
		if t >= badFrom {
			return []bool{false}
		}
		return []bool{true}
	}
	base := func(id, why string, end int64) (*cs, *world) {
		c := T.newCase(id, "F2", why, "A", "B")
		w := newWorld(c, end)
		w.a.paths = bad
		return c, w
	}
	fires := func(c *cs, at int64) {
		c.event(at, "F2", withdrawA).alert(at, T.alertF2, "A", "")
	}
	c, w := base("f2-001", "F2: rd(A) and ready(B) hold for exactly 30 s: A lists one resolve path and it is unhealthy from 20 s, B has a healthy one, so F2 withdraws A at 50 s", end)
	w.lay()
	fires(c, fire)
	out = append(out, c.finish(end))

	c, w = base("f2-002", "F2: only the state false, A already withdrawn: no action", end)
	c.start("A", T.wd())
	w.lay()
	out = append(out, c.finish(end))

	c, w = base("f2-003", "F2: only rd(A) false, its path is healthy: no action", end)
	w.a.paths = healthy
	w.lay()
	out = append(out, c.finish(end))

	c, w = base("f2-004", "F2: only ready(B) false, B's rounds fail: no action", end)
	w.br.pass = fail
	w.lay()
	out = append(out, c.finish(end))

	c, w = base("f2-005", "F2: the inputs break one tick before the timer (a healthy Heartbeat of A at 48.5 s) and begin again with A's Heartbeat at 50 s, so F2 comes 30 s later, at 80 s", fire+T.f2For+T.tick)
	w.lay()
	c.hbOne(fire-1500, hbSpec{node: "A", peer: "B"})
	fires(c, fire+T.f2For)
	out = append(out, c.finish(fire+T.f2For+T.tick))

	c, w = base("f2-008", "F2: only rd(A) false, A lists no resolve path at all (its Heartbeat has an empty upstreams list, as before the first health check) while B has a healthy one: rd needs at least one listed path and none healthy, so no action", end)
	w.a.paths = func(int64) []bool { return nil }
	w.lay()
	out = append(out, c.finish(end))

	// F2 runs the flap rule like F1 (8a.6): a withdrawal less than 3600 s after
	// the failback is a flap.
	c, w = base("f2-009", "flap rule in F2: A failed back 3599 s before the withdrawal at 50 s, so F2 sets flap_until a day ahead and raises the flapping alert after its own", end)
	c.start("A", col{LastFailbackAt: i64(fire - (T.flapWindow - 1000))})
	w.lay()
	c.event(fire, "F2", map[string]col{"A": {Withdrawn: true, LastFailbackAt: i64(fire - (T.flapWindow - 1000)), FlapUntil: i64(fire + T.flapFor)}}).alert(fire, T.alertF2, "A", "").alert(fire, T.alertFlap, "A", "")
	out = append(out, c.finish(end))

	// rd reads the peer's Heartbeat from the last 15 s.
	peerAge := func(id, why string, lastB int64, fireF2 bool) {
		c, w := base(id, why, end)
		w.b.to = 32500
		w.lay()
		c.hbOne(lastB, hbSpec{node: "B", peer: "A"})
		if fireF2 {
			fires(c, fire)
		}
		out = append(out, c.finish(end))
	}
	peerAge("f2-006", "input rd: B's last Heartbeat is 15 s old at 50 s, so B no longer reports a healthy path and ready(B) fails: no F2", fire-T.hbStale, false)
	peerAge("f2-007", "input rd: B's last Heartbeat is 14.5 s old at 50 s: rd(A) and ready(B) still hold and F2 comes at 50 s", fire-T.hbStale+500, true)
	return out
}

// f3Cases: row F3, S of 300 s and 1800 s, and its conditions.
func f3Cases(T thresholds) []Case {
	var out []Case
	begin := T.probeRounds * T.probeEvery // fit(A) holds from A's third passing round
	base := func(id, why string, stable, end int64) (*cs, *world) {
		c := T.newCase(id, "F3", why, "A", "B")
		c.start("A", T.wd())
		w := newWorld(c, end)
		return c, w
	}
	back := func(c *cs, at int64, flap *int64) {
		c.event(at, "F3", map[string]col{"A": {LastFailbackAt: i64(at), FlapUntil: flap}}).alert(at, T.alertF3, "A", "")
	}
	end := begin + T.stable + T.tick
	c, w := base("f3-001", "F3: A is withdrawn, fit(A) and view(A) up hold from 15 s (its third passing round), so after S = 300 s, at 315 s, A is cleared and its last_failback_at is set", T.stable, end)
	w.lay()
	back(c, begin+T.stable, nil)
	out = append(out, c.finish(end))

	flapUntil := i64(86400000)
	endF := begin + T.stableFlapping + T.tick
	c, w = base("f3-002", "F3: while now < flap_until S is 1800 s, so A comes back at 1815 s and not at 315 s, and the refreshes of F7 come meanwhile", T.stableFlapping, endF)
	c.start("A", col{Withdrawn: true, FlapUntil: flapUntil})
	w.lay()
	back(c, begin+T.stableFlapping, flapUntil)
	out = append(out, c.finish(endF))

	c, w = base("f3-003", "F3: only fit(A) false, A reports isolated in every Heartbeat: no failback", T.stable, end)
	w.a.isolated = func(int64) bool { return true }
	w.lay()
	out = append(out, c.finish(end))

	c, w = base("f3-004", "F3: only view(A) up false, B's PeerView has A as not known: no failback", T.stable, end)
	w.b.view = func(int64) int { return 2 }
	w.lay()
	out = append(out, c.finish(end))

	c, w = base("f3-005", "F3: only the state false, A is withdrawn and held: no failback (a Release must come first)", T.stable, end)
	c.start("A", col{Withdrawn: true, Hold: true})
	w.lay()
	out = append(out, c.finish(end))

	c, w = base("f3-006", "F3: only the state false, A is not withdrawn: nothing to do", T.stable, end)
	c.start("A", col{})
	w.lay()
	out = append(out, c.finish(end))

	// The inputs break one tick before the timer.
	fire := begin + T.stable
	end2 := fire + T.stable + T.tick
	c, w = base("f3-007", "F3: the inputs break one tick before the timer (A reports isolated at 313.5 s), so the 300 s begin again at 315 s and A comes back at 615 s, after the refresh at 600 s", T.stable, end2)
	w.lay()
	c.hbOne(fire-1500, hbSpec{node: "A", peer: "B", isolated: func(int64) bool { return true }})
	back(c, fire+T.stable, nil)
	out = append(out, c.finish(end2))
	return out
}

// requestCases: rows F4, F5 and F6, and the fit input through F6.
func requestCases(T thresholds) []Case {
	var out []Case
	const at = 20000
	end := int64(21000)
	req := func(c *cs, id, node, op string, requestedAt int64) {
		c.add(ev{At: at, Kind: "request", ID: id, Node: node, Op: op, RequestedAt: i64(requestedAt)})
	}
	// A request world: A, B, and C in no pair. B's third passing round is at 15 s.
	mk := func(id, why string, setup func(c *cs, w *world)) *cs {
		row := strings.ToUpper(id[:2])
		c := T.newCase(id, row, why, "A", "B", "C")
		w := newWorld(c, end)
		if setup != nil {
			setup(c, w)
		}
		w.lay()
		return c
	}
	hold := T.reqF4
	rel := T.reqF5
	force := T.reqF6
	// F4
	c := mk("f4-001", "F4: a Hold for A with B fit and not withdrawn is done at once: A is withdrawn and held, the flap rule does not run", nil)
	req(c, "r1", "A", hold, at)
	c.event(at, "F4", map[string]col{"A": {Withdrawn: true, Hold: true}}).done(at, "r1").alert(at, T.alertF4, "A", "")
	out = append(out, c.finish(end))

	c = mk("f4-002", "F4: only fit(B) false (B is isolated): refused with the reason peer_not_fit", func(c *cs, w *world) {
		w.b.isolated = func(int64) bool { return true }
	})
	req(c, "r1", "A", hold, at)
	c.refused(at, "r1", T.f4Reasons[1])
	out = append(out, c.finish(end))

	c = mk("f4-003", "F4: only B withdrawn false (B is withdrawn, fit): refused with the reason peer_withdrawn", func(c *cs, w *world) {
		c.start("B", T.wd())
	})
	req(c, "r1", "A", hold, at)
	c.refused(at, "r1", T.f4Reasons[2])
	out = append(out, c.finish(end))

	c = mk("f4-004", "F4: C is in no pair, so every condition that presupposes a peer is false: refused with the reason not_paired, the first", nil)
	req(c, "r1", "C", hold, at)
	c.refused(at, "r1", T.f4Reasons[0])
	out = append(out, c.finish(end))

	c = mk("f4-005", "F4: B is not fit and withdrawn: refused with the reason of the first condition that fails, peer_not_fit", func(c *cs, w *world) {
		c.start("B", T.wd())
		w.b.isolated = func(int64) bool { return true }
	})
	req(c, "r1", "A", hold, at)
	c.refused(at, "r1", T.f4Reasons[1])
	out = append(out, c.finish(end))

	// F5
	c = mk("f5-001", "F5: a Release for a held A is done: the hold is cleared and A stays withdrawn (F3 decides its return)", func(c *cs, w *world) {
		c.start("A", col{Withdrawn: true, Hold: true})
		w.a.to, w.ar.to = -1, -1
	})
	req(c, "r1", "A", rel, at)
	c.event(at, "F5", map[string]col{"A": {Withdrawn: true}}).done(at, "r1").alert(at, T.alertF5, "A", "")
	out = append(out, c.finish(end))

	c = mk("f5-002", "F5: only held false (A is not held): refused with the reason not_held", nil)
	req(c, "r1", "A", rel, at)
	c.refused(at, "r1", T.f5Reasons[0])
	out = append(out, c.finish(end))

	c = mk("f5-003", "F5: a Release for a held node in no pair is done, and the node stays withdrawn", func(c *cs, w *world) {
		c.start("C", col{Withdrawn: true, Hold: true})
	})
	req(c, "r1", "C", rel, at)
	c.event(at, "F5", map[string]col{"C": {Withdrawn: true}}).done(at, "r1").alert(at, T.alertF5, "C", "")
	out = append(out, c.finish(end))

	// F6
	c = mk("f6-001", "F6: a Force failback for a withdrawn A that is fit clears the withdrawal at once, sets last_failback_at, and no S is left", func(c *cs, w *world) {
		c.start("A", T.wd())
	})
	req(c, "r1", "A", force, at)
	c.event(at, "F6", map[string]col{"A": {LastFailbackAt: i64(at)}}).done(at, "r1").alert(at, T.alertF6, "A", "")
	out = append(out, c.finish(end))

	c = mk("f6-002", "F6: a Force failback also clears a hold", func(c *cs, w *world) {
		c.start("A", col{Withdrawn: true, Hold: true})
	})
	req(c, "r1", "A", force, at)
	c.event(at, "F6", map[string]col{"A": {LastFailbackAt: i64(at)}}).done(at, "r1").alert(at, T.alertF6, "A", "")
	out = append(out, c.finish(end))

	c = mk("f6-003", "F6: only withdrawn false (A is not withdrawn): refused with the reason not_withdrawn", nil)
	req(c, "r1", "A", force, at)
	c.refused(at, "r1", T.f6Reasons[1])
	out = append(out, c.finish(end))

	c = mk("f6-004", "F6: only fit(A) false (A is isolated): refused with the reason not_fit", func(c *cs, w *world) {
		c.start("A", T.wd())
		w.a.isolated = func(int64) bool { return true }
	})
	req(c, "r1", "A", force, at)
	c.refused(at, "r1", T.f6Reasons[2])
	out = append(out, c.finish(end))

	c = mk("f6-005", "F6: C is in no pair: refused with the reason not_paired, the first", func(c *cs, w *world) {
		c.start("C", T.wd())
	})
	req(c, "r1", "C", force, at)
	c.refused(at, "r1", T.f6Reasons[0])
	out = append(out, c.finish(end))

	c = mk("f6-006", "F6: the first reason that fails, not_withdrawn, when A is neither withdrawn nor fit", func(c *cs, w *world) {
		w.a.isolated = func(int64) bool { return true }
	})
	req(c, "r1", "A", force, at)
	c.refused(at, "r1", T.f6Reasons[1])
	out = append(out, c.finish(end))

	// Input fit(X): applied_seq against a HeadNotice sent more than 30 s ago.
	notice := int64(20000)
	lag := func(id, why string, askAt int64, seqAt func(int64) uint64, ok bool) {
		end := askAt + 2*T.tick
		c := T.newCase(id, "F6", why, "A", "B")
		c.start("A", T.wd())
		w := newWorld(c, end)
		w.a.seq = seqAt
		w.lay()
		c.add(ev{At: notice, Kind: "head_notice", Node: "A", Seq: 5})
		c.add(ev{At: askAt, Kind: "request", ID: "r1", Node: "A", Op: force, RequestedAt: i64(askAt)})
		if ok {
			c.event(askAt, "F6", map[string]col{"A": {LastFailbackAt: i64(askAt)}}).done(askAt, "r1").alert(askAt, T.alertF6, "A", "")
		} else {
			c.refused(askAt, "r1", T.f6Reasons[2])
		}
		out = append(out, c.finish(end))
	}
	lagging := func(int64) uint64 { return 4 }
	caught := func(t int64) uint64 {
		if t > notice {
			return 5
		}
		return 4
	}
	grace := T.headNotice
	lag("f6-010", "input fit: a HeadNotice sent exactly 30 s ago is not yet required (more than 30 s), so a lagging A is fit and the Force failback is done", notice+grace, lagging, true)
	lag("f6-011", "input fit: a HeadNotice sent 31 s ago is required, so A with applied_seq 4 below it is not fit: refused with not_fit", notice+grace+T.tick, lagging, false)
	lag("f6-012", "input fit: A has applied the entry of the HeadNotice (applied_seq 5) in time: fit, the Force failback is done", notice+grace+T.tick, caught, true)
	return out
}

// f7Cases: the refresh.
func f7Cases(T thresholds) []Case {
	var out []Case
	r := T.refresh
	c := T.newCase("f7-001", "F7", "F7: ten minutes after the last signing event, with no flag change, a refresh is signed", "A", "B")
	out = append(out, c.finish(r))
	c = T.newCase("f7-002", "F7", "F7: no refresh one tick before the ten minutes", "A", "B")
	out = append(out, c.finish(r-T.tick))
	c = T.newCase("f7-003", "F7", "F7: a refresh repeats every ten minutes, and it carries the stable period of a withdrawn node", "A", "B")
	c.start("A", T.wd())
	out = append(out, c.finish(2*r))
	c = T.newCase("f7-004", "F7", "F7: an event on the tick on which the refresh is due replaces it (a Release signs its own version), and the next refresh is ten minutes after that event", "A", "B")
	c.start("A", col{Withdrawn: true, Hold: true})
	c.add(ev{At: r, Kind: "request", ID: "r1", Node: "A", Op: T.reqF5, RequestedAt: i64(r)})
	c.event(r, "F5", map[string]col{"A": {Withdrawn: true}}).done(r, "r1").alert(r, T.alertF5, "A", "")
	out = append(out, c.finish(r+T.tick))
	return out
}

// orderCases: the order of rows on a tick, and the age of a request.
func orderCases(T thresholds) []Case {
	var out []Case

	// F1 and F2 due for one X on one tick: F1 acts, F2 no longer applies.
	{
		rdFrom := int64(20000)
		fire := rdFrom + T.f2For
		deadFrom := fire - T.f1For // the third failing round
		end := fire + 2*T.tick
		c := T.newCase("order-001", "order:f1-f2", "order: F1 and F2 are due for A on the same tick (50 s): F1 acts, A is withdrawn, F2 does not apply and the alert is the Withdrawal", "A", "B")
		w := newWorld(c, end)
		w.a.paths = func(t int64) []bool { return []bool{t < rdFrom} }
		w.b.view = downFrom(30000)
		w.ar.pass = func(t int64) bool { return t < deadFrom-2*T.probeEvery }
		w.lay()
		c.event(fire, "F1", map[string]col{"A": {Withdrawn: true}}).alert(fire, T.alertF1, "A", "")
		out = append(out, c.finish(end))
	}
	// F0 and F1 on one tick.
	{
		fire := int64(40000)
		end := fire + 2*T.tick
		c := T.newCase("order-002", "order:f0-f1", "order: F0 and F1 on one tick: C and D are made a pair at 40 s, the tick on which F1 is due for A, so F0 acts first and withdraws C, then F1 withdraws A", "A", "B", "C", "D")
		w := newWorld(c, end)
		w.a.to, w.ar.to = 20000, 20000
		w.b.view = downFrom(25000)
		w.lay()
		c.add(ev{At: fire, Kind: "membership", Membership: &Membership{
			Pairs:  []Pair{{ID: "p1", Primary: "A", Fallback: "B"}, {ID: "p2", Primary: "C", Fallback: "D"}},
			Global: "p1",
		}})
		c.event(fire, "F0", map[string]col{"C": {Withdrawn: true}}).alert(fire, T.alertF0, "C", "withdrawn")
		c.event(fire, "F1", map[string]col{"A": {Withdrawn: true}}).alert(fire, T.alertF1, "A", "")
		out = append(out, c.finish(end))
	}
	// F1 for X and F3 for Y on one tick: F1 clears Y, so F3 for Y has nothing to do.
	{
		begin := T.probeRounds * T.probeEvery
		f3 := begin + T.stable
		deadFrom := f3 - T.f1For
		end := f3 + 2*T.tick
		c := T.newCase("order-003", "order:f1-f3", "order: F1 for A and F3 for B due on the same tick (315 s): F1 acts first, withdraws A and clears B's withdrawal, so F3 for B has nothing to do", "A", "B")
		c.start("B", T.wd())
		w := newWorld(c, end)
		w.b.view = downFrom(deadFrom - 5000)
		w.ar.pass = func(t int64) bool { return t < deadFrom-2*T.probeEvery }
		w.lay()
		c.event(f3, "F1", map[string]col{"A": {Withdrawn: true}, "B": {LastFailbackAt: i64(f3)}}).alert(f3, T.alertF1, "A", "")
		out = append(out, c.finish(end))
	}
	// A request read on the tick on which F1 acts is judged on the state F1 left.
	{
		fire := int64(40000)
		end := fire + 2*T.tick
		c := T.newCase("order-004", "order:f1-request", "order: a Release for B read on the tick on which F1 acts for A: F1 clears B's withdrawal and hold, so the Release is refused with not_held", "A", "B")
		c.start("B", col{Withdrawn: true, Hold: true})
		w := newWorld(c, end)
		w.a.to, w.ar.to = 20000, 20000
		w.b.view = downFrom(25000)
		w.lay()
		c.add(ev{At: fire, Kind: "request", ID: "r1", Node: "B", Op: T.reqF5, RequestedAt: i64(fire)})
		c.event(fire, "F1", map[string]col{"A": {Withdrawn: true}, "B": {LastFailbackAt: i64(fire)}}).alert(fire, T.alertF1, "A", "").alert(fire, T.alertF1, "B", "cleared_hold")
		c.refused(fire, "r1", T.f5Reasons[0])
		out = append(out, c.finish(end))
	}
	// Two requests on one tick, in requested_at order, then id.
	{
		at := int64(6000)
		c := T.newCase("order-005", "order:requests", "order: three Release requests read on one tick are decided in requested_at order, then id: d (requested at 4 s), then c1 and c2 (both at 5 s)", "A", "B", "C", "D", "E")
		c.start("C", col{Withdrawn: true, Hold: true}).start("D", col{Withdrawn: true, Hold: true}).start("E", col{Withdrawn: true, Hold: true})
		c.add(ev{At: at, Kind: "request", ID: "c2", Node: "E", Op: T.reqF5, RequestedAt: i64(5000)})
		c.add(ev{At: at, Kind: "request", ID: "c1", Node: "C", Op: T.reqF5, RequestedAt: i64(5000)})
		c.add(ev{At: at, Kind: "request", ID: "d", Node: "D", Op: T.reqF5, RequestedAt: i64(4000)})
		for _, r := range [][2]string{{"d", "D"}, {"c1", "C"}, {"c2", "E"}} {
			c.event(at, "F5", map[string]col{r[1]: {Withdrawn: true}}).done(at, r[0]).alert(at, T.alertF5, r[1], "")
		}
		out = append(out, c.finish(at+T.tick))
	}
	// The age of a request, by the database clock.
	for i, tc := range []struct {
		id  string
		age int64
		why string
	}{
		{"order-006", T.requestMax, "order: a request read 10 s after its requested_at is decided (a request is expired only when older than 10 s)"},
		{"order-007", T.requestMax + T.tick, "order: a request read 10 s plus one tick after its requested_at is expired and never carried out"},
	} {
		c := T.newCase(tc.id, "order:request-age", tc.why, "A", "B", "C")
		c.start("C", col{Withdrawn: true, Hold: true})
		at := tc.age
		c.add(ev{At: at, Kind: "request", ID: "r1", Node: "C", Op: T.reqF5, RequestedAt: i64(0)})
		if i == 0 {
			c.event(at, "F5", map[string]col{"C": {Withdrawn: true}}).done(at, "r1").alert(at, T.alertF5, "C", "")
		} else {
			c.expired(at, "r1")
		}
		out = append(out, c.finish(at+T.tick))
	}
	return out
}

// f0Cases: the generated cases of row F0.
func f0Cases(T thresholds) []Case {
	var out []Case
	at := int64(10000)
	c := T.newCase("f0-001", "F0", "F0: the first pair is created, (A, B), by the change that also makes it the global pair: A, a primary with no peer before, is withdrawn at once and B answers", "A", "B")
	c.pairs("")
	c.add(ev{At: at, Kind: "membership", Membership: &Membership{
		Pairs: []Pair{{ID: "p1", Primary: "A", Fallback: "B"}}, Global: "p1"}})
	c.event(at, "F0", map[string]col{"A": {Withdrawn: true}}).alert(at, T.alertF0, "A", "withdrawn")
	out = append(out, c.finish(at+2*T.tick))

	c = T.newCase("f0-002", "F0", "F0: only the state false: a swap of the two roles inside one pair changes no node's peer, so there is no F0 and no event", "A", "B")
	c.add(ev{At: at, Kind: "membership", Membership: &Membership{
		Pairs: []Pair{{ID: "p1", Primary: "B", Fallback: "A"}}, Global: "p1"}})
	out = append(out, c.finish(at+2*T.tick))
	return out
}

// Cases returns every generated case, in file order.
func generated() []Case {
	T := load()
	var all []Case
	for _, f := range []func(thresholds) []Case{f0Cases, f1Cases, f2Cases, f3Cases, requestCases, f7Cases, orderCases} {
		all = append(all, f(T)...)
	}
	return all
}

var _ = fmt.Sprintf
