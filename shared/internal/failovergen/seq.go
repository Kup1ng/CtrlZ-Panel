package failovergen

import (
	"fmt"
)

// The fixed sequences of 8a.10. Each expectation is written by hand from the
// text of 8a.3, 8a.4 and 8a.6 named in the case's why, not computed from a run.

func (c *cs) live(node, peer string, phase, to int64, view func(int64) int) {
	c.heartbeats(hbSpec{node: node, peer: peer, phase: phase, to: to, view: view})
	c.rounds(roundSpec{node: node, to: to})
}

func sequences() []Case {
	T := load()
	var all []Case
	for _, f := range []func(thresholds) []Case{
		timingSeqs, outageSeqs, noMoveSeqs, fallbackDiesSeqs, bothDownSeqs, restartSeqs, flapSeqs, resolveSeqs,
		revocationSeqs, membershipSeqs,
	} {
		all = append(all, f(T)...)
	}
	return all
}

// timingSeqs: the worst case of 8a.3.
func timingSeqs(T thresholds) []Case {
	var out []Case
	mk := func(id, why string, lastHB int64, hbPhase int64) {
		kill := int64(100500)
		end := kill + 30000
		c := T.newCase(id, "sequence:worst-case", why, "A", "B")
		c.heartbeats(hbSpec{node: "A", peer: "B", phase: hbPhase, to: lastHB})
		// The hub's rounds of A pass up to the kill and the three after it fail
		// 7, 12 and 17 s later (a 5 s round and a 2 s timeout, 8a.3).
		for t := int64(5500); t <= kill; t += 5000 {
			c.roundAt(t, "A", true)
		}
		for t := kill + 7000; t <= end; t += 5000 {
			c.roundAt(t, "A", false)
		}
		// B's own probe of A reaches its third failure at 17.5 s and rides the
		// Heartbeat after the next one, at 22.5 s (B's Heartbeats are at 2.5 s
		// past the 5 s grid, and the one at 17.5 s still says up).
		c.heartbeats(hbSpec{node: "B", peer: "A", phase: 2500, to: end, view: downFrom(kill + 22000)})
		c.rounds(roundSpec{node: "B", to: end})
		// dead(A) holds from the tick after B's Heartbeat that says down, 23 s;
		// F1 is 5 s later.
		c.event(kill+27500, "F1", map[string]col{"A": {Withdrawn: true}}).alert(kill+27500, T.alertF1, "A", "")
		out = append(out, c.finish(end))
	}
	mk("seq-001", "worst case of 8a.3: A dies just after a passing round and its last Heartbeat (at the kill). Its probe is down at 17 s, its Heartbeat is 15 s old at 16 s, B's down view reaches the hub at 22.5 s, and F1 acts 5 s after the next tick, 27.5 s after the kill (about 28 s)", 100500, 500)
	mk("seq-002", "worst case of 8a.3 with the last Heartbeat of A 4.9 s before the death: the hub's own Heartbeat signal comes earlier, at 111 s, but the decision still waits for B's down view, so F1 is at the same 27.5 s", 95600, 600)
	return out
}

// outageSeqs: short outages, which three rounds in a row must outlast.
func outageSeqs(T thresholds) []Case {
	var out []Case
	end := int64(80000)
	// A dead dns with a live agent for L seconds from o: a round that starts at
	// s fails when s is in (o-2 s, o+L), because it ends 2 s later at the latest.
	// Such an outage fails at most floor((L+2)/5)+1 rounds in a row.
	outage := func(c *cs, o, L int64) {
		for s := T.probeEvery; s <= end; s += T.probeEvery {
			if s > o-2000 && s < o+L {
				c.roundAt(s+2000, "A", false)
			} else {
				c.roundAt(s, "A", true)
			}
		}
	}
	for _, L := range []int64{5000, 6000} {
		for _, phase := range []int64{0, 1000, 2000, 3000, 4000} {
			o := 50000 + phase
			c := T.newCase(fmt.Sprintf("outage-%d-%d", L/1000, phase/1000), "sequence:outage",
				fmt.Sprintf("outage: A's dns is down for %d s from %d s, %d s into the 5 s round grid: at most %d rounds in a row fail, which is below the 3 that make A down, so nothing moves", L/1000, o/1000, phase/1000, (L+2000)/5000+1), "A", "B")
			c.heartbeats(hbSpec{node: "A", peer: "B", to: end})
			outage(c, o, L)
			c.live("B", "A", 2500, end, up)
			out = append(out, c.finish(end))
		}
	}
	for _, L := range []int64{25000, 30000} {
		o := int64(50000)
		c := T.newCase(fmt.Sprintf("outage-%d", L/1000), "sequence:outage",
			fmt.Sprintf("outage: A's dns is down for %d s from 50 s with its agent alive: five rounds fail, A is down at 62 s, B's own three failed rounds (shifted 2.5 s) end at 64.5 s and ride its Heartbeat at 67.5 s, so dead(A) holds from 68 s and F1 acts at 73 s", L/1000), "A", "B")
		c.heartbeats(hbSpec{node: "A", peer: "B", to: 74000})
		outage(c, o, L)
		c.heartbeats(hbSpec{node: "B", peer: "A", phase: 2500, to: 74000, view: downFrom(67500)})
		c.rounds(roundSpec{node: "B", to: 74000})
		c.event(73000, "F1", map[string]col{"A": {Withdrawn: true}}).alert(73000, T.alertF1, "A", "")
		out = append(out, c.finish(74000))
	}
	return out
}

// noMoveSeqs: cases in which one signal alone moves nothing.
func noMoveSeqs(T thresholds) []Case {
	var out []Case
	c := T.newCase("seq-010", "sequence:agent-dead", "a dead agent beside a live dns: A's Heartbeats stop at 20 s but its probes pass and B sees it up, so hb(A) is false from 35 s and nothing moves", "A", "B")
	c.heartbeats(hbSpec{node: "A", peer: "B", to: 20000})
	c.rounds(roundSpec{node: "A", to: 80000})
	c.live("B", "A", 2500, 80000, up)
	out = append(out, c.finish(80000))

	c = T.newCase("seq-011", "sequence:dns-dead", "a dead dns beside a live agent: A's Heartbeats go on, its rounds fail from 25 s (down at 35 s) and B reports it down from its Heartbeat at 37.5 s, so F1 acts at 43 s", "A", "B")
	c.heartbeats(hbSpec{node: "A", peer: "B", to: 45000})
	c.rounds(roundSpec{node: "A", to: 45000, pass: func(t int64) bool { return t < 25000 }})
	c.heartbeats(hbSpec{node: "B", peer: "A", phase: 2500, to: 45000, view: downFrom(37500)})
	c.rounds(roundSpec{node: "B", to: 45000})
	c.event(43000, "F1", map[string]col{"A": {Withdrawn: true}}).alert(43000, T.alertF1, "A", "")
	out = append(out, c.finish(45000))

	c = T.newCase("seq-012", "sequence:path-cut", "a full cut of the panel's path to A while B marks A up: no Heartbeat, every round fails, and view(A) is up, so the hub's two signals never decide alone and nothing moves in 100 s", "A", "B")
	c.heartbeats(hbSpec{node: "A", peer: "B", to: 20000})
	c.rounds(roundSpec{node: "A", to: 100000, pass: func(t int64) bool { return t < 25000 }})
	c.live("B", "A", 2500, 100000, up)
	out = append(out, c.finish(100000))

	c = T.newCase("seq-013", "sequence:prober-frozen", "a frozen hub prober while A's dns dies: the last rounds are at 40 s, A's dns dies at 45 s and B reports it down, but every probe state is unknown from 55 s, so there is no F1", "A", "B")
	c.heartbeats(hbSpec{node: "A", peer: "B", to: 120000})
	c.rounds(roundSpec{node: "A", to: 40000})
	c.heartbeats(hbSpec{node: "B", peer: "A", phase: 2500, to: 120000, view: downFrom(62500)})
	c.rounds(roundSpec{node: "B", to: 40000})
	out = append(out, c.finish(120000))
	return out
}

// fallbackDiesSeqs: the fallback dying while a recovered primary is inside S, flapping or held.
func fallbackDiesSeqs(T thresholds) []Case {
	var out []Case
	for _, tc := range []struct {
		id, what string
		start    col
		after    col
		hold     bool
	}{
		{"seq-020", "inside S", col{Withdrawn: true}, col{LastFailbackAt: i64(48000)}, false},
		{"seq-021", "flapping", col{Withdrawn: true, FlapUntil: i64(86400000)}, col{LastFailbackAt: i64(48000), FlapUntil: i64(86400000)}, false},
		{"seq-022", "held", col{Withdrawn: true, Hold: true}, col{LastFailbackAt: i64(48000)}, true},
	} {
		c := T.newCase(tc.id, "sequence:fallback-dies",
			"the advertised fallback B dies while the recovered primary A is "+tc.what+": F1 for B needs only ready(A), so it withdraws B and clears A's withdrawal"+map[bool]string{true: " and hold (the cleared-hold alert)", false: ""}[tc.hold]+" at once, and the answer moves back to A", "A", "B")
		c.start("A", tc.start)
		c.live("A", "B", 0, 49000, func(t int64) int {
			if t >= 32500 {
				return 1
			}
			return 0
		})
		c.live("B", "A", 2500, 27500, up)
		// B's last Heartbeat is at 27.5 s, so hb(B) is false from 43 s, when
		// A's report that B is down (from 32.5 s) is fresh: F1 at 48 s.
		c.event(48000, "F1", map[string]col{"A": tc.after, "B": {Withdrawn: true}}).alert(48000, T.alertF1, "B", "")
		if tc.hold {
			c.alert(48000, T.alertF1, "A", "cleared_hold")
		}
		out = append(out, c.finish(49000))
	}
	return out
}

// bothDownSeqs: both nodes down, and each one returning first.
func bothDownSeqs(T thresholds) []Case {
	var out []Case
	back := int64(100000)
	end := int64(125000)
	rounds3 := back + T.probeRounds*T.probeEvery
	// a: A is withdrawn, B is advertised, both are silent; A returns first.
	c := T.newCase("seq-030", "sequence:both-down", "both nodes down, the withdrawn primary A returns first: B's death is seen by both observers (A's view and B's missing Heartbeats) once A is up at 115 s, so F1 for B clears A's withdrawal at 120 s", "A", "B")
	c.start("A", T.wd())
	c.heartbeats(hbSpec{node: "A", peer: "B", from: back, to: end, view: down})
	for t := back + T.probeEvery; t <= end; t += T.probeEvery {
		c.roundAt(t, "A", true)
	}
	// B's rounds are probed too, and fail while it is silent.
	for t := T.probeEvery; t <= end; t += T.probeEvery {
		c.roundAt(t, "B", false)
	}
	c.event(rounds3+T.f1For, "F1", map[string]col{"B": {Withdrawn: true}, "A": {LastFailbackAt: i64(rounds3 + T.f1For)}}).alert(rounds3+T.f1For, T.alertF1, "B", "")
	out = append(out, c.finish(end))

	// b: A is withdrawn; B returns first. Nothing moves: the answer is on B already.
	c = T.newCase("seq-031", "sequence:both-down", "both nodes down, the advertised fallback B returns first while A is withdrawn: nothing moves, the answer is on B", "A", "B")
	c.start("A", T.wd())
	c.heartbeats(hbSpec{node: "B", peer: "A", phase: 2500 + back, from: back, to: end, view: down})
	for t := back + T.probeEvery; t <= end; t += T.probeEvery {
		c.roundAt(t, "B", true)
	}
	out = append(out, c.finish(end))

	// c: nobody withdrawn; the fallback returns first: A is moved off.
	c = T.newCase("seq-032", "sequence:both-down", "both nodes down, neither withdrawn, the fallback B returns first: A has been silent and B sees it down, so F1 for A withdraws it at 120 s", "A", "B")
	c.heartbeats(hbSpec{node: "B", peer: "A", phase: 2500 + back, from: back, to: end, view: down})
	for t := back + T.probeEvery; t <= end; t += T.probeEvery {
		c.roundAt(t, "B", true)
	}
	for t := T.probeEvery; t <= end; t += T.probeEvery {
		c.roundAt(t, "A", false)
	}
	c.event(rounds3+T.f1For, "F1", map[string]col{"A": {Withdrawn: true}}).alert(rounds3+T.f1For, T.alertF1, "A", "")
	out = append(out, c.finish(end))

	// d: both silent; nothing at all moves.
	c = T.newCase("seq-033", "sequence:both-down", "both nodes down and silent: no view, so dead(X) holds for neither and nothing moves", "A", "B")
	out = append(out, c.finish(end))
	return out
}

// restartSeqs: a hub restart.
func restartSeqs(T thresholds) []Case {
	var out []Case
	// a: a withdrawn node, eligible since 15 s, and a hub restart at 60 s: the
	// start event is the refresh (no F0 is due) and the timer of F3 begins again
	// once the probe states are known, so A returns 300 s after 75 s.
	rs := int64(60000)
	third := rs + T.probeRounds*T.probeEvery
	end := third + T.stable + T.tick
	c := T.newCase("seq-040", "sequence:hub-restart", "hub restart with a withdrawn node: the start event is the F7 refresh, every probe state is unknown again, so nothing moves until three rounds after the restart (75 s) and F3 comes S after that, at 375 s, not at 315 s", "A", "B")
	c.start("A", T.wd())
	c.live("A", "B", 0, end, up)
	c.live("B", "A", 2500, end, up)
	c.add(ev{At: rs, Kind: "hub_start"})
	c.event(rs, "F7", nil)
	c.event(third+T.stable, "F3", map[string]col{"A": {LastFailbackAt: i64(third + T.stable)}}).alert(third+T.stable, T.alertF3, "A", "")
	out = append(out, c.finish(end))

	// b: a held node and a fallback that dies just before the restart: the
	// restart delays F1 by the time the states need to be known again.
	rs = 50000
	f1 := int64(70000)
	c = T.newCase("seq-041", "sequence:hub-restart", "hub restart with a held node: B dies at 40 s and F1 for B would be at 58 s, but the hub restarts at 50 s, so hb(B) counts from 50 s and A's probe is unknown until 65 s: F1 for B comes at 70 s and clears A's withdrawal and hold", "A", "B")
	c.start("A", col{Withdrawn: true, Hold: true})
	c.live("A", "B", 0, f1+1000, func(t int64) int {
		if t >= 42500 {
			return 1
		}
		return 0
	})
	c.live("B", "A", 2500, 37500, up)
	c.add(ev{At: rs, Kind: "hub_start"})
	c.event(rs, "F7", nil)
	c.event(f1, "F1", map[string]col{"A": {LastFailbackAt: i64(f1)}, "B": {Withdrawn: true}}).alert(f1, T.alertF1, "B", "").alert(f1, T.alertF1, "A", "cleared_hold")
	out = append(out, c.finish(f1+1000))
	return out
}

// flapSeqs: hold and Release, and the peer that never agrees.
func flapSeqs(T thresholds) []Case {
	var out []Case
	// a hold, a Release after 2000 s, and F3 only S after the Release.
	holdAt, relAt := int64(20000), int64(2020000)
	back := relAt + T.stable
	end := back + T.tick
	c := T.newCase("seq-050", "sequence:hold-release", "a Hold at 20 s, a Release at 2020 s (2000 s later) and F3 only S = 300 s after the Release, at 2320 s; the refresh comes every 600 s meanwhile", "A", "B")
	c.live("A", "B", 0, end, up)
	c.live("B", "A", 2500, end, up)
	c.add(ev{At: holdAt, Kind: "request", ID: "h1", Node: "A", Op: T.reqF4, RequestedAt: i64(holdAt)})
	c.add(ev{At: relAt, Kind: "request", ID: "h2", Node: "A", Op: T.reqF5, RequestedAt: i64(relAt)})
	c.event(holdAt, "F4", map[string]col{"A": {Withdrawn: true, Hold: true}}).done(holdAt, "h1").alert(holdAt, T.alertF4, "A", "")
	c.event(relAt, "F5", map[string]col{"A": {Withdrawn: true}}).done(relAt, "h2").alert(relAt, T.alertF5, "A", "")
	c.event(back, "F3", map[string]col{"A": {LastFailbackAt: i64(back)}}).alert(back, T.alertF3, "A", "")
	out = append(out, c.finish(end))

	// the peer that keeps marking a recovered primary down.
	force := int64(400000)
	die := int64(420000)
	f1 := die + T.hbStale + T.f1For // hb(A) is false 15 s after its last Heartbeat
	c = T.newCase("seq-051", "sequence:peer-disagrees", "B keeps marking the recovered primary A down: view(A) is never up, so F3 never comes in 400 s. A Force failback at 400 s moves it, and when A dies at 420 s F1 withdraws it again 20 s later with the flap rule (less than 3600 s after the failback): flapping alert, S 1800 s", "A", "B")
	c.start("A", T.wd())
	c.live("A", "B", 0, die, up)
	c.live("B", "A", 2500, f1+1000, down)
	c.add(ev{At: force, Kind: "request", ID: "r1", Node: "A", Op: T.reqF6, RequestedAt: i64(force)})
	c.event(force, "F6", map[string]col{"A": {LastFailbackAt: i64(force)}}).done(force, "r1").alert(force, T.alertF6, "A", "")
	c.event(f1, "F1", map[string]col{"A": {Withdrawn: true, LastFailbackAt: i64(force), FlapUntil: i64(f1 + T.flapFor)}}).alert(f1, T.alertF1, "A", "").alert(f1, T.alertFlap, "A", "")
	out = append(out, c.finish(f1+1000))

	// F3 brings the primary back, then its resolve paths go bad: F2 withdraws it
	// again within 3600 s of the failback, so the flap rule applies to F2 too.
	failback := begin3(T) + T.stable
	badFrom := failback + 85000
	f2 := badFrom + T.f2For
	end2 := f2 + 2*T.tick
	c = T.newCase("seq-052", "sequence:flap-f2", "A is withdrawn and F3 brings it back at 315 s; from 400 s its only resolve path is unhealthy while B's is healthy, so F2 withdraws it at 430 s, 115 s after the failback: flap_until is a day ahead and the flapping alert follows the F2 alert", "A", "B")
	c.start("A", T.wd())
	bad := func(t int64) []bool { return []bool{t < badFrom} }
	c.heartbeats(hbSpec{node: "A", peer: "B", to: end2, paths: bad})
	c.rounds(roundSpec{node: "A", to: end2})
	c.live("B", "A", 2500, end2, up)
	c.event(failback, "F3", map[string]col{"A": {LastFailbackAt: i64(failback)}}).alert(failback, T.alertF3, "A", "")
	c.event(f2, "F2", map[string]col{"A": {Withdrawn: true, LastFailbackAt: i64(failback), FlapUntil: i64(f2 + T.flapFor)}}).alert(f2, T.alertF2, "A", "").alert(f2, T.alertFlap, "A", "")
	out = append(out, c.finish(end2))
	return out
}

// begin3 is when fit(A) first holds for a node that starts withdrawn: its
// third passing round.
func begin3(T thresholds) int64 { return T.probeRounds * T.probeEvery }

// resolveSeqs: rd in upstream and recursive mode, and a cut on both nodes.
func resolveSeqs(T thresholds) []Case {
	var out []Case
	from := int64(20000)
	fire := from + T.f2For
	bad := func(n int) func(int64) []bool {
		return func(t int64) []bool {
			p := make([]bool, n)
			for i := range p {
				p[i] = t < from
			}
			return p
		}
	}
	c := T.newCase("seq-060", "sequence:rd", "upstream mode: both of A's upstreams are unhealthy from 20 s, so rd(A) holds and F2 acts at 50 s", "A", "B")
	w := newWorld(c, fire+1000)
	w.a.paths = bad(2)
	w.lay()
	c.event(fire, "F2", map[string]col{"A": {Withdrawn: true}}).alert(fire, T.alertF2, "A", "")
	out = append(out, c.finish(fire+1000))

	c = T.newCase("seq-061", "sequence:rd", "upstream mode: one of A's two upstreams is healthy, so it still resolves and nothing moves", "A", "B")
	w = newWorld(c, 80000)
	w.a.paths = func(t int64) []bool { return []bool{false, true} }
	w.lay()
	out = append(out, c.finish(80000))

	heal := int64(100000)
	back := heal + T.stable
	c = T.newCase("seq-062", "sequence:rd", "recursive mode, through the entry of the local Unbound: F2 acts at 50 s. While rd lasts there is no F3 (A is not ready), and it comes only S after the path is back at 100 s, at 400 s, not at 350 s", "A", "B")
	w = newWorld(c, back+1000)
	w.a.paths = func(t int64) []bool { return []bool{t < from || t >= heal} }
	w.lay()
	c.event(fire, "F2", map[string]col{"A": {Withdrawn: true}}).alert(fire, T.alertF2, "A", "")
	c.event(back, "F3", map[string]col{"A": {LastFailbackAt: i64(back)}}).alert(back, T.alertF3, "A", "")
	out = append(out, c.finish(back+1000))

	c = T.newCase("seq-063", "sequence:rd", "a cut of every resolve path on both nodes: rd is comparative and holds for neither, so nothing moves", "A", "B")
	w = newWorld(c, 100000)
	w.a.paths, w.b.paths = bad(1), bad(1)
	w.lay()
	out = append(out, c.finish(100000))

	// The fallback withdrawn by F2, then the primary dying with its last
	// Heartbeat listing a healthy path: F1 comes once that Heartbeat is 15 s old.
	die := int64(60000)
	ready := die + T.hbStale
	c = T.newCase("seq-064", "sequence:rd-then-death", "B is withdrawn by F2 at 53 s (its first unhealthy Heartbeat is at 22.5 s), then A dies at 60 s with a last Heartbeat that lists a healthy path: rd(B) still holds while that Heartbeat is fresh, so B is not ready, and F1 for A comes only when it is 15 s old, at 75 s, plus 5 s: it withdraws A and clears B", "A", "B")
	c.live("A", "B", 0, die, up)
	c.heartbeats(hbSpec{node: "B", peer: "A", phase: 2500, to: ready + 6000, view: downFrom(die + 2500), paths: bad(1)})
	c.rounds(roundSpec{node: "B", to: ready + 6000})
	f2 := int64(22500) + 500 + T.f2For
	c.event(f2, "F2", map[string]col{"B": {Withdrawn: true}}).alert(f2, T.alertF2, "B", "")
	c.event(ready+T.f1For, "F1", map[string]col{"A": {Withdrawn: true}, "B": {LastFailbackAt: i64(ready + T.f1For)}}).alert(ready+T.f1For, T.alertF1, "A", "")
	out = append(out, c.finish(ready+T.f1For+1000))
	return out
}

// revocationSeqs: a revoked node (8a.4, 8a.6).
func revocationSeqs(T thresholds) []Case {
	var out []Case
	rv := int64(30000)
	fire := rv + T.f1For
	// a: the advertised node revoked while its peer is ready.
	c := T.newCase("rev-001", "sequence:revocation", "A is revoked at 30 s while B is ready: revoked(A) is the one fact the hub acts on, dead(A) holds at once, and F1 acts 5 s after the revocation is read", "A", "B")
	c.live("A", "B", 0, 90000, up)
	c.live("B", "A", 2500, 90000, up)
	c.add(ev{At: rv, Kind: "revoke", Node: "A"})
	c.event(fire, "F1", map[string]col{"A": {Withdrawn: true}}).alert(fire, T.alertF1, "A", "")
	// Afterwards neither F3, nor F6, nor the peer's F1 clears it.
	c.add(ev{At: 60000, Kind: "request", ID: "r1", Node: "A", Op: T.reqF6, RequestedAt: i64(60000)})
	c.refused(60000, "r1", T.f6Reasons[2])
	out = append(out, c.finish(90000))

	// b: the peer held, then cleared by the F1 for the revoked node.
	c = T.newCase("rev-002", "sequence:revocation", "A is revoked while its peer B is held: F1 withdraws A and clears B's withdrawal and hold, with the cleared-hold alert", "A", "B")
	c.start("B", col{Withdrawn: true, Hold: true})
	c.live("A", "B", 0, fire+1000, up)
	c.live("B", "A", 2500, fire+1000, up)
	c.add(ev{At: rv, Kind: "revoke", Node: "A"})
	c.event(fire, "F1", map[string]col{"A": {Withdrawn: true}, "B": {LastFailbackAt: i64(fire)}}).alert(fire, T.alertF1, "A", "").alert(fire, T.alertF1, "B", "cleared_hold")
	out = append(out, c.finish(fire+1000))

	// c: the peer is not ready: no event.
	c = T.newCase("rev-003", "sequence:revocation", "A is revoked while B is not ready (its rounds fail): F1 needs ready(B), so nothing moves", "A", "B")
	c.live("A", "B", 0, 90000, up)
	c.heartbeats(hbSpec{node: "B", peer: "A", phase: 2500, to: 90000})
	c.rounds(roundSpec{node: "B", to: 90000, pass: fail})
	c.add(ev{At: rv, Kind: "revoke", Node: "A"})
	out = append(out, c.finish(90000))

	// d: the peer's F1 does not clear a revoked node: B dies after A was withdrawn.
	dieB := int64(70000)
	c = T.newCase("rev-004", "sequence:revocation", "after A was revoked and withdrawn, B dies at 70 s: F1 for B needs ready(A), and a revoked node is never ready, so the answer stays on B's address and nothing clears A", "A", "B")
	c.start("A", T.wd())
	c.live("A", "B", 0, 120000, downFrom(dieB+2500))
	c.live("B", "A", 2500, dieB, up)
	c.add(ev{At: 1000, Kind: "revoke", Node: "A"})
	out = append(out, c.finish(120000))

	// e: the peer that keeps marking a recovered primary down, revoked.
	c = T.newCase("rev-005", "sequence:revocation", "B keeps marking the recovered primary A down and is revoked at 30 s: F1 for B needs ready(A), which holds, so it withdraws B and clears A's withdrawal: the answer moves to A", "A", "B")
	c.start("A", T.wd())
	c.live("A", "B", 0, fire+1000, up)
	c.live("B", "A", 2500, fire+1000, down)
	c.add(ev{At: rv, Kind: "revoke", Node: "B"})
	c.event(fire, "F1", map[string]col{"B": {Withdrawn: true}, "A": {LastFailbackAt: i64(fire)}}).alert(fire, T.alertF1, "B", "")
	out = append(out, c.finish(fire+1000))
	return out
}

// membershipSeqs: row F0.
func membershipSeqs(T thresholds) []Case {
	var out []Case
	pr := func(id, p, f string) Pair {
		return Pair{ID: id, Primary: p, Fallback: f}
	}
	at := int64(10000)
	mem := func(c *cs, ms ...Pair) {
		g := "p1"
		if len(ms) == 0 {
			g = ""
		}
		c.add(ev{At: at, Kind: "membership", Membership: &Membership{Pairs: ms, Global: g}})
	}
	f0 := func(c *cs, changes map[string]col, alerts ...[2]string) {
		c.event(at, "F0", changes)
		if len(alerts) == 0 {
			c.alert(at, T.alertF0, "", "")
		}
		for _, a := range alerts {
			c.alert(at, T.alertF0, a[0], a[1])
		}
	}
	short := at + 2*T.tick
	W := func(n string) [2]string { return [2]string{n, "withdrawn"} }
	C := func(n string) [2]string { return [2]string{n, "cleared"} }
	CH := func(n string) [2]string { return [2]string{n, "cleared_hold"} }

	// New primary: F3 after S from the event.
	{
		end := int64(15000) + T.stable + T.tick
		c := T.newCase("mem-001", "F0", "a first pair (A, B) made while both nodes run: A is withdrawn by F0 at 10 s, B answers, and A is back by F3 300 s after fit(A) holds from 15 s, at 315 s", "A", "B")
		c.pairs("")
		c.live("A", "B", 0, end, up)
		c.live("B", "A", 2500, end, up)
		mem(c, pr("p1", "A", "B"))
		f0(c, map[string]col{"A": {Withdrawn: true}}, W("A"))
		c.event(15000+T.stable, "F3", map[string]col{"A": {LastFailbackAt: i64(15000 + T.stable)}}).alert(15000+T.stable, T.alertF3, "A", "")
		out = append(out, c.finish(end))
	}
	// (A, B) and (B, A) created together.
	{
		c := T.newCase("mem-002", "F0", "pairs (A, B) and (B, A) created together from no pair: step 1 withdraws A and B, step 2 decides both pairs from that state and clears both fallbacks, which are both nodes, so neither ends withdrawn and each answers the pair it is the primary of", "A", "B")
		c.pairs("")
		mem(c, pr("p1", "A", "B"), pr("p2", "B", "A"))
		f0(c, nil)
		out = append(out, c.finish(short))
	}
	// (B, C) with B dead and withdrawn to (A, B) and (B, A) with A new.
	{
		c := T.newCase("mem-003", "F0", "(B, C) with B dead and withdrawn changed to (A, B) and (B, A) with A new: step 1 withdraws A, step 2 clears A and B, step 3 withdraws C as it leaves; B answers (B, A) until F1 moves it to A once B is dead to both observers and A is ready, at 20 s, with no flapping alert", "A", "B", "C")
		c.pairs("p1", pr("p1", "B", "C")).start("B", T.wd())
		c.live("A", "B", 0, 21000, down)
		mem(c, pr("p1", "A", "B"), pr("p2", "B", "A"))
		f0(c, map[string]col{"B": {}, "C": {Withdrawn: true}}, C("B"), W("C"))
		c.event(20000, "F1", map[string]col{"B": {Withdrawn: true}}).alert(20000, T.alertF1, "B", "")
		out = append(out, c.finish(21000))
	}
	// Re-pair to a node never withdrawn.
	{
		c := T.newCase("mem-004", "F0", "(A, C) with A dead and withdrawn changed to (A, B), B never withdrawn and in no pair: no flag changes, B answers at once and never A, and C leaves while its old peer A is withdrawn, so C is not withdrawn", "A", "B", "C")
		c.pairs("p1", pr("p1", "A", "C")).start("A", T.wd())
		mem(c, pr("p1", "A", "B"))
		f0(c, nil)
		out = append(out, c.finish(short))
	}
	// A dead, withdrawn primary replaced.
	{
		end := int64(15000) + T.stable + T.tick
		c := T.newCase("mem-005", "F0", "a dead, withdrawn primary replaced, (A, B) to (C, B) with C running: C is withdrawn, B is kept, A keeps its withdrawal, and C is back by F3 300 s after fit(C) holds, at 315 s", "A", "B", "C")
		c.start("A", T.wd())
		c.live("B", "C", 2500, end, up)
		c.live("C", "B", 1000, end, up)
		mem(c, pr("p1", "C", "B"))
		f0(c, map[string]col{"C": {Withdrawn: true}}, W("C"))
		c.event(15000+T.stable, "F3", map[string]col{"C": {LastFailbackAt: i64(15000 + T.stable)}}).alert(15000+T.stable, T.alertF3, "C", "")
		out = append(out, c.finish(end))
	}
	// Advertised fallback replaced while the primary is dead.
	{
		c := T.newCase("mem-006", "F0", "the advertised fallback replaced while the primary is dead, (A, B) to (A, C) with A withdrawn: A is kept withdrawn, C answers at once, B is not withdrawn because A is, so a node still on the older entry answers B", "A", "B", "C")
		c.start("A", T.wd())
		mem(c, pr("p1", "A", "C"))
		f0(c, nil)
		out = append(out, c.finish(short))
	}
	// Planned primary change with A advertised.
	{
		end := int64(15000) + T.stable + T.tick
		c := T.newCase("mem-007", "F0", "a planned primary change (A, B) to (C, B) with A advertised: C is withdrawn, A is withdrawn as it leaves, B answers, and C is back by F3 at 315 s", "A", "B", "C")
		c.live("B", "C", 2500, end, up)
		c.live("C", "B", 1000, end, up)
		mem(c, pr("p1", "C", "B"))
		f0(c, map[string]col{"A": {Withdrawn: true}, "C": {Withdrawn: true}}, W("A"), W("C"))
		c.event(15000+T.stable, "F3", map[string]col{"C": {LastFailbackAt: i64(15000 + T.stable)}}).alert(15000+T.stable, T.alertF3, "C", "")
		out = append(out, c.finish(end))
	}
	// ... with B dead.
	{
		c := T.newCase("mem-008", "F0", "the same change with B dead: B answers, then F1 moves the answer to C once C is ready (20 s), with no flapping alert, and F0 wrote no last_failback_at so S(B) is still 300 s", "A", "B", "C")
		c.live("C", "B", 1000, 21000, down)
		mem(c, pr("p1", "C", "B"))
		f0(c, map[string]col{"A": {Withdrawn: true}, "C": {Withdrawn: true}}, W("A"), W("C"))
		c.event(20000, "F1", map[string]col{"B": {Withdrawn: true}, "C": {LastFailbackAt: i64(20000)}}).alert(20000, T.alertF1, "B", "")
		out = append(out, c.finish(21000))
	}
	// ... the membership read only at a hub start.
	{
		c := T.newCase("mem-009", "F0", "the membership change of (A, B) to (C, B) read only at a hub start: the start event is F0 and sets the same flags as the tick case", "A", "B", "C")
		c.add(ev{At: at, Kind: "membership", Membership: &Membership{Pairs: []Pair{pr("p1", "C", "B")}, Global: "p1"}})
		c.add(ev{At: at, Kind: "hub_start"})
		f0(c, map[string]col{"A": {Withdrawn: true}, "C": {Withdrawn: true}}, W("A"), W("C"))
		out = append(out, c.finish(short))
	}
	// A withdrawn node with 250 s met that F0 gives a new peer.
	{
		ch := int64(265000)
		back := ch + T.stable
		end := back + T.tick
		c := T.newCase("mem-010", "F0", "a withdrawn node with 250 s of its 300 s met that F0 gives a new peer while it stays withdrawn: F3 comes 300 s after the F0 event (565 s), not 50 s", "A", "B", "C")
		c.start("A", T.wd())
		c.live("A", "B", 0, end, up)
		c.live("B", "A", 2500, end, up)
		c.live("C", "A", 1000, end, up)
		c.add(ev{At: ch, Kind: "membership", Membership: &Membership{Pairs: []Pair{pr("p1", "A", "C")}, Global: "p1"}})
		c.event(ch, "F0", nil).alert(ch, T.alertF0, "", "")
		c.event(back, "F3", map[string]col{"A": {LastFailbackAt: i64(back)}}).alert(back, T.alertF3, "A", "")
		out = append(out, c.finish(end))
	}
	// The fallback replaced while the primary is advertised.
	{
		c := T.newCase("mem-011", "F0", "the fallback replaced while the primary is advertised, (A, B) to (A, C): no move, the old fallback B is withdrawn as it leaves", "A", "B", "C")
		mem(c, pr("p1", "A", "C"))
		f0(c, map[string]col{"B": {Withdrawn: true}}, W("B"))
		out = append(out, c.finish(short))
	}
	// A pair replaced by two new nodes.
	{
		c := T.newCase("mem-012", "F0", "a pair replaced by two new nodes, (A, B) to (C, D): C is withdrawn, D answers at once, A and B keep their flags (a node that leaves every pair while its old peer leaves too is not evaluated)", "A", "B", "C", "D")
		mem(c, pr("p1", "C", "D"))
		f0(c, map[string]col{"C": {Withdrawn: true}}, W("C"))
		out = append(out, c.finish(short))
	}
	// A held primary whose fallback is replaced.
	{
		c := T.newCase("mem-013", "F0", "a held primary whose fallback is replaced, (A, B) to (A, C): the hold is kept, the new fallback answers, and there is no cleared-hold alert", "A", "B", "C")
		c.start("A", col{Withdrawn: true, Hold: true})
		mem(c, pr("p1", "A", "C"))
		f0(c, nil)
		out = append(out, c.finish(short))
	}
	// A new primary beside a held fallback.
	{
		c := T.newCase("mem-014", "F0", "a new primary beside a held fallback, (A, B) with B held to (C, B): C is withdrawn, B's withdrawal and hold are cleared with the alert and B answers, A is withdrawn as it leaves", "A", "B", "C")
		c.start("B", col{Withdrawn: true, Hold: true})
		mem(c, pr("p1", "C", "B"))
		f0(c, map[string]col{"A": {Withdrawn: true}, "B": {}, "C": {Withdrawn: true}}, W("A"), CH("B"), W("C"))
		out = append(out, c.finish(short))
	}
	// A dead, withdrawn primary whose advertised fallback is replaced by a held node.
	{
		c := T.newCase("mem-015", "F0", "a dead, withdrawn primary whose advertised fallback is replaced by a held node, (A, B) to (A, C): C's hold is cleared with the alert and C answers, A stays withdrawn and is never answered, B is not withdrawn because A is", "A", "B", "C")
		c.start("A", T.wd()).start("C", col{Withdrawn: true, Hold: true})
		mem(c, pr("p1", "A", "C"))
		f0(c, map[string]col{"C": {}}, CH("C"))
		out = append(out, c.finish(short))
	}
	// A new primary beside a revoked, withdrawn fallback.
	{
		c := T.newCase("mem-016", "F0", "a new primary beside a revoked, withdrawn fallback, (A, R) to (C, R): step 1 withdraws C, step 2 clears C because R is revoked, so C answers and R never does", "A", "R", "C")
		c.pairs("p1", pr("p1", "A", "R")).start("R", T.wd())
		c.c.Start.Membership.Revoked = []string{"R"}
		c.add(ev{At: at, Kind: "membership", Membership: &Membership{Pairs: []Pair{pr("p1", "C", "R")}, Global: "p1", Revoked: []string{"R"}}})
		f0(c, nil)
		out = append(out, c.finish(short))
	}
	// (N, R) with R revoked while in no pair.
	{
		c := T.newCase("mem-017", "F0", "(N, R) with R revoked while in no pair and N just enrolled: step 1 withdraws N and R, step 2 clears N, so N answers and R never does", "N", "R")
		c.pairs("")
		c.c.Start.Membership.Revoked = []string{"R"}
		c.add(ev{At: at, Kind: "membership", Membership: &Membership{Pairs: []Pair{pr("p1", "N", "R")}, Global: "p1", Revoked: []string{"R"}}})
		f0(c, map[string]col{"R": {Withdrawn: true}}, W("R"))
		out = append(out, c.finish(short))
	}
	// Two held nodes put into one pair.
	{
		c := T.newCase("mem-018", "F0", "two held nodes put into one pair, (A, B): the fallback's hold is cleared, with the alert", "A", "B")
		c.pairs("")
		c.start("A", col{Withdrawn: true, Hold: true}).start("B", col{Withdrawn: true, Hold: true})
		mem(c, pr("p1", "A", "B"))
		f0(c, map[string]col{"B": {}}, CH("B"))
		out = append(out, c.finish(short))
	}
	// A switch of the global pair.
	{
		c := T.newCase("mem-019", "F0", "a switch of the global pair from (A, B) to an existing (C, D): no node's peer changes, so there is no F0 and no event, and every flag is kept (A then drains on the node, which is not an output of the evaluator)", "A", "B", "C", "D")
		c.pairs("p1", pr("p1", "A", "B"), pr("p2", "C", "D"))
		c.add(ev{At: at, Kind: "membership", Membership: &Membership{Pairs: []Pair{pr("p1", "A", "B"), pr("p2", "C", "D")}, Global: "p2"}})
		out = append(out, c.finish(short))
	}
	out = append(out, memRoundTrip(T, true), memRoundTrip(T, false))
	_ = C
	return out
}

// memRoundTrip is the membership sequence of 8a.10 that goes through three
// tables: pair (A, B) with B dead and withdrawn; B replaced by C, so (A, C),
// with B keeping its withdrawal (step 3 of F0: A is not withdrawn, so B leaves
// withdrawn as it was); A dies and F1 withdraws it; then (A, B) is restored.
// At that event A and B are both withdrawn, so step 2 clears the fallback B,
// and C leaves while A is withdrawn, so step 3 does not withdraw it. With B
// repaired A comes back by F3; with B still down nothing moves until A is
// ready, and then F1 for B moves the answer to A, with no flapping alert
// because F0 never writes dns_last_failback_at.
func memRoundTrip(T thresholds, repaired bool) Case {
	pr := func(p, f string) []Pair { return []Pair{{ID: "p1", Primary: p, Fallback: f}} }
	const (
		toC   = int64(10000) // (A, B) to (A, C)
		f1At  = int64(43000) // the death of A is seen from 38 s, as in seq-011
		back  = int64(60000) // (A, C) to (A, B)
		aBack = int64(70000) // A's dns answers again from here
	)
	id, why := "mem-021", "the same sequence with B still down: the flags after the restore are the same, nothing moves while A is down too, and F1 for B moves the answer to A at 85 s, 5 s after A is ready (80 s) and B is dead to both observers (75 s), with no flapping alert for B"
	if repaired {
		id, why = "mem-020", "(A, B) with B dead and withdrawn; B replaced by C with no move (B keeps its withdrawal); A dies and F1 withdraws it at 43 s; then (A, B) is restored with B repaired: A stays withdrawn, B is cleared and answers at once, C is left not withdrawn because A is withdrawn, and A is back by F3 300 s after fit(A) and view(A) up first hold, at 383 s"
	}
	end := int64(86000)
	if repaired {
		end = 384000
	}
	c := T.newCase(id, "F0", why, "A", "B", "C")
	c.start("B", T.wd())
	c.add(ev{At: toC, Kind: "membership", Membership: &Membership{Pairs: pr("A", "C"), Global: "p1"}})
	c.event(toC, "F0", nil).alert(toC, T.alertF0, "", "")

	// A's agent lives throughout; its dns fails from 25 s to aBack, and C
	// reports it down from 37.5 s.
	aPass := func(t int64) bool { return t < 25000 || t >= aBack }
	bView := down
	if repaired {
		bView = func(int64) int { return 0 }
	}
	c.heartbeats(hbSpec{node: "A", peer: "B", to: end, view: bView})
	c.rounds(roundSpec{node: "A", to: end, pass: aPass})
	c.heartbeats(hbSpec{node: "C", peer: "A", phase: 2500, to: back, view: downFrom(37500)})
	c.rounds(roundSpec{node: "C", to: back})
	c.event(f1At, "F1", map[string]col{"A": {Withdrawn: true}}).alert(f1At, T.alertF1, "A", "")

	c.add(ev{At: back, Kind: "membership", Membership: &Membership{Pairs: pr("A", "B"), Global: "p1"}})
	c.event(back, "F0", map[string]col{"B": {}}).alert(back, T.alertF0, "B", "cleared")
	if repaired {
		// B is alive again from the restore; its own view of A is down until A's
		// rounds are up (80 s), then up from its Heartbeat at 82.5 s.
		c.heartbeats(hbSpec{node: "B", peer: "A", phase: 2500 + back, from: back, to: end, view: func(t int64) int {
			if t < 80000 {
				return 1
			}
			return 0
		}})
		c.rounds(roundSpec{node: "B", from: back, to: end})
		// fit(A) holds from 80 s (three rounds), view(A) is up from the tick
		// after 82.5 s: S = 300 s from 83 s.
		fire := int64(83000) + T.stable
		c.event(fire, "F3", map[string]col{"A": {LastFailbackAt: i64(fire)}}).alert(fire, T.alertF3, "A", "")
	} else {
		// B stays silent and its rounds fail. hb(B) counts from the restore and
		// is stale at 75 s, when its third failed round also lands.
		c.rounds(roundSpec{node: "B", from: back, to: end, pass: fail})
		// ready(A) from 80 s; F1 for B needs it for 5 s.
		fire := int64(80000) + T.f1For
		c.event(fire, "F1", map[string]col{"B": {Withdrawn: true}, "A": {LastFailbackAt: i64(fire)}}).alert(fire, T.alertF1, "B", "")
	}
	return c.finish(end)
}
