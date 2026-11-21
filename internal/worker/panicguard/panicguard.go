// Package panicguard keeps a panic of the worker role's code with the unit of work that raised it
// (P1 auth review round 17, sms-r17-5 and sms-r17-17; rule goroutine-recover).
//
// Why the worker role needs it. A panic in any goroutine ends the whole process, and in the worker
// that is not harmless: up to Concurrency rows of the SMS queue are in flight at once, each already
// handed to a provider that may have accepted the message, and a restart does not undo it. The
// message is sent again when the claim lapses, billed again, and its price never reaches the money
// counter (spec 18.3). So no goroutine of the role may end the process while another goroutine of it
// holds an accepted send that is not yet recorded: the row goroutines of the SMS drain, the two
// sweep cadences, the admin job loop and the SMS loop itself all keep their panics through this one
// function, so the invariant does not depend on which of them was thought of.
//
// It is used in two places, and both matter:
//
//   - as the FIRST deferred statement of a goroutine, the shape internal/lint
//     TestEveryGoroutineKeepsItsPanic accepts, with the WaitGroup of that goroutine, so a goroutine
//     is never left without a count-down; and
//   - around ONE PASS of a loop (one sweep run, one drain, one job pass), without a WaitGroup, so a
//     panic in a pass costs that pass and the loop goes on at its next tick. A loop that ended on a
//     panic would leave a worker that looks healthy to Compose and does nothing.
//
// What it logs: the name of the unit and a closed value, never the value of the panic, which can
// hold anything the code was handling (a phone number, a reply of a provider). What it does not do:
// it does not retry, undo or compensate. The unit is left as a crash would leave it, and every unit
// of the worker role is written to be run again from a crash (a claim lapses, a sweep is idempotent,
// a job resumes).
package panicguard

import (
	"log/slog"
	"sync"

	"github.com/Kup1ng/CtrlZ-Panel/internal/closed"
	"github.com/Kup1ng/CtrlZ-Panel/internal/logattr"
)

// Msg is the one log message of a kept panic, so an operator can search for it.
const Msg = "worker unit panicked"

// Keep is deferred directly (`defer panicguard.Keep(...)`): recover only stops a panic when the
// deferred function itself calls it, so a wrapper around Keep would stop nothing. what is the closed value that says which unit it was
// (the log attribute is always "unit": logattr.Enum takes a constant key). wg is the count-down of the goroutine, or nil when Keep guards a pass inside a goroutine that has its own.
func Keep[K closed.Closed](log *slog.Logger, what K, wg *sync.WaitGroup) {
	if wg != nil {
		defer wg.Done()
	}
	if recover() != nil {
		log.Error(Msg, logattr.Enum("unit", what))
	}
}
