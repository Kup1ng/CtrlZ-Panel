package lint_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/Kup1ng/CtrlZ-Panel/internal/toolcmd"
)

// The escape-hatch ban (owner decision D63; it grew out of the capability guard of P1 auth review
// round 16, sms-r16-21 and sms-r16-22, and answers sms-r15-2).
//
// Why one ban. A guard (a lint, a catalog check, a test oracle) is written against ordinary Go: a
// call, a method value, an alias, an interface value, a wrapper in the same package, a file in
// shared/, a library in go.mod. Go also has tools that defeat the type system and the package
// boundary themselves, and with one of them any guard can be walked around: reflect took the inner
// *http.Client out of smshttp.Client (sms-r15-2) and the answer was a deny list of reflect members
// inside one guard, and the same door stood open in every other guard. So these tools are refused
// once, here, for every package, and a guard does not have to judge them. A bypass that needs one of
// them is judged against this ban and nowhere else. A bypass made of ordinary Go still counts
// against the guard in full.
//
// The tools, derived from the Go specification and the toolchain and not from past findings. Code can
// read or write memory the type system hides, reach an unexported identifier of another package, open
// a file by a path it chooses, call a method by a name it computes, or run code the type checker never
// saw, and each is refused unless a directory is listed for it with a reason:
//
//   - package unsafe (the spec's "Package unsafe": any pointer becomes any type) and package reflect
//     (Value.UnsafePointer returns an unsafe.Pointer that converts to any pointer type with no import
//     of unsafe, reflect.NewAt builds a value at an address, Value.Call calls a method by name): the
//     import is judged with the member list of the directory (memberJudged), so what an entry may do
//     with the package is the list of members, and the methods of the types of reflect are judged too,
//     by the receiver type go/types resolves (reflectMethods). It is the whole package that starts
//     refused, not a list of its members: a member added later starts refused.
//   - package plugin (code loaded at run time) and `import "C"` (cgo: C compiled by a compiler no lint
//     reads): imports, judged with stdCapabilities, where nobody is listed.
//   - text/template, which calls any exported method of a value by the name the template spells, with
//     no call expression in the Go source: it is the call half of reflect and is listed like it
//     (stdCapabilities).
//   - os, syscall and runtime, which reach a process, a file such as /proc/self/mem, a system call or
//     the call stack with no other import: judged by the member a selector names, whatever the import
//     is called (the import table of the file, not the type checker), and a directory that is not
//     listed may not import them at all. os.OpenFile is judged by its flags as well: the flag argument
//     must be spelled as os.O_* constants joined by |, and must contain O_CREATE and O_EXCL together
//     (a new file, which cannot be a device, /proc/self/mem or any file that is there) unless the
//     directory is in openExistingDirs.
//   - net/http and crypto/tls, whose members http.Dir, http.ServeFile, http.FileServer and
//     tls.LoadX509KeyPair open or read a file by a path the caller chooses with no os import: any
//     directory may import them, for the members of anyDirMembers only.
//   - every standard package not in moduleStdSafe: the list names what is allowed, so a package added
//     to the standard library tomorrow starts refused.
//   - compiler and linker directives: a comment `//go:name` and the position directive `//line` are
//     refused unless the name is in goDirectiveSafe (build, embed: they choose files and embed data)
//     or the directory is listed in directiveDirs. //go:linkname reaches an unexported identifier of
//     another package, //go:nocheckptr and //go:norace switch off checks, //go:cgo_* and //go:noescape
//     need code no lint reads, //go:generate runs any command, and the toolchain's own set of names
//     grows: the allow list refuses the ones it does not know.
//   - a function declaration with no body (its body is assembly or a linkname): bodylessDirs.
//   - every file go list reports for a package besides Go source, which the toolchain builds in or
//     would build in on another platform: C, C++, Objective-C, Fortran, assembly, objects, SWIG, the
//     cgo flags, a binary-only package, and any field go list adds later. The set is read from the go
//     list output and not from a list of extensions, an unknown field fails (the table of fields is
//     compared with `go help list`), and every module under the tree is listed, shared/ included,
//     because go list does not enter a nested module. The directories go list ./... does not name
//     (testdata, a name that begins with a dot or an underscore, a directory whose every file is
//     constrained out) are asked for by name when they hold Go source: nonGoSourceDirs.
//   - what decides the code that is built besides the packages: a vendor directory (go build uses it
//     in place of the module graph, with no check against go.sum), a go.work file and a replace
//     directive that points at a directory that is not a module of this tree.
//   - the third-party packages of shared/ (sharedThirdParty): the Panel's libraries are reviewed in
//     imports.yaml, and shared/ is a module of its own that it did not judge, so a library whose type
//     is unsafe.Pointer by another name (protoimpl.Pointer) could be imported with no review.
//   - a package only test files may import (testOnlyImports: shared/vectors takes a *testing.T).
//
// What it judges: EVERY Go file under the repository, whatever the directory is called and whatever
// its build constraints say (parseEveryModule), except the store of the version control system, the
// installed packages of the web code and the CI overlay of the published tree, which nothing may
// import (unreadImportProblems); and every module of the tree, shared/ included (the module the Panel
// imports and the Node carries as a byte-identical copy; the same lists apply to both). The non-test
// files of the harness packages (internal/testpg, internal/testtls and the others of harnessPackages)
// are judged like product code: a harness is built into the binary of its own tests and into
// whatever imports it by mistake.
//
// What it does not judge, on purpose, so that a reviewer knows these are the contract and not gaps:
//
//   - test files (*_test.go). A test is not shipped. A test that cheats is judged by the
//     tests-that-cannot-fail rule and its mutants, and a test may import anything, reflect and unsafe
//     included.
//   - third-party packages of the Panel. A library is listed in imports.yaml with a reason, and a
//     library that wraps one of these tools is a diff a reviewer reads there. Which library functions a
//     guard allows is that guard's business. A reflect value that a library returns has no type the
//     stub of that library resolves, so reflectMethods does not see its methods.
//   - what a listed directory does with its tool beyond the members and methods listed. An entry says
//     the directory may use them, for the reason written; the path argument of a listed os.OpenFile
//     is not judged (a lint cannot bound a path), which is why only the development gateway may open
//     an existing file.
//   - output of values by fmt, encoding/json and templates, which read what they are given; the
//     logging and wire guards judge what reaches them.
//   - toolchain flags (-toolexec, -overlay, -ldflags, GOFLAGS) and the Go packages of the Node
//     repository outside shared/, which has no lint of its own yet (the Node's own ban is phase P4).
//
// A list entry whose directory does not use the tool any more fails, and so does an entry for a
// directory with no non-test Go source: a list cannot rot into a free pass kept for later.

// escapeImports are the packages whose import is an escape hatch, with what each gives. They are
// judged with stdCapabilities (one list of directories for every package that is judged by import),
// and a guard that scopes itself to some packages leaves them to the ban.
var escapeImports = map[string]string{
	"reflect": "reads and writes the memory of a value the type system hid (Value.UnsafePointer, reflect.NewAt)",
	"unsafe":  "casts any pointer to any type and reads or writes memory the type system hides",
	"plugin":  "loads code the type checker never saw, at run time",
	"C":       "is cgo: it calls C compiled by a compiler no lint reads",
}

// moduleStdSafe are the standard packages any directory may import: none of them gives a way to
// read or write memory the type system hid, start a process or load code.
var moduleStdSafe = map[string]string{
	"bufio":           "buffered I/O",
	"bytes":           "bytes",
	"container/list":  "a list",
	"context":         "deadlines and cancellation",
	"crypto/aes":      "AES for the key ring",
	"crypto/cipher":   "GCM for the key ring",
	"crypto/ecdh":     "the node's key agreement for the certificate bundle the hub seals to it (hubctl, p4-nodes 5.2) and the X25519 intake keys an uploaded certificate key is sealed to (internal/intakeseal)",
	"crypto/ecdsa":    "keys of the dev certificate tools",
	"crypto/ed25519":  "the manifest signature of the shared module and its vectors",
	"crypto/elliptic": "curves of the dev certificate tools",
	"crypto/hkdf":     "subkeys of the key ring",
	"crypto/hmac":     "MACs",
	"crypto/hpke":     "the hybrid public key encryption that seals a certificate bundle to the node's key (hubctl, p4-nodes 5.2) and an uploaded certificate key (internal/intakeseal)",
	"crypto/rand":     "random bytes",
	"crypto/rsa":      "the key type of an uploaded certificate (internal/certcheck)",
	"crypto/sha1":     "the HIBP style k-anonymity prefix and the TOTP algorithm named by RFC 6238",
	"crypto/sha256":   "digests",
	"crypto/subtle":   "constant time comparison",
	"crypto/x509":     "certificates and pools",
	"database/sql":    "the type of a NULL column",
	"embed":           "files compiled in",
	"image":           "the image interface and the header reader of assets.Store (P4b 10.5)",
	"image/jpeg":      "the JPEG decoder of assets.Store, which writes the logo again as PNG (P4b 10.5)",
	"image/png":       "the PNG decoder and encoder of assets.Store (P4b 10.5)",
	"encoding/base32": "TOTP seeds",
	"encoding/base64": "text forms",
	"encoding/binary": "framing",
	"encoding/hex":    "text forms",
	"encoding/json":   "JSON",
	"encoding/xml":    "the Melipayamak reply",
	"errors":          "errors",
	"flag":            "command line flags",
	"fmt":             "formatting",
	"go/format":       "the generator of the layout tables",
	"io":              "readers and writers",
	"io/fs":           "file system types",
	"iter":            "iterators of the shared name type",
	"log":             "the standard logger of a tool",
	"log/slog":        "logging",
	"math":            "arithmetic",
	"math/big":        "arithmetic",
	"math/bits":       "bit counts of the policy tables",
	"math/rand/v2":    "non-security randomness, judged by the randsource lint",
	"net":             "addresses and listeners of the servers; a gateway call is judged by the SMS scope",
	"net/netip":       "addresses",
	"net/url":         "URLs",
	"path":            "slash paths",
	"path/filepath":   "file paths",
	"regexp":          "regular expressions",
	"slices":          "slices",
	"sort":            "ordering",
	"strconv":         "numbers",
	"strings":         "strings",
	"sync":            "locks",
	"sync/atomic":     "counters",
	"time":            "time",
	"time/tzdata":     "the zone database compiled in, so no host file is needed",
	"unicode":         "character classes",
	"unicode/utf16":   "the UTF-16 dress of a provider reply",
	"unicode/utf8":    "lengths",

	// A block of its own: gofmt aligns the values of a block to its longest key, and the mutants of mutants.yaml
	// edit the lines above by their exact text.
	"crypto/x509/pkix": "the names and extensions of a certificate the hub's CAs issue (hubpki, enrollproof); a type of values, no file and no process",
	"encoding/asn1":    "the DER of an enrolment proof and of certificate extensions; a codec over bytes",
	"encoding/pem":     "PEM text of keys and certificates, over bytes in memory, and of an uploaded certificate chain and key",
}

// generatedProtobuf lists the seven packages protoc-gen-go and protoc-gen-go-grpc write under
// shared/gen/ctrlz, one by one and never as a glob: a new generated package is a reviewed entry.
var generatedProtobuf = []string{
	"shared/gen/ctrlz/common/v1", "shared/gen/ctrlz/enroll/v1", "shared/gen/ctrlz/hub/v1",
	"shared/gen/ctrlz/peer/v1", "shared/gen/ctrlz/policy/v1", "shared/gen/ctrlz/sign/v1",
	"shared/gen/ctrlz/telemetry/v1",
}

// onGenerated gives each generated protobuf package the same member list.
func onGenerated(members ...string) map[string][]string {
	out := map[string][]string{}
	for _, p := range generatedProtobuf {
		out[p] = members
	}
	return out
}

// withDirs adds the directories of b to a.
func withDirs(a, b map[string][]string) map[string][]string {
	for k, v := range b {
		a[k] = v
	}
	return a
}

// stdCapabilities are the packages that do reach outside the type system or the process, with the
// directories that may import each and why. Each entry must be matched by an import (a stale one is
// a free pass kept for later). reflect and unsafe are not here: a directory is listed for them with
// the members it uses (memberJudged), so the reason of an entry is the list of members.
var stdCapabilities = map[string]map[string]string{
	// text/template calls any exported method of a value it is given, by the name the template text
	// spells, through reflect and with no call expression in the Go source (q9-2, q9-16): it is the
	// call half of reflect, so it is listed like reflect is.
	"text/template": {
		"internal/migrategen":        "the generator renders fixed text for the migration files and the layout tables; it never meets a value of the sms package. A template reaches a method of any value it is given by reflection ({{.Err.Class}}), which the lint of rule sms-failure-classification cannot follow, so no other directory may import it (sms-r17-8)",
		"internal/store/catalogtest": "a harness renders the seed SQL of the catalog checks from fixed ids",
	},
	"os/signal": {
		"cmd/ctrlz":     "the service's graceful stop",
		"tools/mutants": "the mutation tool restores the tree when interrupted",
	},
	"os/exec": {
		"internal/mutant":  "the mutation tool runs go test in a scratch copy of the tree",
		"deploy":           "the one place a Go test builds a docker command (deploy.Docker, deploy.DockerRun, deploy.PinReaper); TestGoRunsNoContainerCommandOutsideDeploy fails for any other",
		"internal/toolcmd": "the one place go and git are started: it judges the verb, the flags and the environment (admin-r18-13)",
	},
	"testing": {
		"internal/authtest":           "a harness",
		"internal/authtest/isolation": "a harness",
		"internal/authtest/oracle":    "a harness",
		"internal/testpg":             "a harness",
		"internal/testvalkey":         "a harness",
		"internal/testwait":           "a harness",
		"shared/vectors":              "the runner of the golden vectors takes a *testing.T so the Panel and the Node run the same files (contract 15); the package is imported by test files only",
	},
	"net/http/httptest": {
		"internal/authtest/boundary": "a harness",
		"internal/authtest/oracle":   "a harness",
		"internal/testtls":           "a harness",
	},
}

// osMembers are the members of os a directory may use, per directory. os opens a file or starts a
// process (os.StartProcess, os.OpenFile on /proc/self/mem), so it is judged by the object a selector
// names, whatever the import is called, and a directory that is not listed may not import it at all.
// It is not the only way to a file: net/http (http.Dir) and crypto/tls (LoadX509KeyPair) reach one
// too, and anyDirMembers lists what they may be used for.
var osMembers = map[string][]string{
	"internal/sms/noop":    {"OpenFile", "O_APPEND", "O_CREATE", "O_WRONLY"}, // the development driver appends to one configured file
	"internal/admission":   {"CreateTemp", "MkdirTemp", "ReadDir", "Remove"}, // the spool directory of the heavy operations: emptied at start, probed for writing, or made private for a test
	"internal/httpx":       {"CreateTemp", "File", "Remove"},                 // the spool file of one heavy request (spec 6.5): created in the spool directory and removed as soon as it is open
	"internal/secret":      {"ReadFile", "PathError"},                        // a secret read from a file, an error type
	"internal/keyring":     {"ErrNotExist"},                                  // a missing key file is not an error of the ring
	"internal/sms/smshttp": {"ReadFile"},                                     // the bundle of trusted roots, read from one absolute path (sms-r17-12)
	"internal/resolvguard": {"ErrNotExist", "ReadFile"},                      // the worker reads the container's own /etc/resolv.conf once at start to refuse a host-namespace DNS forward (p6-ops 9.5); a missing file is not the bypass

	"cmd/ctrlz":                            {"Args", "Exit", "Interrupt", "Stderr"},                                                                                                                                        // the command line, the exit status and the stop signal of the service
	"internal/app":                         {"DirFS", "Getenv", "Open", "ReadFile", "Stderr", "Stdout"},                                                                                                                    // the roles read their environment and log to stdout; load-fixture reads a lab file and prints its result; the hub reads its key files (CTRLZ_HUB_HOST and the secrets of 3.2) from the paths Compose mounts
	"internal/domainapply":                 {"ErrNotExist", "FileMode", "Getenv", "MkdirAll", "O_CREATE", "O_EXCL", "O_WRONLY", "Open", "OpenFile", "ReadDir", "ReadFile", "Remove", "Rename", "Stat", "Stderr", "Stdout"}, // the apply step writes the Caddy certificate files by temp file and rename, reads the .env, and prints the new one
	"internal/hub/hubinstall":              {"File", "O_RDONLY", "Open", "OpenRoot", "ReadDir"},                                                                                                                            // GET /install/* serves the signed bundles under one directory: OpenRoot confines every open to it (a name that escapes is refused by the root), ReadDir lists the versions and Open reads root.json and the manifests, each capped
	"internal/hub/hubtrust":                {"Chmod", "Chown", "CreateTemp", "FileMode", "ReadFile", "Remove", "Rename", "Stat", "WriteFile"},                                                                              // the pin file hub_tls.spki and the NTS key and leaf go by a temporary file in their own directory and a rename, so nobody reads half of one; the NTS leaf is read back to judge it, the debt marker is an empty file, and a renewed key keeps the group of the one it replaces (Stat, Chown)
	"internal/admincli":                    {"ErrExist", "ErrNotExist", "FileMode", "Getenv", "O_CREATE", "O_EXCL", "O_WRONLY", "OpenFile", "Remove", "Rename", "Stderr", "Stdin", "Stdout"},                               // the console writes secret files exclusively and prints to the terminal
	"internal/testpg":                      {"ReadFile", "Stderr"},                                                                                                                                                         // a harness: the wiring test reads the Compose scripts it copies in
	"deploy":                               {"Environ", "Getenv", "IsNotExist", "ReadFile", "UserHomeDir"},                                                                                                                 // the image reference a developer may override, and only with a pinned one
	"internal/testvalkey":                  {"Stderr"},                                                                                                                                                                     // a harness
	"internal/toolcmd":                     {"DevNull", "Environ"},                                                                                                                                                         // the process environment the neutral settings of go and git are added to
	"internal/hub/hubxfer":                 {"ErrNotExist", "File"},                                                                                                                                                        // a blob, a snapshot or a bundle file is opened by the store that names it and read through the handle, chunk by chunk; a missing one is ErrNotExist
	"internal/compiler":                    {"Chmod", "CreateTemp", "File", "Lstat", "MkdirAll", "Open", "Remove", "Rename"},                                                                                               // the artifact store writes a blob through a temporary file, a chmod and a rename, and reads it back (P4 6.5)
	"internal/mutant":                      {"MkdirAll", "MkdirTemp", "ReadDir", "ReadFile", "RemoveAll", "Stat", "WriteFile"},                                                                                             // the mutation tool works in a scratch copy of the tree
	"tools/mutants":                        {"Exit", "Getwd", "Interrupt", "Stat", "Stderr", "Stdout"},                                                                                                                     // the mutation tool's command
	"tools/genmig":                         {"Exit", "Stderr"},                                                                                                                                                             // the migration generator's command
	"tools/genpublicapi":                   {"Exit", "ReadFile", "Stderr", "WriteFile"},                                                                                                                                    // the public document generator reads api/openapi.yaml and writes api/public-openapi.yaml
	"internal/migrategen":                  {"Open", "ReadDir", "ReadFile", "WriteFile"},                                                                                                                                   // the migration generator reads the SQL and writes the generated files
	"internal/auth/pwstrength/layouts/gen": {"Args", "Exit", "Stderr", "WriteFile"},                                                                                                                                        // the generator of the layout tables
	"shared/cmd/sharedtool":                {"Args", "Chmod", "CreateTemp", "Exit", "MkdirAll", "ReadDir", "ReadFile", "Remove", "Rename", "Stat", "Stderr", "Stdout"},                                                     // the checksum tool reads the module tree and rewrites CHECKSUMS and the copy through a temp file, a chmod and a rename
}

// syscallMembers and runtimeMembers: the packages that give a raw system call, the call stack and
// the scheduler to whoever imports them, judged by member like os (a bare syscall.Syscall, Mmap or
// LoadLibrary is as good as unsafe).
var syscallMembers = map[string][]string{
	"cmd/ctrlz":             {"SIGTERM"}, // the stop signal of the service
	"internal/hub/hubtrust": {"Stat_t"},  // the group id of the NTS key file, so a renewed key (a new inode) keeps the group chrony reads it by
}

var runtimeMembers = map[string][]string{
	"internal/logattr":         {"Callers", "CallersFrames"}, // logattr.Stack reads the function names, files and lines of the call stack, never a value a frame holds
	"internal/auth/pwstrength": {"GOMAXPROCS"},               // reads the number of CPUs to size the check pool
}

// reflectMembers and unsafeMembers: reflect and unsafe are judged by member too, not only by import,
// so the reason an entry gives is enforced (q9-10): reflect.NewAt in internal/logattr is refused
// although the directory is listed for reflect, because it does not list NewAt.
var reflectMembers = withDirs(onGenerated("TypeOf"), map[string][]string{
	"internal/closed":  {"Array", "Bool", "Int", "Int8", "Int16", "Int32", "Int64", "Uint8", "Uint16", "Uint32", "Uint64", "Kind", "Pointer", "Slice", "String", "Struct", "Type", "TypeOf", "Uint", "Value", "ValueOf"}, // reads kinds (Array to recognise the zero-size marker that makes a type incomparable), fields and elements of a closed value to check it and calls its Valid method by name; takes no pointer and builds no value
	"internal/logattr": {"TypeOf"},                                                                                                                                                                                       // reads the type of a value a log attribute is given, to refuse the ones that are not closed
	"shared/vectors":   {"DeepEqual"},                                                                                                                                                                                    // the runner of the golden vectors compares an expected and an observed value and nothing else
})

// unsafeMembers: protoc-gen-go output uses unsafe.Slice(unsafe.StringData(rawDesc), len(rawDesc)) to
// give the protobuf runtime a read-only byte view of the file descriptor string constant. The
// runtime's own unsafe field access for message reflection is third party code.
var unsafeMembers = onGenerated("Slice", "StringData")

// anyDirMembers are packages any directory may import but only for the members listed: the rest of
// the package opens a file by a path the caller chooses (http.Dir, http.ServeFile and http.FileServer
// open any file, /proc/self/mem and a secret file included, with no os import; tls.LoadX509KeyPair
// reads one), which is the monopoly of internal/secret and of the os member lists (q9-15). The list
// is an allow list: a member added to the package tomorrow starts refused.
var anyDirMembers = map[string][]string{
	"net/http": {
		"CanonicalHeaderKey", "Client", "Cookie", "DefaultClient", "Error", "ErrAbortHandler", "ErrServerClosed", "ErrUseLastResponse",
		"Handler", "HandlerFunc", "Header", "MaxBytesError", "MethodGet", "MethodHead", "MethodOptions", "MethodPost",
		"NewCrossOriginProtection", "NewRequestWithContext", "NewServeMux", "NoBody", "NotFound", "NotFoundHandler", "Request",
		"Response", "ResponseWriter", "SameSite", "SameSiteLaxMode", "SameSiteStrictMode", "Server", "StatusBadRequest",
		"StatusConflict", "StatusForbidden", "StatusInternalServerError", "StatusNotFound", "StatusNotImplemented", "StatusOK",
		"StatusRequestEntityTooLarge", "StatusServiceUnavailable", "StatusTooManyRequests", "StatusUnauthorized",
		"StatusUnprocessableEntity", "Transport",
		// The hub's node port: the deadlines of a request and its body, and the HTTP/2 windows.
		"HTTP2Config", "MaxBytesReader", "NewResponseController",
	},
	"crypto/tls": {"Certificate", "Client", "ClientHelloInfo", "Config", "Conn", "ConnectionState", "Dialer", "RequestClientCert", "Server", "VersionTLS12", "VersionTLS13"}, // Client wraps one dialled connection (the hub's prober, over a net.Conn it dialled itself); Dialer dials a DoT server for the DDNS job (internal/worker/periodic) and reads no file
}

// memberJudged maps a package judged by the member a selector names to its per directory lists.
var memberJudged = map[string]map[string][]string{
	"os":      osMembers,
	"syscall": syscallMembers,
	"runtime": runtimeMembers,
	"reflect": reflectMembers,
	"unsafe":  unsafeMembers,
}

// goDirectiveSafe are the `//go:` directives any directory may carry. Every other directive, the
// ones the toolchain knows and the ones it will learn, is refused unless the directory is listed in
// directiveDirs. A name here must be one the toolchain acts on without reaching outside the type
// system.
var goDirectiveSafe = map[string]string{
	"build": "build constraints choose which files are compiled; the ban reads every file whatever its constraint",
	"embed": "embeds files as data",
}

// directiveDirs are the directories that may carry a refused directive, per directive name, with the
// reason ("line" is the position directive). //go:generate is here and not in goDirectiveSafe: the
// line names a command, any command, that whoever runs `go generate ./...` runs (q9-5), so a new
// line starts refused until a person has read the command and listed the directory.
var directiveDirs = map[string]map[string]string{
	"generate": {
		"internal/adminapi":        "go tool oapi-codegen, the generator pinned in go.mod (the tool directive), over api/admin-openapi.yaml",
		"internal/api":             "go tool oapi-codegen, the generator pinned in go.mod (the tool directive), over api/openapi.yaml",
		"internal/auth/pwstrength": "go run ./layouts/gen, the generator of the layout tables in this tree",
	},
}

// bodylessDirs are the directories that may declare a function with no body (assembly or linkname
// supplies it). Nobody does today.
var bodylessDirs = map[string]string{}

// nonGoSourceDirs are the directories that may hold a file go list reports besides Go source (C,
// assembly, objects, SWIG, cgo flags). Nobody does today.
var nonGoSourceDirs = map[string]string{}

// escapePolicy is the set of lists the ban judges by, so that a test can plant an entry that the real
// lists do not have.
type escapePolicy struct {
	safeStd       map[string]string
	std           map[string]map[string]string
	members       map[string]map[string][]string // by directory: the import itself needs a listing
	anyDir        map[string][]string            // any directory may import the package, for these members only
	directiveSafe map[string]string
	directives    map[string]map[string]string
	bodyless      map[string]string
	nonGo         map[string]string
	// openExisting are the directories whose os.OpenFile may open a file that already exists. Every
	// other OpenFile must create exclusively (O_CREATE and O_EXCL together), which cannot open a
	// device, /proc/self/mem or any file that is there: the flags, not the path, are what the ban can
	// see (q9-17).
	openExisting map[string]string
	// sharedThird are the third-party packages shared/ imports, with the directories that may. The
	// Panel judges its libraries in imports.yaml and shared/ is a module of its own that it did not
	// judge, so a library such as protoimpl, whose Pointer is unsafe.Pointer, could be imported by any
	// shared package with no unsafe import and no review (q9-14).
	sharedThird map[string]map[string]string
	// testOnly are packages that only test files, and the package itself, may import (q9-9).
	testOnly map[string]string
}

// openExistingDirs: nobody but the development gateway.
var openExistingDirs = map[string]string{
	"internal/sms/noop": "the development gateway appends to one file the operator configures; New refuses to build it outside dev and test, so no production process runs this call",
}

// sharedThirdParty lists the third-party packages the non-test code of shared/ imports.
var sharedThirdParty = map[string]map[string]string{
	"golang.org/x/text/unicode/norm": {"shared/identity": "NFKC of the client slug"},
	"golang.org/x/net/idna":          {"shared/names": "the IDNA profile of user names"},
	"golang.org/x/net/publicsuffix":  {"shared/rules": "the public suffix list compiled into the library"},
	"google.golang.org/protobuf/proto": {
		"shared/manifest": "the wire form of the signed manifest", "shared/quarantine": "the wire form of a pending policy", "shared/wire": "marshal and unmarshal of the messages",
		"shared/vectors": "the quarantine vector group builds the pending-policy messages it feeds a node and marshals a block page to give a blob its bytes (imported by test files only)",
	},
	"google.golang.org/protobuf/reflect/protoreflect": generatedWhy("protoc-gen-go output"),
	"google.golang.org/protobuf/runtime/protoimpl":    generatedWhy("protoc-gen-go output: protoimpl.Pointer is unsafe.Pointer by another name, so it is named only where the generator writes it"),
	"google.golang.org/grpc":                          grpcWhy("protoc-gen-go-grpc output"),
	"google.golang.org/grpc/codes":                    grpcWhy("protoc-gen-go-grpc output"),
	"google.golang.org/grpc/status":                   grpcWhy("protoc-gen-go-grpc output"),
}

func generatedWhy(why string) map[string]string {
	out := map[string]string{}
	for _, d := range generatedProtobuf {
		out[d] = why
	}
	return out
}

func grpcWhy(why string) map[string]string {
	return map[string]string{"shared/gen/ctrlz/enroll/v1": why, "shared/gen/ctrlz/hub/v1": why, "shared/gen/ctrlz/peer/v1": why}
}

// testOnlyImports: the runner of the golden vectors takes a *testing.T and reflect.DeepEqual, which
// is why it is listed for them; that is safe only because nothing but test files imports it.
var testOnlyImports = map[string]string{
	sharedModule + "/vectors": "shared/vectors",
}

func realPolicy() escapePolicy {
	return escapePolicy{
		safeStd: moduleStdSafe, std: stdCapabilities, members: memberJudged, anyDir: anyDirMembers,
		directiveSafe: goDirectiveSafe, directives: directiveDirs, bodyless: bodylessDirs, nonGo: nonGoSourceDirs,
		openExisting: openExistingDirs, sharedThird: sharedThirdParty, testOnly: testOnlyImports,
	}
}

// directiveName says whether a comment is a directive the compiler or the linker acts on and, if so,
// its name. `//go:name` is one wherever it stands in the file (the compiler wants it at the start of a
// line; reading it anywhere only refuses more), and the position directives `//line ` and `/*line `
// change where the compiler says code is.
func directiveName(text string) (string, bool) {
	switch {
	case strings.HasPrefix(text, "//go:"):
		name := text[len("//go:"):]
		if i := strings.IndexAny(name, " \t"); i >= 0 {
			name = name[:i]
		}
		return name, true
	case strings.HasPrefix(text, "//line "), strings.HasPrefix(text, "/*line "):
		return "line", true
	}
	return "", false
}

// importTable maps the name a file gives each import to its path: the local name when there is one,
// else the last element of the path, which is the package name of every package this ban judges (os,
// syscall, runtime, reflect, unsafe, net/http and crypto/tls). It is read from the file's own import
// declarations and not from go/types, so a file the type checker drops (another package clause, an
// ignored generator) is judged the same as any other (q9-1, q9-7, q9-11).
func importTable(f *ast.File) map[string]string {
	out := map[string]string{}
	for _, im := range f.Imports {
		p, err := strconv.Unquote(im.Path.Value)
		if err != nil {
			continue
		}
		name := path.Base(p)
		if im.Name != nil {
			name = im.Name.Name
		}
		if name == "_" || name == "." {
			continue
		}
		out[name] = p
	}
	return out
}

// pkgMember says whether a selector names a member of an imported package, and which. The qualifier
// is a package when its name is an import of the file and the parser did not resolve it to a
// declaration of the file (an identifier the parser leaves unresolved is a package or an undefined
// name; one it resolved is a local variable, parameter or field that shadows the import). An
// unresolved identifier is read as the package, so whatever the parser cannot place fails closed.
func pkgMember(table map[string]string, sx *ast.SelectorExpr) (pkg, member string, ok bool) {
	id, isIdent := sx.X.(*ast.Ident)
	if !isIdent || id.Obj != nil {
		return "", "", false
	}
	p, imported := table[id.Name]
	if !imported {
		return "", "", false
	}
	return p, sx.Sel.Name, true
}

// calleeSelector returns the selector a call calls, through parentheses.
func calleeSelector(e ast.Expr) *ast.SelectorExpr {
	for {
		switch x := e.(type) {
		case *ast.ParenExpr:
			e = x.X
		case *ast.SelectorExpr:
			return x
		default:
			return nil
		}
	}
}

// openFlagNames reads the flag argument of os.OpenFile when it is spelled as constants of os joined
// by |. Anything else (a literal, a variable, a call) is not readable by a lint, and a flag the lint
// cannot read is a flag it cannot limit.
func openFlagNames(table map[string]string, e ast.Expr) ([]string, bool) {
	switch x := e.(type) {
	case *ast.ParenExpr:
		return openFlagNames(table, x.X)
	case *ast.BinaryExpr:
		if x.Op != token.OR {
			return nil, false
		}
		l, ok := openFlagNames(table, x.X)
		if !ok {
			return nil, false
		}
		r, ok := openFlagNames(table, x.Y)
		return append(l, r...), ok
	case *ast.SelectorExpr:
		if p, m, ok := pkgMember(table, x); ok && p == "os" && strings.HasPrefix(m, "O_") {
			return []string{m}, true
		}
	}
	return nil, false
}

// capabilityProblems judges the non-test files by the lists of pol. With stale it also says which
// entry of a list no file uses and which names a directory with no non-test Go source. It does not
// judge the files go list reports (foreignProblems does) nor the files of a directory it was not given.
func capabilityProblems(fset *token.FileSet, files []file, pol escapePolicy, stale bool) []string {
	var out []string
	add := func(pos token.Pos, format string, a ...any) {
		out = append(out, fset.Position(pos).String()+": "+fmt.Sprintf(format, a...))
	}
	usedStd := map[string]map[string]bool{}
	usedMember := map[string]map[string]map[string]bool{}
	usedAny := map[string]map[string]bool{}
	usedDirective := map[string]map[string]bool{}
	usedThird := map[string]map[string]bool{}
	usedBodyless := map[string]bool{}
	usedOpenExisting := map[string]bool{}
	usedSafe := map[string]bool{}
	dirs := map[string]bool{}
	mark2 := func(m map[string]map[string]bool, a, b string) {
		if m[a] == nil {
			m[a] = map[string]bool{}
		}
		m[a][b] = true
	}
	for _, f := range files {
		if f.test {
			continue
		}
		dir := dirOf(f.path)
		dirs[dir] = true
		table := importTable(f.ast)
		for _, im := range f.ast.Imports {
			// The path is read as Go reads it: a raw string or an escape spells the same package, and a
			// trimmed quote would leave `reflect` (with backticks) looking like a package nobody knows.
			p, err := strconv.Unquote(im.Path.Value)
			if err != nil {
				add(im.Pos(), "the import path %s cannot be read", im.Path.Value)
				continue
			}
			if target, only := pol.testOnly[p]; only && dir != target {
				add(im.Pos(), "%s imports %s, which only test files and the package itself may import: it takes a *testing.T and its listing for testing and reflect rests on that (q9-9)", dir, p)
			}
			if !isStdPath(p) {
				// A library of shared/ is judged here, a library of the Panel in imports.yaml.
				if inSharedTree(dir) && p != sharedModule && !strings.HasPrefix(p, sharedModule+"/") && !strings.HasPrefix(p, module+"/") {
					if _, ok := pol.sharedThird[p][dir]; ok {
						mark2(usedThird, p, dir)
					} else {
						add(im.Pos(), "%s imports %s, a third-party package that is not listed for this directory (sharedThirdParty): a library can hand out unsafe.Pointer or reach a file by another name, and shared/ is not judged by imports.yaml; list it with the reason, or use another package (owner decision D63)", dir, p)
					}
				}
				continue
			}
			dot := im.Name != nil && im.Name.Name == "."
			if byDir, judged := pol.members[p]; judged {
				if _, ok := byDir[dir]; !ok {
					what := "reaches a process, a file, a system call or the call stack with no other import"
					if w, hatch := escapeImports[p]; hatch {
						what = w
					}
					add(im.Pos(), "%s imports %s, which %s; only the directories of its member list may, and each only for the members listed (owner decision D63)", dir, p, what)
				}
				if dot {
					add(im.Pos(), "a dot import of %s hides which member is used", p)
				}
				continue
			}
			if _, anyDir := pol.anyDir[p]; anyDir {
				if dot {
					add(im.Pos(), "a dot import of %s hides which member is used", p)
				}
				usedSafe[p] = true
				continue
			}
			if _, ok := pol.safeStd[p]; ok {
				usedSafe[p] = true
				continue
			}
			if _, ok := pol.std[p][dir]; ok {
				mark2(usedStd, p, dir)
				continue
			}
			if what, hatch := escapeImports[p]; hatch {
				add(im.Pos(), "%s imports %s, which %s; the escape-hatch ban refuses it in every directory that stdCapabilities[%q] does not list with a reason: remove the use, or list the directory there and say why (owner decision D63)", dir, p, what, p)
				continue
			}
			add(im.Pos(), "%s imports %s, which is not in moduleStdSafe and is not a listed capability of this directory (stdCapabilities); a package nobody reviewed may reach memory or a process the type system hides: use another package, or list it with the reason (sms-r16-21)", dir, p)
		}
		for _, cg := range f.ast.Comments {
			for _, c := range cg.List {
				name, ok := directiveName(c.Text)
				if !ok {
					continue
				}
				if _, safe := pol.directiveSafe[name]; safe {
					continue
				}
				if _, listed := pol.directives[name][dir]; listed {
					mark2(usedDirective, name, dir)
					continue
				}
				add(c.Pos(), "%s carries the directive %q, which changes how the compiler or the linker treats the code (go:linkname reaches an unexported identifier of another package, go:nocheckptr and go:norace switch checks off, go:cgo_* and go:noescape need code no lint reads, go:generate runs any command); remove it, or list the directory in directiveDirs with the reason (owner decision D63)", dir, name)
			}
		}
		// The selectors that are called, so that a member used as a value is told from a member called.
		called := map[*ast.SelectorExpr]bool{}
		ast.Inspect(f.ast, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.FuncDecl:
				if x.Body == nil {
					if _, listed := pol.bodyless[dir]; listed {
						usedBodyless[dir] = true
					} else {
						add(x.Pos(), "%s declares %s with no body: assembly or a linkname supplies it, code no lint reads; give it a body, or list the directory in bodylessDirs with the reason (owner decision D63)", dir, x.Name.Name)
					}
				}
			case *ast.CallExpr:
				sx := calleeSelector(x.Fun)
				if sx == nil {
					return true
				}
				called[sx] = true
				if p, m, ok := pkgMember(table, sx); ok && p == "os" && m == "OpenFile" {
					if len(x.Args) != 3 || x.Ellipsis != token.NoPos {
						add(x.Pos(), "%s calls os.OpenFile with arguments the ban cannot read; pass the path, the flags and the mode", dir)
						return true
					}
					flags, ok := openFlagNames(table, x.Args[1])
					if !ok {
						add(x.Args[1].Pos(), "%s calls os.OpenFile with a flag that is not spelled as os.O_* constants joined by |: a literal such as 2 or a variable opens /proc/self/mem read-write and the ban cannot tell (q9-17)", dir)
						return true
					}
					if slices.Contains(flags, "O_CREATE") && slices.Contains(flags, "O_EXCL") {
						return true
					}
					if _, listed := pol.openExisting[dir]; listed {
						usedOpenExisting[dir] = true
						return true
					}
					add(x.Args[1].Pos(), "%s calls os.OpenFile without O_CREATE and O_EXCL together: it may open a file that exists, a device or /proc/self/mem among them; create exclusively, or list the directory in openExistingDirs with the reason (q9-17)", dir)
				}
			case *ast.SelectorExpr:
				pkg, member, ok := pkgMember(table, x)
				if !ok {
					return true
				}
				if pkg == "os" && member == "OpenFile" && !called[x] {
					add(x.Pos(), "%s uses os.OpenFile as a value; it is only judged where it is called, because the flags are its limit (q9-17)", dir)
					return true
				}
				if byDir, judged := pol.members[pkg]; judged {
					if slices.Contains(byDir[dir], member) {
						if usedMember[pkg] == nil {
							usedMember[pkg] = map[string]map[string]bool{}
						}
						mark2(usedMember[pkg], dir, member)
						return true
					}
					add(x.Pos(), "%s uses %s.%s, which is not a member listed for the directory (the member lists of the ban); use a member that is listed, or list this one with the reason", dir, pkg, member)
					return true
				}
				if list, anyDir := pol.anyDir[pkg]; anyDir {
					if slices.Contains(list, member) {
						mark2(usedAny, pkg, member)
						return true
					}
					add(x.Pos(), "%s uses %s.%s, which is not in anyDirMembers: the rest of %s can open a file by a path the caller chooses or hand out what the type system hides; use a listed member, or list this one with the reason (q9-15)", dir, pkg, member, pkg)
				}
			}
			return true
		})
	}
	if stale {
		gone := func(list, d string) bool {
			if dirs[d] {
				return false
			}
			out = append(out, list+" lists "+d+", which has no non-test Go source (no such directory, or only test files): remove the entry")
			return true
		}
		for p, byDir := range pol.std {
			for d := range byDir {
				if gone("stdCapabilities["+p+"]", d) {
					continue
				}
				if !usedStd[p][d] {
					out = append(out, "stdCapabilities lists "+p+" for "+d+", which does not import it: remove the entry")
				}
			}
		}
		for p, byDir := range pol.members {
			for d, ms := range byDir {
				if gone("the member list of "+p, d) {
					continue
				}
				for _, m := range ms {
					if !usedMember[p][d][m] {
						out = append(out, "the member list of "+p+" lists "+p+"."+m+" for "+d+", which does not use it: remove the entry")
					}
				}
			}
		}
		for p, ms := range pol.anyDir {
			for _, m := range ms {
				if !usedAny[p][m] {
					out = append(out, "anyDirMembers lists "+p+"."+m+", which no non-test file uses: remove the entry")
				}
			}
		}
		for name, byDir := range pol.directives {
			for d := range byDir {
				if gone("directiveDirs["+name+"]", d) {
					continue
				}
				if !usedDirective[name][d] {
					out = append(out, "directiveDirs lists "+name+" for "+d+", which does not carry it: remove the entry")
				}
			}
		}
		for d := range pol.bodyless {
			if gone("bodylessDirs", d) {
				continue
			}
			if !usedBodyless[d] {
				out = append(out, "bodylessDirs lists "+d+", which declares no function without a body: remove the entry")
			}
		}
		for d := range pol.openExisting {
			if gone("openExistingDirs", d) {
				continue
			}
			if !usedOpenExisting[d] {
				out = append(out, "openExistingDirs lists "+d+", which calls no os.OpenFile that may open an existing file: remove the entry")
			}
		}
		for p, byDir := range pol.sharedThird {
			for d := range byDir {
				if gone("sharedThirdParty["+p+"]", d) {
					continue
				}
				if !usedThird[p][d] {
					out = append(out, "sharedThirdParty lists "+p+" for "+d+", which does not import it: remove the entry")
				}
			}
		}
		for p, target := range pol.testOnly {
			gone("testOnlyImports["+p+"]", target)
		}
		for p := range pol.safeStd {
			if !usedSafe[p] && !strings.Contains(strings.SplitN(p, "/", 2)[0], ".") {
				out = append(out, "moduleStdSafe lists "+p+", which no non-test file imports: remove the entry")
			}
		}
	}
	sort.Strings(out)
	return dedupe(out)
}

func TestNoDirectoryReachesMemoryOrAProcessUnlisted(t *testing.T) {
	// Every Go file of every module of the tree is judged, shared/ included, by the same lists: the
	// Panel imports it and the Node carries a byte-identical copy.
	fset := token.NewFileSet()
	files, err := parseEveryModule(fset, repoRoot(t), parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range capabilityProblems(fset, files, realPolicy(), true) {
		t.Error(p)
	}
	for _, p := range unreadImportProblems(fset, files) {
		t.Error(p)
	}
}

// reflectMethods are the methods and fields of the types of package reflect (Value, Type, StructField
// and the rest) that a directory may use, per directory. A listing for reflect gives a directory the
// package, and the package's members are judged by name above, but most of what reflect does is a
// method of a value it hands out, and one of them (Value.UnsafePointer) returns an unsafe.Pointer that
// converts to any pointer type without importing unsafe (q9-10). So the methods are judged too, by
// the type of the receiver go/types resolves, in every directory: a directory that holds a reflect
// value with no entry here (it got one from a function) is refused. The reason an entry gives for
// reflect is enforced.
var reflectMethods = withDirs(onGenerated("PkgPath"), map[string][]string{
	"internal/closed":  {"Bool", "Call", "Elem", "Field", "Implements", "Index", "IsExported", "IsNil", "Kind", "Len", "MethodByName", "Name", "NumField", "NumIn", "NumOut", "Out", "PkgPath", "String", "Type"}, // reads kinds, fields and elements of a closed value and calls its Valid method by name (member, closed.go): the one by-name call of reflect in the tree
	"internal/logattr": {"String"},                                                                                                                                                                                // the name of the type of a value a log attribute is given
})

// reflectMethodProblems judges every selection whose receiver is a type of package reflect. info
// must have been made with reflect AND every standard package whose exported API names a reflect type
// type-checked from source (stdExposingReflect, reflectexpose_test.go), not reflect alone (round 18,
// primitives-r18-12): a reflect.Type reaches a
// directory that never imports reflect through the API of another package (the Type field of
// encoding/json's UnmarshalTypeError, ColumnType.ScanType of database/sql), and with that package
// stubbed the chain Type.Method(0).Func.UnsafePointer() had no types and was never judged. A receiver
// that did not resolve is not seen, which is the limit of a stub for a library's own return type, and
// imports.yaml reviews libraries.
func reflectMethodProblems(fset *token.FileSet, files []file, info *types.Info, methods map[string][]string, stale bool) []string {
	var out []string
	used := map[string]map[string]bool{}
	dirs := map[string]bool{}
	for _, f := range files {
		if f.test {
			continue
		}
		dir := dirOf(f.path)
		dirs[dir] = true
		ast.Inspect(f.ast, func(n ast.Node) bool {
			sx, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			sel := info.Selections[sx]
			if sel == nil {
				return true
			}
			t := sel.Recv()
			for {
				p, isPtr := t.(*types.Pointer)
				if !isPtr {
					break
				}
				t = p.Elem()
			}
			named, ok := types.Unalias(t).(*types.Named)
			if !ok || named.Obj().Pkg() == nil || named.Obj().Pkg().Path() != "reflect" {
				return true
			}
			if slices.Contains(methods[dir], sx.Sel.Name) {
				if used[dir] == nil {
					used[dir] = map[string]bool{}
				}
				used[dir][sx.Sel.Name] = true
				return true
			}
			out = append(out, fmt.Sprintf("%s: %s uses %s.%s of a reflect type, which is not listed for the directory (reflectMethods): Value.UnsafePointer and the like hand out memory the type system hides without an import of unsafe; use a listed method, or list this one with the reason (q9-10)", fset.Position(sx.Pos()), dir, named.Obj().Name(), sx.Sel.Name))
			return true
		})
	}
	if stale {
		for d, ms := range methods {
			if !dirs[d] {
				out = append(out, "reflectMethods lists "+d+", which has no non-test Go source: remove the entry")
				continue
			}
			for _, m := range ms {
				if !used[d][m] {
					out = append(out, "reflectMethods lists "+m+" for "+d+", which does not use it: remove the entry")
				}
			}
		}
	}
	sort.Strings(out)
	return dedupe(out)
}

// TestNoReflectValueReachesMemoryUnlisted type-checks the tree with reflect from source and judges
// the methods of its types.
func TestNoReflectValueReachesMemoryUnlisted(t *testing.T) {
	fset := token.NewFileSet()
	files, err := parseEveryModule(fset, repoRoot(t), parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	exposing, err := stdExposingReflect(importedStdPaths(files))
	if err != nil {
		t.Fatal(err)
	}
	info, ok := typeInfoReal(fset, files, append([]string{"reflect"}, exposing...)...)
	if !ok {
		t.Fatal("type information unavailable")
	}
	for _, p := range reflectMethodProblems(fset, files, info, reflectMethods, true) {
		t.Error(p)
	}
}

// TestReflectMethodLintCanFail plants the ways a reflect value gives memory away through a method:
// UnsafePointer converted to a pointer type with no unsafe import, Value.Pointer, UnsafeAddr, a value
// the directory got from a function, and the clean reads.
func TestReflectMethodLintCanFail(t *testing.T) {
	methods := map[string][]string{"internal/logattr": {"Kind"}}
	cases := []struct {
		name, path, src string
		want            int
	}{
		{"UnsafePointer converted with no unsafe import", "internal/logattr/x.go", "import \"reflect\"\nfunc f(v reflect.Value) *int { return (*int)(v.UnsafePointer()) }", 1},
		{"UnsafeAddr", "internal/logattr/x.go", "import \"reflect\"\nfunc f(v reflect.Value) uintptr { return v.UnsafeAddr() }", 1},
		{"Pointer", "internal/logattr/x.go", "import \"reflect\"\nfunc f(v reflect.Value) uintptr { return v.Pointer() }", 1},
		{"a method expression", "internal/logattr/x.go", "import \"reflect\"\nvar _ = reflect.Value.UnsafePointer", 1},
		{"a value through a pointer", "internal/logattr/x.go", "import \"reflect\"\nfunc f(v *reflect.Value) { _ = v.UnsafePointer() }", 1},
		{"a value of a directory that is not listed", "internal/api/x.go", "import \"reflect\"\nfunc f(v reflect.Value) { _ = v.Kind() }", 1},
		{"a value a function returned, in a directory that never imports reflect", "internal/api/x.go", "import \"fmt\"\nimport \"reflect\"\nfunc g() reflect.Value { return reflect.Value{} }\nfunc f() { fmt.Println(g().UnsafePointer()) }", 2},
		{"a listed method", "internal/logattr/x.go", "import \"reflect\"\nfunc f(v reflect.Value) reflect.Kind { return v.Kind() }", 0},
		{"a method of a type that is not reflect's", "internal/api/x.go", "import \"strings\"\nfunc f(b *strings.Builder) { b.WriteString(\"x\") }", 0},
		// Round 18 (primitives-r18-12): a reflect.Type that arrives through another standard package, in
		// a directory that imports neither reflect nor unsafe.
		{"UnsafePointer from a json error", "internal/api/x.go", "import \"encoding/json\"\nfunc f(e *json.UnmarshalTypeError) *int { return (*int)(e.Type.Method(0).Func.UnsafePointer()) }", 2},
		{"a method of a type from an xml error", "internal/api/x.go", "import \"encoding/xml\"\nfunc f(e *xml.UnsupportedTypeError) { _ = e.Type.Method(0) }", 1},
		{"the scan type of a sql column", "internal/api/x.go", "import \"database/sql\"\nfunc f(c *sql.ColumnType) { _ = c.ScanType().NumMethod() }", 1},
		{"a json error that only reads a message", "internal/api/x.go", "import \"encoding/json\"\nfunc f(e *json.UnmarshalTypeError) string { return e.Error() }", 0},
	}
	for _, c := range cases {
		fset := token.NewFileSet()
		fs := parsePlanted(t, fset, []planted{{c.path, c.src}})
		exposing, err := stdExposingReflect(importedStdPaths(fs))
		if err != nil {
			t.Fatal(err)
		}
		info, ok := typeInfoReal(fset, fs, append([]string{"reflect", "strings", "fmt"}, exposing...)...)
		if !ok {
			t.Fatalf("%s: no type information", c.name)
		}
		got := reflectMethodProblems(fset, fs, info, methods, false)
		if (c.want == 0) != (len(got) == 0) {
			t.Errorf("%s: %d problems, want %d or more: %v", c.name, len(got), c.want, got)
		}
	}
	// A list entry nobody uses fails.
	fset := token.NewFileSet()
	fs := parsePlanted(t, fset, []planted{{"internal/logattr/x.go", "import \"reflect\"\nfunc f(v reflect.Value) reflect.Kind { return v.Kind() }"}})
	info, _ := typeInfoReal(fset, fs, "reflect")
	if got := reflectMethodProblems(fset, fs, info, map[string][]string{"internal/logattr": {"Kind", "Len"}, "internal/ghost": {}}, true); len(got) != 2 {
		t.Errorf("stale entries: %v", got)
	}
}

// TestTypeInfoChecksEveryPackageClauseOfADirectory plants a directory that holds an ignored generator
// (package main) that sorts before the real file and shows the real file still gets type information
// (q9-11): the selectors of the real file resolve to their packages.
func TestTypeInfoChecksEveryPackageClauseOfADirectory(t *testing.T) {
	fset := token.NewFileSet()
	fs := parsePlanted(t, fset, []planted{
		{"internal/sms/noop/0gen.go", wholeFile + "//go:build ignore\n\npackage main\n\nfunc main() {}"},
		{"internal/sms/noop/noop.go", "import \"os\"\nfunc f() { os.Exit(1) }"},
	})
	info, ok := typeInfoReal(fset, fs)
	if !ok {
		t.Fatal("no type information")
	}
	found := false
	ast.Inspect(fs[1].ast, func(n ast.Node) bool {
		if id, isIdent := n.(*ast.Ident); isIdent && id.Name == "os" {
			if _, isPkg := info.Uses[id].(*types.PkgName); isPkg {
				found = true
			}
		}
		return true
	})
	if !found {
		t.Error("the real file of a directory with an ignored generator got no type information")
	}
}

// goListClass says what a field of the go list package record is for the ban.
type goListClass int

const (
	// listMeta describes the package or names data; it builds nothing.
	listMeta goListClass = iota
	// listGo is Go source, which the Go walk of the ban reads.
	listGo
	// listSetting is a field that sets how the binary behaves at run time (DefaultGODEBUG: the defaults of the
	// runtime's and the standard library's compatibility switches, such as panicnil, x509sha1, tlsrsakex and
	// tls10server). It is judged by value (godebugProblems), not by being empty: sms-r18-7 and sms-r18-13.
	listSetting
	// listForeign is something the toolchain builds in (or would build in on another platform) that
	// is not Go source, and that no Go walk reads.
	listForeign
)

// goListFields is the closed table of the fields of `go list -json`, taken from the Package struct of
// `go help list` (TestGoListFieldsAreClassified compares the two). A field that is not here fails, so
// a source kind the toolchain learns later (it learned .syso and SWIG once) starts refused.
var goListFields = map[string]goListClass{
	"Dir": listMeta, "ImportPath": listMeta, "ImportComment": listMeta, "Name": listMeta, "Doc": listMeta,
	"Target": listMeta, "Shlib": listMeta, "Goroot": listMeta, "Standard": listMeta, "Stale": listMeta,
	"StaleReason": listMeta, "Root": listMeta, "ConflictDir": listMeta, "ForTest": listMeta, "Export": listMeta,
	"BuildID": listMeta, "Module": listMeta, "Match": listMeta, "DepOnly": listMeta, "DefaultGODEBUG": listSetting,
	"EmbedPatterns": listMeta, "EmbedFiles": listMeta, "TestEmbedPatterns": listMeta, "TestEmbedFiles": listMeta,
	"XTestEmbedPatterns": listMeta, "XTestEmbedFiles": listMeta,
	"Imports": listMeta, "ImportMap": listMeta, "Deps": listMeta, "TestImports": listMeta, "XTestImports": listMeta,
	"Incomplete": listMeta, "Error": listMeta, "DepsErrors": listMeta,

	"GoFiles": listGo, "CompiledGoFiles": listGo, "IgnoredGoFiles": listGo, "TestGoFiles": listGo, "XTestGoFiles": listGo,

	// BinaryOnly is a package with no source at all. CgoFiles are Go files that import "C". The rest
	// are the files other languages and the linker bring in, and IgnoredOtherFiles are the same kinds
	// left out of this platform's build, which another platform builds.
	"BinaryOnly": listForeign, "CgoFiles": listForeign, "CFiles": listForeign, "CXXFiles": listForeign,
	"MFiles": listForeign, "HFiles": listForeign, "FFiles": listForeign, "SFiles": listForeign,
	"SwigFiles": listForeign, "SwigCXXFiles": listForeign, "SysoFiles": listForeign, "IgnoredOtherFiles": listForeign,
	"CgoCFLAGS": listForeign, "CgoCPPFLAGS": listForeign, "CgoCXXFLAGS": listForeign, "CgoFFLAGS": listForeign,
	"CgoLDFLAGS": listForeign, "CgoPkgConfig": listForeign,
}

// goListRequest names the fields asked of go list: those of the table that say what a package builds,
// plus where it is and whether it loaded. `-json` with no list computes staleness of every package
// too, which is most of the time of the command; with a list the rest is left out, and the unknown
// fields are the table's business (TestGoListFieldsAreClassified), not the output's.
func goListRequest() string {
	names := []string{"Dir", "ImportPath", "Error"}
	for f, c := range goListFields {
		if c != listMeta {
			names = append(names, f)
		}
	}
	sort.Strings(names)
	return "-json=" + strings.Join(names, ",")
}

// foreignSeen collects, across the modules of the tree, which directories go list listed and which
// entries of nonGoSourceDirs were used.
type foreignSeen struct {
	dirs map[string]bool
	used map[string]bool
	// judgeGodebug says whether the run compares the DefaultGODEBUG of a main package with wantGodebug, what the
	// toolchain in use gives a module with no godebug setting (pinnedDefaultGODEBUG), which is EMPTY when every
	// default is the current one. It is off for the planted trees of the can-fail tests, whose go lines are not
	// the toolchain's.
	judgeGodebug bool
	wantGodebug  string
	// skipLoadError leaves out the packages that did not load: the directories that go list ./... does not
	// name are asked for by name, and a generator whose every file is constrained out loads as an error.
	skipLoadError bool
}

// askedByName is the state for the pass over the directories go list ./... did not name: a copy of
// the run's own state that differs in the one field that pass needs, so a field added to foreignSeen
// reaches it by default and cannot be forgotten (sms-r18-21: judgeGodebug was copied by name, and
// nothing proved it was). The maps are shared, which is the point: the used entries and the listed
// directories are the run's.
func (s *foreignSeen) askedByName() *foreignSeen {
	q := *s
	q.skipLoadError = true
	return &q
}

// canonPath resolves a path to the name the file system gives it (a Windows short name such as
// ADMINI~1 and its long form are one directory), so a package directory and the root can be compared.
func canonPath(p string) string {
	if e, err := filepath.EvalSymlinks(p); err == nil {
		return e
	}
	return p
}

func emptyJSON(raw json.RawMessage) bool {
	switch strings.TrimSpace(string(raw)) {
	case "", "null", "[]", `""`, "false", "{}", "0":
		return true
	}
	return false
}

// foreignFromList reads the records of go list for one module and reports every field that names
// something besides Go source, every field it does not know and every package it could not load.
func foreignFromList(root string, listing []byte, pol escapePolicy, seen *foreignSeen) []string {
	var out []string
	dec := json.NewDecoder(bytes.NewReader(listing))
	for dec.More() {
		var pkg map[string]json.RawMessage
		if err := dec.Decode(&pkg); err != nil {
			out = append(out, "go list output cannot be read: "+err.Error())
			break
		}
		var dir string
		_ = json.Unmarshal(pkg["Dir"], &dir)
		rel, err := filepath.Rel(canonPath(root), canonPath(dir))
		if err != nil {
			rel = dir
		}
		rel = filepath.ToSlash(rel)
		seen.dirs[rel] = true
		for field, raw := range pkg {
			class, known := goListFields[field]
			switch {
			case !known:
				out = append(out, fmt.Sprintf("%s: go list reports the field %s, which the ban does not know; say in goListFields whether it names something the toolchain builds that is not Go source (owner decision D63)", rel, field))
			case class == listSetting:
				var have string
				_ = json.Unmarshal(raw, &have)
				if seen.judgeGodebug {
					out = append(out, godebugProblems(rel, have, seen.wantGodebug)...)
				}
			case field == "Error" && !emptyJSON(raw) && !seen.skipLoadError:
				out = append(out, fmt.Sprintf("%s: go list could not load the package (%s), so the ban cannot see what it builds", rel, strings.TrimSpace(string(raw))))
			case class == listForeign && !emptyJSON(raw):
				if _, listed := pol.nonGo[rel]; listed {
					seen.used[rel] = true
					continue
				}
				var names []string
				if json.Unmarshal(raw, &names) != nil || len(names) == 0 {
					names = []string{strings.TrimSpace(string(raw))}
				}
				for _, n := range names {
					out = append(out, fmt.Sprintf("%s: go list reports %s %s, which is not Go source (%s); C, assembly, objects and cgo are compiled or linked into the package and no lint reads them: remove it, or list the directory in nonGoSourceDirs with the reason (owner decision D63, sms-r16-21)", rel, field, n, nonGoWhat(field)))
				}
			}
		}
	}
	sort.Strings(out)
	return dedupe(out)
}

// nonGoWhat says in words what a foreign field of go list is.
func nonGoWhat(field string) string {
	switch field {
	case "CgoFiles":
		return "a Go file that imports C"
	case "IgnoredOtherFiles":
		return "a file of another platform's build"
	case "BinaryOnly":
		return "a package with no source"
	case "SysoFiles":
		return "an object linked in"
	case "SFiles":
		return "assembly"
	}
	return "a foreign source or flag"
}

// goModDirs finds the module roots under root: go list does not enter a nested module, so shared/
// (and any module added later) is asked for on its own. This is the one walk of the tree, and it looks
// for go.mod files and nothing else, in every directory but the two that hold other people's code
// (.git, node_modules): a module hidden under a dot directory or testdata is found and judged, so
// the answer to "is this a module" is never "it is under a name somebody skipped".
func goModDirs(root string) ([]string, error) {
	var out []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if n := d.Name(); n == ".git" || n == "node_modules" {
				return fs.SkipDir
			}
			return nil
		}
		if d.Name() == "go.mod" {
			out = append(out, filepath.Dir(p))
		}
		return nil
	})
	return out, err
}

// goListDirs asks go list about explicit directories of a module, for one platform. It is not cached:
// the set is small and changes with the tree.
func goListDirs(modDir, goos string, dirs []string) ([]byte, error) {
	args := []string{"list", "-find", "-e", goListRequest()}
	for _, d := range dirs {
		args = append(args, "./"+filepath.ToSlash(d))
	}
	cmd := toolcmd.Go(context.Background(), []string{"CGO_ENABLED=1", "GOWORK=off", "GOFLAGS=", "GOOS=" + goos}, args[0], args[1:]...).InDir(modDir)
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("go list failed in %s for GOOS=%s over %d directories go list ./... does not name: %w", modDir, goos, len(dirs), err)
	}
	return out, nil
}

// extraGoDirs finds the directories of a module that hold Go source and that `go list ./...` did not
// name (testdata, a name that begins with a dot or an underscore, a directory whose every Go file is
// excluded by a constraint): they can still be built by an import of their path or by `go run`, so the
// files besides Go source that they hold are asked of go list by name (q9-12). Nested modules are
// their own turn and the directories the ban does not read are left out. Paths are relative to modDir.
func extraGoDirs(root, modDir string, listed map[string]bool) ([]string, error) {
	base, mod := canonPath(root), canonPath(modDir)
	var out []string
	err := filepath.WalkDir(mod, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			return nil
		}
		relRoot, rerr := filepath.Rel(base, p)
		if rerr != nil {
			return rerr
		}
		if relRoot != "." && unreadRel(filepath.ToSlash(relRoot)) {
			return fs.SkipDir
		}
		if p != mod {
			if _, statErr := os.Stat(filepath.Join(p, "go.mod")); statErr == nil {
				return fs.SkipDir // a module of its own, asked for on its own
			}
		}
		ents, rerr := os.ReadDir(p)
		if rerr != nil {
			return rerr
		}
		hasGo := false
		for _, e := range ents {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".go") && !strings.HasSuffix(e.Name(), "_test.go") {
				hasGo = true
			}
		}
		if hasGo && !listed[p] {
			rel, _ := filepath.Rel(mod, p)
			out = append(out, rel)
		}
		return nil
	})
	return out, err
}

// listedDirs reads the directories of a go list stream.
func listedDirs(listing []byte, into map[string]bool) {
	dec := json.NewDecoder(bytes.NewReader(listing))
	for dec.More() {
		var r struct{ Dir string }
		if dec.Decode(&r) != nil {
			return
		}
		into[canonPath(r.Dir)] = true
	}
}

// moduleRootProblems judges what decides which code the build compiles besides the packages of the
// module: a vendor directory (go build uses it in place of the module graph and does not check it
// against go.sum, and neither go list ./... nor the walk of go.mod files names what is in it, so a
// copy of a library or of shared/ edited there would be built and judged by nobody), a go.work file
// (the Docker build honours it and the lints switch it off), and a replace directive that points at a
// directory that is not a module of this tree (code the ban never reads). q9-13.
func moduleRootProblems(root string, mods []string) []string {
	var out []string
	known := map[string]bool{}
	for _, m := range mods {
		known[canonPath(m)] = true
	}
	base := canonPath(root)
	for _, m := range mods {
		rel, _ := filepath.Rel(base, canonPath(m))
		rel = filepath.ToSlash(rel)
		if st, err := os.Stat(filepath.Join(m, "vendor")); err == nil && st.IsDir() {
			out = append(out, rel+": a vendor directory: go build uses it in place of the module graph with no check against go.sum, and no lint reads the copy of a library or of shared/ that it holds; remove it (q9-13)")
		}
		cmd := toolcmd.Go(context.Background(), []string{"GOWORK=off", "GOFLAGS="}, "mod", "edit", "-json").InDir(m)
		b, err := cmd.Output()
		if err != nil {
			out = append(out, rel+": go mod edit -json failed: "+err.Error())
			continue
		}
		var mf struct {
			Godebug []struct{ Key, Value string }
			Replace []struct {
				Old, New struct{ Path, Version string }
			}
		}
		if err := json.Unmarshal(b, &mf); err != nil {
			out = append(out, rel+": the go.mod cannot be read: "+err.Error())
			continue
		}
		// A godebug line of go.mod sets the same defaults as a //go:debug directive of a main package, which the
		// directive ban refuses, with no Go source at all (sms-r18-7, sms-r18-13). Every module is judged and
		// none may carry one, so a setting that lowers a security default (x509sha1, tlsrsakex, tls3des), or
		// one that stops recover from seeing panic(nil) (panicnil), is a visible change of a place nobody
		// was watching. The value that reaches the binary is read back from go list (godebugProblems), so a
		// lowered go line is caught too.
		for _, g := range mf.Godebug {
			out = append(out, fmt.Sprintf("%s: go.mod sets godebug %s=%s, a runtime default the escape-hatch ban refuses as //go:debug (owner decision D63); remove it", rel, g.Key, g.Value))
		}
		for _, r := range mf.Replace {
			if r.New.Version != "" {
				continue // another version of a module: a library, which imports.yaml reviews
			}
			target := r.New.Path
			if !filepath.IsAbs(target) {
				target = filepath.Join(m, filepath.FromSlash(target))
			}
			if !known[canonPath(target)] {
				out = append(out, fmt.Sprintf("%s: replace %s => %s names a directory that is not a module of this tree, so the ban never reads the code the build takes from it (q9-13)", rel, r.Old.Path, r.New.Path))
			}
		}
	}
	return out
}

// godebugProblems judges the DefaultGODEBUG go list reports for one package: only a main package has one,
// and it must be exactly what the toolchain in use gives a module with no godebug setting, so the go.mod
// godebug block, a //go:debug directive and a lowered go line (which brings back the older defaults of
// the standard library) are one finding by one comparison and not three guards of three spellings.
// want is the value of a clean module, which is empty when every default is the current one. A package that
// reports no value is a library (go list gives only a main package one), and a main package of a clean module
// reports exactly want, so an empty have is never a change.
//
// Contract (sms-r18-21): it judges what is compiled into the binary as its default. It does not judge the
// GODEBUG environment variable of a running process (no deployment file of this tree sets one, and the
// os member list refuses a program that sets one itself), and it judges no package that is not main.
func godebugProblems(rel, have, want string) []string {
	if have == "" || have == want {
		return nil
	}
	return []string{fmt.Sprintf("%s: the default GODEBUG of this main package is %q, but the toolchain gives %q to a module with no godebug setting; a godebug line of go.mod or go.work, a //go:debug directive or a lowered go line changed a runtime default (sms-r18-7, owner decision D63)", rel, have, want)}
}

// pinnedDefaultGODEBUG is what the toolchain in use gives a main package of a module whose go line is its
// own version and that has no godebug setting, read from go list itself in a scratch module (so the
// value is the toolchain's and not a list kept here).
func pinnedDefaultGODEBUG(root string) (string, error) {
	b, err := toolcmd.Go(context.Background(), []string{"GOWORK=off", "GOFLAGS="}, "env", "GOVERSION").InDir(root).Output()
	if err != nil {
		return "", fmt.Errorf("go env GOVERSION: %w", err)
	}
	return scratchDefaultGODEBUG(root, strings.TrimPrefix(strings.TrimSpace(string(b)), "go"))
}

// scratchDefaultGODEBUG is the DefaultGODEBUG of a main package of a scratch module with that go line.
func scratchDefaultGODEBUG(root, version string) (string, error) {
	dir, err := os.MkdirTemp("", "ctrlz-godebug-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(dir)
	for name, body := range map[string]string{
		"go.mod":  "module scratch\n\ngo " + version + "\n",
		"main.go": "package main\n\nfunc main() {}\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			return "", err
		}
	}
	// The go line of the scratch module is the toolchain's own or an older one, so the command never needs another
	// toolchain and GOTOOLCHAIN is not set (toolcmd does not take it from a caller, admin-r18-17).
	b, err := toolcmd.Go(context.Background(), []string{"GOWORK=off", "GOFLAGS="}, "list", "-f", "{{.DefaultGODEBUG}}", ".").InDir(dir).Output()
	if err != nil {
		return "", fmt.Errorf("go list in the scratch module: %w", err)
	}
	return strings.TrimSpace(string(b)), nil
}

// goWorkProblems refuses a go.work or go.work.sum anywhere under root.
func goWorkProblems(root string) []string {
	var out []string
	base := canonPath(root)
	_ = filepath.WalkDir(base, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(base, p)
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if rel != "." && (unreadDirName(d.Name())) {
				return fs.SkipDir
			}
			return nil
		}
		if d.Name() == "go.work" || d.Name() == "go.work.sum" {
			out = append(out, rel+": a go.work file: the Docker build honours it and every lint of this package switches it off (GOWORK=off), so they would judge a module graph that is not the one built (q9-13)")
		}
		return nil
	})
	return out
}

// foreignProblems asks go list, for every module under root, about the files each package builds
// besides Go source, and judges what else decides the code that is built (moduleRootProblems,
// goWorkProblems). The toolchain's own classification is the source of truth, so a file the lint
// never parses (C, assembly, an object, SWIG) cannot ride along in a package that looks clean.
func foreignProblems(root string, pol escapePolicy, stale bool) []string {
	mods, err := goModDirs(root)
	if err != nil || len(mods) == 0 {
		return []string{fmt.Sprintf("no module found under %s (%v)", root, err)}
	}
	var out []string
	out = append(out, moduleRootProblems(root, mods)...)
	out = append(out, goWorkProblems(root)...)
	seen := &foreignSeen{dirs: map[string]bool{}, used: map[string]bool{}}
	if stale {
		// The real tree only: the planted trees of the can-fail tests have go lines of their own.
		want, err := pinnedDefaultGODEBUG(root)
		if err != nil {
			out = append(out, err.Error())
		}
		seen.judgeGodebug, seen.wantGodebug = err == nil, want
	}
	goListAll(mods)
	for _, m := range mods {
		listed := map[string]bool{}
		for _, goos := range goListPlatforms() {
			b, err := goListOutput(m, goos)
			if err != nil {
				out = append(out, err.Error())
				continue
			}
			listedDirs(b, listed)
			out = append(out, foreignFromList(root, b, pol, seen)...)
		}
		extra, err := extraGoDirs(root, m, listed)
		if err != nil {
			out = append(out, "the directories of "+m+" cannot be walked: "+err.Error())
			continue
		}
		if len(extra) == 0 {
			continue
		}
		// Directories go list ./... did not name: asked for by name, a load error is not a finding here
		// (a lone `//go:build ignore` generator loads as "build constraints exclude all Go files").
		quiet := seen.askedByName()
		for _, goos := range goListPlatforms() {
			b, err := goListDirs(m, goos, extra)
			if err != nil {
				out = append(out, err.Error())
				continue
			}
			out = append(out, foreignFromList(root, b, pol, quiet)...)
		}
	}
	if stale {
		for d := range pol.nonGo {
			switch {
			case !seen.dirs[d]:
				out = append(out, "nonGoSourceDirs lists "+d+", which is no package of any module of the tree: remove the entry")
			case !seen.used[d]:
				out = append(out, "nonGoSourceDirs lists "+d+", which holds no file besides Go source: remove the entry")
			}
		}
	}
	sort.Strings(out)
	return dedupe(out)
}

func TestNoPackageBuildsAFileThatIsNotGoSource(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("no go tool on PATH")
	}
	for _, p := range foreignProblems(repoRoot(t), realPolicy(), true) {
		t.Error(p)
	}
}

// TestTreeMarkersCanFail plants what decides which code the build compiles besides the packages the
// ban reads: a vendor directory, a go.work file, a replace directive that points outside the tree (and
// one that points at a module of the tree, which is how shared/ is reached and is clean), and a
// package that go list ./... does not name (under testdata, under a name that begins with an
// underscore) that holds assembly, which the build compiles when something imports the directory
// (q9-12, q9-13).
func TestTreeMarkersCanFail(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("no go tool on PATH")
	}
	// What decides the code that is built: judged without go list, which a vendor directory in a
	// scratch module would fail on its own (inconsistent vendoring).
	root := plantTree(t, map[string]string{
		"go.mod":             "module " + module + "\n\ngo 1.22\n\nreplace " + sharedModule + " => ./shared\n\nreplace example.com/lib => ../lib\n\nreplace example.com/versioned => example.com/other v1.0.0\n",
		"shared/go.mod":      "module " + sharedModule + "\n\ngo 1.22\n",
		"vendor/modules.txt": "# example.com/x v1.0.0\n",
		"go.work":            "go 1.22\n\nuse .\n",
		"sub/go.work.sum":    "x",
		"internal/a/a.go":    "package a\n",
	})
	mods, err := goModDirs(root)
	if err != nil {
		t.Fatal(err)
	}
	all := filepath.ToSlash(strings.Join(append(moduleRootProblems(root, mods), goWorkProblems(root)...), "\n"))
	for _, w := range []string{
		".: a vendor directory",
		"go.work: a go.work file",
		"sub/go.work.sum: a go.work file",
		"replace example.com/lib => ../lib names a directory that is not a module of this tree",
	} {
		if !strings.Contains(all, w) {
			t.Errorf("no problem for %q in:\n%s", w, all)
		}
	}
	for _, w := range []string{"replace github.com/Kup1ng/CtrlZ-Shared", "example.com/versioned"} {
		if strings.Contains(all, w) {
			t.Errorf("a clean replace was reported (%s):\n%s", w, all)
		}
	}
	// Packages go list ./... does not name that hold assembly or cgo: asked for by name.
	root2 := plantTree(t, map[string]string{
		"go.mod":              "module " + module + "\n\ngo 1.22\n\nreplace " + sharedModule + " => ./shared\n",
		"shared/go.mod":       "module " + sharedModule + "\n\ngo 1.22\n",
		"internal/a/a.go":     "package a\n",
		"testdata/asm/a.go":   "package asm\n",
		"testdata/asm/a.s":    "x\n",
		"_hid/cgo/c.go":       "package cgo\n\n// int one(void) { return 1; }\nimport \"C\"\n",
		"internal/gen/gen.go": "//go:build ignore\n\npackage main\n\nfunc main() {}\n",
	})
	got := filepath.ToSlash(strings.Join(foreignProblems(root2, realPolicy(), false), "\n"))
	for _, w := range []string{"testdata/asm: go list reports SFiles", "_hid/cgo: go list reports CgoFiles"} {
		if !strings.Contains(got, w) {
			t.Errorf("no problem for %q in:\n%s", w, got)
		}
	}
	for _, w := range []string{"internal/gen", "internal/a:", "could not load"} {
		if strings.Contains(got, w) {
			t.Errorf("a clean directory was reported (%s):\n%s", w, got)
		}
	}
}

// TestGoListFieldsAreClassified compares the table of go list fields with the Package struct that the
// installed toolchain documents in `go help list`, in both directions: a field the toolchain adds is
// unclassified (and the ban would fail on it), and a field it drops is a stale row.
func TestGoListFieldsAreClassified(t *testing.T) {
	b, err := toolcmd.Go(context.Background(), nil, "help", "list").Output()
	if err != nil {
		t.Skip("no go tool on PATH")
	}
	text := strings.ReplaceAll(string(b), "\r\n", "\n")
	_, rest, ok := strings.Cut(text, "type Package struct {")
	if !ok {
		t.Fatal("go help list no longer shows the Package struct; the table of fields cannot be checked")
	}
	body, _, _ := strings.Cut(rest, "\n    }\n")
	documented := map[string]bool{}
	for _, l := range strings.Split(body, "\n") {
		cols := strings.Fields(l)
		if len(cols) >= 2 && !strings.HasPrefix(cols[0], "//") {
			documented[cols[0]] = true
		}
	}
	if len(documented) < 30 {
		t.Fatalf("only %d fields read from go help list; the format changed", len(documented))
	}
	for f := range documented {
		if _, ok := goListFields[f]; !ok {
			t.Errorf("go list documents the field %s and goListFields does not classify it: say whether it names something the toolchain builds that is not Go source", f)
		}
	}
	for f := range goListFields {
		if !documented[f] {
			t.Errorf("goListFields lists %s, which go help list no longer documents: remove the row", f)
		}
	}
}

// harnessImportsOf and the production list: see packageClassProblems.

// packageClassProblems makes every directory with non-test Go source one of two things: a
// production package (listed in testdata/packages.golden) or a test harness (harnessPackages, with
// its reason). A directory that is neither fails, whatever it is called (sms-r16-22): the earlier
// check flagged a package whose directory began or ended with "test", and a harness called mocks,
// fakegw or fixtures that shipped its own certificate authority was in neither list and was not
// named like one. Now a new directory starts refused until somebody says which it is, and the
// import ban (testOnlyProblems) applies to the declared harnesses.
func packageClassProblems(dirs map[string]bool, production map[string]bool) []string {
	var out []string
	for dir := range dirs {
		_, harness := underAny(dir, harnessPackages)
		switch {
		case harness && production[dir]:
			out = append(out, dir+": listed as a production package and declared a harness; it is one or the other")
		case !harness && !production[dir]:
			out = append(out, dir+": a directory with Go source that is neither in testdata/packages.golden nor in harnessPackages; decide which it is (a harness that production code must not import is declared in harnessPackages with its reason)")
		}
	}
	for dir := range production {
		if !dirs[dir] {
			out = append(out, "testdata/packages.golden lists "+dir+", which has no non-test Go source: remove the line")
		}
	}
	sort.Strings(out)
	return out
}

func readProductionGolden(t *testing.T) map[string]bool {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(repoRoot(t), "internal", "lint", "testdata", "packages.golden"))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]bool{}
	for _, l := range strings.Split(string(b), "\n") {
		l = strings.TrimSpace(l)
		if l != "" && !strings.HasPrefix(l, "#") {
			out[l] = true
		}
	}
	return out
}

func TestEveryPackageIsProductionOrADeclaredHarness(t *testing.T) {
	_, files := parseRepo(t)
	dirs := map[string]bool{}
	for _, f := range files {
		if !f.test {
			dirs[dirOf(f.path)] = true
		}
	}
	for _, p := range packageClassProblems(dirs, readProductionGolden(t)) {
		t.Error(p)
	}
}

func TestPackageClassLintCanFail(t *testing.T) {
	dirs := map[string]bool{"internal/a": true, "internal/testpg": true, "internal/fakegw": true}
	prod := map[string]bool{"internal/a": true}
	got := packageClassProblems(dirs, prod)
	if len(got) != 1 || !strings.Contains(got[0], "internal/fakegw") {
		t.Errorf("an undeclared package called fakegw: %v", got)
	}
	for _, name := range []string{"mocks", "stub", "fixtures", "smstest", "testfake"} {
		d := map[string]bool{"internal/a": true, "internal/testpg": true, "internal/" + name: true}
		if got := packageClassProblems(d, prod); len(got) != 1 {
			t.Errorf("an undeclared package called %s: %v", name, got)
		}
	}
	if got := packageClassProblems(map[string]bool{"internal/a": true, "internal/testpg": true}, prod); len(got) != 0 {
		t.Errorf("a classified tree has problems: %v", got)
	}
	if got := packageClassProblems(map[string]bool{"internal/testpg": true}, prod); len(got) != 1 {
		t.Errorf("a golden line with no source: %v", got)
	}
	both := map[string]bool{"internal/a": true, "internal/testpg": true}
	if got := packageClassProblems(both, map[string]bool{"internal/a": true, "internal/testpg": true}); len(got) != 1 {
		t.Errorf("a package that is production and harness: %v", got)
	}
}

// TestCapabilityLintCanFail plants one case for each form Go allows of each escape hatch, in a Panel
// package and in a shared/ package, and the clean uses, so the ban is shown to fail and to pass. The
// Panel directories are the worker, the admin routes and a gateway on purpose: the places that hold
// the built sender, and the ones the per-guard deny lists of rounds 15 and 16 were written for. Every
// problem must name the file it is in.
func TestCapabilityLintCanFail(t *testing.T) {
	type tcase struct {
		name, path, src string
		want            int // problems, at least; 0 means none
	}
	var cases []tcase

	// Where a case is planted: a worker, a gateway and an admin route of the Panel, and two directories
	// of shared/ (a hand-written one and a generated one that is not listed).
	places := []string{
		"internal/worker/smssend/x.go", "internal/sms/newdrv/d.go", "internal/adminapi/x.go",
		"shared/identity/x.go", "shared/gen/ctrlz/future/v1/x.go",
	}
	// Every form of an import: plain, aliased, blank, dot, a parenthesised group, a raw string path
	// and a path written with an escape (all of them spell the same package).
	forms := map[string]string{
		"plain":   `import "%s"`,
		"alias":   `import zz "%s"`,
		"blank":   `import _ "%s"`,
		"dot":     `import . "%s"`,
		"group":   "import (\n\t\"fmt\"\n\t\"%s\"\n)",
		"raw":     "import `%s`",
		"escaped": `import "\x%02x%s"`,
	}
	for _, tool := range []string{"reflect", "unsafe", "plugin"} {
		for fname, f := range forms {
			for _, place := range places {
				src := ""
				if fname == "escaped" {
					src = fmt.Sprintf(f, tool[0], tool[1:])
				} else {
					src = fmt.Sprintf(f, tool)
				}
				cases = append(cases, tcase{tool + " " + fname + " in " + place, place, src, 1})
			}
		}
	}
	// cgo, with a preamble the way cgo wants it, plain and with a group.
	for _, place := range places {
		cases = append(cases,
			tcase{"cgo with a preamble in " + place, place, "/*\n#include <stdio.h>\nstatic int one(void) { return 1; }\n*/\nimport \"C\"\nvar _ = C.one()", 1},
			tcase{"cgo in a group in " + place, place, "// #include <stdlib.h>\nimport (\n\t\"C\"\n\t\"fmt\"\n)", 1},
		)
	}
	// Directives: the push and the pull form of linkname, every directive the toolchain acts on at the
	// time of writing, one it does not know yet, and the position directive in both comment forms.
	for _, place := range places {
		cases = append(cases,
			tcase{"go:linkname, the pull form, in " + place, place, "import _ \"unsafe\"\n//go:linkname nanotime runtime.nanotime\nfunc nanotime() int64", 3},
			tcase{"go:linkname, the push form, in " + place, place, "import _ \"unsafe\"\n//go:linkname handle\nfunc handle() int { return 1 }", 2},
			tcase{"a line directive in " + place, place, "//line other.go:10\nvar x int", 1},
			tcase{"a line directive in a block comment in " + place, place, "/*line other.go:10*/\nvar x int", 1},
			tcase{"a function with no body in " + place, place, "func raw(x int) int", 1},
			tcase{"a method with no body in " + place, place, "type T struct{}\nfunc (T) raw() int", 1},
		)
	}
	for _, d := range []string{
		"linkname", "noinline", "nosplit", "noescape", "norace", "nocheckptr", "uintptrescapes", "uintptrkeepalive",
		"systemstack", "nowritebarrier", "nowritebarrierrec", "yeswritebarrierrec", "registerparams", "nointerface",
		"notinheap", "wasmimport", "wasmexport", "debug", "cgo_import_dynamic", "cgo_ldflag", "cgo_export_static",
		"somedirectivethetoolchainlearnstomorrow",
	} {
		cases = append(cases,
			tcase{"go:" + d + " in the worker", "internal/worker/smssend/x.go", "//go:" + d + " x\nfunc f() {}", 1},
			tcase{"go:" + d + " in shared", "shared/names/x.go", "//go:" + d + " x\nfunc f() {}", 1},
			tcase{"go:" + d + " after a tab", "internal/api/x.go", "//go:" + d + "\tx\nfunc f() {}", 1},
		)
	}
	// os, syscall and runtime are judged by member.
	cases = append(cases,
		tcase{"os.StartProcess in a listed directory", "internal/sms/noop/x.go", "import \"os\"\nfunc f() { os.StartProcess(\"x\", nil, nil) }", 1},
		tcase{"os through an alias in a listed directory", "internal/secret/x.go", "import o \"os\"\nfunc f() { o.OpenFile(\"/proc/self/mem\", 2, 0) }", 1},
		tcase{"os imported with a dot", "internal/sms/noop/x.go", "import . \"os\"\nfunc f() { OpenFile(\"x\", O_APPEND, 0) }", 1},
		tcase{"os in a directory not listed", "internal/api/x.go", "import \"os\"\nfunc f() { os.Exit(1) }", 2},
		tcase{"os in shared, in a directory not listed", "shared/identity/x.go", "import \"os\"\nfunc f() { os.Exit(1) }", 2},
		tcase{"a member not listed in shared/cmd/sharedtool", "shared/cmd/sharedtool/x.go", "import \"os\"\nfunc f() { os.StartProcess(\"x\", nil, nil) }", 1},
		tcase{"syscall.Syscall in cmd/ctrlz", "cmd/ctrlz/x.go", "import \"syscall\"\nfunc f() { syscall.Syscall(0, 0, 0, 0) }", 1},
		tcase{"syscall through an alias, a member not listed", "cmd/ctrlz/x.go", "import sc \"syscall\"\nfunc f() { _ = sc.Mmap }", 1},
		tcase{"syscall imported with a dot", "cmd/ctrlz/x.go", "import . \"syscall\"\nvar _ = SIGTERM", 1},
		tcase{"syscall in the api", "internal/api/x.go", "import _ \"syscall\"", 1},
		tcase{"runtime.SetFinalizer in logattr", "internal/logattr/x.go", "import \"runtime\"\nfunc f() { runtime.SetFinalizer(nil, nil) }", 1},
		tcase{"runtime in a directory not listed", "internal/api/x.go", "import _ \"runtime\"", 1},
		tcase{"runtime imported with a dot", "internal/logattr/x.go", "import . \"runtime\"\nvar _ = Callers", 1},
		tcase{"runtime/debug", "internal/api/x.go", "import _ \"runtime/debug\"", 1},
		tcase{"os/exec in the admin console", "internal/admincli/x.go", "import _ \"os/exec\"", 1},
		tcase{"a package nobody listed", "internal/api/x.go", "import _ \"archive/zip\"", 1},
		tcase{"a package nobody listed, in shared", "shared/names/x.go", "import _ \"go/importer\"", 1},
		tcase{"io/ioutil", "internal/api/x.go", "import _ \"io/ioutil\"", 1},
		tcase{"testing in production", "internal/api/x.go", "import _ \"testing\"", 1},
		tcase{"testing in a harness's non-test file in the wrong directory", "internal/authtest/boundary/x.go", "import _ \"testing\"", 1},
		tcase{"httptest in production", "internal/api/x.go", "import _ \"net/http/httptest\"", 1},
		// The cases of the per-guard deny lists of the SMS lint, moved here: the NewAt sequence of
		// sms-r15-2 in a gateway package, and the same calls in a package a gateway merely imports.
		tcase{"the NewAt sequence of sms-r15-2, in a gateway", "internal/sms/newdrv/d.go", "import \"reflect\"\ntype D struct{ client *int }\nfunc f(d *D) {\n\tf0 := reflect.ValueOf(d.client).Elem().Field(0)\n\tw := reflect.NewAt(f0.Type().Elem(), f0.UnsafePointer())\n\tw.Elem().FieldByName(\"Transport\").Elem().Elem().FieldByName(\"InsecureSkipVerify\").SetBool(true)\n}", 1},
		tcase{"reflect.NewAt in a package a gateway imports", "internal/elsewhere/e.go", "import \"reflect\"\nfunc f(t reflect.Type) { _ = reflect.NewAt(t, nil) }", 1},
		tcase{"Value.UnsafePointer in a package a gateway imports", "internal/elsewhere/e.go", "import \"reflect\"\nfunc f(v reflect.Value) { _ = v.UnsafePointer() }", 1},
		tcase{"Value.UnsafeAddr in a package a gateway imports", "internal/elsewhere/e.go", "import \"reflect\"\nfunc f(v reflect.Value) { _ = v.UnsafeAddr() }", 1},
		tcase{"Value.Pointer in a package a gateway imports", "internal/elsewhere/e.go", "import \"reflect\"\nfunc f(v reflect.Value) { _ = v.Pointer() }", 1},
		tcase{"reflect.ValueOf over a driver in a package a gateway imports", "internal/elsewhere/e.go", "import \"reflect\"\ntype holder struct{ inner struct{ c []*int } }\nfunc f(h holder) { _ = reflect.ValueOf(h) }", 1},

		// Members of reflect and unsafe, judged by name where a directory is listed (q9-10, q9-14).
		tcase{"reflect.NewAt in internal/logattr, which is listed for reflect", "internal/logattr/x.go", "import \"reflect\"\nfunc f(t reflect.Type) { _ = reflect.NewAt(t, nil) }", 1},
		tcase{"reflect.SliceHeader in internal/closed", "internal/closed/x.go", "import \"reflect\"\nvar _ reflect.SliceHeader", 1},
		tcase{"unsafe.Pointer in a listed generated package", "shared/gen/ctrlz/common/v1/x.go", "import \"unsafe\"\nvar _ unsafe.Pointer", 1},
		tcase{"unsafe.Add in a listed generated package", "shared/gen/ctrlz/hub/v1/x.go", "import \"unsafe\"\nvar _ = unsafe.Add", 1},
		// A library whose type is unsafe.Pointer under another name, in shared/ (q9-14).
		tcase{"protoimpl.Pointer from shared/identity", "shared/identity/x.go", "import \"google.golang.org/protobuf/runtime/protoimpl\"\nvar _ protoimpl.Pointer", 1},
		tcase{"protoimpl from a hand-written shared package", "shared/wire/x.go", "import _ \"google.golang.org/protobuf/runtime/protoimpl\"", 1},
		tcase{"a library nobody listed in shared/", "shared/names/x.go", "import _ \"github.com/google/uuid\"", 1},
		tcase{"a listed library in the wrong shared directory", "shared/names/x.go", "import _ \"golang.org/x/text/unicode/norm\"", 1},
		tcase{"x/net/idna in shared/names", "shared/names/x.go", "import _ \"golang.org/x/net/idna\"", 0},
		tcase{"protoimpl in a generated package", "shared/gen/ctrlz/policy/v1/x.go", "import _ \"google.golang.org/protobuf/runtime/protoimpl\"", 0},
		// net/http and crypto/tls: a member that opens a file by a path the caller chooses (q9-15).
		tcase{"http.Dir in the worker", "internal/worker/smssend/x.go", "import \"net/http\"\nfunc f() { _, _ = http.Dir(\"/proc/self\").Open(\"mem\") }", 1},
		tcase{"http.Dir through an alias", "internal/api/x.go", "import h \"net/http\"\nvar _ = h.Dir", 1},
		tcase{"http.ServeFile", "internal/api/x.go", "import \"net/http\"\nvar _ = http.ServeFile", 1},
		tcase{"http.FileServer over http.FS", "internal/api/x.go", "import \"net/http\"\nvar _ = http.FileServer", 1},
		tcase{"http.NewFileTransport", "shared/names/x.go", "import \"net/http\"\nvar _ = http.NewFileTransport", 1},
		tcase{"net/http with a dot import", "internal/api/x.go", "import . \"net/http\"\nvar _ = StatusOK", 1},
		tcase{"tls.LoadX509KeyPair", "internal/api/x.go", "import \"crypto/tls\"\nvar _ = tls.LoadX509KeyPair", 1},
		tcase{"a listed member of net/http and crypto/tls", "internal/api/x.go", "import (\n\t\"crypto/tls\"\n\t\"net/http\"\n)\nvar _ = http.StatusOK\nvar _ tls.Config", 0},
		tcase{"a local named http is not the package", "internal/api/x.go", "import \"net/http\"\nvar _ http.Handler\nfunc f(http struct{ Dir int }) int { return http.Dir }", 0},
		// text/template calls methods by name (q9-2, q9-16).
		tcase{"text/template in the worker", "internal/worker/smssend/x.go", "import _ \"text/template\"", 1},
		tcase{"text/template in shared", "shared/names/x.go", "import _ \"text/template\"", 1},
		tcase{"text/template in the migration generator", "internal/migrategen/x.go", "import _ \"text/template\"", 0},
		// go:generate runs any command (q9-5).
		tcase{"go:generate in a directory not listed", "internal/worker/smssend/x.go", "//go:generate sh -c \"curl x | sh\"\nvar a int", 1},
		tcase{"go:generate in shared", "shared/names/x.go", "//go:generate go run x.go\nvar a int", 1},
		// os.OpenFile: the flags are the limit (q9-17).
		tcase{"OpenFile with a literal flag", "internal/admincli/x.go", "import \"os\"\nfunc f() { os.OpenFile(\"/proc/self/mem\", 2, 0) }", 1},
		tcase{"OpenFile with a variable flag", "internal/admincli/x.go", "import \"os\"\nfunc f(fl int) { os.OpenFile(\"x\", fl, 0) }", 1},
		tcase{"OpenFile that opens an existing file", "internal/admincli/x.go", "import \"os\"\nfunc f() { os.OpenFile(\"x\", os.O_WRONLY|os.O_CREATE, 0) }", 1},
		tcase{"OpenFile with O_CREATE alone", "internal/admincli/x.go", "import \"os\"\nfunc f() { os.OpenFile(\"x\", os.O_CREATE|os.O_WRONLY, 0) }", 1},
		tcase{"OpenFile as a value", "internal/admincli/x.go", "import \"os\"\nvar open = os.OpenFile", 1},
		tcase{"OpenFile through an alias with a literal flag", "internal/admincli/x.go", "import o \"os\"\nfunc f() { o.OpenFile(\"x\", 1, 0) }", 1},
		tcase{"OpenFile with a spread argument", "internal/admincli/x.go", "import \"os\"\nfunc f(a []any) { os.OpenFile(a...) }", 1},
		tcase{"OpenFile in parentheses", "internal/admincli/x.go", "import \"os\"\nfunc f() { (os.OpenFile)(\"x\", 2, 0) }", 1},
		tcase{"os.Create in a listed directory", "internal/admincli/x.go", "import \"os\"\nfunc f() { os.Create(\"x\") }", 1},
		tcase{"os imported with a raw string path, a member not listed", "internal/secret/x.go", "import `os`\nfunc f() { os.StartProcess(\"x\", nil, nil) }", 1},
		tcase{"os imported with an escaped path, a member not listed", "internal/secret/x.go", "import \"\x6fs\"\nfunc f() { os.StartProcess(\"x\", nil, nil) }", 1},
		tcase{"OpenFile with O_EXCL alone", "internal/admincli/x.go", "import \"os\"\nfunc f() { os.OpenFile(\"x\", os.O_EXCL|os.O_WRONLY, 0) }", 1},
		tcase{"a parenthesised OpenFile that creates exclusively", "internal/admincli/x.go", "import \"os\"\nfunc f() { (os.OpenFile)(\"x\", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) }", 0},
		tcase{"OpenFile that creates exclusively", "internal/admincli/x.go", "import \"os\"\nfunc f() { os.OpenFile(\"x\", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) }", 0},
		tcase{"OpenFile that creates exclusively, flags in parentheses", "internal/admincli/x.go", "import \"os\"\nfunc f() { os.OpenFile(\"x\", (os.O_EXCL | os.O_CREATE | os.O_WRONLY), 0o600) }", 0},
		tcase{"the development gateway appends", "internal/sms/noop/x.go", "import \"os\"\nfunc f() { os.OpenFile(\"x\", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600) }", 0},
		tcase{"a local named os that shadows the import", "internal/secret/x.go", "import \"os\"\nvar _ = os.ReadFile\nfunc f(x int) { os := struct{ Exit func() }{}; os.Exit() }", 0},
		tcase{"a package-level name that is not the import", "internal/api/x.go", "func f() { os.Exit() }", 0},
		// A package imported under a name that is another package's name.
		tcase{"os imported under the name of another package", "internal/api/x.go", "import fmt \"os\"\nfunc f() { fmt.Exit(1) }", 2},
		// A test harness package that only test files may import (q9-9).
		tcase{"production code importing the vectors", "internal/api/x.go", "import _ \"github.com/Kup1ng/CtrlZ-Shared/vectors\"", 1},
		tcase{"shared production code importing the vectors", "shared/policy/x.go", "import _ \"github.com/Kup1ng/CtrlZ-Shared/vectors\"", 1},
		tcase{"a test importing the vectors", "internal/api/x_test.go", "import _ \"github.com/Kup1ng/CtrlZ-Shared/vectors\"", 0},
		// The clean uses.
		tcase{"os/signal and syscall.SIGTERM in cmd/ctrlz", "cmd/ctrlz/x.go", "import _ \"os/signal\"\nimport \"syscall\"\nvar _ = syscall.SIGTERM", 0},
		tcase{"os/exec in the mutation tool", "internal/mutant/x.go", "import _ \"os/exec\"", 0},
		tcase{"a listed os member", "internal/secret/x.go", "import \"os\"\nfunc f() { os.ReadFile(\"x\") }", 0},
		tcase{"a listed os member in shared/cmd/sharedtool", "shared/cmd/sharedtool/x.go", "import \"os\"\nfunc f() { os.Rename(\"a\", \"b\") }", 0},
		tcase{"runtime.Callers in logattr", "internal/logattr/x.go", "import \"runtime\"\nfunc f(p []uintptr) { runtime.Callers(2, p) }", 0},
		tcase{"the safe standard packages", "internal/api/x.go", "import (_ \"net/http\"; _ \"encoding/json\"; _ \"context\"; _ \"time\")", 0},
		tcase{"the safe directives", "internal/api/x.go", "//go:build linux\n//go:generate go run x.go\n//go:embed a.txt\nvar a string", 0},
		tcase{"a raw string import path of a listed package", "internal/closed/e.go", "import `reflect`\nvar _ = reflect.String", 0},
		tcase{"an escaped import path of a listed package", "internal/closed/e.go", "import \"\\x72eflect\"\nvar _ = reflect.String", 0},
		tcase{"a safe directive after a tab", "internal/api/x.go", "//go:embed\ta.txt\nvar a string", 0},
		tcase{"a function with a body", "internal/api/x.go", "func f(x int) int { return x }", 0},
		tcase{"a comment that only talks about a directive", "internal/api/x.go", "// the go:linkname directive and a //go:noinline mention in prose, and a line of text\nvar x int", 0},
		tcase{"a third party library is another list", "internal/api/x.go", "import _ \"github.com/google/uuid\"", 0},
		tcase{"reading kinds and elements by reflect in internal/closed", "internal/closed/e.go", "import \"reflect\"\nfunc f(v any) bool { rv := reflect.ValueOf(v); return rv.Kind() == reflect.String }", 0},
		tcase{"reflect in shared/vectors", "shared/vectors/e.go", "import \"reflect\"\nfunc f(a, b any) bool { return reflect.DeepEqual(a, b) }", 0},
		tcase{"testing in shared/vectors", "shared/vectors/t.go", "import \"testing\"\nfunc Run(t *testing.T) {}", 0},
		tcase{"protoc-gen-go output in a listed generated package", "shared/gen/ctrlz/common/v1/x.go", "import (\n\t\"reflect\"\n\t\"unsafe\"\n)\nvar _ = reflect.TypeOf(0)\nvar _ = unsafe.Slice(unsafe.StringData(\"x\"), 1)", 0},
	)
	// A test file may import anything and carry any directive: it is not shipped (the boundary of the
	// contract). The same holds in shared/.
	for _, place := range []string{"internal/worker/smssend/x_test.go", "shared/identity/x_test.go"} {
		cases = append(cases, tcase{"a test file that imports reflect, unsafe, plugin, C and os/exec, in " + place, place,
			"import _ \"reflect\"\nimport _ \"unsafe\"\nimport _ \"plugin\"\nimport _ \"os/exec\"\nimport \"os\"\n//go:noinline\nfunc f() { os.Exit(1) }\nfunc g(x int) int", 0})
	}

	for _, c := range cases {
		fset := token.NewFileSet()
		fs := parsePlanted(t, fset, []planted{{c.path, c.src}})
		if strings.HasSuffix(c.path, "_test.go") {
			fs = append(fs, parsePlanted(t, fset, []planted{{"internal/zz/z.go", `var Z int`}})...)
		}
		got := capabilityProblems(fset, fs, realPolicy(), false)
		if (c.want == 0) != (len(got) == 0) {
			t.Errorf("%s: %d problems, want %d or more: %v", c.name, len(got), c.want, got)
			continue
		}
		for _, p := range got {
			if !strings.Contains(p, c.path) {
				t.Errorf("%s: a problem that does not name the file %s: %s", c.name, c.path, p)
			}
		}
	}
}

// TestCapabilityLintCanFailInADirectoryOfSeveralFiles plants a directory that holds a file with another
// package clause next to the real ones: the generator layout (`//go:build ignore`, package main) that
// `go run` uses. go/types takes the package name from the first file and drops every file that does not
// match, so a judgment that waited for the type checker to resolve a selector never ran on the dropped
// files, or on the real ones when the odd file sorts first (q9-1, q9-7, q9-11). The member of os,
// syscall and runtime is read from the file's own imports, so each of these is refused, whichever file
// holds the call and whichever sorts first.
func TestCapabilityLintCanFailInADirectoryOfSeveralFiles(t *testing.T) {
	gen := func(body string) string {
		return wholeFile + "//go:build ignore\n\npackage main\n\n" + body
	}
	cases := []struct {
		name  string
		files []planted
		want  string // the file a problem must name; "" for none
	}{
		{"os.StartProcess in the real file, the generator sorts first", []planted{
			{"internal/sms/noop/0gen.go", gen("func main() {}")},
			{"internal/sms/noop/noop.go", "import \"os\"\nfunc f() { os.StartProcess(\"/bin/sh\", nil, nil) }"},
		}, "noop.go"},
		{"os.StartProcess in the generator", []planted{
			{"internal/sms/noop/a_gen.go", gen("import \"os\"\nfunc main() { os.StartProcess(\"x\", nil, nil) }")},
			{"internal/sms/noop/noop.go", "func g() {}"},
		}, "a_gen.go"},
		{"os.OpenFile on /proc/self/mem in the generator", []planted{
			{"internal/secret/0gen.go", gen("import \"os\"\nfunc main() { os.OpenFile(\"/proc/self/mem\", 2, 0) }")},
			{"internal/secret/secret.go", "import \"os\"\nvar _ = os.ReadFile"},
		}, "0gen.go"},
		{"syscall.Syscall in a generator of cmd/ctrlz", []planted{
			{"cmd/ctrlz/gen.go", gen("import \"syscall\"\nfunc main() { syscall.Syscall(0, 0, 0, 0) }")},
			{"cmd/ctrlz/main.go", "import \"syscall\"\nvar _ = syscall.SIGTERM"},
		}, "gen.go"},
		{"runtime.SetFinalizer in a generator of logattr", []planted{
			{"internal/logattr/0gen.go", gen("import \"runtime\"\nfunc main() { runtime.SetFinalizer(nil, nil) }")},
			{"internal/logattr/logattr.go", "import \"runtime\"\nfunc f(p []uintptr) { runtime.Callers(2, p) }"},
		}, "0gen.go"},
		{"http.Dir in a generator of an api directory", []planted{
			{"internal/api/0gen.go", gen("import \"net/http\"\nfunc main() { _ = http.Dir(\"/\") }")},
			{"internal/api/api.go", "func f() {}"},
		}, "0gen.go"},
		{"reflect.NewAt in a generator of internal/closed", []planted{
			{"internal/closed/0gen.go", gen("import \"reflect\"\nfunc main() { _ = reflect.NewAt }")},
			{"internal/closed/closed.go", "import \"reflect\"\nvar _ = reflect.String"},
		}, "0gen.go"},
		{"a clean generator next to a clean file", []planted{
			{"internal/sms/noop/0gen.go", gen("import \"fmt\"\nfunc main() { fmt.Println() }")},
			{"internal/sms/noop/noop.go", "import \"os\"\nfunc f() { os.OpenFile(\"x\", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600) }"},
		}, ""},
	}
	for _, c := range cases {
		fset := token.NewFileSet()
		fs := parsePlanted(t, fset, c.files)
		got := capabilityProblems(fset, fs, realPolicy(), false)
		if c.want == "" {
			if len(got) != 0 {
				t.Errorf("%s: unexpected problems %v", c.name, got)
			}
			continue
		}
		found := false
		for _, p := range got {
			found = found || strings.Contains(p, c.want)
		}
		if !found {
			t.Errorf("%s: no problem names %s: %v", c.name, c.want, got)
		}
	}
}

// TestEscapeHatchBanListsCanFail plants the entries of the lists that go wrong: an entry whose
// directory no longer uses the tool, one whose directory does not exist (a glob among them: a
// generated package is listed by name), one that only a test file uses, and the entries that are
// used, which must pass.
func TestEscapeHatchBanListsCanFail(t *testing.T) {
	minimal := func() escapePolicy {
		return escapePolicy{
			safeStd:       map[string]string{},
			std:           map[string]map[string]string{"reflect": {"internal/a": "why"}, "unsafe": {"shared/gen/x/v1": "why"}},
			members:       map[string]map[string][]string{"os": {"internal/a": {"Getenv"}}},
			directiveSafe: goDirectiveSafe,
			directives:    map[string]map[string]string{"linkname": {"internal/a": "why"}},
			bodyless:      map[string]string{"internal/a": "why"},
			nonGo:         map[string]string{},
		}
	}
	used := []planted{
		{"internal/a/a.go", "import \"reflect\"\nimport \"os\"\nvar _ = reflect.String\nvar _ = os.Getenv\n//go:linkname x y\nfunc raw() int"},
		{"shared/gen/x/v1/g.go", "import \"unsafe\"\nvar _ unsafe.Pointer"},
	}
	cases := []struct {
		name   string
		mutate func(p *escapePolicy)
		files  []planted
		want   string // a fragment of the problem, or "" for none
	}{
		{"every entry used", func(p *escapePolicy) {}, used, ""},
		{"a listed directory that no longer imports the tool", func(p *escapePolicy) {},
			[]planted{{"internal/a/a.go", "import \"os\"\nvar _ = os.Getenv\n//go:linkname x y\nfunc raw() int"}, used[1]}, "which does not import it"},
		{"an entry for a directory that does not exist", func(p *escapePolicy) { p.std["reflect"]["internal/ghost"] = "why" }, used, "internal/ghost, which has no non-test Go source"},
		{"a glob for the generated packages", func(p *escapePolicy) { p.std["unsafe"]["shared/gen/**"] = "why" }, used, "shared/gen/**, which has no non-test Go source"},
		{"a directory that only a test file imports from", func(p *escapePolicy) {},
			[]planted{{"internal/a/a.go", "import \"os\"\nvar _ = os.Getenv\n//go:linkname x y\nfunc raw() int"}, {"internal/a/a_test.go", "import \"reflect\"\nvar _ = reflect.String"}, used[1]}, "which does not import it"},
		{"a member that no file uses", func(p *escapePolicy) { p.members["os"]["internal/a"] = []string{"Getenv", "Exit"} }, used, "os.Exit for internal/a, which does not use it"},
		{"a member list of a directory that does not exist", func(p *escapePolicy) { p.members["os"]["internal/ghost"] = []string{"Exit"} }, used, "internal/ghost, which has no non-test Go source"},
		{"a directive that nobody carries", func(p *escapePolicy) { p.directives["norace"] = map[string]string{"internal/a": "why"} }, used, "directiveDirs lists norace for internal/a"},
		{"a directive entry of a directory that does not exist", func(p *escapePolicy) { p.directives["linkname"]["internal/ghost"] = "why" }, used, "internal/ghost, which has no non-test Go source"},
		{"a body-less entry that nobody uses", func(p *escapePolicy) { p.bodyless["shared/gen/x/v1"] = "why" }, used, "bodylessDirs lists shared/gen/x/v1"},
		{"a safe package that nobody imports", func(p *escapePolicy) { p.safeStd["archive/zip"] = "why" }, used, "moduleStdSafe lists archive/zip"},
		{"a member of an any-directory package that nobody uses", func(p *escapePolicy) {
			p.anyDir = map[string][]string{"net/http": {"StatusOK", "StatusTeapot"}}
		}, append(append([]planted{}, used...), planted{"internal/b/b.go", "import \"net/http\"\nvar _ = http.StatusOK"}), "anyDirMembers lists net/http.StatusTeapot"},
		{"an exclusive open for a directory listed to open existing files", func(p *escapePolicy) { p.openExisting = map[string]string{"internal/b": "why"} },
			append(append([]planted{}, used...), planted{"internal/b/b.go", "import \"os\"\nfunc f() { os.OpenFile(\"x\", os.O_CREATE|os.O_EXCL, 0) }"}), "openExistingDirs lists internal/b"},
		{"an open-existing entry of a directory that does not exist", func(p *escapePolicy) { p.openExisting = map[string]string{"internal/ghost": "why"} }, used, "internal/ghost, which has no non-test Go source"},
		{"a shared library entry that nobody imports", func(p *escapePolicy) {
			p.sharedThird = map[string]map[string]string{"golang.org/x/net/idna": {"shared/gen/x/v1": "why"}}
		}, used, "sharedThirdParty lists golang.org/x/net/idna for shared/gen/x/v1, which does not import it"},
		{"a shared library entry of a directory that does not exist", func(p *escapePolicy) {
			p.sharedThird = map[string]map[string]string{"golang.org/x/net/idna": {"shared/ghost": "why"}}
		}, used, "shared/ghost, which has no non-test Go source"},
		{"a test-only package whose directory does not exist", func(p *escapePolicy) { p.testOnly = map[string]string{"example.com/x": "shared/ghost"} }, used, "testOnlyImports[example.com/x] lists shared/ghost"},
		{"a go:generate entry that nobody carries", func(p *escapePolicy) { p.directives["generate"] = map[string]string{"internal/a": "why"} }, used, "directiveDirs lists generate for internal/a"},
	}
	for _, c := range cases {
		pol := minimal()
		c.mutate(&pol)
		fset := token.NewFileSet()
		fs := parsePlanted(t, fset, c.files)
		got := capabilityProblems(fset, fs, pol, true)
		switch {
		case c.want == "" && len(got) != 0:
			t.Errorf("%s: unexpected problems %v", c.name, got)
		case c.want != "":
			found := false
			for _, g := range got {
				found = found || strings.Contains(g, c.want)
			}
			if !found {
				t.Errorf("%s: no problem with %q in %v", c.name, c.want, got)
			}
		}
	}
}

// TestBuildFileListingCanFail feeds the reader of go list a record for each foreign field, a
// field it does not know, a package that did not load and a clean package, so a row dropped from the
// table is seen (it would let that kind of file through).
func TestBuildFileListingCanFail(t *testing.T) {
	root := filepath.Join(os.TempDir(), "r")
	dir := filepath.ToSlash(filepath.Join(root, "internal", "x"))
	one := func(extra string) string {
		return `{"Dir":"` + dir + `","ImportPath":"x"` + extra + `}`
	}
	run := func(listing string) []string {
		return foreignFromList(root, []byte(listing), escapePolicy{nonGo: map[string]string{}}, &foreignSeen{dirs: map[string]bool{}, used: map[string]bool{}})
	}
	for field, class := range goListFields {
		if class != listForeign {
			continue
		}
		value := `["a.file"]`
		if field == "BinaryOnly" {
			value = `true`
		}
		if got := run(one(`,"` + field + `":` + value)); len(got) != 1 {
			t.Errorf("a record with %s was reported %d times: %v", field, len(got), got)
		}
	}
	for field, class := range goListFields {
		if class == listForeign || field == "Error" || field == "Dir" || field == "ImportPath" {
			continue
		}
		if got := run(one(`,"` + field + `":[]`)); len(got) != 0 {
			t.Errorf("an empty %s was reported: %v", field, got)
		}
	}
	if got := run(one(`,"RustFiles":["a.rs"]`)); len(got) != 1 || !strings.Contains(got[0], "RustFiles") {
		t.Errorf("a field go list adds later: %v", got)
	}
	if got := run(one(`,"Error":{"Err":"build constraints exclude all Go files"}`)); len(got) != 1 {
		t.Errorf("a package that did not load: %v", got)
	}
	if got := run(one(`,"GoFiles":["a.go"],"TestGoFiles":["a_test.go"],"EmbedFiles":["a.txt"],"Imports":["fmt"],"Error":null`)); len(got) != 0 {
		t.Errorf("a clean package has problems: %v", got)
	}
	// Two records in one stream, one clean and one not.
	if got := run(one(`,"GoFiles":["a.go"]`) + "\n" + one(`,"SFiles":["a.s"]`)); len(got) != 1 {
		t.Errorf("a stream of two records: %v", got)
	}
}

// TestBuildFileCheckSeesEveryFileTheToolchainBuildsIn runs the real go list over a scratch tree that holds a Panel
// module and a nested shared module, with one package for each kind of file besides Go source (and
// one for a platform this host does not build), so the request made of go list is shown to name them
// (a field dropped from it would let that kind through), a module go list does not enter on its own
// is shown to be asked, and a package of Go files alone is clean. A listed directory is let through,
// a listed directory with no such file is stale and one that is no package is reported.
func TestBuildFileCheckSeesEveryFileTheToolchainBuildsIn(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("no go tool on PATH")
	}
	root := t.TempDir()
	write := func(rel, body string) {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod", "module "+module+"\n\ngo 1.22\n")
	write("shared/go.mod", "module "+sharedModule+"\n\ngo 1.22\n")
	// kind of file by directory, in the Panel and in shared/.
	kinds := map[string]string{
		"asm": "a.s", "cfile": "a.c", "cxx": "a.cc", "objc": "a.m", "hdr": "a.h", "fortran": "a.f",
		"obj": "a.syso", "swig": "a.swig", "swigcxx": "a.swigcxx", "allowed": "a.s",
	}
	var wantReported []string
	for _, prefix := range []string{"internal/", "shared/"} {
		for d, f := range kinds {
			write(prefix+d+"/a.go", "package "+d+"\n")
			write(prefix+d+"/"+f, "x\n")
			if d != "allowed" {
				wantReported = append(wantReported, prefix+d+": go list reports")
			}
		}
		write(prefix+"clean/a.go", "package clean\n")
		write(prefix+"cgo/a.go", "package cgo\n\n// int f(void) { return 0; }\nimport \"C\"\n")
		wantReported = append(wantReported, prefix+"cgo: go list reports CgoFiles")
		// A file another platform builds: constrained out here, whatever the host is.
		write(prefix+"other/a.go", "package other\n")
		write(prefix+"other/b.s", "//go:build ignore\n")
		wantReported = append(wantReported, prefix+"other: go list reports IgnoredOtherFiles")
	}
	pol := realPolicy()
	pol.nonGo = map[string]string{
		"internal/allowed": "why", "shared/allowed": "why",
		"internal/clean": "stale: holds only Go source", "internal/ghost": "no such package",
	}
	got := foreignProblems(root, pol, true)
	all := strings.Join(got, "\n")
	for _, w := range wantReported {
		if !strings.Contains(all, w) {
			t.Errorf("no problem for %q in:\n%s", w, all)
		}
	}
	for _, g := range got {
		if strings.HasPrefix(g, "internal/clean: go list") || strings.HasPrefix(g, "shared/clean: go list") || strings.Contains(g, "allowed: go list") {
			t.Errorf("a package that is clean or listed was reported: %s", g)
		}
	}
	for _, w := range []string{"nonGoSourceDirs lists internal/clean, which holds no file besides Go source", "nonGoSourceDirs lists internal/ghost, which is no package"} {
		if !strings.Contains(all, w) {
			t.Errorf("no problem for %q in:\n%s", w, all)
		}
	}
}

// The scoped list of the gateway packages is stricter than the module-wide one, and a member the
// first allows must be allowed by the second too, or one of the two lists is stale.
func TestScopedOSMembersAreMembersOfTheModuleList(t *testing.T) {
	for dir, ms := range smsOSMembers {
		for _, m := range ms {
			found := false
			for _, x := range osMembers[dir] {
				found = found || x == m
			}
			if !found {
				t.Errorf("smsOSMembers allows os.%s for %s and osMembers does not", m, dir)
			}
		}
	}
}

// TestGodebugCanFail plants the ways to change a runtime default with no Go source and no //go:debug
// directive (sms-r18-7, sms-r18-13): a godebug line of go.mod, in every spelling go mod edit reads (a
// single line and a block), and a value that reaches a main package through a lowered go line or
// anything else, which godebugProblems finds by comparing what go list reports with what the toolchain
// gives a clean module. A clean module and a package with no value (a library has none) are not reported.
func TestGodebugCanFail(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("no go tool on PATH")
	}
	root := plantTree(t, map[string]string{
		"go.mod":          "module " + module + "\n\ngo 1.24\n\ngodebug panicnil=1\n",
		"a/go.mod":        "module example.com/a\n\ngo 1.24\n\ngodebug (\n\tx509sha1=1\n\ttlsrsakex=1\n)\n",
		"clean/go.mod":    "module example.com/clean\n\ngo 1.24\n",
		"internal/x/x.go": "package x\n",
		"a/a.go":          "package a\n",
		"clean/c.go":      "package c\n",
	})
	mods, err := goModDirs(root)
	if err != nil {
		t.Fatal(err)
	}
	all := filepath.ToSlash(strings.Join(moduleRootProblems(root, mods), "\n"))
	for _, w := range []string{"godebug panicnil=1", "godebug x509sha1=1", "godebug tlsrsakex=1"} {
		if !strings.Contains(all, w) {
			t.Errorf("no problem for %q in:\n%s", w, all)
		}
	}
	if strings.Contains(all, "clean:") {
		t.Errorf("a module with no godebug line was reported:\n%s", all)
	}

	// The value that reaches the binary.
	if got := godebugProblems("cmd/x", "panicnil=1", "x509sha1=0"); len(got) != 1 {
		t.Errorf("a changed default passed: %v", got)
	}
	if got := godebugProblems("cmd/x", "x509sha1=0", "x509sha1=0"); len(got) != 0 {
		t.Errorf("the toolchain's own default was reported: %v", got)
	}
	if got := godebugProblems("internal/lib", "", "x509sha1=0"); len(got) != 0 {
		t.Errorf("a package with no default (not a main package) was reported: %v", got)
	}
	if got := godebugProblems("cmd/x", "panicnil=1", ""); len(got) != 1 {
		t.Errorf("a changed default against the clean value (empty: every default is the current one) passed: %v", got)
	}
	if got := godebugProblems("cmd/x", "", ""); len(got) != 0 {
		t.Errorf("the clean value was reported: %v", got)
	}
	// Through the reader of go list: a record carrying the field, judged against the value the run holds.
	rootDir := filepath.Join(os.TempDir(), "r")
	dir := filepath.ToSlash(filepath.Join(rootDir, "cmd", "x"))
	rec := `{"Dir":"` + dir + `","ImportPath":"x","Name":"main","DefaultGODEBUG":"panicnil=1"}`
	judge := func(want string) []string {
		return foreignFromList(rootDir, []byte(rec), escapePolicy{nonGo: map[string]string{}}, &foreignSeen{dirs: map[string]bool{}, used: map[string]bool{}, judgeGodebug: true, wantGodebug: want})
	}
	if got := judge("x509sha1=0"); len(got) != 1 || !strings.Contains(got[0], "cmd/x") {
		t.Errorf("a main package whose default differs: %v", got)
	}
	if got := judge("panicnil=1"); len(got) != 0 {
		t.Errorf("a main package with the expected default: %v", got)
	}
	// The expected value is the toolchain's own, read from go list, and a clean module has it.
	want, err := pinnedDefaultGODEBUG(root)
	if err != nil {
		t.Fatal(err)
	}
	if want != "" {
		t.Errorf("a main package of a module on the toolchain's own go line has non-default settings %q; the pinned value would be what is judged", want)
	}
	// A lowered go line brings back the older defaults of the standard library, and go list says so: the
	// comparison can fail for it, which is what makes an empty answer above mean something.
	old, err := scratchDefaultGODEBUG(root, "1.20")
	if err != nil {
		t.Fatal(err)
	}
	if old == want || old == "" {
		t.Errorf("a scratch module on go 1.20 reported %q, the same as the clean value %q: the comparison could not see a lowered go line", old, want)
	}
	if got := godebugProblems("cmd/x", old, want); len(got) != 1 {
		t.Errorf("a lowered go line passed: %v", got)
	}
}

// TestGodebugIsJudgedOverTheTree runs the whole question over a planted module whose go line is lowered
// (so its main package reports older defaults of the standard library) and over one on the toolchain's own
// line: the first is one finding that names the package, the second is clean. It is the run over the tree
// with the comparison switched on, which the real run does and the other planted trees do not.
func TestGodebugIsJudgedOverTheTree(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("no go tool on PATH")
	}
	pol := escapePolicy{nonGo: map[string]string{}}
	old := plantTree(t, map[string]string{
		"go.mod":          "module " + module + "\n\ngo 1.20\n",
		"cmd/x/main.go":   "package main\n\nfunc main() {}\n",
		"internal/a/a.go": "package a\n",
	})
	got := strings.Join(foreignProblems(old, pol, true), "\n")
	if !strings.Contains(filepath.ToSlash(got), "cmd/x: the default GODEBUG of this main package") {
		t.Errorf("a main package on a lowered go line was not reported:\n%s", got)
	}
	if strings.Contains(filepath.ToSlash(got), "internal/a:") {
		t.Errorf("a library was reported:\n%s", got)
	}
	version, err := scratchGoVersion(old)
	if err != nil {
		t.Fatal(err)
	}
	clean := plantTree(t, map[string]string{
		"go.mod":        "module " + module + "\n\ngo " + version + "\n",
		"cmd/x/main.go": "package main\n\nfunc main() {}\n",
	})
	if got := foreignProblems(clean, pol, true); len(got) != 0 {
		t.Errorf("a module on the toolchain's own go line has problems: %v", got)
	}
}

// scratchGoVersion is the version of the go command in use, without the "go" prefix.
func scratchGoVersion(root string) (string, error) {
	b, err := toolcmd.Go(context.Background(), []string{"GOWORK=off", "GOFLAGS="}, "env", "GOVERSION").InDir(root).Output()
	if err != nil {
		return "", err
	}
	return strings.TrimPrefix(strings.TrimSpace(string(b)), "go"), nil
}

// The pass over the directories asked for by name judges what the main pass judges (sms-r18-21).
func TestTheQuietPassCarriesTheRunsJudgement(t *testing.T) {
	main := &foreignSeen{dirs: map[string]bool{}, used: map[string]bool{}, judgeGodebug: true, wantGodebug: "x509sha1=0"}
	q := main.askedByName()
	if !q.judgeGodebug || q.wantGodebug != "x509sha1=0" || !q.skipLoadError {
		t.Errorf("the quiet pass lost the judgement or does not skip load errors: %+v", q)
	}
	q.dirs["d"], q.used["u"] = true, true
	if !main.dirs["d"] || !main.used["u"] {
		t.Errorf("the quiet pass does not share the run's maps")
	}
	if main.skipLoadError {
		t.Errorf("the quiet pass changed the main pass")
	}
}
