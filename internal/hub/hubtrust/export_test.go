package hubtrust

// GroupOf lets the external tests read a file's group without importing syscall, which the capability lint keeps out of test
// files.
var GroupOf = groupOf
