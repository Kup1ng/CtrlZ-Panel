package hubtrust

// GroupOf lets the external tests read a file's group without importing syscall, which the capability lint keeps out of test
// files.
var GroupOf = groupOf

// SetChgrp replaces the call that hands the renewed key to a group. Only a process that may hand a file to any group can make the
// real call fail on purpose, so a test supplies the failure.
func (n *NTS) SetChgrp(f func(path string, uid, gid int) error) { n.chgrp = f }
