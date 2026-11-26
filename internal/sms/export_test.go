package sms

// UncheckedError is a struct literal that bypasses NewError, for the tests that show a value built that
// way still cannot put text in the params of an alert or in a status. The class is unexported
// (sms-r17-8), so a test of another package cannot build one by hand; this is the one way, and a _test.go
// file is not part of the package production code imports.
func UncheckedError(provider ProviderName, class Class, code Code) *Error {
	return &Error{Provider: provider, class: class, Code: code}
}
