package lint_test

import "go/ast"

// A site is the unit a security allow list names (round 17, primitives-r17-10 and tenant-r17-9; round
// 18, primitives-r18-7 and -8): "file::Func" or "file::Type.Method", and "" for a package-level
// declaration that is not a function. A list keyed by file lets any other function of a listed file
// use the exception, and a reviewer reads one function and approves a file. Every list that excuses a
// call, a primitive or a lane keys by site and has a stale-entry check, so an entry whose function no
// longer does the thing (or was renamed) fails.

// enclosingSite is the site of the innermost function declaration in a stack of ancestors (a function
// literal belongs to the declaration that holds it), "" outside every function.
func enclosingSite(path string, stack []ast.Node) string {
	for i := len(stack) - 1; i >= 0; i-- {
		if fd, ok := stack[i].(*ast.FuncDecl); ok {
			return totpSite(path, fd)
		}
	}
	return ""
}

// walkSites calls fn for every node of the file with the site that holds it.
func walkSites(path string, f *ast.File, fn func(site string, n ast.Node)) {
	var stack []ast.Node
	ast.Inspect(f, func(n ast.Node) bool {
		if n == nil {
			stack = stack[:len(stack)-1]
			return true
		}
		fn(enclosingSite(path, stack), n)
		stack = append(stack, n)
		return true
	})
}
