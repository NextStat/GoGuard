package fixtures

import "fmt"

// TypeAssertionWithoutOk demonstrates unchecked type assertion.
func TypeAssertionWithoutOk(val any) {
	// BUG: type assertion without ok check — panics if val is not string
	s := val.(string) // NIL002: use s, ok := val.(string) instead
	fmt.Println(s)
}

// TypeAssertionSafe is the correct pattern.
func TypeAssertionSafe(val any) {
	s, ok := val.(string)
	if !ok {
		return
	}
	fmt.Println(s)
}
