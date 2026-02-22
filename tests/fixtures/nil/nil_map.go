package fixtures

import "fmt"

// NilMapAccess demonstrates reading from an uninitialized map.
func NilMapAccess() {
	var m map[string]int
	// BUG: reading from nil map is fine (returns zero), but writing panics
	// However, this pattern often indicates a bug
	val := m["key"] // NIL004: reading from nil map
	fmt.Println(val)
}

// NilMapWrite demonstrates writing to an uninitialized map (always panics).
func NilMapWrite() {
	var m map[string]int
	m["key"] = 42 // NIL004: writing to nil map — runtime panic
}
