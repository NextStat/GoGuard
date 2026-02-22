package fixtures

import (
	"fmt"
	"os"
)

// IgnoredError demonstrates ignoring an error return value.
func IgnoredError() {
	os.Remove("/tmp/test") // ERR001: error return value ignored
	fmt.Println("done")
}

// ErrorAssignedToBlank demonstrates assigning error to _.
func ErrorAssignedToBlank() {
	_, _ = os.Open("/tmp/test") // ERR002: error assigned to blank identifier
}
