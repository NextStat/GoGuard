package fixtures

import (
	"fmt"
	"os"
)

// SafeErrorHandling — correctly handles all errors.
func SafeErrorHandling() error {
	f, err := os.Open("/tmp/test")
	if err != nil {
		return fmt.Errorf("failed to open: %w", err)
	}
	defer f.Close()
	return nil
}

// AllowedIgnore — fmt.Println error can be ignored per default config.
func AllowedIgnore() {
	fmt.Println("this is fine") // no diagnostic — fmt.Println is in ignore list
}
