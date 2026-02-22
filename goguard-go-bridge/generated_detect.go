package main

import (
	"bufio"
	"os"
	"strings"
)

// IsGeneratedFile checks if a Go file is generated code.
// It looks for the standard "Code generated" comment pattern
// as specified in https://go.dev/s/generatedcode
func IsGeneratedFile(path string) bool {
	// Fast path: check file name patterns
	if strings.HasSuffix(path, ".pb.go") ||
		strings.HasSuffix(path, ".gen.go") ||
		strings.HasSuffix(path, "_generated.go") ||
		strings.HasSuffix(path, "_string.go") ||
		strings.HasSuffix(path, ".mock.go") ||
		strings.HasSuffix(path, "_mock.go") ||
		strings.HasSuffix(path, ".deepcopy.go") {
		return true
	}

	// Scan file for generated code marker
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		// Standard Go generated code pattern:
		// ^// Code generated .* DO NOT EDIT\.$
		if strings.HasPrefix(line, "// Code generated") &&
			strings.HasSuffix(line, "DO NOT EDIT.") {
			return true
		}
		// Stop scanning after package declaration (generated comment must be before it)
		if strings.HasPrefix(line, "package ") {
			break
		}
	}
	return false
}
