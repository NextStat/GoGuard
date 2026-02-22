package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestGenerateFixtures reads each .go fixture file from tests/fixtures/{category}/,
// compiles it to SSA IR via Compile(), serializes to FlatBuffers via
// BuildFlatBuffers(), and writes the binary to tests/bridge_fixtures/{category}/{name}.fb.
//
// Each fixture file is self-contained (defines its own types) so we compile
// them individually to produce separate .fb files for targeted Rust tests.
//
// Run with:
//
//	go test -run TestGenerateFixtures -v -count=1
func TestGenerateFixtures(t *testing.T) {
	categories := []string{"nil", "errcheck", "taint"}
	for _, category := range categories {
		t.Run(category, func(t *testing.T) {
			fixtureDir, err := filepath.Abs("../tests/fixtures/" + category)
			if err != nil {
				t.Fatalf("abs fixture dir: %v", err)
			}
			outputDir, err := filepath.Abs("../tests/bridge_fixtures/" + category)
			if err != nil {
				t.Fatalf("abs output dir: %v", err)
			}

			if err := os.MkdirAll(outputDir, 0o755); err != nil {
				t.Fatalf("mkdir output dir: %v", err)
			}

			entries, err := os.ReadDir(fixtureDir)
			if err != nil {
				t.Fatalf("read fixture dir: %v", err)
			}

			var generated int
			for _, e := range entries {
				if e.IsDir() || filepath.Ext(e.Name()) != ".go" {
					continue
				}
				name := strings.TrimSuffix(e.Name(), ".go")
				t.Run(name, func(t *testing.T) {
					// Create a temporary directory with go.mod + the fixture file
					tmpDir := t.TempDir()

					goMod := "module fixtures\n\ngo 1.22\n"
					if err := os.WriteFile(filepath.Join(tmpDir, "go.mod"), []byte(goMod), 0o644); err != nil {
						t.Fatalf("write go.mod: %v", err)
					}

					// Copy the fixture source file
					src, err := os.ReadFile(filepath.Join(fixtureDir, e.Name()))
					if err != nil {
						t.Fatalf("read fixture %s: %v", e.Name(), err)
					}
					if err := os.WriteFile(filepath.Join(tmpDir, e.Name()), src, 0o644); err != nil {
						t.Fatalf("write fixture %s: %v", e.Name(), err)
					}

					// Compile to SSA IR
					result, err := Compile(tmpDir, []string{"./..."})
					if err != nil {
						t.Fatalf("compile %s: %v", name, err)
					}

					if len(result.Packages) == 0 {
						t.Fatalf("compile %s: no packages produced", name)
					}

					// Count total functions for sanity check
					totalFuncs := 0
					for _, pkg := range result.Packages {
						totalFuncs += len(pkg.Functions)
					}
					if totalFuncs == 0 {
						t.Fatalf("compile %s: no functions found", name)
					}

					// Serialize to FlatBuffers
					buf := BuildFlatBuffers(result)
					if len(buf) == 0 {
						t.Fatalf("serialize %s: FlatBuffers output is empty", name)
					}

					// Write the .fb binary file
					outPath := filepath.Join(outputDir, name+".fb")
					if err := os.WriteFile(outPath, buf, 0o644); err != nil {
						t.Fatalf("write %s: %v", outPath, err)
					}

					t.Logf("generated %s (%d bytes, %d functions)", outPath, len(buf), totalFuncs)
					generated++
				})
			}

			if generated == 0 {
				t.Fatalf("no fixture files were processed for category %s", category)
			}
		})
	}
}

// TestGenerateFixturesAllPresent verifies that all expected fixture files
// exist in the output directory. Run after TestGenerateFixtures.
func TestGenerateFixturesAllPresent(t *testing.T) {
	type categoryFixtures struct {
		category string
		expected []string
	}

	categories := []categoryFixtures{
		{
			category: "nil",
			expected: []string{
				"basic_nil_deref",
				"missing_return",
				"type_assertion",
				"nil_map",
				"error_ignored",
				"safe_patterns",
			},
		},
		{
			category: "errcheck",
			expected: []string{
				"ignored_error",
				"safe_error_handling",
			},
		},
		{
			category: "taint",
			expected: []string{
				"sql_injection",
				"command_injection",
				"path_traversal",
				"xss",
				"safe_sanitized",
				"interprocedural",
			},
		},
	}

	for _, cat := range categories {
		t.Run(cat.category, func(t *testing.T) {
			outputDir, err := filepath.Abs("../tests/bridge_fixtures/" + cat.category)
			if err != nil {
				t.Fatalf("abs output dir: %v", err)
			}

			for _, name := range cat.expected {
				path := filepath.Join(outputDir, name+".fb")
				info, err := os.Stat(path)
				if err != nil {
					t.Errorf("missing fixture %s: %v", name, err)
					continue
				}
				if info.Size() == 0 {
					t.Errorf("fixture %s is empty (0 bytes)", name)
				} else {
					t.Logf("fixture %s: %d bytes", name, info.Size())
				}
			}
		})
	}
}
