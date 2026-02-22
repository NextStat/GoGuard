package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// buildBridge compiles the goguard-go-bridge binary into the given directory
// and returns the path to the built binary.
func buildBridge(t *testing.T, outputDir string) string {
	t.Helper()
	binPath := filepath.Join(outputDir, "goguard-go-bridge")
	bridgeDir := findBridgeSourceDir(t)

	cmd := exec.Command("go", "build", "-o", binPath, ".")
	cmd.Dir = bridgeDir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go build failed: %v\n%s", err, out)
	}
	return binPath
}

// findBridgeSourceDir returns the absolute path to the goguard-go-bridge source directory.
func findBridgeSourceDir(t *testing.T) string {
	t.Helper()
	// We're running inside goguard-go-bridge, so "." relative to the test is the source dir.
	// Use the go test working directory (which is the package directory).
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	return wd
}

// createMinimalGoProject writes a go.mod and main.go into dir.
func createMinimalGoProject(t *testing.T, dir string) {
	t.Helper()
	goMod := []byte("module testproject\n\ngo 1.21\n")
	mainGo := []byte("package main\n\nimport \"fmt\"\n\nfunc main() {\n\tfmt.Println(\"hello\")\n}\n")

	if err := os.WriteFile(filepath.Join(dir, "go.mod"), goMod, 0644); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "main.go"), mainGo, 0644); err != nil {
		t.Fatalf("write main.go: %v", err)
	}
}

// TestCLI_CacheFlag builds the bridge binary, runs it with --cache-dir on a
// minimal Go project, and verifies:
//   - exit code 0
//   - stdout contains at least 8 bytes (4-byte LE length prefix + payload)
//   - cache dir contains at least one .fb and one .meta.json file
//   - stderr contains "cache miss" (first run)
func TestCLI_CacheFlag(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	binDir := t.TempDir()
	binPath := buildBridge(t, binDir)

	projectDir := t.TempDir()
	createMinimalGoProject(t, projectDir)

	cacheDir := t.TempDir()

	cmd := exec.Command(binPath, "analyze", "--packages", "./...", "--cache-dir", cacheDir)
	cmd.Dir = projectDir

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		t.Fatalf("analyze command failed: %v\nstderr: %s", err, stderr.String())
	}

	// Verify stdout has at least 8 bytes (4-byte length prefix + some payload)
	if stdout.Len() < 8 {
		t.Errorf("expected stdout >= 8 bytes, got %d bytes", stdout.Len())
	}

	// Verify the length prefix is consistent with the actual payload
	stdoutBytes := stdout.Bytes()
	if len(stdoutBytes) >= 4 {
		payloadLen := uint32(stdoutBytes[0]) |
			uint32(stdoutBytes[1])<<8 |
			uint32(stdoutBytes[2])<<16 |
			uint32(stdoutBytes[3])<<24
		expectedTotal := 4 + int(payloadLen)
		if len(stdoutBytes) != expectedTotal {
			t.Errorf("length prefix says %d bytes payload, but total stdout is %d bytes (expected %d)",
				payloadLen, len(stdoutBytes), expectedTotal)
		}
	}

	// Verify cache dir contains at least one .fb file and one .meta.json file
	entries, err := os.ReadDir(cacheDir)
	if err != nil {
		t.Fatalf("read cache dir: %v", err)
	}

	var hasFB, hasMeta bool
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".fb") {
			hasFB = true
		}
		if strings.HasSuffix(e.Name(), ".meta.json") {
			hasMeta = true
		}
	}
	if !hasFB {
		t.Error("cache dir should contain at least one .fb file")
	}
	if !hasMeta {
		t.Error("cache dir should contain at least one .meta.json file")
	}

	// Verify stderr contains "cache miss" (first run)
	stderrStr := stderr.String()
	if !strings.Contains(stderrStr, "cache miss") {
		t.Errorf("expected stderr to contain 'cache miss', got: %q", stderrStr)
	}
}

// TestCLI_CacheSecondRun verifies that running the analyze command twice with
// the same --cache-dir produces:
//   - a "cache hit" message on the second run's stderr
//   - identical stdout output (same FlatBuffers payload) on both runs
func TestCLI_CacheSecondRun(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	binDir := t.TempDir()
	binPath := buildBridge(t, binDir)

	projectDir := t.TempDir()
	createMinimalGoProject(t, projectDir)

	cacheDir := t.TempDir()

	// --- First run ---
	cmd1 := exec.Command(binPath, "analyze", "--packages", "./...", "--cache-dir", cacheDir)
	cmd1.Dir = projectDir
	var stdout1, stderr1 bytes.Buffer
	cmd1.Stdout = &stdout1
	cmd1.Stderr = &stderr1

	if err := cmd1.Run(); err != nil {
		t.Fatalf("first run failed: %v\nstderr: %s", err, stderr1.String())
	}

	// Sanity: first run should be a cache miss
	if !strings.Contains(stderr1.String(), "cache miss") {
		t.Errorf("first run should report 'cache miss', got stderr: %q", stderr1.String())
	}

	// --- Second run ---
	cmd2 := exec.Command(binPath, "analyze", "--packages", "./...", "--cache-dir", cacheDir)
	cmd2.Dir = projectDir
	var stdout2, stderr2 bytes.Buffer
	cmd2.Stdout = &stdout2
	cmd2.Stderr = &stderr2

	if err := cmd2.Run(); err != nil {
		t.Fatalf("second run failed: %v\nstderr: %s", err, stderr2.String())
	}

	// Verify second run reports cache hit
	if !strings.Contains(stderr2.String(), "cache hit") {
		t.Errorf("second run should report 'cache hit', got stderr: %q", stderr2.String())
	}

	// Verify both runs produce identical stdout output
	if !bytes.Equal(stdout1.Bytes(), stdout2.Bytes()) {
		t.Errorf("stdout differs between runs: first=%d bytes, second=%d bytes",
			stdout1.Len(), stdout2.Len())
	}
}
