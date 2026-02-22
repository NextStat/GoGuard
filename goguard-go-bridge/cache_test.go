package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestComputeFingerprint_Deterministic verifies that computing the fingerprint
// twice on the same directory produces the same hash.
func TestComputeFingerprint_Deterministic(t *testing.T) {
	dir := t.TempDir()

	// Create a minimal Go project
	os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module test\ngo 1.21\n"), 0644)
	os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\nfunc main() {}\n"), 0644)
	os.MkdirAll(filepath.Join(dir, "pkg"), 0755)
	os.WriteFile(filepath.Join(dir, "pkg", "lib.go"), []byte("package pkg\nfunc Hello() {}\n"), 0644)

	patterns := []string{"./..."}

	fp1, err := ComputeFingerprint(dir, patterns)
	if err != nil {
		t.Fatalf("first ComputeFingerprint failed: %v", err)
	}

	fp2, err := ComputeFingerprint(dir, patterns)
	if err != nil {
		t.Fatalf("second ComputeFingerprint failed: %v", err)
	}

	if fp1 != fp2 {
		t.Errorf("fingerprints differ: %q vs %q", fp1, fp2)
	}

	// Sanity check: fingerprint should be a 64-char hex string (SHA-256)
	if len(fp1) != 64 {
		t.Errorf("expected 64-char hex fingerprint, got %d chars: %q", len(fp1), fp1)
	}
}

// TestComputeFingerprint_ChangesOnFileModify verifies that modifying a .go file
// produces a different fingerprint (due to changed mtime and/or size).
func TestComputeFingerprint_ChangesOnFileModify(t *testing.T) {
	dir := t.TempDir()

	goFile := filepath.Join(dir, "main.go")
	os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module test\ngo 1.21\n"), 0644)
	os.WriteFile(goFile, []byte("package main\nfunc main() {}\n"), 0644)

	patterns := []string{"./..."}

	fp1, err := ComputeFingerprint(dir, patterns)
	if err != nil {
		t.Fatalf("first ComputeFingerprint failed: %v", err)
	}

	// Modify the file content (changes size) and set a different mtime
	os.WriteFile(goFile, []byte("package main\nfunc main() { println(\"hello\") }\n"), 0644)
	// Ensure mtime is visibly different
	futureTime := time.Now().Add(10 * time.Second)
	os.Chtimes(goFile, futureTime, futureTime)

	fp2, err := ComputeFingerprint(dir, patterns)
	if err != nil {
		t.Fatalf("second ComputeFingerprint failed: %v", err)
	}

	if fp1 == fp2 {
		t.Error("fingerprint should change after file modification, but both are identical")
	}
}

// TestComputeFingerprint_IgnoresNonGoFiles verifies that adding a .txt file
// does not change the fingerprint.
func TestComputeFingerprint_IgnoresNonGoFiles(t *testing.T) {
	dir := t.TempDir()

	os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module test\ngo 1.21\n"), 0644)
	os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\nfunc main() {}\n"), 0644)

	patterns := []string{"./..."}

	fp1, err := ComputeFingerprint(dir, patterns)
	if err != nil {
		t.Fatalf("first ComputeFingerprint failed: %v", err)
	}

	// Add a non-Go file
	os.WriteFile(filepath.Join(dir, "README.txt"), []byte("this is a readme"), 0644)
	os.WriteFile(filepath.Join(dir, "notes.md"), []byte("# Notes"), 0644)
	os.WriteFile(filepath.Join(dir, "data.json"), []byte("{}"), 0644)

	fp2, err := ComputeFingerprint(dir, patterns)
	if err != nil {
		t.Fatalf("second ComputeFingerprint failed: %v", err)
	}

	if fp1 != fp2 {
		t.Errorf("fingerprint should not change after adding non-Go files: %q vs %q", fp1, fp2)
	}
}

// TestComputeFingerprint_SkipsVendor verifies that files inside vendor/
// are ignored when computing the fingerprint.
func TestComputeFingerprint_SkipsVendor(t *testing.T) {
	dir := t.TempDir()

	os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module test\ngo 1.21\n"), 0644)
	os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\nfunc main() {}\n"), 0644)

	patterns := []string{"./..."}

	fp1, err := ComputeFingerprint(dir, patterns)
	if err != nil {
		t.Fatalf("first ComputeFingerprint failed: %v", err)
	}

	// Add files in directories that should be skipped
	for _, skipDir := range []string{"vendor", ".git", "testdata", "node_modules"} {
		skipped := filepath.Join(dir, skipDir)
		os.MkdirAll(skipped, 0755)
		os.WriteFile(filepath.Join(skipped, "dep.go"), []byte("package dep\nfunc Dep() {}\n"), 0644)
		os.WriteFile(filepath.Join(skipped, "go.mod"), []byte("module dep\ngo 1.21\n"), 0644)
	}

	fp2, err := ComputeFingerprint(dir, patterns)
	if err != nil {
		t.Fatalf("second ComputeFingerprint failed: %v", err)
	}

	if fp1 != fp2 {
		t.Errorf("fingerprint should not change after adding files in vendor/.git/testdata/node_modules: %q vs %q", fp1, fp2)
	}
}

// TestCachePutGet_RoundTrip verifies that Put followed by Get returns the same bytes.
func TestCachePutGet_RoundTrip(t *testing.T) {
	cacheDir := t.TempDir()
	cache := BridgeCache{
		Dir:        cacheDir,
		MaxEntries: 20,
	}

	fingerprint := "abc123def456abc123def456abc123def456abc123def456abc123def456abcd"
	payload := []byte{0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD}
	patterns := []string{"./..."}

	err := cache.Put(fingerprint, payload, patterns)
	if err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	got, ok := cache.Get(fingerprint)
	if !ok {
		t.Fatal("Get returned false after Put")
	}

	if len(got) != len(payload) {
		t.Fatalf("payload length mismatch: got %d, want %d", len(got), len(payload))
	}
	for i := range payload {
		if got[i] != payload[i] {
			t.Errorf("byte %d mismatch: got %x, want %x", i, got[i], payload[i])
		}
	}

	// Verify that a nonexistent fingerprint returns false
	_, ok = cache.Get("nonexistent0000000000000000000000000000000000000000000000000000")
	if ok {
		t.Error("Get should return false for nonexistent fingerprint")
	}
}

// TestCacheLRU_Eviction verifies that when MaxEntries is exceeded,
// the oldest entry (by CreatedAt) is evicted.
func TestCacheLRU_Eviction(t *testing.T) {
	cacheDir := t.TempDir()
	cache := BridgeCache{
		Dir:        cacheDir,
		MaxEntries: 2,
	}

	patterns := []string{"./..."}

	// Put 3 entries with staggered creation times
	fp1 := "aaaa000000000000000000000000000000000000000000000000000000000001"
	fp2 := "bbbb000000000000000000000000000000000000000000000000000000000002"
	fp3 := "cccc000000000000000000000000000000000000000000000000000000000003"

	if err := cache.Put(fp1, []byte("payload-1"), patterns); err != nil {
		t.Fatalf("Put fp1 failed: %v", err)
	}
	// Small delay so CreatedAt timestamps differ
	time.Sleep(10 * time.Millisecond)

	if err := cache.Put(fp2, []byte("payload-2"), patterns); err != nil {
		t.Fatalf("Put fp2 failed: %v", err)
	}
	time.Sleep(10 * time.Millisecond)

	// This third Put should trigger eviction of fp1 (oldest)
	if err := cache.Put(fp3, []byte("payload-3"), patterns); err != nil {
		t.Fatalf("Put fp3 failed: %v", err)
	}

	// fp1 should be evicted
	_, ok := cache.Get(fp1)
	if ok {
		t.Error("fp1 should have been evicted (oldest entry), but Get returned true")
	}

	// fp2 and fp3 should still exist
	got2, ok := cache.Get(fp2)
	if !ok {
		t.Error("fp2 should still exist after eviction")
	}
	if string(got2) != "payload-2" {
		t.Errorf("fp2 payload mismatch: got %q, want %q", string(got2), "payload-2")
	}

	got3, ok := cache.Get(fp3)
	if !ok {
		t.Error("fp3 should still exist after eviction")
	}
	if string(got3) != "payload-3" {
		t.Errorf("fp3 payload mismatch: got %q, want %q", string(got3), "payload-3")
	}
}
