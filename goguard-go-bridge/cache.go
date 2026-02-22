package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

// BridgeCache provides package-level compilation caching for incremental bridge calls.
// When --cache-dir is specified, the bridge only recompiles changed packages.
// This is additive to Rust's Salsa caching -- two layers of incrementality.
type BridgeCache struct {
	Dir        string // e.g., ~/.cache/goguard/bridge-cache
	MaxEntries int    // LRU eviction threshold (default 20)
}

// CacheMeta stores metadata about a cached compilation result.
type CacheMeta struct {
	Fingerprint string    `json:"fingerprint"`
	CreatedAt   time.Time `json:"created_at"`
	GoVersion   string    `json:"go_version"`
	BridgeVer   string    `json:"bridge_version"`
	Patterns    []string  `json:"patterns"`
	PayloadSize int64     `json:"payload_size"`
}

// skipDirs contains directory names that are skipped during fingerprint computation.
var skipDirs = map[string]bool{
	"vendor":       true,
	".git":         true,
	"testdata":     true,
	"node_modules": true,
}

// fileEntry represents a single file's metadata for fingerprint hashing.
type fileEntry struct {
	RelPath  string
	MtimeNs  int64
	SizeBytes int64
}

// ComputeFingerprint walks dir recursively, collecting all .go, go.mod, and go.sum
// files (skipping vendor/, .git/, testdata/, node_modules/). For each file it records
// (relative_path, mtime_unix_ns, size_bytes). The sorted entries, along with the
// sorted patterns, Go version, and BridgeVersion, are SHA-256 hashed to produce a
// deterministic hex fingerprint.
func ComputeFingerprint(dir string, patterns []string) (string, error) {
	var entries []fileEntry

	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}

		// Skip excluded directories
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}

		// Check if this is a relevant file
		name := d.Name()
		ext := filepath.Ext(name)

		// go.mod and go.sum don't have .mod/.sum extensions via filepath.Ext,
		// they are "go.mod" and "go.sum" — handle them explicitly.
		isRelevant := false
		if ext == ".go" {
			isRelevant = true
		} else if name == "go.mod" || name == "go.sum" {
			isRelevant = true
		}

		if !isRelevant {
			return nil
		}

		info, err := d.Info()
		if err != nil {
			return err
		}

		relPath, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		// Normalize to forward slashes for cross-platform determinism
		relPath = filepath.ToSlash(relPath)

		entries = append(entries, fileEntry{
			RelPath:   relPath,
			MtimeNs:   info.ModTime().UnixNano(),
			SizeBytes: info.Size(),
		})

		return nil
	})
	if err != nil {
		return "", fmt.Errorf("walking directory %s: %w", dir, err)
	}

	// Sort entries by relative path for deterministic ordering
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].RelPath < entries[j].RelPath
	})

	// Build the hash input
	h := sha256.New()

	// Write file entries
	for _, e := range entries {
		fmt.Fprintf(h, "%s\t%d\t%d\n", e.RelPath, e.MtimeNs, e.SizeBytes)
	}

	// Write sorted patterns
	sortedPatterns := make([]string, len(patterns))
	copy(sortedPatterns, patterns)
	sort.Strings(sortedPatterns)
	for _, p := range sortedPatterns {
		fmt.Fprintf(h, "pattern:%s\n", p)
	}

	// Write Go version and bridge version
	fmt.Fprintf(h, "go:%s\n", runtime.Version())
	fmt.Fprintf(h, "bridge:%s\n", BridgeVersion)

	return hex.EncodeToString(h.Sum(nil)), nil
}

// payloadPath returns the path to the cached FlatBuffers payload file.
func (c *BridgeCache) payloadPath(fingerprint string) string {
	return filepath.Join(c.Dir, fingerprint+".fb")
}

// metaPath returns the path to the cached metadata JSON file.
func (c *BridgeCache) metaPath(fingerprint string) string {
	return filepath.Join(c.Dir, fingerprint+".meta.json")
}

// Get retrieves a cached payload by fingerprint. It returns the payload bytes and
// true if the cache entry exists and its BridgeVer matches the current BridgeVersion.
// Otherwise it returns nil, false.
func (c *BridgeCache) Get(fingerprint string) ([]byte, bool) {
	metaFile := c.metaPath(fingerprint)
	payloadFile := c.payloadPath(fingerprint)

	// Read and validate metadata
	metaData, err := os.ReadFile(metaFile)
	if err != nil {
		return nil, false
	}

	var meta CacheMeta
	if err := json.Unmarshal(metaData, &meta); err != nil {
		return nil, false
	}

	// Reject if bridge version doesn't match
	if meta.BridgeVer != BridgeVersion {
		return nil, false
	}

	// Read payload
	payload, err := os.ReadFile(payloadFile)
	if err != nil {
		return nil, false
	}

	return payload, true
}

// Put writes a cache entry with the given fingerprint, payload, and patterns.
// It uses atomic writes (write to temp file, then rename) and runs LRU eviction
// if the entry count exceeds MaxEntries.
func (c *BridgeCache) Put(fingerprint string, payload []byte, patterns []string) error {
	// Ensure cache directory exists
	if err := os.MkdirAll(c.Dir, 0755); err != nil {
		return fmt.Errorf("creating cache dir: %w", err)
	}

	meta := CacheMeta{
		Fingerprint: fingerprint,
		CreatedAt:   time.Now(),
		GoVersion:   runtime.Version(),
		BridgeVer:   BridgeVersion,
		Patterns:    patterns,
		PayloadSize: int64(len(payload)),
	}

	metaJSON, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling meta: %w", err)
	}

	// Atomic write: payload
	payloadFile := c.payloadPath(fingerprint)
	if err := atomicWrite(payloadFile, payload); err != nil {
		return fmt.Errorf("writing payload: %w", err)
	}

	// Atomic write: metadata
	metaFile := c.metaPath(fingerprint)
	if err := atomicWrite(metaFile, metaJSON); err != nil {
		// Clean up payload if meta write fails
		os.Remove(payloadFile)
		return fmt.Errorf("writing meta: %w", err)
	}

	// Run LRU eviction
	if err := c.evict(); err != nil {
		// Eviction failure is non-fatal -- log but don't fail the Put
		fmt.Fprintf(os.Stderr, "goguard-bridge: cache eviction warning: %v\n", err)
	}

	return nil
}

// atomicWrite writes data to path using a temp file + rename for atomicity.
func atomicWrite(path string, data []byte) error {
	tmpPath := path + ".tmp"

	f, err := os.Create(tmpPath)
	if err != nil {
		return err
	}

	_, writeErr := f.Write(data)
	closeErr := f.Close()

	if writeErr != nil {
		os.Remove(tmpPath)
		return writeErr
	}
	if closeErr != nil {
		os.Remove(tmpPath)
		return closeErr
	}

	return os.Rename(tmpPath, path)
}

// evict removes the oldest cache entries (by CreatedAt) when the entry count
// exceeds MaxEntries. An "entry" is a pair of .fb + .meta.json files.
func (c *BridgeCache) evict() error {
	maxEntries := c.MaxEntries
	if maxEntries <= 0 {
		maxEntries = 20
	}

	// Read all .meta.json files
	dirEntries, err := os.ReadDir(c.Dir)
	if err != nil {
		return fmt.Errorf("reading cache dir: %w", err)
	}

	var metas []CacheMeta
	for _, de := range dirEntries {
		if de.IsDir() {
			continue
		}
		name := de.Name()
		if !strings.HasSuffix(name, ".meta.json") {
			continue
		}

		data, err := os.ReadFile(filepath.Join(c.Dir, name))
		if err != nil {
			continue
		}

		var meta CacheMeta
		if err := json.Unmarshal(data, &meta); err != nil {
			continue
		}
		metas = append(metas, meta)
	}

	if len(metas) <= maxEntries {
		return nil
	}

	// Sort by CreatedAt ascending (oldest first)
	sort.Slice(metas, func(i, j int) bool {
		return metas[i].CreatedAt.Before(metas[j].CreatedAt)
	})

	// Remove oldest entries until we're at the limit
	toRemove := len(metas) - maxEntries
	for i := 0; i < toRemove; i++ {
		fp := metas[i].Fingerprint
		os.Remove(c.payloadPath(fp))
		os.Remove(c.metaPath(fp))
	}

	return nil
}
