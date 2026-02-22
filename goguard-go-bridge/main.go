// goguard-go-bridge is the Fat Bridge subprocess for GoGuard.
// It performs full Go compilation (parsing, type-checking, SSA construction)
// using go/packages and golang.org/x/tools/go/ssa, then serializes the
// complete IR for Rust-side analysis.
//
// Modes:
//   - analyze: one-shot compilation, writes length-prefixed FlatBuffers to stdout
//   - serve:   newline-delimited JSON request/response loop on stdin/stdout
package main

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

const BridgeVersion = "0.3.0"

type Request struct {
	Command string          `json:"command"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type Response struct {
	Success bool   `json:"success"`
	Data    any    `json:"data,omitempty"`
	Error   string `json:"error,omitempty"`
}

type CompileParams struct {
	Dir      string   `json:"dir"`
	Patterns []string `json:"patterns"`
}

// rootCmd is the top-level cobra command for goguard-go-bridge.
var rootCmd = &cobra.Command{
	Use:     "goguard-go-bridge",
	Short:   "GoGuard Go bridge — compiles Go code to FlatBuffers IR",
	Version: BridgeVersion,
}

// analyzeCmd performs one-shot compilation and writes length-prefixed
// FlatBuffers binary to stdout. All log output goes to stderr.
var analyzeCmd = &cobra.Command{
	Use:   "analyze",
	Short: "One-shot compile and emit FlatBuffers IR to stdout",
	RunE:  runAnalyze,
}

// serveCmd runs the existing JSON stdin/stdout request loop.
var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Run JSON request/response loop on stdin/stdout",
	Run: func(cmd *cobra.Command, args []string) {
		runServe()
	},
}

// analyzePackages holds the --packages flag value for the analyze subcommand.
var analyzePackages []string

// cacheDirFlag holds the --cache-dir flag value for the analyze subcommand.
var cacheDirFlag string

// maxCacheEntriesFlag holds the --max-cache-entries flag value for the analyze subcommand.
var maxCacheEntriesFlag int

func init() {
	analyzeCmd.Flags().StringSliceVar(&analyzePackages, "packages", []string{"./..."}, "Go package patterns to compile")
	analyzeCmd.Flags().StringVar(&cacheDirFlag, "cache-dir", "", "Directory for FlatBuffers cache (empty = no cache)")
	analyzeCmd.Flags().IntVar(&maxCacheEntriesFlag, "max-cache-entries", 20, "Max cached entries before LRU eviction")

	rootCmd.AddCommand(analyzeCmd)
	rootCmd.AddCommand(serveCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

// runAnalyze compiles the requested packages and writes the FlatBuffers IR
// to stdout as a length-prefixed binary frame: [4 bytes LE length][payload].
// stdout contains EXCLUSIVELY binary data; any diagnostics go to stderr.
func runAnalyze(cmd *cobra.Command, args []string) error {
	result, err := CompileWithCache(".", analyzePackages, cacheDirFlag, maxCacheEntriesFlag)
	if err != nil {
		// Check for cache hit — payload is already FlatBuffers
		if hit, ok := err.(*CacheHit); ok {
			return writeFlatBuffersToStdout(hit.Payload)
		}
		return fmt.Errorf("compile: %w", err)
	}

	fb := BuildFlatBuffers(result)
	return writeFlatBuffersToStdout(fb)
}

// writeFlatBuffersToStdout writes a length-prefixed FlatBuffers payload to stdout.
// Format: [4 bytes LE length][payload bytes].
func writeFlatBuffersToStdout(fb []byte) error {
	lenBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(lenBuf, uint32(len(fb)))
	if _, err := os.Stdout.Write(lenBuf); err != nil {
		return fmt.Errorf("write length prefix: %w", err)
	}
	if _, err := os.Stdout.Write(fb); err != nil {
		return fmt.Errorf("write payload: %w", err)
	}
	return nil
}

// runServe implements the original JSON request/response loop on stdin/stdout.
// Protocol: newline-delimited JSON. Commands: ping, compile, version.
func runServe() {
	scanner := bufio.NewScanner(os.Stdin)
	// Increase buffer for large responses
	scanner.Buffer(make([]byte, 0, 1024*1024), 10*1024*1024)
	encoder := json.NewEncoder(os.Stdout)

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		var req Request
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			encoder.Encode(Response{Error: fmt.Sprintf("invalid request: %v", err)})
			continue
		}

		var resp Response
		switch req.Command {
		case "ping":
			resp = Response{Success: true, Data: map[string]string{
				"status":  "ok",
				"version": BridgeVersion,
			}}

		case "compile":
			var params CompileParams
			if err := json.Unmarshal(req.Params, &params); err != nil {
				resp = Response{Error: fmt.Sprintf("invalid compile params: %v", err)}
				break
			}
			if params.Dir == "" {
				params.Dir = "."
			}
			if len(params.Patterns) == 0 {
				params.Patterns = []string{"./..."}
			}
			result, err := Compile(params.Dir, params.Patterns)
			if err != nil {
				resp = Response{Error: fmt.Sprintf("compile error: %v", err)}
			} else {
				resp = Response{Success: true, Data: result}
			}

		case "version":
			resp = Response{Success: true, Data: map[string]string{
				"version": BridgeVersion,
			}}

		default:
			resp = Response{Error: fmt.Sprintf("unknown command: %s", req.Command)}
		}

		encoder.Encode(resp)
	}
}
