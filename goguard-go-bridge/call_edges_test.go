package main

import (
	"os"
	"path/filepath"
	"testing"

	ir "github.com/goguard/goguard-go-bridge/flatbuffers/goguard/ir"
)

// TestCallEdgesCollected verifies that call edges are populated when main() calls helper().
func TestCallEdgesCollected(t *testing.T) {
	dir := t.TempDir()

	gomod := `module testproject
go 1.21
`
	os.WriteFile(filepath.Join(dir, "go.mod"), []byte(gomod), 0644)

	src := `package main

import "fmt"

func helper() {
	fmt.Println("hello")
}

func main() {
	helper()
}
`
	os.WriteFile(filepath.Join(dir, "main.go"), []byte(src), 0644)

	result, err := Compile(dir, []string{"./..."})
	if err != nil {
		t.Fatalf("Compile failed: %v", err)
	}

	pkg := result.Packages[0]

	if len(pkg.CallEdges) == 0 {
		t.Fatal("expected call edges to be non-empty")
	}

	// Look for main -> helper edge
	found := false
	for _, edge := range pkg.CallEdges {
		if edge.Callee == "testproject.helper" {
			found = true
			if edge.IsGo {
				t.Error("expected IsGo=false for regular call")
			}
			if edge.IsDefer {
				t.Error("expected IsDefer=false for regular call")
			}
			if edge.IsDynamic {
				t.Error("expected IsDynamic=false for static call to helper")
			}
			break
		}
	}
	if !found {
		t.Errorf("expected to find call edge to testproject.helper; got edges: %v", pkg.CallEdges)
	}
}

// TestCallEdgesGo verifies that `go helper()` produces an edge with IsGo=true.
func TestCallEdgesGo(t *testing.T) {
	dir := t.TempDir()

	gomod := `module testproject
go 1.21
`
	os.WriteFile(filepath.Join(dir, "go.mod"), []byte(gomod), 0644)

	src := `package main

func worker() {}

func main() {
	go worker()
}
`
	os.WriteFile(filepath.Join(dir, "main.go"), []byte(src), 0644)

	result, err := Compile(dir, []string{"./..."})
	if err != nil {
		t.Fatalf("Compile failed: %v", err)
	}

	pkg := result.Packages[0]

	found := false
	for _, edge := range pkg.CallEdges {
		if edge.Callee == "testproject.worker" {
			found = true
			if !edge.IsGo {
				t.Error("expected IsGo=true for go worker()")
			}
			if edge.IsDefer {
				t.Error("expected IsDefer=false for go worker()")
			}
			break
		}
	}
	if !found {
		t.Errorf("expected to find call edge to testproject.worker; got edges: %v", pkg.CallEdges)
	}
}

// TestGoInstructionHasCallee verifies that `go worker()` produces an instruction-level callee in the IR.
func TestGoInstructionHasCallee(t *testing.T) {
	dir := t.TempDir()

	gomod := `module testproject
go 1.21
`
	os.WriteFile(filepath.Join(dir, "go.mod"), []byte(gomod), 0644)

	src := `package main

func worker() {}

func main() {
	go worker()
}
`
	os.WriteFile(filepath.Join(dir, "main.go"), []byte(src), 0644)

	result, err := Compile(dir, []string{"./..."})
	if err != nil {
		t.Fatalf("Compile failed: %v", err)
	}

	// Find main function and look for a Go instruction with callee set
	pkg := result.Packages[0]
	found := false
	for _, fn := range pkg.Functions {
		if fn.ShortName != "main" {
			continue
		}
		for _, block := range fn.Blocks {
			for _, instr := range block.Instructions {
				if instr.Kind == "Go" {
					if instr.Callee == "" {
						t.Fatal("Go instruction has empty Callee — callee extraction is broken")
					}
					if instr.Callee != "testproject.worker" {
						t.Errorf("Go instruction Callee = %q, want %q", instr.Callee, "testproject.worker")
					}
					if instr.CalleeIsInterface {
						t.Error("expected CalleeIsInterface=false for static go worker()")
					}
					found = true
				}
			}
		}
	}
	if !found {
		t.Fatal("expected to find a Go instruction in main()")
	}
}

// TestDeferInstructionHasCallee verifies that `defer cleanup()` produces an instruction-level callee in the IR.
func TestDeferInstructionHasCallee(t *testing.T) {
	dir := t.TempDir()

	gomod := `module testproject
go 1.21
`
	os.WriteFile(filepath.Join(dir, "go.mod"), []byte(gomod), 0644)

	src := `package main

func cleanup() {}

func main() {
	defer cleanup()
}
`
	os.WriteFile(filepath.Join(dir, "main.go"), []byte(src), 0644)

	result, err := Compile(dir, []string{"./..."})
	if err != nil {
		t.Fatalf("Compile failed: %v", err)
	}

	// Find main function and look for a Defer instruction with callee set
	pkg := result.Packages[0]
	found := false
	for _, fn := range pkg.Functions {
		if fn.ShortName != "main" {
			continue
		}
		for _, block := range fn.Blocks {
			for _, instr := range block.Instructions {
				if instr.Kind == "Defer" {
					if instr.Callee == "" {
						t.Fatal("Defer instruction has empty Callee — callee extraction is broken")
					}
					if instr.Callee != "testproject.cleanup" {
						t.Errorf("Defer instruction Callee = %q, want %q", instr.Callee, "testproject.cleanup")
					}
					if instr.CalleeIsInterface {
						t.Error("expected CalleeIsInterface=false for static defer cleanup()")
					}
					found = true
				}
			}
		}
	}
	if !found {
		t.Fatal("expected to find a Defer instruction in main()")
	}
}

// TestGoAndDeferCalleeFlatBuffersRoundTrip verifies that instruction-level callees for Go/Defer
// survive FlatBuffers serialization and deserialization.
func TestGoAndDeferCalleeFlatBuffersRoundTrip(t *testing.T) {
	dir := t.TempDir()

	gomod := `module testproject
go 1.21
`
	os.WriteFile(filepath.Join(dir, "go.mod"), []byte(gomod), 0644)

	src := `package main

func cleanup() {}
func worker() {}

func main() {
	defer cleanup()
	go worker()
}
`
	os.WriteFile(filepath.Join(dir, "main.go"), []byte(src), 0644)

	result, err := Compile(dir, []string{"./..."})
	if err != nil {
		t.Fatalf("Compile failed: %v", err)
	}

	// Serialize to FlatBuffers and deserialize
	buf := BuildFlatBuffers(result)
	root := ir.GetRootAsAnalysisResult(buf, 0)

	pkgFB := new(ir.Package)
	root.Packages(pkgFB, 0)

	// Find main function in FB
	var mainFn *ir.Function
	fn := new(ir.Function)
	for i := 0; i < pkgFB.FunctionsLength(); i++ {
		if pkgFB.Functions(fn, i) && string(fn.Name()) == "main" {
			mainFn = new(ir.Function)
			pkgFB.Functions(mainFn, i)
			break
		}
	}
	if mainFn == nil {
		t.Fatal("could not find main function in FlatBuffers output")
	}

	var foundGoCallee, foundDeferCallee bool
	block := new(ir.BasicBlock)
	instr := new(ir.Instruction)

	for bi := 0; bi < mainFn.BlocksLength(); bi++ {
		if !mainFn.Blocks(block, bi) {
			continue
		}
		for ii := 0; ii < block.InstructionsLength(); ii++ {
			if !block.Instructions(instr, ii) {
				continue
			}
			kind := instr.Kind()
			callTarget := string(instr.CallTarget())

			if kind == ir.InstructionKindGo {
				foundGoCallee = true
				if callTarget == "" {
					t.Error("Go instruction CallTarget is empty after FlatBuffers round-trip")
				}
				if callTarget != "testproject.worker" {
					t.Errorf("Go instruction CallTarget = %q, want %q", callTarget, "testproject.worker")
				}
			}
			if kind == ir.InstructionKindDefer {
				foundDeferCallee = true
				if callTarget == "" {
					t.Error("Defer instruction CallTarget is empty after FlatBuffers round-trip")
				}
				if callTarget != "testproject.cleanup" {
					t.Errorf("Defer instruction CallTarget = %q, want %q", callTarget, "testproject.cleanup")
				}
			}
		}
	}

	if !foundGoCallee {
		t.Error("expected to find a Go instruction in FlatBuffers main()")
	}
	if !foundDeferCallee {
		t.Error("expected to find a Defer instruction in FlatBuffers main()")
	}
}

// TestCallEdgeIsDeferIsGo verifies is_go and is_defer via FlatBuffers round-trip deserialization.
func TestCallEdgeIsDeferIsGo(t *testing.T) {
	dir := t.TempDir()

	gomod := `module testproject
go 1.21
`
	os.WriteFile(filepath.Join(dir, "go.mod"), []byte(gomod), 0644)

	src := `package main

func cleanup() {}
func worker() {}

func main() {
	defer cleanup()
	go worker()
}
`
	os.WriteFile(filepath.Join(dir, "main.go"), []byte(src), 0644)

	result, err := Compile(dir, []string{"./..."})
	if err != nil {
		t.Fatalf("Compile failed: %v", err)
	}

	// Serialize to FlatBuffers
	buf := BuildFlatBuffers(result)

	// Deserialize root
	root := ir.GetRootAsAnalysisResult(buf, 0)

	callGraph := new(ir.CallGraph)
	root.CallGraph(callGraph)

	edgeCount := callGraph.EdgesLength()
	if edgeCount == 0 {
		t.Fatal("expected call graph edges in FlatBuffers output")
	}

	var foundDefer, foundGo bool
	edge := new(ir.CallEdge)
	for i := 0; i < edgeCount; i++ {
		if !callGraph.Edges(edge, i) {
			continue
		}
		callee := string(edge.Callee())

		if callee == "testproject.cleanup" {
			foundDefer = true
			if !edge.IsDefer() {
				t.Error("expected IsDefer()=true for defer cleanup()")
			}
			if edge.IsGo() {
				t.Error("expected IsGo()=false for defer cleanup()")
			}
			if !edge.IsStatic() {
				t.Error("expected IsStatic()=true for static call to cleanup")
			}
		}

		if callee == "testproject.worker" {
			foundGo = true
			if !edge.IsGo() {
				t.Error("expected IsGo()=true for go worker()")
			}
			if edge.IsDefer() {
				t.Error("expected IsDefer()=false for go worker()")
			}
			if !edge.IsStatic() {
				t.Error("expected IsStatic()=true for static call to worker")
			}
		}
	}

	if !foundDefer {
		t.Error("expected to find defer cleanup() edge in FlatBuffers call graph")
	}
	if !foundGo {
		t.Error("expected to find go worker() edge in FlatBuffers call graph")
	}
}

// TestFreeVarsExtracted verifies that closure free variables are extracted into FunctionIR.FreeVars.
func TestFreeVarsExtracted(t *testing.T) {
	dir := t.TempDir()

	gomod := `module testproject
go 1.21
`
	os.WriteFile(filepath.Join(dir, "go.mod"), []byte(gomod), 0644)

	src := `package main

func main() {
	x := 42
	fn := func() int {
		return x
	}
	_ = fn()
}
`
	os.WriteFile(filepath.Join(dir, "main.go"), []byte(src), 0644)

	result, err := Compile(dir, []string{"./..."})
	if err != nil {
		t.Fatalf("Compile failed: %v", err)
	}

	pkg := result.Packages[0]

	// Find the anonymous closure function (it should have FreeVars)
	found := false
	for _, fn := range pkg.Functions {
		if len(fn.FreeVars) > 0 {
			found = true
			// Check that 'x' is among the free vars
			hasX := false
			for _, fv := range fn.FreeVars {
				if fv.Name == "x" {
					hasX = true
					if fv.TypeID == 0 {
						t.Error("expected TypeID != 0 for free var x")
					}
				}
			}
			if !hasX {
				t.Errorf("expected free var 'x' in closure; got: %+v", fn.FreeVars)
			}
			break
		}
	}
	if !found {
		t.Fatal("expected to find a function with non-empty FreeVars")
	}
}

// TestDefersExtracted verifies that defers are extracted into FunctionIR.Defers.
func TestDefersExtracted(t *testing.T) {
	dir := t.TempDir()

	gomod := `module testproject
go 1.21
`
	os.WriteFile(filepath.Join(dir, "go.mod"), []byte(gomod), 0644)

	src := `package main

import "os"

func process() {
	f, _ := os.Open("test.txt")
	defer f.Close()
}
`
	os.WriteFile(filepath.Join(dir, "main.go"), []byte(src), 0644)

	result, err := Compile(dir, []string{"./..."})
	if err != nil {
		t.Fatalf("Compile failed: %v", err)
	}

	pkg := result.Packages[0]

	// Find the process function
	found := false
	for _, fn := range pkg.Functions {
		if fn.ShortName == "process" {
			if len(fn.Defers) == 0 {
				t.Fatal("expected non-empty Defers for process()")
			}
			found = true
			d := fn.Defers[0]
			if d.CallTarget == "" {
				t.Error("expected non-empty CallTarget for defer")
			}
			if d.Index != 0 {
				t.Errorf("expected Index=0 for first defer; got %d", d.Index)
			}
			if d.Span == nil {
				t.Error("expected non-nil Span for defer")
			}
			break
		}
	}
	if !found {
		t.Fatal("expected to find function 'process'")
	}
}

// TestFreeVarsAndDefersFlatBuffersRoundTrip verifies free_vars and defers survive FlatBuffers serialization.
func TestFreeVarsAndDefersFlatBuffersRoundTrip(t *testing.T) {
	dir := t.TempDir()

	gomod := `module testproject
go 1.21
`
	os.WriteFile(filepath.Join(dir, "go.mod"), []byte(gomod), 0644)

	src := `package main

import "os"

func doWork() {
	f, _ := os.Open("test.txt")
	defer f.Close()

	x := 10
	fn := func() int {
		return x
	}
	_ = fn()
}
`
	os.WriteFile(filepath.Join(dir, "main.go"), []byte(src), 0644)

	result, err := Compile(dir, []string{"./..."})
	if err != nil {
		t.Fatalf("Compile failed: %v", err)
	}

	// Serialize to FlatBuffers and deserialize
	buf := BuildFlatBuffers(result)
	root := ir.GetRootAsAnalysisResult(buf, 0)

	pkgFB := new(ir.Package)
	root.Packages(pkgFB, 0)

	// Find doWork function — should have defers
	fn := new(ir.Function)
	var foundDefers bool
	for i := 0; i < pkgFB.FunctionsLength(); i++ {
		if pkgFB.Functions(fn, i) && string(fn.QualifiedName()) == "testproject.doWork" {
			if fn.DefersLength() > 0 {
				foundDefers = true
				d := new(ir.DeferInfo)
				if fn.Defers(d, 0) {
					target := string(d.CallTarget())
					if target == "" {
						t.Error("DeferInfo.CallTarget is empty after FlatBuffers round-trip")
					}
					sp := new(ir.SourcePos)
					if d.SourcePos(sp) == nil {
						t.Error("DeferInfo.SourcePos is nil after FlatBuffers round-trip")
					}
				}
			}
			break
		}
	}
	if !foundDefers {
		t.Error("expected defers in doWork() after FlatBuffers round-trip")
	}

	// Find closure function — should have free_vars
	var foundFreeVars bool
	for i := 0; i < pkgFB.FunctionsLength(); i++ {
		if pkgFB.Functions(fn, i) && fn.FreeVarsLength() > 0 {
			foundFreeVars = true
			v := new(ir.Variable)
			if fn.FreeVars(v, 0) {
				name := string(v.Name())
				if name != "x" {
					t.Errorf("expected free var name 'x'; got %q", name)
				}
				ti := new(ir.TypeInfo)
				if v.TypeInfo(ti) == nil {
					t.Error("Variable.TypeInfo is nil after FlatBuffers round-trip")
				}
			}
			break
		}
	}
	if !foundFreeVars {
		t.Error("expected free_vars in closure after FlatBuffers round-trip")
	}
}
