package main

import (
	"os"
	"path/filepath"
	"testing"

	ir "github.com/goguard/goguard-go-bridge/flatbuffers/goguard/ir"
)

// testCompileResult creates a CompileResult from a temporary Go project.
func testCompileResult(t *testing.T, src string) *CompileResult {
	t.Helper()
	dir := t.TempDir()

	gomod := "module testproject\ngo 1.21\n"
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(gomod), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(src), 0644); err != nil {
		t.Fatal(err)
	}

	result, err := Compile(dir, []string{"./..."})
	if err != nil {
		t.Fatalf("Compile failed: %v", err)
	}
	return result
}

func TestBuildFlatBuffers(t *testing.T) {
	result := testCompileResult(t, `package main

import "fmt"

type User struct {
	Name string
}

func GetUser(id int) (*User, error) {
	if id <= 0 {
		return nil, fmt.Errorf("invalid id: %d", id)
	}
	return &User{Name: "test"}, nil
}

func main() {
	user, err := GetUser(42)
	if err != nil {
		fmt.Println("error:", err)
	}
	fmt.Println(user.Name)
}
`)

	buf := BuildFlatBuffers(result)
	if len(buf) == 0 {
		t.Fatal("FlatBuffers output is empty")
	}
	t.Logf("FlatBuffers output size: %d bytes", len(buf))
}

func TestBuildFlatBuffersRoundTrip(t *testing.T) {
	result := testCompileResult(t, `package main

import "fmt"

type User struct {
	Name string
}

func GetUser(id int) (*User, error) {
	if id <= 0 {
		return nil, fmt.Errorf("invalid id: %d", id)
	}
	return &User{Name: "test"}, nil
}

func main() {
	user, err := GetUser(42)
	if err != nil {
		fmt.Println("error:", err)
	}
	fmt.Println(user.Name)
}
`)

	buf := BuildFlatBuffers(result)

	// Read back with generated accessor
	root := ir.GetRootAsAnalysisResult(buf, 0)

	if root.PackagesLength() == 0 {
		t.Fatal("no packages in output")
	}

	pkg := new(ir.Package)
	if !root.Packages(pkg, 0) {
		t.Fatal("failed to read package 0")
	}

	if string(pkg.Name()) == "" {
		t.Fatal("package name is empty")
	}

	t.Logf("Package: %s (%s)", string(pkg.Name()), string(pkg.Path()))
	t.Logf("Functions: %d", pkg.FunctionsLength())

	if pkg.FunctionsLength() == 0 {
		t.Fatal("no functions in package")
	}

	// Verify at least one function has blocks
	fn := new(ir.Function)
	if !pkg.Functions(fn, 0) {
		t.Fatal("failed to read function 0")
	}
	t.Logf("Function: %s, blocks: %d", string(fn.Name()), fn.BlocksLength())

	// Check go_version
	goVersion := string(root.GoVersion())
	if goVersion == "" {
		t.Error("go_version is empty")
	}
	t.Logf("GoVersion: %s", goVersion)
}

func TestBuildFlatBuffersInstructionKinds(t *testing.T) {
	result := testCompileResult(t, `package main

import "fmt"

func Classify(n int) string {
	if n > 0 {
		return "positive"
	} else if n < 0 {
		return "negative"
	}
	return "zero"
}

func main() {
	fmt.Println(Classify(42))
}
`)

	buf := BuildFlatBuffers(result)
	root := ir.GetRootAsAnalysisResult(buf, 0)

	pkg := new(ir.Package)
	root.Packages(pkg, 0)

	// Walk all instructions and verify they have valid kinds
	fn := new(ir.Function)
	instrCount := 0
	for i := 0; i < pkg.FunctionsLength(); i++ {
		pkg.Functions(fn, i)
		block := new(ir.BasicBlock)
		for j := 0; j < fn.BlocksLength(); j++ {
			fn.Blocks(block, j)
			inst := new(ir.Instruction)
				for k := 0; k < block.InstructionsLength(); k++ {
					block.Instructions(inst, k)
					instrCount++
					// Kind should be a valid enum value.
					if _, ok := ir.EnumNamesInstructionKind[inst.Kind()]; !ok {
						t.Errorf("invalid instruction kind: %d", inst.Kind())
					}
				}
			}
		}

	if instrCount == 0 {
		t.Error("expected at least one instruction across all functions")
	}
	t.Logf("Total instructions: %d", instrCount)
}

func TestBuildFlatBuffersCFG(t *testing.T) {
	result := testCompileResult(t, `package main

func Classify(n int) string {
	if n > 0 {
		return "positive"
	} else if n < 0 {
		return "negative"
	}
	return "zero"
}
`)

	buf := BuildFlatBuffers(result)
	root := ir.GetRootAsAnalysisResult(buf, 0)

	pkg := new(ir.Package)
	root.Packages(pkg, 0)

	// Find Classify function
	fn := new(ir.Function)
	var classifyFn *ir.Function
	for i := 0; i < pkg.FunctionsLength(); i++ {
		pkg.Functions(fn, i)
		if string(fn.Name()) == "Classify" {
			classifyFn = new(ir.Function)
			pkg.Functions(classifyFn, i)
			break
		}
	}

	if classifyFn == nil {
		t.Fatal("expected to find Classify function")
	}

	if classifyFn.BlocksLength() < 3 {
		t.Errorf("expected at least 3 blocks for if/else, got %d", classifyFn.BlocksLength())
	}

	// Check that entry block (block 0) has successors
	block := new(ir.BasicBlock)
	classifyFn.Blocks(block, 0)
	if block.SuccessorsLength() == 0 {
		t.Error("entry block should have successors (conditional branch)")
	}
	t.Logf("Entry block successors: %d", block.SuccessorsLength())

	// Check that the entry block is marked as entry
	if !block.IsEntry() {
		t.Error("block 0 should be marked as entry")
	}

	// Check that at least one block is marked as exit
	hasExit := false
	for i := 0; i < classifyFn.BlocksLength(); i++ {
		classifyFn.Blocks(block, i)
		if block.IsExit() {
			hasExit = true
			break
		}
	}
	if !hasExit {
		t.Error("expected at least one exit block (return)")
	}
}

func TestBuildFlatBuffersQualifiedName(t *testing.T) {
	result := testCompileResult(t, `package main

func Hello() string { return "hello" }

func main() {}
`)

	buf := BuildFlatBuffers(result)
	root := ir.GetRootAsAnalysisResult(buf, 0)

	pkg := new(ir.Package)
	root.Packages(pkg, 0)

	fn := new(ir.Function)
	for i := 0; i < pkg.FunctionsLength(); i++ {
		pkg.Functions(fn, i)
		qname := string(fn.QualifiedName())
		name := string(fn.Name())
		if name == "" {
			t.Error("function name should not be empty")
		}
		if qname == "" {
			t.Error("qualified name should not be empty")
		}
		t.Logf("Function: name=%s, qualified=%s", name, qname)
	}
}

func TestBuildFlatBuffersCallGraph(t *testing.T) {
	result := testCompileResult(t, `package main

import "fmt"

func greet(name string) string {
	return fmt.Sprintf("Hello, %s!", name)
}

func main() {
	fmt.Println(greet("World"))
}
`)

	buf := BuildFlatBuffers(result)
	root := ir.GetRootAsAnalysisResult(buf, 0)

	cg := root.CallGraph(nil)
	if cg == nil {
		t.Fatal("call graph is nil")
	}

	t.Logf("Call graph edges: %d", cg.EdgesLength())
	edge := new(ir.CallEdge)
	for i := 0; i < cg.EdgesLength(); i++ {
		cg.Edges(edge, i)
		t.Logf("  %s -> %s (static=%v)", string(edge.Caller()), string(edge.Callee()), edge.IsStatic())
	}
}

func TestBuildFlatBuffersResultType(t *testing.T) {
	result := testCompileResult(t, `package main

func Add(a, b int) int {
	return a + b
}

func main() {
	_ = Add(1, 2)
}
`)

	buf := BuildFlatBuffers(result)
	root := ir.GetRootAsAnalysisResult(buf, 0)

	pkg := new(ir.Package)
	root.Packages(pkg, 0)

	// Find Add function and check that some instructions have result types
	fn := new(ir.Function)
	for i := 0; i < pkg.FunctionsLength(); i++ {
		pkg.Functions(fn, i)
		if string(fn.Name()) != "Add" {
			continue
		}

		hasResultType := false
		block := new(ir.BasicBlock)
		for j := 0; j < fn.BlocksLength(); j++ {
			fn.Blocks(block, j)
			inst := new(ir.Instruction)
			for k := 0; k < block.InstructionsLength(); k++ {
				block.Instructions(inst, k)
				ti := inst.ResultType(nil)
				if ti != nil && len(ti.Name()) > 0 {
					hasResultType = true
					t.Logf("Instruction result type: kind=%s, name=%s", ti.Kind().String(), string(ti.Name()))
				}
			}
		}

		if !hasResultType {
			t.Error("expected at least one instruction with a result type in Add()")
		}
		return
	}

	t.Error("did not find Add function")
}

func TestBuildFlatBuffersEmptyResult(t *testing.T) {
	// Test with an empty CompileResult
	result := &CompileResult{
		GoVersion:     "1.21",
		BridgeVersion: "0.2.0",
	}

	buf := BuildFlatBuffers(result)
	if len(buf) == 0 {
		t.Fatal("FlatBuffers output is empty even for empty result")
	}

	root := ir.GetRootAsAnalysisResult(buf, 0)
	if root.PackagesLength() != 0 {
		t.Errorf("expected 0 packages, got %d", root.PackagesLength())
	}

	goVersion := string(root.GoVersion())
	if goVersion != "1.21" {
		t.Errorf("expected go_version '1.21', got %q", goVersion)
	}
}
