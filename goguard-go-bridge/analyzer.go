package main

import (
	"fmt"
	"go/token"
	"go/types"
	"os"
	"sort"
	"strings"

	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

// CompileResult holds the full SSA IR for serialization
type CompileResult struct {
	Packages      []PackageIR `json:"packages"`
	GoVersion     string      `json:"go_version"`
	BridgeVersion string      `json:"bridge_version"`
}

type PackageIR struct {
	ImportPath string           `json:"import_path"`
	Name       string           `json:"name"`
	Files      []FileInfoIR     `json:"files"`
	Types      []TypeRefIR      `json:"types"`
	Functions  []FunctionIR     `json:"functions"`
	Interfaces []InterfaceSatIR `json:"interface_satisfactions"`
	CallEdges  []CallEdgeIR     `json:"call_edges"`
}

type FileInfoIR struct {
	Path        string   `json:"path"`
	PackageName string   `json:"package_name"`
	IsGenerated bool     `json:"is_generated"`
	IsTest      bool     `json:"is_test"`
	Imports     []string `json:"imports"`
}

type TypeRefIR struct {
	ID         uint   `json:"id"`
	Kind       string `json:"kind"`
	Name       string `json:"name"`
	Underlying uint   `json:"underlying,omitempty"`
	Elem       uint   `json:"elem,omitempty"`
	Key        uint   `json:"key,omitempty"`
	IsNilable  bool   `json:"is_nilable"`
}

type SpanIR struct {
	File      string `json:"file"`
	StartLine int    `json:"start_line"`
	StartCol  int    `json:"start_col"`
	EndLine   int    `json:"end_line"`
	EndCol    int    `json:"end_col"`
}

type OperandIR struct {
	InstrID uint   `json:"instr_id"`
	Name    string `json:"name"`
	IsNil   bool   `json:"is_nil,omitempty"`
	IsConst bool   `json:"is_const,omitempty"`
	TypeID  uint   `json:"type_id,omitempty"`
}

type InstructionIR struct {
	ID       uint        `json:"id"`
	Kind     string      `json:"kind"`
	Name     string      `json:"name"`
	TypeID   uint        `json:"type_id"`
	Span     *SpanIR     `json:"span,omitempty"`
	Operands []OperandIR `json:"operands,omitempty"`
	// Call-specific
	Callee            string `json:"callee,omitempty"`
	CalleeIsInterface bool   `json:"callee_is_interface,omitempty"`
	// TypeAssert-specific
	AssertTypeID uint `json:"assert_type_id,omitempty"`
	CommaOk      bool `json:"comma_ok,omitempty"`
	// Const-specific
	ConstValue string `json:"const_value,omitempty"`
	IsNil      bool   `json:"is_nil,omitempty"`
	// BinOp-specific
	BinOpOperator string `json:"bin_op_operator,omitempty"`
	// Extract-specific
	ExtractIndex uint `json:"extract_index,omitempty"`
}

type CfgEdgeIR struct {
	FromBlock uint   `json:"from_block"`
	ToBlock   uint   `json:"to_block"`
	Kind      string `json:"kind"`
}

type BasicBlockIR struct {
	ID           uint            `json:"id"`
	Name         string          `json:"name"`
	Instructions []InstructionIR `json:"instructions"`
	IsReturn     bool            `json:"is_return"`
	IsPanic      bool            `json:"is_panic"`
}

type VariableIR struct {
	Name   string  `json:"name"`
	TypeID uint    `json:"type_id"`
	Span   *SpanIR `json:"span,omitempty"`
}

type DeferInfoIR struct {
	CallTarget string  `json:"call_target"`
	Span       *SpanIR `json:"span,omitempty"`
	Index      int     `json:"index"`
}

type FunctionIR struct {
	Name           string         `json:"name"`
	ShortName      string         `json:"short_name"`
	Span           *SpanIR        `json:"span,omitempty"`
	Blocks         []BasicBlockIR `json:"blocks"`
	CfgEdges       []CfgEdgeIR    `json:"cfg_edges"`
	IsMethod       bool           `json:"is_method"`
	ReceiverTypeID uint           `json:"receiver_type_id,omitempty"`
	IsExported     bool           `json:"is_exported"`
	FreeVars       []VariableIR   `json:"free_vars,omitempty"`
	Defers         []DeferInfoIR  `json:"defers,omitempty"`
}

type InterfaceSatIR struct {
	ConcreteTypeID  uint          `json:"concrete_type_id"`
	InterfaceTypeID uint          `json:"interface_type_id"`
	Methods         []MethodMapIR `json:"method_mappings"`
}

type MethodMapIR struct {
	InterfaceMethod string `json:"interface_method"`
	ConcreteMethod  string `json:"concrete_method"`
}

type CallEdgeIR struct {
	Caller    string  `json:"caller"`
	Callee    string  `json:"callee"`
	Span      *SpanIR `json:"span,omitempty"`
	IsDynamic bool    `json:"is_dynamic"`
	IsGo      bool    `json:"is_go"`
	IsDefer   bool    `json:"is_defer"`
}

// Compile loads Go packages, builds SSA, and returns the full IR.
func Compile(dir string, patterns []string) (*CompileResult, error) {
	cfg := &packages.Config{
		Mode: packages.NeedName |
			packages.NeedFiles |
			packages.NeedCompiledGoFiles |
			packages.NeedImports |
			packages.NeedDeps |
			packages.NeedTypes |
			packages.NeedSyntax |
			packages.NeedTypesInfo |
			packages.NeedTypesSizes,
		Dir: dir,
	}

	pkgs, err := packages.Load(cfg, patterns...)
	if err != nil {
		return nil, fmt.Errorf("loading packages: %w", err)
	}

	// Check for loading errors
	for _, pkg := range pkgs {
		if len(pkg.Errors) > 0 {
			return nil, fmt.Errorf("package %s has errors: %v", pkg.PkgPath, pkg.Errors)
		}
	}

	// Build SSA
	prog, ssaPkgs := ssautil.AllPackages(pkgs, ssa.InstantiateGenerics)
	prog.Build()

	result := &CompileResult{
		GoVersion:     "1.26",
		BridgeVersion: BridgeVersion,
	}

	typeRegistry := NewTypeRegistry()

	for _, ssaPkg := range ssaPkgs {
		if ssaPkg == nil {
			continue
		}
		pkgIR := serializePackage(prog, ssaPkg, typeRegistry)
		result.Packages = append(result.Packages, pkgIR)
	}

	return result, nil
}

// TypeRegistry tracks unique type IDs.
type TypeRegistry struct {
	types map[types.Type]uint
	refs  []TypeRefIR
	next  uint
}

func NewTypeRegistry() *TypeRegistry {
	return &TypeRegistry{
		types: make(map[types.Type]uint),
		next:  1,
	}
}

func (tr *TypeRegistry) Register(t types.Type) uint {
	if id, ok := tr.types[t]; ok {
		return id
	}
	id := tr.next
	tr.next++
	tr.types[t] = id

	ref := TypeRefIR{
		ID:        id,
		Kind:      typeKindString(t),
		Name:      t.String(),
		IsNilable: isNilable(t),
	}
	tr.refs = append(tr.refs, ref)
	return id
}

func typeKindString(t types.Type) string {
	switch t.(type) {
	case *types.Basic:
		return "Basic"
	case *types.Named:
		return "Named"
	case *types.Pointer:
		return "Pointer"
	case *types.Slice:
		return "Slice"
	case *types.Array:
		return "Array"
	case *types.Map:
		return "Map"
	case *types.Chan:
		return "Chan"
	case *types.Struct:
		return "Struct"
	case *types.Interface:
		return "Interface"
	case *types.Signature:
		return "Signature"
	case *types.Tuple:
		return "Tuple"
	default:
		return "Unknown"
	}
}

func isNilable(t types.Type) bool {
	switch t.Underlying().(type) {
	case *types.Pointer, *types.Slice, *types.Map, *types.Chan, *types.Interface, *types.Signature:
		return true
	default:
		return false
	}
}

func serializePackage(prog *ssa.Program, ssaPkg *ssa.Package, tr *TypeRegistry) PackageIR {
	pkgIR := PackageIR{
		ImportPath: ssaPkg.Pkg.Path(),
		Name:       ssaPkg.Pkg.Name(),
	}

	// Serialize files
	fset := prog.Fset

	// Collect file info from the package's SSA members
	seen := make(map[string]bool)

	var memberNames []string
	for name := range ssaPkg.Members {
		memberNames = append(memberNames, name)
	}
	sort.Strings(memberNames)

	for _, name := range memberNames {
		member := ssaPkg.Members[name]
		if fn, ok := member.(*ssa.Function); ok {
			pos := fset.Position(fn.Pos())
			if pos.IsValid() && !seen[pos.Filename] {
				seen[pos.Filename] = true
				pkgIR.Files = append(pkgIR.Files, FileInfoIR{
					Path:        pos.Filename,
					PackageName: ssaPkg.Pkg.Name(),
					IsGenerated: IsGeneratedFile(pos.Filename),
					IsTest:      strings.HasSuffix(pos.Filename, "_test.go"),
				})
			}
		}
	}

	// Serialize functions
	instrCounter := uint(0)
	fnSeen := make(map[string]bool)
	for _, name := range memberNames {
		member := ssaPkg.Members[name]
		fn, ok := member.(*ssa.Function)
		if !ok {
			continue
		}
		fnSeen[fn.String()] = true
		funcIR := serializeFunction(fn, fset, tr, &instrCounter)
		pkgIR.Functions = append(pkgIR.Functions, funcIR)

		// Also serialize anonymous/nested functions
		for _, anon := range fn.AnonFuncs {
			fnSeen[anon.String()] = true
			anonIR := serializeFunction(anon, fset, tr, &instrCounter)
			pkgIR.Functions = append(pkgIR.Functions, anonIR)
		}
	}

	// Serialize methods (not already collected as top-level functions)
	for _, name := range memberNames {
		member := ssaPkg.Members[name]
		typMember, ok := member.(*ssa.Type)
		if !ok {
			continue
		}
		mset := prog.MethodSets.MethodSet(types.NewPointer(typMember.Type()))
		for i := 0; i < mset.Len(); i++ {
			fn := prog.MethodValue(mset.At(i))
			if fn == nil || fn.Package() != ssaPkg || fnSeen[fn.String()] {
				continue
			}
			fnSeen[fn.String()] = true
			funcIR := serializeFunction(fn, fset, tr, &instrCounter)
			pkgIR.Functions = append(pkgIR.Functions, funcIR)
			for _, anon := range fn.AnonFuncs {
				if !fnSeen[anon.String()] {
					fnSeen[anon.String()] = true
					anonIR := serializeFunction(anon, fset, tr, &instrCounter)
					pkgIR.Functions = append(pkgIR.Functions, anonIR)
				}
			}
		}
	}

	// Serialize types
	pkgIR.Types = tr.refs

	// Collect interface satisfactions
	pkgIR.Interfaces = collectInterfaceSatisfactions(ssaPkg.Pkg.Scope(), tr)

	// Collect call edges from SSA
	pkgIR.CallEdges = collectCallEdges(ssaPkg, prog)

	return pkgIR
}

func serializeFunction(fn *ssa.Function, fset *token.FileSet, tr *TypeRegistry, counter *uint) FunctionIR {
	funcIR := FunctionIR{
		Name:       fn.String(),
		ShortName:  fn.Name(),
		IsExported: fn.Object() != nil && fn.Object().Exported(),
	}

	if fn.Signature != nil {
		funcIR.ReceiverTypeID = 0
		if recv := fn.Signature.Recv(); recv != nil {
			funcIR.IsMethod = true
			funcIR.ReceiverTypeID = tr.Register(recv.Type())
		}
	}

	pos := fset.Position(fn.Pos())
	if pos.IsValid() {
		funcIR.Span = &SpanIR{
			File:      pos.Filename,
			StartLine: pos.Line,
			StartCol:  pos.Column,
		}
	}

	// Extract free variables (captured variables for closures)
	for _, fv := range fn.FreeVars {
		varIR := VariableIR{
			Name:   fv.Name(),
			TypeID: tr.Register(fv.Type()),
		}
		if pos := fv.Pos(); pos.IsValid() {
			ipos := fset.Position(pos)
			varIR.Span = &SpanIR{
				File:      ipos.Filename,
				StartLine: ipos.Line,
				StartCol:  ipos.Column,
			}
		}
		funcIR.FreeVars = append(funcIR.FreeVars, varIR)
	}

	if fn.Blocks == nil {
		return funcIR // external function, no body
	}

	// Extract defers at function level
	deferIdx := 0
	for _, block := range fn.Blocks {
		for _, instr := range block.Instrs {
			deferInstr, ok := instr.(*ssa.Defer)
			if !ok {
				continue
			}
			deferIR := DeferInfoIR{
				Index: deferIdx,
			}
			deferIdx++
			if callee := deferInstr.Call.StaticCallee(); callee != nil {
				deferIR.CallTarget = callee.String()
			} else {
				deferIR.CallTarget = deferInstr.Call.Value.Name()
			}
			if pos := deferInstr.Pos(); pos.IsValid() {
				ipos := fset.Position(pos)
				deferIR.Span = &SpanIR{
					File:      ipos.Filename,
					StartLine: ipos.Line,
					StartCol:  ipos.Column,
				}
			}
			funcIR.Defers = append(funcIR.Defers, deferIR)
		}
	}

	// Map SSA values to instruction IDs
	valueIDs := make(map[ssa.Value]uint)

	// Emit Parameter instructions for function parameters.
	// In Go SSA, parameters are values but NOT instructions in blocks.
	// We synthesize Parameter instructions so Rust analysis can track them.
	var paramInstrs []InstructionIR
	for _, param := range fn.Params {
		*counter++
		valueIDs[param] = *counter
		paramIR := InstructionIR{
			ID:     *counter,
			Kind:   "Parameter",
			Name:   fmt.Sprintf("t%d", *counter),
			TypeID: tr.Register(param.Type()),
		}
		if pos := param.Pos(); pos.IsValid() {
			ppos := fset.Position(pos)
			paramIR.Span = &SpanIR{
				File:      ppos.Filename,
				StartLine: ppos.Line,
				StartCol:  ppos.Column,
			}
		}
		paramInstrs = append(paramInstrs, paramIR)
	}

	for _, block := range fn.Blocks {
		blockIR := BasicBlockIR{
			ID:   uint(block.Index),
			Name: fmt.Sprintf("block%d", block.Index),
		}

		for _, instr := range block.Instrs {
			*counter++
			instrIR := InstructionIR{
				ID:   *counter,
				Kind: instrKind(instr),
				Name: fmt.Sprintf("t%d", *counter),
			}

			// Track the value ID
			if v, ok := instr.(ssa.Value); ok {
				valueIDs[v] = *counter
				instrIR.TypeID = tr.Register(v.Type())
			}

			ipos := fset.Position(instr.Pos())
			if ipos.IsValid() {
				instrIR.Span = &SpanIR{
					File:      ipos.Filename,
					StartLine: ipos.Line,
					StartCol:  ipos.Column,
				}
			}

				// Handle specific instruction types
				switch v := instr.(type) {
				case *ssa.Call:
					if callee := v.Call.StaticCallee(); callee != nil {
						instrIR.Callee = callee.String()
				} else {
					instrIR.CalleeIsInterface = true
					instrIR.Callee = v.Call.Value.Name()
				}
			case *ssa.Go:
				if callee := v.Call.StaticCallee(); callee != nil {
					instrIR.Callee = callee.String()
				} else {
					instrIR.CalleeIsInterface = true
					instrIR.Callee = v.Call.Value.Name()
				}
			case *ssa.Defer:
				if callee := v.Call.StaticCallee(); callee != nil {
					instrIR.Callee = callee.String()
				} else {
					instrIR.CalleeIsInterface = true
					instrIR.Callee = v.Call.Value.Name()
				}
				case *ssa.TypeAssert:
					instrIR.AssertTypeID = tr.Register(v.AssertedType)
					instrIR.CommaOk = v.CommaOk
				case *ssa.BinOp:
					instrIR.BinOpOperator = v.Op.String()
				case *ssa.Extract:
					instrIR.ExtractIndex = uint(v.Index)
				}

			// Collect operands with enriched info
			for _, op := range instr.Operands(nil) {
				if op != nil && *op != nil {
					val := *op
					opIR := OperandIR{
						Name: val.Name(),
					}
					if id, ok := valueIDs[val]; ok {
						opIR.InstrID = id
						opIR.Name = fmt.Sprintf("t%d", id)
					}
					// Detect nil/const from *ssa.Const
					if c, ok := val.(*ssa.Const); ok {
						opIR.IsConst = true
						opIR.IsNil = c.IsNil()
					}
					// Register operand type
					if val.Type() != nil {
						opIR.TypeID = tr.Register(val.Type())
					}
					instrIR.Operands = append(instrIR.Operands, opIR)
				}
			}

			blockIR.Instructions = append(blockIR.Instructions, instrIR)
		}

		// Determine block termination
		if len(block.Instrs) > 0 {
			lastInstr := block.Instrs[len(block.Instrs)-1]
			switch lastInstr.(type) {
			case *ssa.Return:
				blockIR.IsReturn = true
			case *ssa.Panic:
				blockIR.IsPanic = true
			}
		}

		// Prepend parameter instructions to entry block (block 0)
		if block.Index == 0 && len(paramInstrs) > 0 {
			blockIR.Instructions = append(paramInstrs, blockIR.Instructions...)
		}

		funcIR.Blocks = append(funcIR.Blocks, blockIR)
	}

	// Build CFG edges
	for _, block := range fn.Blocks {
		for i, succ := range block.Succs {
			edge := CfgEdgeIR{
				FromBlock: uint(block.Index),
				ToBlock:   uint(succ.Index),
				Kind:      "Unconditional",
			}
			if len(block.Succs) == 2 {
				if i == 0 {
					edge.Kind = "CondTrue"
				} else {
					edge.Kind = "CondFalse"
				}
			}
			funcIR.CfgEdges = append(funcIR.CfgEdges, edge)
		}
	}

	return funcIR
}

func instrKind(instr ssa.Instruction) string {
	switch instr.(type) {
	case *ssa.Alloc:
		return "Alloc"
	case *ssa.Call:
		return "Call"
	case *ssa.BinOp:
		return "BinOp"
	case *ssa.UnOp:
		return "UnOp"
	case *ssa.Phi:
		return "Phi"
	case *ssa.FieldAddr:
		return "FieldAddr"
	case *ssa.IndexAddr:
		return "IndexAddr"
	case *ssa.Extract:
		return "Extract"
	case *ssa.TypeAssert:
		return "TypeAssert"
	case *ssa.MakeChan:
		return "MakeChan"
	case *ssa.MakeMap:
		return "MakeMap"
	case *ssa.MakeSlice:
		return "MakeSlice"
	case *ssa.MakeInterface:
		return "MakeInterface"
	case *ssa.MakeClosure:
		return "MakeClosure"
	case *ssa.Lookup:
		return "Lookup"
	case *ssa.Range:
		return "Range"
	case *ssa.Next:
		return "Next"
	case *ssa.Slice:
		return "Slice"
	case *ssa.Convert:
		return "Convert"
	case *ssa.ChangeInterface:
		return "ChangeInterface"
	case *ssa.ChangeType:
		return "ChangeType"
	case *ssa.Return:
		return "Return"
	case *ssa.If:
		return "If"
	case *ssa.Jump:
		return "Jump"
	case *ssa.Panic:
		return "Panic"
	case *ssa.Go:
		return "Go"
	case *ssa.Defer:
		return "Defer"
	case *ssa.Send:
		return "Send"
	case *ssa.Store:
		return "Store"
	case *ssa.MapUpdate:
		return "MapUpdate"
	case *ssa.DebugRef:
		return "DebugRef"
	default:
		return "Unknown"
	}
}

func collectInterfaceSatisfactions(scope *types.Scope, tr *TypeRegistry) []InterfaceSatIR {
	var result []InterfaceSatIR

	// Collect all interfaces and concrete types in scope
	var interfaces []*types.Named
	var concretes []*types.Named

	for _, name := range scope.Names() {
		obj := scope.Lookup(name)
		tn, ok := obj.(*types.TypeName)
		if !ok {
			continue
		}
		named, ok := tn.Type().(*types.Named)
		if !ok {
			continue
		}
		if _, isIface := named.Underlying().(*types.Interface); isIface {
			interfaces = append(interfaces, named)
		} else {
			concretes = append(concretes, named)
		}
	}

	// Check all concrete types against all interfaces
	for _, iface := range interfaces {
		ifaceType := iface.Underlying().(*types.Interface)
		if ifaceType.NumMethods() == 0 {
			continue // skip empty interfaces
		}
		ifaceTypeID := tr.Register(iface)

		for _, concrete := range concretes {
			// Check both T and *T
			var satisfies bool
			var usePointer bool
			if types.Implements(concrete, ifaceType) {
				satisfies = true
			} else if types.Implements(types.NewPointer(concrete), ifaceType) {
				satisfies = true
				usePointer = true
			}

			if !satisfies {
				continue
			}

			var concreteType types.Type = concrete
			if usePointer {
				concreteType = types.NewPointer(concrete)
			}
			concreteTypeID := tr.Register(concreteType)

			sat := InterfaceSatIR{
				ConcreteTypeID:  concreteTypeID,
				InterfaceTypeID: ifaceTypeID,
			}

			// Build method mappings
			mset := types.NewMethodSet(concreteType)
			for i := 0; i < ifaceType.NumMethods(); i++ {
				ifaceMethod := ifaceType.Method(i)
				for j := 0; j < mset.Len(); j++ {
					sel := mset.At(j)
					if sel.Obj().Name() == ifaceMethod.Name() {
						sat.Methods = append(sat.Methods, MethodMapIR{
							InterfaceMethod: ifaceMethod.Name(),
							ConcreteMethod:  sel.Obj().(*types.Func).FullName(),
						})
						break
					}
				}
			}

			result = append(result, sat)
		}
	}

	return result
}

// collectCallEdges walks all functions in a package and collects call edges from SSA instructions.
func collectCallEdges(ssaPkg *ssa.Package, prog *ssa.Program) []CallEdgeIR {
	var edges []CallEdgeIR
	seen := make(map[string]bool)

	var memberNames []string
	for name := range ssaPkg.Members {
		memberNames = append(memberNames, name)
	}
	sort.Strings(memberNames)

	for _, name := range memberNames {
		member := ssaPkg.Members[name]
		fn, ok := member.(*ssa.Function)
		if !ok {
			continue
		}
		edges = append(edges, collectFunctionCallEdges(fn, prog, seen)...)
		for _, anon := range fn.AnonFuncs {
			edges = append(edges, collectFunctionCallEdges(anon, prog, seen)...)
		}
	}

	// Methods
	for _, name := range memberNames {
		member := ssaPkg.Members[name]
		typMember, ok := member.(*ssa.Type)
		if !ok {
			continue
		}
		mset := prog.MethodSets.MethodSet(types.NewPointer(typMember.Type()))
		for i := 0; i < mset.Len(); i++ {
			fn := prog.MethodValue(mset.At(i))
			if fn == nil || fn.Package() != ssaPkg {
				continue
			}
			edges = append(edges, collectFunctionCallEdges(fn, prog, seen)...)
			for _, anon := range fn.AnonFuncs {
				edges = append(edges, collectFunctionCallEdges(anon, prog, seen)...)
			}
		}
	}

	// Sort edges for determinism
	sort.Slice(edges, func(i, j int) bool {
		if edges[i].Caller != edges[j].Caller {
			return edges[i].Caller < edges[j].Caller
		}
		return edges[i].Callee < edges[j].Callee
	})

	return edges
}

// collectFunctionCallEdges walks all blocks/instructions of a single function and returns call edges.
func collectFunctionCallEdges(fn *ssa.Function, prog *ssa.Program, seen map[string]bool) []CallEdgeIR {
	if fn.Blocks == nil {
		return nil
	}
	var edges []CallEdgeIR
	fset := prog.Fset
	callerName := fn.String()

	for _, block := range fn.Blocks {
		for _, instr := range block.Instrs {
			var calleeName string
			var isDynamic, isGo, isDefer bool
			var pos token.Pos

			switch v := instr.(type) {
			case *ssa.Call:
				pos = v.Pos()
				if callee := v.Call.StaticCallee(); callee != nil {
					calleeName = callee.String()
				} else {
					calleeName = v.Call.Value.Name()
					isDynamic = true
				}
			case *ssa.Go:
				pos = v.Pos()
				isGo = true
				if callee := v.Call.StaticCallee(); callee != nil {
					calleeName = callee.String()
				} else {
					calleeName = v.Call.Value.Name()
					isDynamic = true
				}
			case *ssa.Defer:
				pos = v.Pos()
				isDefer = true
				if callee := v.Call.StaticCallee(); callee != nil {
					calleeName = callee.String()
				} else {
					calleeName = v.Call.Value.Name()
					isDynamic = true
				}
			default:
				continue
			}

			if calleeName == "" {
				continue
			}

			key := callerName + " -> " + calleeName
			if seen[key] {
				continue
			}
			seen[key] = true

			edge := CallEdgeIR{
				Caller:    callerName,
				Callee:    calleeName,
				IsDynamic: isDynamic,
				IsGo:      isGo,
				IsDefer:   isDefer,
			}
			ipos := fset.Position(pos)
			if ipos.IsValid() {
				edge.Span = &SpanIR{
					File:      ipos.Filename,
					StartLine: ipos.Line,
					StartCol:  ipos.Column,
				}
			}
			edges = append(edges, edge)
		}
	}
	return edges
}

// CompileWithCache wraps Compile with filesystem fingerprint caching.
// If cacheDir is empty, falls through to Compile() directly.
func CompileWithCache(dir string, patterns []string, cacheDir string, maxEntries int) (*CompileResult, error) {
	if cacheDir == "" {
		return Compile(dir, patterns)
	}

	cache := &BridgeCache{Dir: cacheDir, MaxEntries: maxEntries}

	fingerprint, err := ComputeFingerprint(dir, patterns)
	if err != nil {
		// Fingerprint failure is non-fatal — fall through to compile
		fmt.Fprintf(os.Stderr, "goguard: cache fingerprint error: %v\n", err)
		return Compile(dir, patterns)
	}

	// Try cache hit
	if payload, ok := cache.Get(fingerprint); ok {
		fmt.Fprintf(os.Stderr, "goguard: cache hit (%s)\n", fingerprint[:12])
		return nil, &CacheHit{Payload: payload, Fingerprint: fingerprint}
	}

	// Cache miss — compile normally
	fmt.Fprintf(os.Stderr, "goguard: cache miss (%s), compiling...\n", fingerprint[:12])
	result, err := Compile(dir, patterns)
	if err != nil {
		return nil, err
	}

	// Store in cache
	fb := BuildFlatBuffers(result)
	if putErr := cache.Put(fingerprint, fb, patterns); putErr != nil {
		fmt.Fprintf(os.Stderr, "goguard: cache store error: %v\n", putErr)
	}

	return result, nil
}

// CacheHit is a sentinel error returned when cache contains pre-built FlatBuffers.
type CacheHit struct {
	Payload     []byte
	Fingerprint string
}

func (c *CacheHit) Error() string {
	return fmt.Sprintf("cache hit: %s", c.Fingerprint[:12])
}
