package main

import (
	"strings"

	ir "github.com/goguard/goguard-go-bridge/flatbuffers/goguard/ir"
	flatbuffers "github.com/google/flatbuffers/go"
)

// BuildFlatBuffers converts a CompileResult to FlatBuffers binary format.
// It builds the tree bottom-up: operands -> instructions -> blocks -> functions -> packages -> root.
func BuildFlatBuffers(result *CompileResult) []byte {
	builder := flatbuffers.NewBuilder(4096)

	// Build type lookup from all packages (id -> TypeRefIR)
	typeMap := make(map[uint]TypeRefIR)
	for _, pkg := range result.Packages {
		for _, t := range pkg.Types {
			typeMap[t.ID] = t
		}
	}

	// Build packages (collect all call edges and interface sats for the root)
	var allCallEdges []CallEdgeIR
	var allInterfaceSats []InterfaceSatIR

	packageOffsets := make([]flatbuffers.UOffsetT, len(result.Packages))
	for i := len(result.Packages) - 1; i >= 0; i-- {
		pkg := result.Packages[i]
		allCallEdges = append(allCallEdges, pkg.CallEdges...)
		allInterfaceSats = append(allInterfaceSats, pkg.Interfaces...)
		packageOffsets[i] = buildPackage(builder, &pkg, typeMap)
	}

	// Build packages vector
	ir.AnalysisResultStartPackagesVector(builder, len(packageOffsets))
	for i := len(packageOffsets) - 1; i >= 0; i-- {
		builder.PrependUOffsetT(packageOffsets[i])
	}
	packagesVec := builder.EndVector(len(packageOffsets))

	// Build call graph
	callGraphOffset := buildCallGraph(builder, allCallEdges)

	// Build interface table
	interfaceTableOffset := buildInterfaceTable(builder, allInterfaceSats, typeMap)

	// Build go_version string
	goVersionOffset := builder.CreateString(result.GoVersion)

	// Build the root AnalysisResult
	ir.AnalysisResultStart(builder)
	ir.AnalysisResultAddPackages(builder, packagesVec)
	ir.AnalysisResultAddCallGraph(builder, callGraphOffset)
	ir.AnalysisResultAddInterfaceTable(builder, interfaceTableOffset)
	ir.AnalysisResultAddGoVersion(builder, goVersionOffset)
	rootOffset := ir.AnalysisResultEnd(builder)

	ir.FinishAnalysisResultBuffer(builder, rootOffset)
	return builder.FinishedBytes()
}

// buildPackage serializes a PackageIR into the FlatBuffer.
func buildPackage(builder *flatbuffers.Builder, pkg *PackageIR, typeMap map[uint]TypeRefIR) flatbuffers.UOffsetT {
	// Build functions
	funcOffsets := make([]flatbuffers.UOffsetT, len(pkg.Functions))
	for i := len(pkg.Functions) - 1; i >= 0; i-- {
		funcOffsets[i] = buildFunction(builder, &pkg.Functions[i], typeMap)
	}

	// Create functions vector
	ir.PackageStartFunctionsVector(builder, len(funcOffsets))
	for i := len(funcOffsets) - 1; i >= 0; i-- {
		builder.PrependUOffsetT(funcOffsets[i])
	}
	functionsVec := builder.EndVector(len(funcOffsets))

	// Create strings
	pathOffset := builder.CreateString(pkg.ImportPath)
	nameOffset := builder.CreateString(pkg.Name)

	// Build Package table
	ir.PackageStart(builder)
	ir.PackageAddPath(builder, pathOffset)
	ir.PackageAddName(builder, nameOffset)
	ir.PackageAddFunctions(builder, functionsVec)
	return ir.PackageEnd(builder)
}

// buildFunction serializes a FunctionIR into the FlatBuffer.
func buildFunction(builder *flatbuffers.Builder, fn *FunctionIR, typeMap map[uint]TypeRefIR) flatbuffers.UOffsetT {
	// Compute successors/predecessors from CfgEdges
	succMap := make(map[uint][]int32) // block ID -> successor block IDs
	predMap := make(map[uint][]int32) // block ID -> predecessor block IDs
	for _, edge := range fn.CfgEdges {
		succMap[edge.FromBlock] = append(succMap[edge.FromBlock], int32(edge.ToBlock))
		predMap[edge.ToBlock] = append(predMap[edge.ToBlock], int32(edge.FromBlock))
	}

	// Build blocks
	blockOffsets := make([]flatbuffers.UOffsetT, len(fn.Blocks))
	for i := len(fn.Blocks) - 1; i >= 0; i-- {
		block := &fn.Blocks[i]
		succs := succMap[block.ID]
		preds := predMap[block.ID]
		blockOffsets[i] = buildBasicBlock(builder, block, succs, preds, typeMap)
	}

	// Create blocks vector
	ir.FunctionStartBlocksVector(builder, len(blockOffsets))
	for i := len(blockOffsets) - 1; i >= 0; i-- {
		builder.PrependUOffsetT(blockOffsets[i])
	}
	blocksVec := builder.EndVector(len(blockOffsets))

	// Build source position
	var sourcePosOffset flatbuffers.UOffsetT
	if fn.Span != nil {
		sourcePosOffset = buildSourcePos(builder, fn.Span)
	}

	// Build an empty FunctionSignature
	ir.FunctionSignatureStart(builder)
	signatureOffset := ir.FunctionSignatureEnd(builder)

	// Build receiver type string (look up in type map if we have a receiver)
	var receiverTypeOffset flatbuffers.UOffsetT
	if fn.IsMethod && fn.ReceiverTypeID != 0 {
		if ref, ok := typeMap[fn.ReceiverTypeID]; ok {
			receiverTypeOffset = builder.CreateString(ref.Name)
		}
	}

	// Build free_vars vector
	var freeVarsVec flatbuffers.UOffsetT
	if len(fn.FreeVars) > 0 {
		varOffsets := make([]flatbuffers.UOffsetT, len(fn.FreeVars))
		for i := len(fn.FreeVars) - 1; i >= 0; i-- {
			fv := &fn.FreeVars[i]
			nameOff := builder.CreateString(fv.Name)
			var spOff flatbuffers.UOffsetT
			if fv.Span != nil {
				spOff = buildSourcePos(builder, fv.Span)
			}
			// Build TypeInfo for the variable
			var typeInfoOff flatbuffers.UOffsetT
			if ref, ok := typeMap[fv.TypeID]; ok {
				typeInfoOff = buildTypeInfo(builder, &ref)
			}
			ir.VariableStart(builder)
			ir.VariableAddName(builder, nameOff)
			if typeInfoOff != 0 {
				ir.VariableAddTypeInfo(builder, typeInfoOff)
			}
			if fv.Span != nil {
				ir.VariableAddSourcePos(builder, spOff)
			}
			varOffsets[i] = ir.VariableEnd(builder)
		}
		ir.FunctionStartFreeVarsVector(builder, len(varOffsets))
		for i := len(varOffsets) - 1; i >= 0; i-- {
			builder.PrependUOffsetT(varOffsets[i])
		}
		freeVarsVec = builder.EndVector(len(varOffsets))
	}

	// Build defers vector
	var defersVec flatbuffers.UOffsetT
	if len(fn.Defers) > 0 {
		deferOffsets := make([]flatbuffers.UOffsetT, len(fn.Defers))
		for i := len(fn.Defers) - 1; i >= 0; i-- {
			d := &fn.Defers[i]
			targetOff := builder.CreateString(d.CallTarget)
			var spOff flatbuffers.UOffsetT
			if d.Span != nil {
				spOff = buildSourcePos(builder, d.Span)
			}
			ir.DeferInfoStart(builder)
			ir.DeferInfoAddCallTarget(builder, targetOff)
			ir.DeferInfoAddIndex(builder, int32(d.Index))
			if d.Span != nil {
				ir.DeferInfoAddSourcePos(builder, spOff)
			}
			deferOffsets[i] = ir.DeferInfoEnd(builder)
		}
		ir.FunctionStartDefersVector(builder, len(deferOffsets))
		for i := len(deferOffsets) - 1; i >= 0; i-- {
			builder.PrependUOffsetT(deferOffsets[i])
		}
		defersVec = builder.EndVector(len(deferOffsets))
	}

	// Create name strings
	nameOffset := builder.CreateString(fn.ShortName)
	qualifiedNameOffset := builder.CreateString(fn.Name)

	// Build Function table
	ir.FunctionStart(builder)
	ir.FunctionAddName(builder, nameOffset)
	ir.FunctionAddQualifiedName(builder, qualifiedNameOffset)
	ir.FunctionAddSignature(builder, signatureOffset)
	ir.FunctionAddBlocks(builder, blocksVec)
	if fn.Span != nil {
		ir.FunctionAddSourcePos(builder, sourcePosOffset)
	}
	if freeVarsVec != 0 {
		ir.FunctionAddFreeVars(builder, freeVarsVec)
	}
	if defersVec != 0 {
		ir.FunctionAddDefers(builder, defersVec)
	}
	ir.FunctionAddIsMethod(builder, fn.IsMethod)
	if receiverTypeOffset != 0 {
		ir.FunctionAddReceiverType(builder, receiverTypeOffset)
	}
	return ir.FunctionEnd(builder)
}

// buildBasicBlock serializes a BasicBlockIR into the FlatBuffer.
func buildBasicBlock(builder *flatbuffers.Builder, block *BasicBlockIR, succs []int32, preds []int32, typeMap map[uint]TypeRefIR) flatbuffers.UOffsetT {
	// Build instructions
	instrOffsets := make([]flatbuffers.UOffsetT, len(block.Instructions))
	for i := len(block.Instructions) - 1; i >= 0; i-- {
		instrOffsets[i] = buildInstruction(builder, &block.Instructions[i], typeMap)
	}

	// Create instructions vector
	ir.BasicBlockStartInstructionsVector(builder, len(instrOffsets))
	for i := len(instrOffsets) - 1; i >= 0; i-- {
		builder.PrependUOffsetT(instrOffsets[i])
	}
	instructionsVec := builder.EndVector(len(instrOffsets))

	// Create successors vector
	var successorsVec flatbuffers.UOffsetT
	if len(succs) > 0 {
		ir.BasicBlockStartSuccessorsVector(builder, len(succs))
		for i := len(succs) - 1; i >= 0; i-- {
			builder.PrependInt32(succs[i])
		}
		successorsVec = builder.EndVector(len(succs))
	}

	// Create predecessors vector
	var predecessorsVec flatbuffers.UOffsetT
	if len(preds) > 0 {
		ir.BasicBlockStartPredecessorsVector(builder, len(preds))
		for i := len(preds) - 1; i >= 0; i-- {
			builder.PrependInt32(preds[i])
		}
		predecessorsVec = builder.EndVector(len(preds))
	}

	// Build BasicBlock table
	ir.BasicBlockStart(builder)
	ir.BasicBlockAddId(builder, int32(block.ID))
	ir.BasicBlockAddInstructions(builder, instructionsVec)
	if len(succs) > 0 {
		ir.BasicBlockAddSuccessors(builder, successorsVec)
	}
	if len(preds) > 0 {
		ir.BasicBlockAddPredecessors(builder, predecessorsVec)
	}
	ir.BasicBlockAddIsEntry(builder, block.ID == 0)
	ir.BasicBlockAddIsExit(builder, block.IsReturn || block.IsPanic)
	return ir.BasicBlockEnd(builder)
}

// buildInstruction serializes an InstructionIR into the FlatBuffer.
func buildInstruction(builder *flatbuffers.Builder, instr *InstructionIR, typeMap map[uint]TypeRefIR) flatbuffers.UOffsetT {
	// Build operands
	var operandsVec flatbuffers.UOffsetT
	if len(instr.Operands) > 0 {
		operandOffsets := make([]flatbuffers.UOffsetT, len(instr.Operands))
		for i := len(instr.Operands) - 1; i >= 0; i-- {
			operandOffsets[i] = buildOperandIR(builder, &instr.Operands[i], typeMap)
		}
		ir.InstructionStartOperandsVector(builder, len(operandOffsets))
		for i := len(operandOffsets) - 1; i >= 0; i-- {
			builder.PrependUOffsetT(operandOffsets[i])
		}
		operandsVec = builder.EndVector(len(operandOffsets))
	}

	// Build source position
	var sourcePosOffset flatbuffers.UOffsetT
	if instr.Span != nil {
		sourcePosOffset = buildSourcePos(builder, instr.Span)
	}

	// Build result type info
	var resultTypeOffset flatbuffers.UOffsetT
	if instr.TypeID != 0 {
		if ref, ok := typeMap[instr.TypeID]; ok {
			resultTypeOffset = buildTypeInfo(builder, &ref)
		}
	}

	// Build result var name
	resultVarOffset := builder.CreateString(instr.Name)

	// Build field_name (used for BinOp operator)
	var fieldNameOffset flatbuffers.UOffsetT
	if instr.BinOpOperator != "" {
		fieldNameOffset = builder.CreateString(instr.BinOpOperator)
	}

	// Build call target strings
	var callTargetOffset flatbuffers.UOffsetT
	if instr.Callee != "" {
		callTargetOffset = builder.CreateString(instr.Callee)
	}

	// Build type assert target
	var typeAssertTargetOffset flatbuffers.UOffsetT
	if instr.AssertTypeID != 0 {
		if ref, ok := typeMap[instr.AssertTypeID]; ok {
			typeAssertTargetOffset = builder.CreateString(ref.Name)
		}
	}

	// Map instruction kind
	kind := mapInstructionKind(instr.Kind)

	// Build Instruction table
	ir.InstructionStart(builder)
	ir.InstructionAddKind(builder, kind)
	if instr.Span != nil {
		ir.InstructionAddSourcePos(builder, sourcePosOffset)
	}
	ir.InstructionAddResultVar(builder, resultVarOffset)
	if resultTypeOffset != 0 {
		ir.InstructionAddResultType(builder, resultTypeOffset)
	}
	if len(instr.Operands) > 0 {
		ir.InstructionAddOperands(builder, operandsVec)
	}
	if callTargetOffset != 0 {
		ir.InstructionAddCallTarget(builder, callTargetOffset)
	}
	ir.InstructionAddIsInterfaceCall(builder, instr.CalleeIsInterface)
	if typeAssertTargetOffset != 0 {
		ir.InstructionAddTypeAssertTarget(builder, typeAssertTargetOffset)
	}
	ir.InstructionAddTypeAssertHasOk(builder, instr.CommaOk)
	if fieldNameOffset != 0 {
		ir.InstructionAddFieldName(builder, fieldNameOffset)
	}
	if instr.Kind == "Extract" {
		ir.InstructionAddExtractIndex(builder, int32(instr.ExtractIndex))
	}
	return ir.InstructionEnd(builder)
}

// buildOperandIR creates an Operand table from an enriched OperandIR.
func buildOperandIR(builder *flatbuffers.Builder, op *OperandIR, typeMap map[uint]TypeRefIR) flatbuffers.UOffsetT {
	nameOffset := builder.CreateString(op.Name)

	// Build type info for the operand if we have a registered type
	var typeInfoOffset flatbuffers.UOffsetT
	if op.TypeID != 0 {
		if ref, ok := typeMap[op.TypeID]; ok {
			typeInfoOffset = buildTypeInfo(builder, &ref)
		}
	}

	// Build constant value string
	var constValOffset flatbuffers.UOffsetT
	if op.IsConst && !op.IsNil {
		constValOffset = builder.CreateString("const")
	}

	ir.OperandStart(builder)
	ir.OperandAddName(builder, nameOffset)
	if typeInfoOffset != 0 {
		ir.OperandAddTypeInfo(builder, typeInfoOffset)
	}
	ir.OperandAddIsConstant(builder, op.IsConst)
	if constValOffset != 0 {
		ir.OperandAddConstantValue(builder, constValOffset)
	}
	ir.OperandAddIsNil(builder, op.IsNil)
	return ir.OperandEnd(builder)
}

// buildSourcePos serializes a SpanIR into a SourcePos table.
func buildSourcePos(builder *flatbuffers.Builder, span *SpanIR) flatbuffers.UOffsetT {
	fileOffset := builder.CreateString(span.File)
	ir.SourcePosStart(builder)
	ir.SourcePosAddFile(builder, fileOffset)
	ir.SourcePosAddLine(builder, int32(span.StartLine))
	ir.SourcePosAddColumn(builder, int32(span.StartCol))
	ir.SourcePosAddEndLine(builder, int32(span.EndLine))
	ir.SourcePosAddEndColumn(builder, int32(span.EndCol))
	return ir.SourcePosEnd(builder)
}

// buildTypeInfo converts a TypeRefIR to a FlatBuffers TypeInfo table.
func buildTypeInfo(builder *flatbuffers.Builder, ref *TypeRefIR) flatbuffers.UOffsetT {
	nameOffset := builder.CreateString(ref.Name)

	kind := mapTypeKind(ref.Kind)

	ir.TypeInfoStart(builder)
	ir.TypeInfoAddKind(builder, kind)
	ir.TypeInfoAddName(builder, nameOffset)
	ir.TypeInfoAddIsPointer(builder, ref.Kind == "Pointer")
	ir.TypeInfoAddIsInterface(builder, ref.Kind == "Interface")
	ir.TypeInfoAddIsError(builder, isErrorType(ref.Name))
	ir.TypeInfoAddIsChannel(builder, ref.Kind == "Chan")
	return ir.TypeInfoEnd(builder)
}

// buildCallGraph creates the CallGraph table from all collected call edges.
func buildCallGraph(builder *flatbuffers.Builder, edges []CallEdgeIR) flatbuffers.UOffsetT {
	edgeOffsets := make([]flatbuffers.UOffsetT, len(edges))
	for i := len(edges) - 1; i >= 0; i-- {
		edgeOffsets[i] = buildCallEdge(builder, &edges[i])
	}

	// Create edges vector
	ir.CallGraphStartEdgesVector(builder, len(edgeOffsets))
	for i := len(edgeOffsets) - 1; i >= 0; i-- {
		builder.PrependUOffsetT(edgeOffsets[i])
	}
	edgesVec := builder.EndVector(len(edgeOffsets))

	ir.CallGraphStart(builder)
	ir.CallGraphAddEdges(builder, edgesVec)
	return ir.CallGraphEnd(builder)
}

// buildCallEdge serializes a CallEdgeIR into a FlatBuffers CallEdge table.
func buildCallEdge(builder *flatbuffers.Builder, edge *CallEdgeIR) flatbuffers.UOffsetT {
	// Build source pos if present
	var callSiteOffset flatbuffers.UOffsetT
	if edge.Span != nil {
		callSiteOffset = buildSourcePos(builder, edge.Span)
	}

	callerOffset := builder.CreateString(edge.Caller)
	calleeOffset := builder.CreateString(edge.Callee)

	ir.CallEdgeStart(builder)
	ir.CallEdgeAddCaller(builder, callerOffset)
	ir.CallEdgeAddCallee(builder, calleeOffset)
	if edge.Span != nil {
		ir.CallEdgeAddCallSite(builder, callSiteOffset)
	}
	ir.CallEdgeAddIsStatic(builder, !edge.IsDynamic)
	ir.CallEdgeAddIsGo(builder, edge.IsGo)
	ir.CallEdgeAddIsDefer(builder, edge.IsDefer)
	return ir.CallEdgeEnd(builder)
}

// buildInterfaceTable creates the InterfaceTable from all collected interface satisfactions.
func buildInterfaceTable(builder *flatbuffers.Builder, sats []InterfaceSatIR, typeMap map[uint]TypeRefIR) flatbuffers.UOffsetT {
	// Group by interface type ID to create InterfaceEntry entries.
	// Each InterfaceEntry has: interface_name, implementors[], methods[]
	type ifaceData struct {
		name         string
		implementors []string
		methods      []string
	}
	ifaceMap := make(map[uint]*ifaceData)
	var ifaceOrder []uint

	for _, sat := range sats {
		data, ok := ifaceMap[sat.InterfaceTypeID]
		if !ok {
			ifaceName := ""
			if ref, ok := typeMap[sat.InterfaceTypeID]; ok {
				ifaceName = ref.Name
			}
			data = &ifaceData{name: ifaceName}
			ifaceMap[sat.InterfaceTypeID] = data
			ifaceOrder = append(ifaceOrder, sat.InterfaceTypeID)
		}

		// Add implementor
		concreteTypeName := ""
		if ref, ok := typeMap[sat.ConcreteTypeID]; ok {
			concreteTypeName = ref.Name
		}
		data.implementors = append(data.implementors, concreteTypeName)

		// Add methods (from the first satisfaction only, they are the same for the interface)
		if len(data.methods) == 0 {
			for _, m := range sat.Methods {
				data.methods = append(data.methods, m.InterfaceMethod)
			}
		}
	}

	// Build InterfaceEntry offsets
	entryOffsets := make([]flatbuffers.UOffsetT, len(ifaceOrder))
	for i := len(ifaceOrder) - 1; i >= 0; i-- {
		data := ifaceMap[ifaceOrder[i]]
		entryOffsets[i] = buildInterfaceEntry(builder, data.name, data.implementors, data.methods)
	}

	// Create entries vector
	ir.InterfaceTableStartEntriesVector(builder, len(entryOffsets))
	for i := len(entryOffsets) - 1; i >= 0; i-- {
		builder.PrependUOffsetT(entryOffsets[i])
	}
	entriesVec := builder.EndVector(len(entryOffsets))

	ir.InterfaceTableStart(builder)
	ir.InterfaceTableAddEntries(builder, entriesVec)
	return ir.InterfaceTableEnd(builder)
}

// buildInterfaceEntry creates a single InterfaceEntry table.
func buildInterfaceEntry(builder *flatbuffers.Builder, name string, implementors []string, methods []string) flatbuffers.UOffsetT {
	// Build methods vector
	methodOffsets := make([]flatbuffers.UOffsetT, len(methods))
	for i := len(methods) - 1; i >= 0; i-- {
		methodOffsets[i] = builder.CreateString(methods[i])
	}
	ir.InterfaceEntryStartMethodsVector(builder, len(methodOffsets))
	for i := len(methodOffsets) - 1; i >= 0; i-- {
		builder.PrependUOffsetT(methodOffsets[i])
	}
	methodsVec := builder.EndVector(len(methodOffsets))

	// Build implementors vector
	implOffsets := make([]flatbuffers.UOffsetT, len(implementors))
	for i := len(implementors) - 1; i >= 0; i-- {
		implOffsets[i] = builder.CreateString(implementors[i])
	}
	ir.InterfaceEntryStartImplementorsVector(builder, len(implOffsets))
	for i := len(implOffsets) - 1; i >= 0; i-- {
		builder.PrependUOffsetT(implOffsets[i])
	}
	implVec := builder.EndVector(len(implOffsets))

	nameOffset := builder.CreateString(name)

	ir.InterfaceEntryStart(builder)
	ir.InterfaceEntryAddInterfaceName(builder, nameOffset)
	ir.InterfaceEntryAddImplementors(builder, implVec)
	ir.InterfaceEntryAddMethods(builder, methodsVec)
	return ir.InterfaceEntryEnd(builder)
}

// mapInstructionKind maps an instruction kind string to the FlatBuffers enum.
func mapInstructionKind(kind string) ir.InstructionKind {
	if val, ok := ir.EnumValuesInstructionKind[kind]; ok {
		return val
	}
	// Handle edge cases where analyzer.go produces kinds not in the enum
	switch kind {
	case "Parameter":
		return ir.InstructionKindFuncParam
	case "DebugRef":
		return ir.InstructionKindUnknown
	default:
		return ir.InstructionKindUnknown
	}
}

// mapTypeKind maps a type kind string from TypeRefIR to the FlatBuffers TypeKind enum.
func mapTypeKind(kind string) ir.TypeKind {
	switch kind {
	case "Basic":
		return ir.TypeKindBasic
	case "Named":
		return ir.TypeKindNamed
	case "Pointer":
		return ir.TypeKindPointer
	case "Slice":
		return ir.TypeKindSlice
	case "Array":
		return ir.TypeKindArray
	case "Map":
		return ir.TypeKindMap
	case "Chan":
		return ir.TypeKindChannel
	case "Struct":
		return ir.TypeKindStruct
	case "Interface":
		return ir.TypeKindInterface
	case "Signature":
		return ir.TypeKindFunction
	case "Tuple":
		return ir.TypeKindTuple
	default:
		return ir.TypeKindBasic
	}
}

// isErrorType checks whether a type name represents Go's error interface.
func isErrorType(name string) bool {
	return name == "error" || strings.HasSuffix(name, ".error")
}
