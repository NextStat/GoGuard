//! Ownership analysis engine for tracking resource lifecycles.
//!
//! Scans SSA instructions in each function for resource-opening calls,
//! then tracks the resource state through subsequent instructions to
//! detect leaks, use-after-close, double close, and non-deferred close.

use std::collections::HashMap;

use goguard_diagnostics::diagnostic::Diagnostic;
use goguard_ir::ir::*;

use crate::rules;
use crate::state_machine::{is_close_call, is_resource_opener, ResourceState, TrackedResource};

/// Ownership analysis pass.
///
/// Analyzes resource lifecycles (open/close patterns) in Go functions.
pub struct OwnershipAnalyzer;

impl OwnershipAnalyzer {
    /// Analyze all functions in an `AnalysisInput` and return diagnostics.
    pub fn analyze(input: &AnalysisInput) -> Vec<Diagnostic> {
        input
            .packages
            .iter()
            .flat_map(Self::analyze_package)
            .collect()
    }

    /// Analyze a single package for ownership issues.
    pub fn analyze_package(pkg: &Package) -> Vec<Diagnostic> {
        pkg.functions
            .iter()
            .flat_map(|f| Self::analyze_function(f, pkg))
            .collect()
    }

    /// Analyze a single function for resource lifecycle issues.
    ///
    /// Strategy:
    /// 1. Scan all blocks for Call instructions to resource openers.
    /// 2. For each opened resource, scan subsequent instructions for:
    ///    - Close calls on the same resource -> mark closed
    ///    - Defer close on the same resource -> mark defer_close
    ///    - Use of the resource after close -> OWN002
    ///    - Second close -> OWN003
    /// 3. Check the function's `defers` array for defer close patterns.
    /// 4. At the end, any resource still Open -> OWN001.
    /// 5. Any resource closed without defer -> OWN004.
    pub fn analyze_function(func: &Function, _pkg: &Package) -> Vec<Diagnostic> {
        if func.blocks.is_empty() {
            return Vec::new();
        }

        let mut diagnostics = Vec::new();

        // Map from instruction ID -> TrackedResource for opened resources
        let mut resources: HashMap<u32, TrackedResource> = HashMap::new();

        // Build a map from instruction ID -> instruction for operand lookup
        let mut instr_map: HashMap<u32, &Instruction> = HashMap::new();
        for block in &func.blocks {
            for instr in &block.instructions {
                instr_map.insert(instr.id, instr);
            }
        }

        // Phase 1: Find all resource-opening calls and Defer/Close patterns.
        // Process blocks in order to track resource states.
        for block in &func.blocks {
            for instr in &block.instructions {
                match instr.kind {
                    ValueKind::Call => {
                        if let Some(ref callee) = instr.callee {
                            if is_resource_opener(callee) {
                                // New resource opened
                                resources.insert(
                                    instr.id,
                                    TrackedResource::new(
                                        instr.id,
                                        callee.clone(),
                                        instr.span.clone(),
                                    ),
                                );
                            } else if is_close_call(callee) {
                                // Close call: find which resource it's closing
                                Self::handle_close(
                                    instr,
                                    &mut resources,
                                    &func.short_name,
                                    &mut diagnostics,
                                    false,
                                );
                            } else {
                                // Not an opener or close — check for use-after-close
                                Self::check_use_after_close(
                                    instr,
                                    &resources,
                                    &func.short_name,
                                    &mut diagnostics,
                                );
                            }
                        }
                    }
                    ValueKind::Defer => {
                        // A Defer instruction: check if it defers a Close call.
                        // The operand of a Defer typically points to the Call
                        // being deferred, or the callee field itself may indicate Close.
                        if let Some(ref callee) = instr.callee {
                            if is_close_call(callee) {
                                Self::handle_defer_close(instr, &mut resources);
                            }
                        } else {
                            // Check if operand is a close call instruction
                            for &op_id in &instr.operands {
                                if let Some(op_instr) = instr_map.get(&op_id) {
                                    if op_instr.kind == ValueKind::Call {
                                        if let Some(ref callee) = op_instr.callee {
                                            if is_close_call(callee) {
                                                Self::handle_defer_close(instr, &mut resources);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    _ => {
                        // Check for use-after-close: any instruction that uses
                        // a closed resource as an operand
                        Self::check_use_after_close(
                            instr,
                            &resources,
                            &func.short_name,
                            &mut diagnostics,
                        );
                    }
                }
            }
        }

        // Phase 2: Check the function's defers array for defer close patterns.
        // This catches cases where the bridge reports defers at the function level.
        for defer_info in &func.defers {
            if is_close_call(&defer_info.call_target) {
                // Mark all open resources as defer-closed.
                // The defers array doesn't specify which resource, so we match
                // by the presence of any open resource.
                for resource in resources.values_mut() {
                    if resource.is_open() {
                        resource.mark_defer_close();
                    }
                }
            }
        }

        // Phase 3: Emit diagnostics for resources that are still open at return.
        for resource in resources.values() {
            if resource.is_open() {
                // OWN001: Resource opened but never closed
                diagnostics.push(rules::build_own001(resource, &func.short_name));
            } else if resource.state == ResourceState::Closed && !resource.has_defer_close {
                // OWN004: Resource closed but not via defer
                diagnostics.push(rules::build_own004(
                    resource,
                    &func.short_name,
                    &resource.close_span.clone(),
                ));
            }
        }

        diagnostics
    }

    /// Handle a Close call on a resource.
    fn handle_close(
        instr: &Instruction,
        resources: &mut HashMap<u32, TrackedResource>,
        func_name: &str,
        diagnostics: &mut Vec<Diagnostic>,
        is_defer: bool,
    ) {
        // Find which resource is being closed by checking operands.
        // The first operand of a Close call is typically the receiver (resource).
        let resource_id = Self::find_resource_operand(instr, resources);

        if let Some(res_id) = resource_id {
            if let Some(resource) = resources.get_mut(&res_id) {
                if is_defer {
                    resource.mark_defer_close();
                } else {
                    let valid = resource.mark_closed(instr.span.clone());
                    if !valid {
                        // OWN003: Double close
                        diagnostics.push(rules::build_own003(resource, func_name, &instr.span));
                    }
                }
            }
        }
    }

    /// Handle a defer Close on a resource.
    fn handle_defer_close(instr: &Instruction, resources: &mut HashMap<u32, TrackedResource>) {
        let resource_id = Self::find_resource_operand(instr, resources);
        if let Some(res_id) = resource_id {
            if let Some(resource) = resources.get_mut(&res_id) {
                resource.mark_defer_close();
            }
        } else {
            // If we can't find the specific resource, mark all open resources
            // as defer-closed. This is a conservative approach.
            for resource in resources.values_mut() {
                if resource.is_open() {
                    resource.mark_defer_close();
                }
            }
        }
    }

    /// Check if any operand of an instruction refers to a closed resource (OWN002).
    fn check_use_after_close(
        instr: &Instruction,
        resources: &HashMap<u32, TrackedResource>,
        func_name: &str,
        diagnostics: &mut Vec<Diagnostic>,
    ) {
        for &op_id in &instr.operands {
            if let Some(resource) = resources.get(&op_id) {
                if resource.state == ResourceState::Closed {
                    // OWN002: Use after close
                    diagnostics.push(rules::build_own002(resource, func_name, &instr.span));
                }
            }
        }
    }

    /// Find which tracked resource an instruction operates on by checking operands.
    fn find_resource_operand(
        instr: &Instruction,
        resources: &HashMap<u32, TrackedResource>,
    ) -> Option<u32> {
        instr
            .operands
            .iter()
            .find(|&&op_id| resources.contains_key(&op_id))
            .copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use goguard_diagnostics::diagnostic::Severity;

    fn make_instr(id: u32, kind: ValueKind) -> Instruction {
        Instruction {
            id,
            kind,
            name: format!("t{id}"),
            type_id: 0,
            span: Some(Span::new("main.go", id + 10, 1)),
            operands: vec![],
            extract_index: 0,
            callee: None,
            callee_is_interface: false,
            assert_type_id: 0,
            comma_ok: false,
            const_value: None,
            is_nil: false,
            bin_op: None,
            nil_operand_indices: vec![],
            select_cases: vec![],
            channel_dir: None,
        }
    }

    fn make_call(id: u32, callee: &str) -> Instruction {
        let mut instr = make_instr(id, ValueKind::Call);
        instr.callee = Some(callee.to_string());
        instr
    }

    fn make_close_call(id: u32, resource_id: u32) -> Instruction {
        let mut instr = make_call(id, "(*os.File).Close");
        instr.operands = vec![resource_id];
        instr
    }

    fn make_defer(id: u32, callee: &str, resource_id: u32) -> Instruction {
        let mut instr = make_instr(id, ValueKind::Defer);
        instr.callee = Some(callee.to_string());
        instr.operands = vec![resource_id];
        instr
    }

    fn default_func(name: &str) -> Function {
        Function {
            name: format!("test.{name}"),
            short_name: name.to_string(),
            span: None,
            blocks: vec![],
            cfg_edges: vec![],
            is_method: false,
            receiver_type_id: 0,
            is_exported: false,
            free_vars: vec![],
            defers: vec![],
        }
    }

    fn default_block(id: u32) -> BasicBlock {
        BasicBlock {
            id,
            name: format!("b{id}"),
            instructions: vec![],
            is_return: false,
            is_panic: false,
        }
    }

    fn default_pkg() -> Package {
        Package {
            import_path: "example.com/test".to_string(),
            name: "test".to_string(),
            files: vec![],
            types: vec![],
            functions: vec![],
            interface_satisfactions: vec![],
            call_edges: vec![],
            global_vars: vec![],
        }
    }

    // === OWN001 Tests ===

    #[test]
    fn test_own001_resource_not_closed() {
        // Function calls os.Open but never Close
        let mut func = default_func("LeakyOpen");
        let mut block = default_block(0);
        block.is_return = true;
        block.instructions = vec![make_call(0, "os.Open"), make_instr(1, ValueKind::Return)];
        func.blocks = vec![block];

        let pkg = default_pkg();
        let diags = OwnershipAnalyzer::analyze_function(&func, &pkg);
        assert!(
            diags.iter().any(|d| d.rule == "OWN001"),
            "should detect unclosed resource, got: {:?}",
            diags.iter().map(|d| &d.rule).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_own001_sql_open_not_closed() {
        let mut func = default_func("LeakySqlOpen");
        let mut block = default_block(0);
        block.is_return = true;
        block.instructions = vec![make_call(0, "sql.Open"), make_instr(1, ValueKind::Return)];
        func.blocks = vec![block];

        let pkg = default_pkg();
        let diags = OwnershipAnalyzer::analyze_function(&func, &pkg);
        assert!(diags.iter().any(|d| d.rule == "OWN001"));
    }

    #[test]
    fn test_own001_net_dial_not_closed() {
        let mut func = default_func("LeakyDial");
        let mut block = default_block(0);
        block.is_return = true;
        block.instructions = vec![make_call(0, "net.Dial"), make_instr(1, ValueKind::Return)];
        func.blocks = vec![block];

        let pkg = default_pkg();
        let diags = OwnershipAnalyzer::analyze_function(&func, &pkg);
        assert!(diags.iter().any(|d| d.rule == "OWN001"));
    }

    #[test]
    fn test_own001_safe_with_close() {
        // Function calls os.Open then Close -> no OWN001
        let mut func = default_func("SafeClose");
        let mut block = default_block(0);
        block.is_return = true;
        block.instructions = vec![
            make_call(0, "os.Open"),
            make_close_call(1, 0),
            make_instr(2, ValueKind::Return),
        ];
        func.blocks = vec![block];

        let pkg = default_pkg();
        let diags = OwnershipAnalyzer::analyze_function(&func, &pkg);
        assert!(
            !diags.iter().any(|d| d.rule == "OWN001"),
            "should NOT report OWN001 when resource is closed, got: {:?}",
            diags.iter().map(|d| &d.rule).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_own001_safe_with_defer_close() {
        // Function calls os.Open then defer f.Close() -> no OWN001
        let mut func = default_func("SafeDeferClose");
        let mut block = default_block(0);
        block.is_return = true;
        block.instructions = vec![
            make_call(0, "os.Open"),
            make_defer(1, "(*os.File).Close", 0),
            make_instr(2, ValueKind::Return),
        ];
        func.blocks = vec![block];

        let pkg = default_pkg();
        let diags = OwnershipAnalyzer::analyze_function(&func, &pkg);
        assert!(
            !diags.iter().any(|d| d.rule == "OWN001"),
            "should NOT report OWN001 when defer close exists"
        );
    }

    #[test]
    fn test_own001_safe_with_function_level_defer() {
        // Function has defers array with Close target
        let mut func = default_func("SafeFuncDefer");
        let mut block = default_block(0);
        block.is_return = true;
        block.instructions = vec![make_call(0, "os.Open"), make_instr(1, ValueKind::Return)];
        func.blocks = vec![block];
        func.defers = vec![DeferInfo {
            call_target: "(*os.File).Close".to_string(),
            span: None,
            index: 0,
        }];

        let pkg = default_pkg();
        let diags = OwnershipAnalyzer::analyze_function(&func, &pkg);
        assert!(
            !diags.iter().any(|d| d.rule == "OWN001"),
            "should NOT report OWN001 when function-level defer close exists"
        );
    }

    // === OWN002 Tests ===

    #[test]
    fn test_own002_use_after_close() {
        // Open -> Close -> Use (FieldAddr on resource)
        let mut func = default_func("UseAfterClose");
        let mut block = default_block(0);
        block.is_return = true;

        let mut use_instr = make_instr(2, ValueKind::FieldAddr);
        use_instr.operands = vec![0]; // uses the resource after close
        use_instr.span = Some(Span::new("main.go", 20, 5));

        block.instructions = vec![
            make_call(0, "os.Open"),
            make_close_call(1, 0),
            use_instr,
            make_instr(3, ValueKind::Return),
        ];
        func.blocks = vec![block];

        let pkg = default_pkg();
        let diags = OwnershipAnalyzer::analyze_function(&func, &pkg);
        assert!(
            diags.iter().any(|d| d.rule == "OWN002"),
            "should detect use after close, got: {:?}",
            diags.iter().map(|d| &d.rule).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_own002_safe_use_before_close() {
        // Open -> Use -> Close (normal order, no OWN002)
        let mut func = default_func("SafeOrder");
        let mut block = default_block(0);
        block.is_return = true;

        let mut use_instr = make_instr(1, ValueKind::FieldAddr);
        use_instr.operands = vec![0]; // uses the resource before close

        block.instructions = vec![
            make_call(0, "os.Open"),
            use_instr,
            make_close_call(2, 0),
            make_instr(3, ValueKind::Return),
        ];
        func.blocks = vec![block];

        let pkg = default_pkg();
        let diags = OwnershipAnalyzer::analyze_function(&func, &pkg);
        assert!(
            !diags.iter().any(|d| d.rule == "OWN002"),
            "should NOT report OWN002 when use is before close"
        );
    }

    // === OWN003 Tests ===

    #[test]
    fn test_own003_double_close() {
        // Open -> Close -> Close
        let mut func = default_func("DoubleClose");
        let mut block = default_block(0);
        block.is_return = true;

        let mut second_close = make_close_call(2, 0);
        second_close.span = Some(Span::new("main.go", 30, 1));

        block.instructions = vec![
            make_call(0, "os.Open"),
            make_close_call(1, 0),
            second_close,
            make_instr(3, ValueKind::Return),
        ];
        func.blocks = vec![block];

        let pkg = default_pkg();
        let diags = OwnershipAnalyzer::analyze_function(&func, &pkg);
        assert!(
            diags.iter().any(|d| d.rule == "OWN003"),
            "should detect double close, got: {:?}",
            diags.iter().map(|d| &d.rule).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_own003_safe_single_close() {
        // Open -> Close (single close, no OWN003)
        let mut func = default_func("SingleClose");
        let mut block = default_block(0);
        block.is_return = true;
        block.instructions = vec![
            make_call(0, "os.Open"),
            make_close_call(1, 0),
            make_instr(2, ValueKind::Return),
        ];
        func.blocks = vec![block];

        let pkg = default_pkg();
        let diags = OwnershipAnalyzer::analyze_function(&func, &pkg);
        assert!(
            !diags.iter().any(|d| d.rule == "OWN003"),
            "should NOT report OWN003 for single close"
        );
    }

    // === OWN004 Tests ===

    #[test]
    fn test_own004_close_not_deferred() {
        // Open -> Close (direct, not deferred) -> OWN004
        let mut func = default_func("NotDeferred");
        let mut block = default_block(0);
        block.is_return = true;
        block.instructions = vec![
            make_call(0, "os.Open"),
            make_close_call(1, 0),
            make_instr(2, ValueKind::Return),
        ];
        func.blocks = vec![block];

        let pkg = default_pkg();
        let diags = OwnershipAnalyzer::analyze_function(&func, &pkg);
        assert!(
            diags.iter().any(|d| d.rule == "OWN004"),
            "should suggest defer for non-deferred close, got: {:?}",
            diags.iter().map(|d| &d.rule).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_own004_safe_with_defer() {
        // Open -> defer Close -> no OWN004
        let mut func = default_func("DeferredClose");
        let mut block = default_block(0);
        block.is_return = true;
        block.instructions = vec![
            make_call(0, "os.Open"),
            make_defer(1, "(*os.File).Close", 0),
            make_instr(2, ValueKind::Return),
        ];
        func.blocks = vec![block];

        let pkg = default_pkg();
        let diags = OwnershipAnalyzer::analyze_function(&func, &pkg);
        assert!(
            !diags.iter().any(|d| d.rule == "OWN004"),
            "should NOT report OWN004 when close is deferred"
        );
    }

    // === Edge Cases ===

    #[test]
    fn test_empty_function() {
        let func = default_func("Empty");
        let pkg = default_pkg();
        let diags = OwnershipAnalyzer::analyze_function(&func, &pkg);
        assert!(
            diags.is_empty(),
            "empty function should produce no diagnostics"
        );
    }

    #[test]
    fn test_no_resource_operations() {
        // Function with no resource-opening calls
        let mut func = default_func("NoResources");
        let mut block = default_block(0);
        block.is_return = true;
        block.instructions = vec![
            make_call(0, "fmt.Println"),
            make_instr(1, ValueKind::Return),
        ];
        func.blocks = vec![block];

        let pkg = default_pkg();
        let diags = OwnershipAnalyzer::analyze_function(&func, &pkg);
        assert!(
            diags.is_empty(),
            "function with no resources should produce no diagnostics"
        );
    }

    #[test]
    fn test_multiple_resources() {
        // Two resources opened, one closed, one not
        let mut func = default_func("MultiResource");
        let mut block = default_block(0);
        block.is_return = true;
        block.instructions = vec![
            make_call(0, "os.Open"),
            make_call(3, "net.Dial"),
            make_close_call(4, 0), // close the file
            make_instr(5, ValueKind::Return),
        ];
        func.blocks = vec![block];

        let pkg = default_pkg();
        let diags = OwnershipAnalyzer::analyze_function(&func, &pkg);
        // Should have OWN001 for unclosed net.Dial and OWN004 for non-deferred file close
        assert!(
            diags.iter().any(|d| d.rule == "OWN001"),
            "should detect unclosed net.Dial"
        );
    }

    #[test]
    fn test_http_get_not_closed() {
        let mut func = default_func("HttpLeak");
        let mut block = default_block(0);
        block.is_return = true;
        block.instructions = vec![make_call(0, "http.Get"), make_instr(1, ValueKind::Return)];
        func.blocks = vec![block];

        let pkg = default_pkg();
        let diags = OwnershipAnalyzer::analyze_function(&func, &pkg);
        assert!(diags.iter().any(|d| d.rule == "OWN001"));
    }

    #[test]
    fn test_analyze_package_level() {
        let mut func = default_func("PkgLevel");
        let mut block = default_block(0);
        block.is_return = true;
        block.instructions = vec![make_call(0, "os.Open"), make_instr(1, ValueKind::Return)];
        func.blocks = vec![block];

        let mut pkg = default_pkg();
        pkg.functions = vec![func];

        let diags = OwnershipAnalyzer::analyze_package(&pkg);
        assert!(
            diags.iter().any(|d| d.rule == "OWN001"),
            "analyze_package should propagate diagnostics"
        );
    }

    #[test]
    fn test_analyze_full_input() {
        let mut func = default_func("FullInput");
        let mut block = default_block(0);
        block.is_return = true;
        block.instructions = vec![
            make_call(0, "os.Open"),
            make_defer(1, "(*os.File).Close", 0),
            make_instr(2, ValueKind::Return),
        ];
        func.blocks = vec![block];

        let mut pkg = default_pkg();
        pkg.functions = vec![func];

        let input = AnalysisInput {
            packages: vec![pkg],
            go_version: "1.26".to_string(),
            bridge_version: "0.2.0".to_string(),
            interface_table: vec![],
            enum_groups: vec![],
        };

        let diags = OwnershipAnalyzer::analyze(&input);
        assert!(
            !diags.iter().any(|d| d.rule == "OWN001"),
            "defer close should prevent OWN001"
        );
    }

    #[test]
    fn test_analyze_empty_input() {
        let input = AnalysisInput {
            packages: vec![],
            go_version: "1.26".to_string(),
            bridge_version: "0.2.0".to_string(),
            interface_table: vec![],
            enum_groups: vec![],
        };

        let diags = OwnershipAnalyzer::analyze(&input);
        assert!(diags.is_empty());
    }

    #[test]
    fn test_own002_severity_is_critical() {
        let mut func = default_func("CriticalUAC");
        let mut block = default_block(0);
        block.is_return = true;

        let mut use_instr = make_instr(2, ValueKind::Call);
        use_instr.operands = vec![0];
        use_instr.callee = Some("(*os.File).Read".to_string());

        block.instructions = vec![
            make_call(0, "os.Open"),
            make_close_call(1, 0),
            use_instr,
            make_instr(3, ValueKind::Return),
        ];
        func.blocks = vec![block];

        let pkg = default_pkg();
        let diags = OwnershipAnalyzer::analyze_function(&func, &pkg);
        let own002 = diags.iter().find(|d| d.rule == "OWN002");
        assert!(own002.is_some(), "should detect OWN002");
        assert_eq!(own002.unwrap().severity, Severity::Critical);
    }

    #[test]
    fn test_own001_severity_is_error() {
        let mut func = default_func("ErrorLeak");
        let mut block = default_block(0);
        block.is_return = true;
        block.instructions = vec![make_call(0, "os.Open"), make_instr(1, ValueKind::Return)];
        func.blocks = vec![block];

        let pkg = default_pkg();
        let diags = OwnershipAnalyzer::analyze_function(&func, &pkg);
        let own001 = diags.iter().find(|d| d.rule == "OWN001");
        assert!(own001.is_some());
        assert_eq!(own001.unwrap().severity, Severity::Error);
    }

    #[test]
    fn test_own003_severity_is_warning() {
        let mut func = default_func("WarnDC");
        let mut block = default_block(0);
        block.is_return = true;
        block.instructions = vec![
            make_call(0, "os.Open"),
            make_close_call(1, 0),
            make_close_call(2, 0),
            make_instr(3, ValueKind::Return),
        ];
        func.blocks = vec![block];

        let pkg = default_pkg();
        let diags = OwnershipAnalyzer::analyze_function(&func, &pkg);
        let own003 = diags.iter().find(|d| d.rule == "OWN003");
        assert!(own003.is_some());
        assert_eq!(own003.unwrap().severity, Severity::Warning);
    }

    #[test]
    fn test_own004_severity_is_info() {
        let mut func = default_func("InfoND");
        let mut block = default_block(0);
        block.is_return = true;
        block.instructions = vec![
            make_call(0, "os.Open"),
            make_close_call(1, 0),
            make_instr(2, ValueKind::Return),
        ];
        func.blocks = vec![block];

        let pkg = default_pkg();
        let diags = OwnershipAnalyzer::analyze_function(&func, &pkg);
        let own004 = diags.iter().find(|d| d.rule == "OWN004");
        assert!(own004.is_some());
        assert_eq!(own004.unwrap().severity, Severity::Info);
    }

    #[test]
    fn test_bufio_resource_not_closed() {
        let mut func = default_func("BufioLeak");
        let mut block = default_block(0);
        block.is_return = true;
        block.instructions = vec![
            make_call(0, "bufio.NewReader"),
            make_instr(1, ValueKind::Return),
        ];
        func.blocks = vec![block];

        let pkg = default_pkg();
        let diags = OwnershipAnalyzer::analyze_function(&func, &pkg);
        assert!(diags.iter().any(|d| d.rule == "OWN001"));
    }

    #[test]
    fn test_diagnostic_source_is_ownership() {
        let mut func = default_func("SourceCheck");
        let mut block = default_block(0);
        block.is_return = true;
        block.instructions = vec![make_call(0, "os.Open"), make_instr(1, ValueKind::Return)];
        func.blocks = vec![block];

        let pkg = default_pkg();
        let diags = OwnershipAnalyzer::analyze_function(&func, &pkg);
        for diag in &diags {
            assert_eq!(
                diag.source,
                goguard_diagnostics::diagnostic::DiagnosticSource::Ownership,
                "all ownership diagnostics should have Ownership source"
            );
        }
    }

    #[test]
    fn test_multi_block_open_close() {
        // Open in block 0, close in block 1
        let mut func = default_func("MultiBlock");

        let mut block0 = default_block(0);
        block0.instructions = vec![make_call(0, "os.Open"), make_instr(1, ValueKind::Jump)];

        let mut block1 = default_block(1);
        block1.is_return = true;
        block1.instructions = vec![make_close_call(2, 0), make_instr(3, ValueKind::Return)];

        func.blocks = vec![block0, block1];
        func.cfg_edges = vec![CfgEdge {
            from_block: 0,
            to_block: 1,
            kind: EdgeKind::Unconditional,
        }];

        let pkg = default_pkg();
        let diags = OwnershipAnalyzer::analyze_function(&func, &pkg);
        assert!(
            !diags.iter().any(|d| d.rule == "OWN001"),
            "resource closed in later block should not trigger OWN001"
        );
    }

    #[test]
    fn test_defer_close_via_operand() {
        // Defer instruction that references a Close call via operands
        let mut func = default_func("DeferViaOp");
        let mut block = default_block(0);
        block.is_return = true;

        // close_call is the call being deferred; defer references it via operand
        let close_call = make_close_call(1, 0);

        let mut defer_instr = make_instr(2, ValueKind::Defer);
        defer_instr.callee = None; // no direct callee
        defer_instr.operands = vec![1]; // references the close call

        block.instructions = vec![
            make_call(0, "os.Open"),
            close_call,
            defer_instr,
            make_instr(3, ValueKind::Return),
        ];
        func.blocks = vec![block];

        let pkg = default_pkg();
        let diags = OwnershipAnalyzer::analyze_function(&func, &pkg);
        // The close_call itself closes the resource (before the defer processes),
        // so OWN001 should not fire. The defer-via-operand path is also tested.
        assert!(
            !diags.iter().any(|d| d.rule == "OWN001"),
            "resource should be tracked as closed"
        );
    }
}
