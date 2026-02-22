//! CFG navigation helpers over deserialized bridge data.
//!
//! Provides graph algorithms (dominators, reachability, cycle detection)
//! over the CFG that was built by go/ssa in the Go bridge.

use crate::ir::{BasicBlock, EdgeKind, Function, Instruction, ValueKind};
use std::collections::{HashMap, HashSet, VecDeque};

/// A traversable view of a function's CFG
pub struct Cfg<'a> {
    func: &'a Function,
    successors: HashMap<u32, Vec<(u32, &'a EdgeKind)>>,
    predecessors: HashMap<u32, Vec<(u32, &'a EdgeKind)>>,
    block_map: HashMap<u32, &'a BasicBlock>,
}

impl<'a> Cfg<'a> {
    /// Build traversal indices from a deserialized function
    pub fn from_function(func: &'a Function) -> Self {
        let mut successors: HashMap<u32, Vec<(u32, &EdgeKind)>> = HashMap::new();
        let mut predecessors: HashMap<u32, Vec<(u32, &EdgeKind)>> = HashMap::new();
        let mut block_map = HashMap::new();

        for block in &func.blocks {
            block_map.insert(block.id, block);
            successors.entry(block.id).or_default();
            predecessors.entry(block.id).or_default();
        }

        for edge in &func.cfg_edges {
            successors
                .entry(edge.from_block)
                .or_default()
                .push((edge.to_block, &edge.kind));
            predecessors
                .entry(edge.to_block)
                .or_default()
                .push((edge.from_block, &edge.kind));
        }

        Self {
            func,
            successors,
            predecessors,
            block_map,
        }
    }

    /// Entry block (always block 0 in go/ssa)
    pub fn entry_block(&self) -> Option<&'a BasicBlock> {
        self.block_map.get(&0).copied()
    }

    /// Get block by ID
    pub fn block(&self, id: u32) -> Option<&'a BasicBlock> {
        self.block_map.get(&id).copied()
    }

    /// Successors of a block
    pub fn successors(&self, block_id: u32) -> &[(u32, &'a EdgeKind)] {
        self.successors
            .get(&block_id)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Predecessors of a block
    pub fn predecessors(&self, block_id: u32) -> &[(u32, &'a EdgeKind)] {
        self.predecessors
            .get(&block_id)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// All blocks in the CFG
    pub fn blocks(&self) -> impl Iterator<Item = &'a BasicBlock> {
        self.func.blocks.iter()
    }

    /// Number of blocks
    pub fn block_count(&self) -> usize {
        self.func.blocks.len()
    }

    /// All return blocks
    pub fn return_blocks(&self) -> Vec<&'a BasicBlock> {
        self.func.blocks.iter().filter(|b| b.is_return).collect()
    }

    /// All panic blocks
    pub fn panic_blocks(&self) -> Vec<&'a BasicBlock> {
        self.func.blocks.iter().filter(|b| b.is_panic).collect()
    }

    /// BFS traversal from entry
    pub fn bfs_order(&self) -> Vec<u32> {
        let mut visited = HashSet::new();
        let mut order = Vec::new();
        let mut queue = VecDeque::new();

        if let Some(entry) = self.entry_block() {
            queue.push_back(entry.id);
            visited.insert(entry.id);
        }

        while let Some(id) = queue.pop_front() {
            order.push(id);
            for &(succ_id, _) in self.successors(id) {
                if visited.insert(succ_id) {
                    queue.push_back(succ_id);
                }
            }
        }

        order
    }

    /// Reverse post-order (useful for dataflow analysis)
    pub fn reverse_postorder(&self) -> Vec<u32> {
        let mut visited = HashSet::new();
        let mut postorder = Vec::new();

        if let Some(entry) = self.entry_block() {
            self.dfs_postorder(entry.id, &mut visited, &mut postorder);
        }

        postorder.reverse();
        postorder
    }

    fn dfs_postorder(&self, block_id: u32, visited: &mut HashSet<u32>, postorder: &mut Vec<u32>) {
        if !visited.insert(block_id) {
            return;
        }
        for &(succ_id, _) in self.successors(block_id) {
            self.dfs_postorder(succ_id, visited, postorder);
        }
        postorder.push(block_id);
    }

    /// Detect if the CFG has cycles (loops)
    pub fn has_cycle(&self) -> bool {
        let mut visited = HashSet::new();
        let mut in_stack = HashSet::new();

        if let Some(entry) = self.entry_block() {
            return self.has_cycle_dfs(entry.id, &mut visited, &mut in_stack);
        }
        false
    }

    fn has_cycle_dfs(
        &self,
        id: u32,
        visited: &mut HashSet<u32>,
        in_stack: &mut HashSet<u32>,
    ) -> bool {
        visited.insert(id);
        in_stack.insert(id);

        for &(succ_id, _) in self.successors(id) {
            if !visited.contains(&succ_id) {
                if self.has_cycle_dfs(succ_id, visited, in_stack) {
                    return true;
                }
            } else if in_stack.contains(&succ_id) {
                return true;
            }
        }

        in_stack.remove(&id);
        false
    }

    /// Find all blocks reachable from a given block
    pub fn reachable_from(&self, start: u32) -> HashSet<u32> {
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(start);

        while let Some(id) = queue.pop_front() {
            if visited.insert(id) {
                for &(succ_id, _) in self.successors(id) {
                    queue.push_back(succ_id);
                }
            }
        }

        visited
    }

    /// Find all instructions of a given kind across all blocks
    pub fn find_instructions(&self, kind: &ValueKind) -> Vec<(u32, &'a Instruction)> {
        let mut results = Vec::new();
        for block in &self.func.blocks {
            for instr in &block.instructions {
                if &instr.kind == kind {
                    results.push((block.id, instr));
                }
            }
        }
        results
    }

    /// Get all call instructions
    pub fn call_sites(&self) -> Vec<(u32, &'a Instruction)> {
        self.find_instructions(&ValueKind::Call)
    }

    /// Get all type assertions (for nil analysis)
    pub fn type_assertions(&self) -> Vec<(u32, &'a Instruction)> {
        self.find_instructions(&ValueKind::TypeAssert)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::*;

    fn make_linear_func() -> Function {
        Function {
            name: "test.Linear".into(),
            short_name: "Linear".into(),
            span: None,
            blocks: vec![
                BasicBlock {
                    id: 0,
                    name: "entry".into(),
                    instructions: vec![],
                    is_return: false,
                    is_panic: false,
                },
                BasicBlock {
                    id: 1,
                    name: "body".into(),
                    instructions: vec![],
                    is_return: false,
                    is_panic: false,
                },
                BasicBlock {
                    id: 2,
                    name: "exit".into(),
                    instructions: vec![],
                    is_return: true,
                    is_panic: false,
                },
            ],
            cfg_edges: vec![
                CfgEdge {
                    from_block: 0,
                    to_block: 1,
                    kind: EdgeKind::Unconditional,
                },
                CfgEdge {
                    from_block: 1,
                    to_block: 2,
                    kind: EdgeKind::Unconditional,
                },
            ],
            is_method: false,
            receiver_type_id: 0,
            is_exported: false,
            free_vars: vec![],
            defers: vec![],
        }
    }

    fn make_branch_func() -> Function {
        Function {
            name: "test.Branch".into(),
            short_name: "Branch".into(),
            span: None,
            blocks: vec![
                BasicBlock {
                    id: 0,
                    name: "entry".into(),
                    instructions: vec![],
                    is_return: false,
                    is_panic: false,
                },
                BasicBlock {
                    id: 1,
                    name: "if.then".into(),
                    instructions: vec![],
                    is_return: true,
                    is_panic: false,
                },
                BasicBlock {
                    id: 2,
                    name: "if.else".into(),
                    instructions: vec![],
                    is_return: true,
                    is_panic: false,
                },
            ],
            cfg_edges: vec![
                CfgEdge {
                    from_block: 0,
                    to_block: 1,
                    kind: EdgeKind::CondTrue,
                },
                CfgEdge {
                    from_block: 0,
                    to_block: 2,
                    kind: EdgeKind::CondFalse,
                },
            ],
            is_method: false,
            receiver_type_id: 0,
            is_exported: false,
            free_vars: vec![],
            defers: vec![],
        }
    }

    fn make_loop_func() -> Function {
        Function {
            name: "test.Loop".into(),
            short_name: "Loop".into(),
            span: None,
            blocks: vec![
                BasicBlock {
                    id: 0,
                    name: "entry".into(),
                    instructions: vec![],
                    is_return: false,
                    is_panic: false,
                },
                BasicBlock {
                    id: 1,
                    name: "loop.head".into(),
                    instructions: vec![],
                    is_return: false,
                    is_panic: false,
                },
                BasicBlock {
                    id: 2,
                    name: "loop.body".into(),
                    instructions: vec![],
                    is_return: false,
                    is_panic: false,
                },
                BasicBlock {
                    id: 3,
                    name: "exit".into(),
                    instructions: vec![],
                    is_return: true,
                    is_panic: false,
                },
            ],
            cfg_edges: vec![
                CfgEdge {
                    from_block: 0,
                    to_block: 1,
                    kind: EdgeKind::Unconditional,
                },
                CfgEdge {
                    from_block: 1,
                    to_block: 2,
                    kind: EdgeKind::CondTrue,
                },
                CfgEdge {
                    from_block: 1,
                    to_block: 3,
                    kind: EdgeKind::CondFalse,
                },
                CfgEdge {
                    from_block: 2,
                    to_block: 1,
                    kind: EdgeKind::Unconditional,
                }, // back edge
            ],
            is_method: false,
            receiver_type_id: 0,
            is_exported: false,
            free_vars: vec![],
            defers: vec![],
        }
    }

    #[test]
    fn test_linear_cfg() {
        let func = make_linear_func();
        let cfg = Cfg::from_function(&func);

        assert_eq!(cfg.block_count(), 3);
        assert!(cfg.entry_block().is_some());
        assert_eq!(cfg.entry_block().unwrap().name, "entry");
        assert_eq!(cfg.return_blocks().len(), 1);
        assert!(!cfg.has_cycle());
    }

    #[test]
    fn test_branch_cfg() {
        let func = make_branch_func();
        let cfg = Cfg::from_function(&func);

        assert_eq!(cfg.successors(0).len(), 2);
        assert_eq!(cfg.predecessors(1).len(), 1);
        assert_eq!(cfg.predecessors(2).len(), 1);
        assert_eq!(cfg.return_blocks().len(), 2);
        assert!(!cfg.has_cycle());
    }

    #[test]
    fn test_loop_cfg() {
        let func = make_loop_func();
        let cfg = Cfg::from_function(&func);

        assert!(cfg.has_cycle());
        assert_eq!(cfg.return_blocks().len(), 1);
    }

    #[test]
    fn test_bfs_order() {
        let func = make_linear_func();
        let cfg = Cfg::from_function(&func);

        let order = cfg.bfs_order();
        assert_eq!(order, vec![0, 1, 2]);
    }

    #[test]
    fn test_reverse_postorder() {
        let func = make_branch_func();
        let cfg = Cfg::from_function(&func);

        let rpo = cfg.reverse_postorder();
        assert_eq!(rpo[0], 0); // entry is always first
        assert_eq!(rpo.len(), 3);
    }

    #[test]
    fn test_reachable_from() {
        let func = make_branch_func();
        let cfg = Cfg::from_function(&func);

        let reachable = cfg.reachable_from(0);
        assert_eq!(reachable.len(), 3); // all blocks reachable from entry

        let reachable_from_then = cfg.reachable_from(1);
        assert_eq!(reachable_from_then.len(), 1); // only block 1 (it's a return)
    }

    #[test]
    fn test_find_call_instructions() {
        let func = Function {
            name: "test.WithCalls".into(),
            short_name: "WithCalls".into(),
            span: None,
            blocks: vec![BasicBlock {
                id: 0,
                name: "entry".into(),
                instructions: vec![
                    Instruction {
                        id: 1,
                        kind: ValueKind::Call,
                        name: "t1".into(),
                        type_id: 1,
                        span: None,
                        operands: vec![],
                        extract_index: 0,
                        callee: Some("db.Find".into()),
                        callee_is_interface: false,
                        assert_type_id: 0,
                        comma_ok: false,
                        const_value: None,
                        is_nil: false,
                        bin_op: None,
                        nil_operand_indices: vec![],
                        select_cases: vec![],
                        channel_dir: None,
                    },
                    Instruction {
                        id: 2,
                        kind: ValueKind::Alloc,
                        name: "t2".into(),
                        type_id: 2,
                        span: None,
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
                    },
                ],
                is_return: true,
                is_panic: false,
            }],
            cfg_edges: vec![],
            is_method: false,
            receiver_type_id: 0,
            is_exported: false,
            free_vars: vec![],
            defers: vec![],
        };

        let cfg = Cfg::from_function(&func);
        let calls = cfg.call_sites();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].1.callee.as_deref(), Some("db.Find"));
    }

    #[test]
    fn test_panic_blocks() {
        let func = Function {
            name: "test.WithPanic".into(),
            short_name: "WithPanic".into(),
            span: None,
            blocks: vec![
                BasicBlock {
                    id: 0,
                    name: "entry".into(),
                    instructions: vec![],
                    is_return: false,
                    is_panic: false,
                },
                BasicBlock {
                    id: 1,
                    name: "ok".into(),
                    instructions: vec![],
                    is_return: true,
                    is_panic: false,
                },
                BasicBlock {
                    id: 2,
                    name: "panic".into(),
                    instructions: vec![],
                    is_return: false,
                    is_panic: true,
                },
            ],
            cfg_edges: vec![
                CfgEdge {
                    from_block: 0,
                    to_block: 1,
                    kind: EdgeKind::CondTrue,
                },
                CfgEdge {
                    from_block: 0,
                    to_block: 2,
                    kind: EdgeKind::CondFalse,
                },
            ],
            is_method: false,
            receiver_type_id: 0,
            is_exported: false,
            free_vars: vec![],
            defers: vec![],
        };

        let cfg = Cfg::from_function(&func);
        assert_eq!(cfg.panic_blocks().len(), 1);
        assert_eq!(cfg.return_blocks().len(), 1);
    }
}
