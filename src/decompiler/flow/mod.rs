pub mod analysis;

use crate::disassembler::instructions::{Instruction, LiteralInstructionType};
use petgraph::graph::{DiGraph, NodeIndex};
use rustc_hash::{FxHashMap, FxHashSet};

pub type NodeId = usize;

#[derive(Clone, Debug)]
pub enum EdgeKind {
    Unconditional,
    Conditional,
    Fallthrough,
}

#[derive(Clone, Debug)]
pub struct Successor {
    pub target_id: NodeId,
    pub kind: EdgeKind,
    pub cond: Option<usize>,
}

#[derive(Clone, Debug)]
pub struct Predecessor {
    pub previous_id: NodeId,
    pub kind: EdgeKind,
    pub cond: Option<usize>,
}

#[derive(Clone, Debug)]
pub struct BasicBlock {
    pub id: NodeId,
    pub instructions: Vec<Instruction>,
    pub successors: Vec<Successor>,
    pub predecessors: Vec<Predecessor>,
}

impl BasicBlock {
    pub fn new(id: NodeId) -> Self {
        Self {
            id,
            instructions: Vec::new(),
            successors: Vec::new(),
            predecessors: Vec::new(),
        }
    }

    pub fn add_successor(&mut self, target_id: NodeId, kind: EdgeKind, cond: Option<usize>) {
        self.successors.push(Successor {
            target_id,
            kind,
            cond,
        })
    }

    pub fn add_predecessor(&mut self, previous_id: NodeId, kind: EdgeKind, cond: Option<usize>) {
        self.predecessors.push(Predecessor {
            previous_id,
            kind,
            cond,
        });
    }

    pub fn is_exit_block(&self) -> bool {
        self.successors.is_empty()
            || matches!(self.instructions.last(), Some(Instruction::Return(_)) | Some(Instruction::Throw(_)))
    }
}

pub struct ControlFlowGraph {
    instructions: Vec<(usize, Instruction)>,

    pub entry: NodeId,
    pub exit: NodeId,
    pub blocks: FxHashMap<NodeId, BasicBlock>,
}

macro_rules! ensure_block {
    ($blocks:expr, $block_id:expr) => {
        $blocks
            .entry($block_id)
            .or_insert_with(|| BasicBlock::new($block_id))
    };
}

impl ControlFlowGraph {
    pub fn make(func_start: usize, instructions: Vec<(usize, Instruction)>) -> Self {
        let exit = instructions.last().map(|k| k.0).unwrap_or_else(|| 0); // this is completely wrong btw

        let mut ret = Self {
            instructions,
            entry: func_start,
            exit,
            blocks: FxHashMap::default(),
        };

        ret.construct();
        ret
    }

    pub fn construct(&mut self) {
        let mut targets: FxHashSet<usize> = FxHashSet::default();

        for (_, instruction) in self.instructions.iter() {
            match instruction {
                Instruction::Jump(jmp) => {
                    targets.insert(jmp.pos);
                }
                Instruction::ConditionalJump(cond) => {
                    targets.insert(cond.jump.pos);
                }
                _ => {}
            }
        }

        let mut current_block = self.entry;
        let mut instructions_to_skip: FxHashSet<NodeId> = FxHashSet::default();
        let mut should_not_add_successor_and_predecessor = false;

        for (vec_idx, (idx, instruction)) in self.instructions.iter().enumerate() {
            ensure_block!(self.blocks, current_block);

            let is_target = targets.contains(&idx);

            if is_target {
                let old_block = current_block;

                if !should_not_add_successor_and_predecessor {
                    self.blocks.get_mut(&old_block).unwrap().add_successor(
                        *idx,
                        EdgeKind::Fallthrough,
                        None,
                    );
                }

                let block = ensure_block!(self.blocks, *idx);

                if !should_not_add_successor_and_predecessor {
                    block.add_predecessor(old_block, EdgeKind::Fallthrough, None);
                }

                current_block = block.id;
            }

            should_not_add_successor_and_predecessor = false;

            match instruction {
                Instruction::Jump(jump) => {
                    should_not_add_successor_and_predecessor = true;

                    self.blocks.get_mut(&current_block).unwrap().add_successor(
                        jump.pos,
                        EdgeKind::Unconditional,
                        None,
                    );

                    ensure_block!(self.blocks, jump.pos).add_predecessor(
                        current_block,
                        EdgeKind::Unconditional,
                        None,
                    );
                    if let Some((next_idx, _)) = self.instructions.get(vec_idx + 1) {
                        current_block = *next_idx;
                        ensure_block!(self.blocks, current_block);
                    }

                    continue;
                }

                Instruction::ConditionalJump(cond) => {
                    let cond_value = Some(cond.test_reg as usize);
                    self.blocks.get_mut(&current_block).unwrap().add_successor(
                        cond.jump.pos,
                        EdgeKind::Conditional,
                        cond_value,
                    );

                    ensure_block!(self.blocks, cond.jump.pos).add_predecessor(
                        current_block,
                        EdgeKind::Conditional,
                        cond_value,
                    );

                    if let Some((next_idx, _)) = self.instructions.get(vec_idx + 1) {
                        self.blocks.get_mut(&current_block).unwrap().add_successor(
                            *next_idx,
                            EdgeKind::Fallthrough,
                            None,
                        );

                        ensure_block!(self.blocks, *next_idx).add_predecessor(
                            current_block,
                            EdgeKind::Fallthrough,
                            None,
                        );
                        current_block = *next_idx;
                    }

                    continue;
                }

                Instruction::NewLiteral(instruction)
                if matches!(instruction.data, LiteralInstructionType::CopyState(_)) =>
                    {
                        if let LiteralInstructionType::CopyState(jmp) = &instruction.data {
                            {
                                ensure_block!(self.blocks, current_block).add_successor(
                                    *idx,
                                    EdgeKind::Fallthrough,
                                    None,
                                );
                                let try_block = ensure_block!(self.blocks, *idx);
                                try_block.add_predecessor(current_block, EdgeKind::Fallthrough, None);
                                current_block = *idx;
                            }

                            ensure_block!(self.blocks, jmp.pos);

                            let opt_res = self
                                .instructions
                                .iter()
                                .find(|k| k.0 == jmp.pos - 4 - 1);
                            if opt_res.is_none() {
                                continue;
                            }
                            let (jmp_catch_idx, _) = opt_res.unwrap();
                            instructions_to_skip.insert(*jmp_catch_idx);
                            continue;
                        }
                    }

                Instruction::Throw(_) | Instruction::Return(_) => {
                    self.blocks
                        .get_mut(&current_block)
                        .unwrap()
                        .instructions
                        .push(instruction.clone());

                    if let Some((next_idx, _)) = self.instructions.get(vec_idx + 1) {
                        current_block = *next_idx;
                        ensure_block!(self.blocks, current_block);
                        should_not_add_successor_and_predecessor = true;
                    }
                }

                _ => {
                    self.blocks
                        .get_mut(&current_block)
                        .unwrap()
                        .instructions
                        .push(instruction.clone());
                }
            }
        }

        self.exit = current_block;
    }
}

pub fn run_petgraph(
    cfg: &ControlFlowGraph,
) -> (DiGraph<NodeId, EdgeKind>, FxHashMap<NodeId, NodeIndex>) {
    let mut graph: DiGraph<NodeId, EdgeKind> = DiGraph::new();

    let mut id_to_petgraph: FxHashMap<NodeId, NodeIndex<u32>> = FxHashMap::default();
    for (_, bb) in &cfg.blocks {
        let bb_idx = graph.add_node(bb.id);
        id_to_petgraph.insert(bb.id, bb_idx);
    }

    for (_, bb) in &cfg.blocks {
        for successor in &bb.successors {
            graph.add_edge(
                id_to_petgraph.get(&bb.id).unwrap().clone(),
                id_to_petgraph.get(&successor.target_id).unwrap().clone(),
                successor.kind.clone(),
            );
        }
    }

    (graph, id_to_petgraph)
}
