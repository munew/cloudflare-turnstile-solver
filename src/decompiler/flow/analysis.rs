use crate::decompiler::flow::{ControlFlowGraph, EdgeKind, NodeId};
use petgraph::algo::dominators::{simple_fast, Dominators};
use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::visit::Reversed;
use rustc_hash::{FxHashMap, FxHashSet};

pub struct ControlFlowAnalysis<'a> {
    cfg: &'a ControlFlowGraph,
    digraph: DiGraph<NodeId, EdgeKind>,

    id_to_index: FxHashMap<NodeId, NodeIndex<u32>>,
    index_to_id: FxHashMap<NodeIndex<u32>, NodeId>,
}

#[derive(Clone, Debug)]
pub struct IfElseThenStructure {
    pub condition_block: NodeId,
    pub then_block: NodeId,
    pub else_block: Option<NodeId>,
    pub merge_block: NodeId,

    pub cond: usize,
}

#[derive(Clone, Debug)]
pub enum FlowStructure {
    IfElseThen(IfElseThenStructure),
}

impl FlowStructure {
    pub fn get_merge_block(&self) -> NodeId {
        match self {
            FlowStructure::IfElseThen(s) => s.merge_block,
        }
    }
}

pub struct FlowAnalysis {
    pub structures: FxHashMap<NodeId, FlowStructure>,
}

impl<'a> ControlFlowAnalysis<'a> {
    pub fn new(cfg: &'a ControlFlowGraph) -> Self {
        let (digraph, ids) = cfg_to_petgraph(&cfg);
        let mut index_to_id: FxHashMap<NodeIndex<u32>, NodeId> = FxHashMap::default();

        for (id, index) in &ids {
            index_to_id.insert(*index, *id);
        }

        ControlFlowAnalysis {
            cfg,
            digraph,
            id_to_index: ids,
            index_to_id,
        }
    }

    pub fn quick_conditionals_analysis(&self) -> FlowAnalysis {
        if self.cfg.blocks.len() == 0 {
            return FlowAnalysis {
                structures: FxHashMap::default(),
            };
        }

        let post_dominators = self.calculate_post_dominators();
        let mut checked_blocks = FxHashSet::default();

        FlowAnalysis {
            structures: self.detect_conditionals(&post_dominators, &mut checked_blocks),
        }
    }

    fn detect_conditionals(
        &self,
        post_dominators: &Dominators<NodeIndex<u32>>,
        checked_blocks: &mut FxHashSet<NodeId>,
    ) -> FxHashMap<NodeId, FlowStructure> {
        let mut structures: FxHashMap<NodeId, FlowStructure> = FxHashMap::default();

        for (_, block) in &self.cfg.blocks {
            if checked_blocks.contains(&block.id) {
                continue;
            }

            let successors = &block.successors;
            if successors.len() != 2
                || !matches!(successors[0].kind, EdgeKind::Conditional)
                || !matches!(successors[1].kind, EdgeKind::Fallthrough)
            {
                continue;
            }

            if let Some(merge_block_node) =
                post_dominators.immediate_dominator(self.id_to_index[&block.id])
            {
                let merge_block = self.index_to_id[&merge_block_node];

                let cond = successors[0].cond.unwrap();
                if merge_block == successors[0].target_id {
                    structures.insert(
                        block.id,
                        FlowStructure::IfElseThen(IfElseThenStructure {
                            condition_block: block.id,
                            then_block: successors[1].target_id,
                            else_block: None,
                            merge_block,
                            cond,
                        }),
                    );
                } else {
                    structures.insert(
                        block.id,
                        FlowStructure::IfElseThen(IfElseThenStructure {
                            condition_block: block.id,
                            then_block: successors[1].target_id,
                            else_block: Some(successors[0].target_id),
                            merge_block,
                            cond,
                        }),
                    );
                }

                checked_blocks.insert(block.id);
            }
        }

        structures
    }

    fn calculate_post_dominators(&self) -> Dominators<NodeIndex> {
        let mut post_dom_graph = self.digraph.clone();
        let exit_index = self.id_to_index[&self.cfg.exit];

        for (node_id, block) in &self.cfg.blocks {
            if block.successors.len() == 0 {
                let block_index = self.id_to_index[node_id];
                if !post_dom_graph.contains_edge(block_index, exit_index) {
                    post_dom_graph.add_edge(block_index, exit_index, EdgeKind::Fallthrough);
                }
            }
        }

        let reversed = Reversed(&post_dom_graph);
        simple_fast(&reversed, self.id_to_index[&self.cfg.exit])
    }
}

fn cfg_to_petgraph(
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
