use super::{IN_MEMORY_DEPTH, SMT_DEPTH};
use crate::{
    Word,
    merkle::{EmptySubtreeRoots, NodeIndex},
};

/// Checks if a node with the given children is empty.
/// A node is considered empty if both children equal the empty hash for that depth.
pub(super) fn is_empty_parent(left: Word, right: Word, child_depth: u8) -> bool {
    let empty_hash = *EmptySubtreeRoots::entry(SMT_DEPTH, child_depth);
    left == empty_hash && right == empty_hash
}

/// Converts a NodeIndex to a flat vector index using 1-indexed layout.
/// Index 0 is unused, index 1 is root.
/// For a node at index i: left child at 2*i, right child at 2*i+1.
pub(super) fn to_memory_index(index: &NodeIndex) -> usize {
    debug_assert!(index.depth() < IN_MEMORY_DEPTH);
    debug_assert!(index.value() < (1 << index.depth()));
    (1usize << index.depth()) + index.value() as usize
}
