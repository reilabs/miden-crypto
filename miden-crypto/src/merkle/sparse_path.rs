use alloc::vec::Vec;
use core::iter;

use super::{EmptySubtreeRoots, MerklePath, RpoDigest, SMT_MAX_DEPTH};

/// A different representation of [`MerklePath`] designed for memory efficiency for Merkle paths
/// with empty nodes.
///
/// Empty nodes in the path are stored only as their position, represented with a bitmask. A
/// maximum of 64 nodes in the path can be empty. The number of empty nodes has no effect on memory
/// usage by this struct, but will incur overhead during iteration or conversion to a
/// [`MerklePath`], for each empty node.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct SparseMerklePath {
    /// A bitmask representing empty nodes. The set bit corresponds to the depth of an empty node.
    empty_nodes: u64,
    /// The non-empty nodes, stored in depth-order, but not contiguous across depth.
    nodes: Vec<RpoDigest>,
}

impl SparseMerklePath {
    /// Converts a Merkle path to a sparse representation.
    ///
    /// Returns `None` if `path` contains more elements than we can represent ([`SMT_MAX_DEPTH`]).
    pub fn from_path(tree_depth: u8, path: MerklePath) -> Option<Self> {
        // Note that the path does not include the node itself that it is a path to.
        // That is to say, the path is not inclusive of its ending.

        if path.len() > SMT_MAX_DEPTH.into() {
            return None;
        }
        let path_depth: u8 = path.len().try_into().unwrap();

        let mut nodes: Vec<RpoDigest> = Default::default();
        let mut empty_nodes: u64 = 0;

        for (depth, node) in iter::zip(0..path_depth, path) {
            let &equivalent_empty_node = EmptySubtreeRoots::entry(tree_depth, depth);
            if node == equivalent_empty_node {
                // FIXME: should we just fallback to the Vec if we're out of bits?
                assert!(depth < 64, "SparseMerklePath may have at most 64 empty nodes");
                empty_nodes |= u64::checked_shl(1, depth.into()).unwrap();
            } else {
                nodes.push(node);
            }
        }

        Some(Self { empty_nodes, nodes })
    }

    /// Converts this sparse representation back to a normal [`MerklePath`].
    pub fn into_path(mut self, tree_depth: u8) -> MerklePath {
        let path_depth = self.depth();
        let mut nodes: Vec<RpoDigest> = Default::default();
        let mut sparse_nodes = self.nodes.drain(..);

        for depth in 0..path_depth {
            let empty_bit = u64::checked_shl(1, depth.into()).unwrap();
            let is_empty = (self.empty_nodes & empty_bit) != 0;
            if is_empty {
                let &equivalent_empty_node = EmptySubtreeRoots::entry(tree_depth, depth);
                nodes.push(equivalent_empty_node);
            } else {
                nodes.push(sparse_nodes.next().unwrap());
            }
        }

        debug_assert_eq!(sparse_nodes.next(), None);
        drop(sparse_nodes);

        debug_assert!(self.nodes.is_empty());

        MerklePath::from(nodes)
    }

    /// Returns the total depth of this path, i.e., the number of nodes this path represents.
    pub fn depth(&self) -> u8 {
        (self.nodes.len() + self.empty_nodes.count_ones() as usize) as u8
    }

    /// Get a specific node in this path at a given depth.
    ///
    /// # Panics
    /// With debug assertions enabled, this function panics if `node_depth` is greater than
    /// `tree_depth` (as it is impossible to have a node of greater depth than the tree it is
    /// contained in).
    pub fn get(&self, tree_depth: u8, node_depth: u8) -> Option<RpoDigest> {
        if node_depth == tree_depth || node_depth > self.depth() {
            return None;
        }

        debug_assert!(
            tree_depth >= node_depth,
            "tree depth {tree_depth} must be greater than node depth {node_depth}",
        );

        let empty_bit = u64::checked_shl(1, node_depth.into()).unwrap();
        let is_empty = (self.empty_nodes & empty_bit) != 0;

        if is_empty {
            return Some(*EmptySubtreeRoots::entry(tree_depth, node_depth));
        }

        // Our index needs to account for all the empty nodes that aren't in `self.nodes`.
        let nonempty_index: usize = {
            // TODO: this could also be u64::unbounded_shl(1, node_depth + 1).wrapping_sub(1).
            // We should check if that has any performance benefits over using 128-bit integers.
            let mask: u64 = ((1u128 << (node_depth + 1)) - 1u128).try_into().unwrap();

            let empty_before = u64::count_ones(self.empty_nodes & mask);
            u64::checked_sub(node_depth as u64, empty_before as u64)
                .unwrap()
                .try_into()
                .unwrap()
        };
        Some(self.nodes[nonempty_index])
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::SparseMerklePath;
    use crate::{
        Felt, ONE, Word,
        hash::rpo::RpoDigest,
        merkle::{SMT_DEPTH, Smt, smt::SparseMerkleTree},
    };

    fn make_smt(pair_count: u64) -> Smt {
        let entries: Vec<(RpoDigest, Word)> = (0..pair_count)
            .map(|n| {
                let leaf_index = ((n as f64 / pair_count as f64) * 255.0) as u64;
                let key = RpoDigest::new([ONE, ONE, Felt::new(n), Felt::new(leaf_index)]);
                let value = [ONE, ONE, ONE, ONE];
                (key, value)
            })
            .collect();

        Smt::with_entries(entries).unwrap()
    }

    #[test]
    fn roundtrip() {
        let pair_count: u64 = 8192;
        let entries: Vec<(RpoDigest, Word)> = (0..pair_count)
            .map(|n| {
                let leaf_index = ((n as f64 / pair_count as f64) * 255.0) as u64;
                let key = RpoDigest::new([ONE, ONE, Felt::new(n), Felt::new(leaf_index)]);
                let value = [ONE, ONE, ONE, ONE];
                (key, value)
            })
            .collect();
        let tree = Smt::with_entries(entries).unwrap();

        for (key, _value) in tree.entries() {
            let control_path = tree.path(key);
            let sparse_path = SparseMerklePath::from_path(SMT_DEPTH, control_path.clone()).unwrap();
            assert_eq!(control_path.depth(), sparse_path.depth());
            let test_path = sparse_path.into_path(SMT_DEPTH);

            assert_eq!(control_path, test_path);
        }
    }

    #[test]
    fn random_access() {
        let tree = make_smt(8192);

        for (i, (key, _value)) in tree.entries().enumerate() {
            let control_path = tree.path(key);
            let sparse_path = SparseMerklePath::from_path(SMT_DEPTH, control_path.clone()).unwrap();
            assert_eq!(control_path.depth(), sparse_path.depth());

            for (depth, control_node) in control_path.iter().enumerate() {
                let test_node = sparse_path.get(SMT_DEPTH, depth as u8).unwrap();
                assert_eq!(*control_node, test_node, "at depth {depth} for entry {i}");
            }
        }
    }
}
