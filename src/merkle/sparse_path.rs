use alloc::vec::Vec;
use core::iter;

use super::{EmptySubtreeRoots, MerklePath, RpoDigest};

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
    pub fn from_path(tree_depth: u8, path: MerklePath) -> Self {
        // Note that the path does not include the node itself that it is a path to.
        // That is to say, the path is not inclusive of its ending.
        assert!(path.len() <= u8::MAX.into(), "SparseMerklePath may have at most 256 items");
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

        Self { empty_nodes, nodes }
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

    pub fn depth(&self) -> u8 {
        (self.nodes.len() + self.empty_nodes.count_ones() as usize) as u8
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::SparseMerklePath;
    use crate::{
        hash::rpo::RpoDigest,
        merkle::{smt::SparseMerkleTree, Smt, SMT_DEPTH},
        Felt, Word, ONE,
    };

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
            let sparse_path = SparseMerklePath::from_path(SMT_DEPTH, control_path.clone());
            let test_path = sparse_path.into_path(SMT_DEPTH);

            assert_eq!(control_path, test_path);
        }
    }
}
