use alloc::vec::Vec;
use core::iter;

use super::{EmptySubtreeRoots, MerklePath, RpoDigest, SMT_MAX_DEPTH};
use crate::utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable};

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
        assert!(
            path.len() <= SMT_MAX_DEPTH.into(),
            "SparseMerklePath may have at most 256 items",
        );
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
                let node = sparse_nodes.next().unwrap();
                nodes.push(node);
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

    pub fn get(&self, tree_depth: u8, node_depth: u8) -> RpoDigest {
        let empty_bit = u64::checked_shl(1, node_depth as u32).unwrap();
        let is_empty = (self.empty_nodes & empty_bit) != 0;
        if is_empty {
            *EmptySubtreeRoots::entry(tree_depth, node_depth)
        } else {
            // Get rid of 1s that are more significant than the one that indicates our empty bit.
            let mask = u64::unbounded_shl(u64::MAX, node_depth as u32);
            let empty_before = u64::count_ones(self.empty_nodes & mask);
            std::dbg!(node_depth, empty_before);
            //let index = node_depth - empty_before as u8;
            let index = empty_before as u8 - node_depth;
            self.nodes[index as usize]
        }
    }
}

// ITERATORS
// ================================================================================================

struct SparseMerkleIter {
    path: SparseMerklePath,
    current_depth: u8,
    tree_depth: u8,
}

impl Iterator for SparseMerkleIter {
    type Item = RpoDigest;

    fn next(&mut self) -> Option<RpoDigest> {
        todo!();
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let len: usize = self.path.depth().into();
        (len, Some(len))
    }
}

impl ExactSizeIterator for SparseMerkleIter {
    fn len(&self) -> usize {
        self.path.depth().into()
    }
}

impl DoubleEndedIterator for SparseMerkleIter {
    fn next_back(&mut self) -> Option<RpoDigest> {
        todo!();
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for SparseMerklePath {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        // TODO: if this is enforced in the constructor, then maybe this should be `debug_assert`?
        assert!(self.depth() <= SMT_MAX_DEPTH, "Length enforced in the constructor");
        target.write_u64(self.empty_nodes);
        target.write_many(&self.nodes);
    }
}

//impl Deserializable for SparseMerklePath {
//    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {}
//}

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

    #[test]
    fn get() {
        todo!();
    }
}
