//! The subtree structure for use inside the SMT forest.

use alloc::vec::Vec;

use crate::{
    Map, Word,
    merkle::{
        EmptySubtreeRoots, NodeIndex,
        smt::{InnerNode, SMT_DEPTH, SubtreeError, SubtreeLevels},
    },
};

// TYPE ALIASES
// ================================================================================================

/// The result type used for operations on a subtree.
pub type Result<T> = core::result::Result<T, SubtreeError>;

// FOREST SUBTREE
// ================================================================================================

/// Represents a complete subtree of a larger tree in the forest.
///
/// This representation is **not** intended to be compact/sparse in memory, though when serialized
/// will produce a compact representation that does not encode default values for nodes.
#[derive(Debug, Clone)]
pub struct ForestSubtree {
    /// The index of the subtree's root in the parent tree.
    root_index: NodeIndex,

    /// The nodes in the subtree by their subtree-local index (using binary heap ordering),
    /// possibly sparse.
    nodes: Map<u64, InnerNode>,

    /// The number of levels stored in the tree.
    levels: SubtreeLevels,

    /// The maximum number of nodes that can be stored in this subtree based on the number of
    /// levels it contains.
    max_nodes: u64,

    /// The size in bits of the bitmask for this subtree based on the number of levels it contains.
    bitmask_size_bytes: u64,
}

/// This block contains methods that either query or mutate self.
impl ForestSubtree {
    const BITS_PER_NODE: u64 = 2;

    /// Constructs a new subtree with its root at `root_index` and storing `levels`
    pub fn new(root_index: NodeIndex, levels: SubtreeLevels) -> Self {
        let nodes = Map::new();

        let pow2_nodes = 2u64.pow(levels.into());
        let max_nodes = pow2_nodes - 1;
        let bitmask_size_bits = pow2_nodes * Self::BITS_PER_NODE;
        let bitmask_size_bytes = bitmask_size_bits / 8;

        Self {
            root_index,
            nodes,
            levels,
            max_nodes,
            bitmask_size_bytes,
        }
    }

    /// Gets the index of the subtree's root node in the parent tree.
    pub fn root_index(&self) -> NodeIndex {
        self.root_index
    }

    /// Gets the number of nodes that are actually stored in the subtree.
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Inserts the provided `inner_node` into the subtree at the provided full tree `index`,
    /// returning any overwritten value or [`None`] otherwise.
    ///
    /// # Panics
    ///
    /// If the provided `index` is not valid within the bounds of the subtree.
    pub fn insert(&mut self, index: NodeIndex, inner_node: InnerNode) -> Option<InnerNode> {
        let local_index = self.global_index_to_local_offset(index);
        self.nodes.insert(local_index, inner_node)
    }

    /// Gets the node associated with the provided full tree `index` or returns [`None`] if no such
    /// node is found.
    ///
    /// # Panics
    ///
    /// If the provided `index` is not valid within the bounds of the subtree.
    pub fn get(&self, index: NodeIndex) -> Option<InnerNode> {
        let local_index = self.global_index_to_local_offset(index);
        self.nodes.get(&local_index).cloned()
    }

    /// Removes the node with the provided full tree `index` and returns it if it exists, or returns
    /// [`None`] otherwise.
    ///
    /// # Panics
    ///
    /// If the provided `index` is not valid within the bounds of the subtree.
    pub fn remove(&mut self, index: NodeIndex) -> Option<InnerNode> {
        let local_index = self.global_index_to_local_offset(index);
        self.nodes.remove(&local_index)
    }

    /// Converts a global index to a local offset.
    fn global_index_to_local_offset(&self, global_index: NodeIndex) -> u64 {
        Self::local_index_to_offset(self.global_index_to_local_index(global_index))
    }

    /// Serializes the subtree into a compact byte representation.
    ///
    /// The encoding is made up of three parts:
    ///
    /// 1. **Level Count:** A single byte containing the number of levels in the subtree.
    /// 2. **Bitmask:** A bitmask that is `self.bitmask_size_bytes` big, with each internal node (up
    ///    to `self.max_nodes`) allocated two bits: one for its left child and one for its right
    ///    child. A bit being set indicates that the corresponding child differs from the canonical
    ///    empty hash at its depth.
    /// 3. **Node Data:** For every set bit in the mask, the corresponding 32-byte hash of the node
    ///    is appended to the data section, in breadth-first, local-index order.
    ///
    /// This implements a sparse encoding, as any omitted children are reconstructed using the
    /// [`EmptySubtreeRoots`].
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut data: Vec<u8> = Vec::with_capacity(self.node_count() * size_of::<Word>());
        let mut bitmask = vec![0u8; self.bitmask_size_bytes as usize];

        for local_index in 0..self.max_nodes {
            if let Some(node) = self.nodes.get(&local_index) {
                let bit_offset = (local_index * Self::BITS_PER_NODE) as usize;
                let depth_in_subtree = Self::offset_to_depth_in_subtree(local_index);
                let child_depth_in_whole_tree = self.root_index.depth() + depth_in_subtree + 1;
                let empty_hash = *EmptySubtreeRoots::entry(SMT_DEPTH, child_depth_in_whole_tree);

                if node.left != empty_hash {
                    Self::set_bit(&mut bitmask, bit_offset);
                    data.extend_from_slice(&node.left.as_bytes());
                }

                if node.right != empty_hash {
                    Self::set_bit(&mut bitmask, bit_offset + 1);
                    data.extend_from_slice(&node.right.as_bytes());
                }
            }
        }

        let mut result = Vec::with_capacity(1 + self.bitmask_size_bytes as usize + data.len());
        result.push(self.levels.into());
        result.extend_from_slice(&bitmask);
        result.extend_from_slice(&data);
        result
    }

    /// Deserializes the subtree from its compact byte representation at the provided `root_index`.
    ///
    /// The encoding is made up of three parts:
    ///
    /// 1. **Level Count:** A single byte containing the number of levels in the subtree.
    /// 2. **Bitmask:** A bitmask whose size is `2.pow(levels) * BITS_PER_NODE / 8` bytes, with each
    ///    internal node (up to a maximum of `2.pow(levels) - 1`) given 2 bits. The first bit
    ///    describes its left child and the second describes its right child. A bit being set
    ///    indicates that the corresponding child differs from the canonical empty hash at its
    ///    depth.
    /// 3. **Node Data:** For every set bit, the corresponding [`Word`] hash is read sequentially
    ///    from the data section. If a bit is unset, the value is reconstructed from
    ///    [`EmptySubtreeRoots`] based on the child's depth.
    ///
    /// # Errors
    ///
    /// - [`SubtreeError::BadHashLen`] if the node data is not a full number of hashes.
    /// - [`SubtreeError::BadLeft`] if the data in the left child is not a valid hash.
    /// - [`SubtreeError::BadRight`] if the data in the right child is not a valid hash.
    /// - [`SubtreeError::ExtraData`] if not all data was consumed during the decoding.
    /// - [`SubtreeError::InvalidLevelCount`] if the decoded number of levels is not valid for a
    ///   subtree.
    /// - [`SubtreeError::MissingLeft`] if the data for an expected left node child is missing.
    /// - [`SubtreeError::MissingRight`] if the data for an expected right node child is missing.
    /// - [`SubtreeError::TooShort`] if the provided data is not sufficient to construct a subtree
    ///   of the expected size.
    pub fn from_bytes(root_index: NodeIndex, data: &[u8]) -> Result<Self> {
        // We start by parsing the number of levels out of the data, and failing if we cannot.
        let levels = SubtreeLevels::new_unchecked(
            *data.first().ok_or(SubtreeError::TooShort { found: data.len(), min: 1 })?,
        );
        let pow2_nodes = 2u64.pow(levels.into());
        let bitmask_size_bytes = (pow2_nodes * Self::BITS_PER_NODE) as usize / 8;
        let max_nodes = pow2_nodes - 1;

        // Given we have that, we can forget about it.
        let data = &data[1..];

        // If we have too little data to even parse the bitmask we fail immediately.
        if data.len() < bitmask_size_bytes {
            return Err(SubtreeError::TooShort {
                found: data.len(),
                min: bitmask_size_bytes,
            });
        }

        // Given we have enough, we can split the data into the bitmask portion and the node data
        // portion.
        let (bitmask, node_data) = data.split_at(bitmask_size_bytes);

        // We then fail early if we have too little node data to match up with the bitmask's count
        // of populated nodes.
        let present_nodes: usize = bitmask.iter().map(|&byte| byte.count_ones() as usize).sum();
        if node_data.len() != present_nodes * size_of::<Word>() {
            return Err(SubtreeError::BadHashLen {
                expected: present_nodes * size_of::<Word>(),
                found: node_data.len(),
            });
        }

        // Having satisfied our preconditions, we can now parse the nodes themselves out of the
        // encoding.
        let mut nodes = Map::new();
        let mut node_data = node_data.chunks_exact(size_of::<Word>());

        for local_index in 0..max_nodes {
            let bit_offset = (local_index * Self::BITS_PER_NODE) as usize;
            let has_left = Self::get_bit(bitmask, bit_offset);
            let has_right = Self::get_bit(bitmask, bit_offset + 1);

            // If either the left or right exist, we have to look them up and insert them.
            if has_left || has_right {
                let depth_in_subtree = Self::offset_to_depth_in_subtree(local_index);
                let child_depth = root_index.depth() + depth_in_subtree + 1;
                let empty_hash = *EmptySubtreeRoots::entry(SMT_DEPTH, child_depth);

                // We then try and query for the left hash if it exists.
                let left_node = if has_left {
                    let node_bytes = node_data
                        .next()
                        .ok_or(SubtreeError::MissingLeft { index: local_index as usize })?;
                    Word::try_from(node_bytes)
                        .map_err(|_| SubtreeError::BadLeft { index: local_index as usize })?
                } else {
                    empty_hash
                };

                // We then try and query for the right hash if it exists.
                let right_node = if has_right {
                    let node_bytes = node_data
                        .next()
                        .ok_or(SubtreeError::MissingRight { index: local_index as usize })?;
                    Word::try_from(node_bytes)
                        .map_err(|_| SubtreeError::BadRight { index: local_index as usize })?
                } else {
                    empty_hash
                };

                let inner_node = InnerNode { left: left_node, right: right_node };
                nodes.insert(local_index, inner_node);
            }
        }

        if node_data.next().is_some() {
            return Err(SubtreeError::ExtraData);
        }

        Ok(Self {
            root_index,
            nodes,
            levels,
            max_nodes,
            bitmask_size_bytes: bitmask_size_bytes as u64,
        })
    }

    /// Computes the local index in the subtree based on the provided `global_index`.
    ///
    /// # Panics
    ///
    /// If the global index does not exist within the subtree in either breadth or depth. This will
    /// only panic in debug builds.
    #[must_use]
    fn global_index_to_local_index(&self, global_index: NodeIndex) -> NodeIndex {
        // Check that the global index falls in the subtree in depth.
        assert!(
            global_index.depth() >= self.root_index.depth()
                && global_index.depth() < self.root_index.depth() + u8::from(self.levels),
            "Global index depth {} was not inside the subtree",
            global_index.depth(),
        );

        let depth_g = global_index.depth();
        let width_g = global_index.value();
        let depth_r = self.root_index.depth();
        let width_r = self.root_index.value();

        let depth_s = depth_g - depth_r;
        let subtree_nodes_at_level = 2u64.pow(depth_s as u32);
        let width_before = width_r * subtree_nodes_at_level;

        // Check that the global index falls into the subtree in breadth.
        assert!(
            width_before <= width_g && width_before + subtree_nodes_at_level > width_g,
            "Global index breadth {width_g} was not inside the subtree",
        );

        let width_s = width_g - width_before;

        NodeIndex::new_unchecked(depth_s, width_s)
    }
}

/// This block contains associated helper functions that are intended to remain private.
impl ForestSubtree {
    /// Converts the provided `local_index` to the local node index for lookup.
    #[must_use]
    fn local_index_to_offset(local_index: NodeIndex) -> u64 {
        2u64.pow(local_index.depth() as u32) + local_index.value() - 1
    }

    /// Converts the local `offset` into the corresponding depth in the subtree.
    #[inline]
    #[must_use]
    fn offset_to_depth_in_subtree(_offset: u64) -> u8 {
        let n = _offset + 1;
        (u64::BITS as u8 - 1) - n.leading_zeros() as u8
    }

    /// Sets the bit in the `bitmask` at the provided `bit_offset` from the LSB.
    #[inline]
    fn set_bit(bitmask: &mut [u8], bit_offset: usize) {
        bitmask[bit_offset / 8] |= 1 << (bit_offset % 8);
    }

    /// Gets the value of the bit in the `bitmask` at the provided `bit_offset` from the LSB.
    #[inline]
    fn get_bit(bitmask: &[u8], bit_offset: usize) -> bool {
        (bitmask[bit_offset / 8] >> (bit_offset % 8)) & 1 != 0
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod test {
    use rand_utils::rand_value;

    use super::Result;
    use crate::merkle::{
        EmptySubtreeRoots, NodeIndex,
        smt::{ForestSubtree, InnerNode, SMT_DEPTH, SubtreeLevels},
    };

    #[test]
    fn construction_correct() {
        let subtree =
            ForestSubtree::new(NodeIndex::new_unchecked(8, 0), SubtreeLevels::new_unchecked(8));

        // It should start with no nodes and the correct root index.
        assert_eq!(subtree.node_count(), 0);
        assert_eq!(subtree.root_index, NodeIndex::new_unchecked(8, 0));

        // It should also have calculated the structure parameters correctly.
        assert_eq!(subtree.max_nodes, 255);
        assert_eq!(subtree.bitmask_size_bytes, 64);
    }

    #[test]
    fn insert_get_remove() {
        // Start by preparing our test data.
        let mut subtree =
            ForestSubtree::new(NodeIndex::new_unchecked(8, 16), SubtreeLevels::new_unchecked(8));

        // Inserting something under a key that doesn't yet have a value should return None
        let index_1 = NodeIndex::new_unchecked(8, 16);
        let inner_1 = InnerNode { left: rand_value(), right: rand_value() };
        assert!(subtree.insert(index_1, inner_1.clone()).is_none());

        // We should then be able to get it
        assert_eq!(subtree.get(index_1), Some(inner_1.clone()));

        // If we overwrite it, we should get it back.
        let inner_2 = InnerNode { left: rand_value(), right: rand_value() };
        assert_eq!(subtree.insert(index_1, inner_2.clone()), Some(inner_1));

        // We should be able to remove something that is there
        assert_eq!(subtree.remove(index_1), Some(inner_2));

        // And not crash if something is not.
        assert!(subtree.remove(index_1).is_none());

        // Finally, we should not be able to get something that doesn't exist
        assert!(subtree.get(index_1).is_none());
    }

    #[test]
    fn to_bytes_from_bytes() -> Result<()> {
        // We start by constructing a subtree.
        let subtree_root = NodeIndex::new_unchecked(13, 4111);
        let mut subtree = ForestSubtree::new(subtree_root, SubtreeLevels::new_unchecked(3));

        // We then have to construct the data to add to it...
        let l1 = InnerNode { left: rand_value(), right: rand_value() };
        let l2 = *EmptySubtreeRoots::entry(SMT_DEPTH, 15);
        let l3 = InnerNode { left: rand_value(), right: rand_value() };
        let l4 = InnerNode {
            left: rand_value(),
            right: *EmptySubtreeRoots::entry(SMT_DEPTH, 16),
        };
        let n1 = InnerNode { left: l1.hash(), right: l2 };
        let n2 = InnerNode { left: l3.hash(), right: l4.hash() };
        let root = InnerNode { left: n1.hash(), right: n2.hash() };

        // ... and add it
        assert!(subtree.insert(NodeIndex::new_unchecked(15, 16444), l1.clone()).is_none());
        assert!(subtree.insert(NodeIndex::new_unchecked(15, 16446), l3.clone()).is_none());
        assert!(subtree.insert(NodeIndex::new_unchecked(15, 16447), l4.clone()).is_none());
        assert!(subtree.insert(NodeIndex::new_unchecked(14, 8222), n1.clone()).is_none());
        assert!(subtree.insert(NodeIndex::new_unchecked(14, 8223), n2.clone()).is_none());
        assert!(subtree.insert(NodeIndex::new_unchecked(13, 4111), root.clone()).is_none());

        // Next we can serialize this to bytes and deserialize the result...
        let bytes = subtree.to_bytes();
        let restored = ForestSubtree::from_bytes(subtree_root, &bytes)?;

        // ... which should result in a round-trip.
        assert_eq!(restored.root_index, subtree.root_index);
        assert_eq!(restored.levels, subtree.levels);
        assert_eq!(restored.max_nodes, subtree.max_nodes);
        assert_eq!(restored.bitmask_size_bytes, subtree.bitmask_size_bytes);

        assert_eq!(restored.get(NodeIndex::new_unchecked(15, 16444)), Some(l1));
        assert_eq!(restored.get(NodeIndex::new_unchecked(15, 16446)), Some(l3));
        assert_eq!(restored.get(NodeIndex::new_unchecked(15, 16447)), Some(l4));
        assert_eq!(restored.get(NodeIndex::new_unchecked(14, 8222)), Some(n1));
        assert_eq!(restored.get(NodeIndex::new_unchecked(14, 8223)), Some(n2));
        assert_eq!(restored.get(NodeIndex::new_unchecked(13, 4111)), Some(root));

        Ok(())
    }

    #[test]
    fn global_index_to_local_index() {
        // Try with the leftmost subtree
        let subtree =
            ForestSubtree::new(NodeIndex::new_unchecked(8, 0), SubtreeLevels::new_unchecked(8));

        assert_eq!(
            subtree.global_index_to_local_index(NodeIndex::new_unchecked(8, 0)),
            NodeIndex::new_unchecked(0, 0)
        );
        assert_eq!(
            subtree.global_index_to_local_index(NodeIndex::new_unchecked(11, 0)),
            NodeIndex::new_unchecked(3, 0)
        );
        assert_eq!(
            subtree.global_index_to_local_index(NodeIndex::new_unchecked(15, 0)),
            NodeIndex::new_unchecked(7, 0)
        );

        assert_eq!(
            subtree.global_index_to_local_index(NodeIndex::new_unchecked(11, 7)),
            NodeIndex::new_unchecked(3, 7)
        );
        assert_eq!(
            subtree.global_index_to_local_index(NodeIndex::new_unchecked(15, 127)),
            NodeIndex::new_unchecked(7, 127)
        );

        assert_eq!(
            subtree.global_index_to_local_index(NodeIndex::new_unchecked(11, 3)),
            NodeIndex::new_unchecked(3, 3)
        );

        // Try with the rightmost subtree
        let subtree =
            ForestSubtree::new(NodeIndex::new_unchecked(8, 255), SubtreeLevels::new_unchecked(4));

        assert_eq!(
            subtree.global_index_to_local_index(NodeIndex::new_unchecked(8, 255)),
            NodeIndex::new_unchecked(0, 0)
        );
        assert_eq!(
            subtree.global_index_to_local_index(NodeIndex::new_unchecked(9, 510)),
            NodeIndex::new_unchecked(1, 0)
        );
        assert_eq!(
            subtree.global_index_to_local_index(NodeIndex::new_unchecked(11, 2040)),
            NodeIndex::new_unchecked(3, 0)
        );

        assert_eq!(
            subtree.global_index_to_local_index(NodeIndex::new_unchecked(9, 511)),
            NodeIndex::new_unchecked(1, 1)
        );
        assert_eq!(
            subtree.global_index_to_local_index(NodeIndex::new_unchecked(11, 2047)),
            NodeIndex::new_unchecked(3, 7)
        );

        assert_eq!(
            subtree.global_index_to_local_index(NodeIndex::new_unchecked(11, 2043)),
            NodeIndex::new_unchecked(3, 3)
        );

        // Try with a subtree in the middle
        let subtree =
            ForestSubtree::new(NodeIndex::new_unchecked(4, 8), SubtreeLevels::new_unchecked(4));

        assert_eq!(
            subtree.global_index_to_local_index(NodeIndex::new_unchecked(4, 8)),
            NodeIndex::new_unchecked(0, 0)
        );
        assert_eq!(
            subtree.global_index_to_local_index(NodeIndex::new_unchecked(5, 16)),
            NodeIndex::new_unchecked(1, 0)
        );
        assert_eq!(
            subtree.global_index_to_local_index(NodeIndex::new_unchecked(7, 64)),
            NodeIndex::new_unchecked(3, 0)
        );

        assert_eq!(
            subtree.global_index_to_local_index(NodeIndex::new_unchecked(5, 17)),
            NodeIndex::new_unchecked(1, 1)
        );
        assert_eq!(
            subtree.global_index_to_local_index(NodeIndex::new_unchecked(7, 71)),
            NodeIndex::new_unchecked(3, 7)
        );

        assert_eq!(
            subtree.global_index_to_local_index(NodeIndex::new_unchecked(7, 69)),
            NodeIndex::new_unchecked(3, 5)
        );
    }

    #[test]
    fn local_index_to_offset() {
        assert_eq!(ForestSubtree::local_index_to_offset(NodeIndex::new_unchecked(0, 0)), 0);
        assert_eq!(ForestSubtree::local_index_to_offset(NodeIndex::new_unchecked(1, 0)), 1);
        assert_eq!(ForestSubtree::local_index_to_offset(NodeIndex::new_unchecked(1, 1)), 2);
        assert_eq!(ForestSubtree::local_index_to_offset(NodeIndex::new_unchecked(2, 1)), 4);
        assert_eq!(ForestSubtree::local_index_to_offset(NodeIndex::new_unchecked(8, 7)), 262);
    }

    #[test]
    fn offset_to_depth() {
        assert_eq!(ForestSubtree::offset_to_depth_in_subtree(0), 0);
        assert_eq!(ForestSubtree::offset_to_depth_in_subtree(1), 1);
        assert_eq!(ForestSubtree::offset_to_depth_in_subtree(2), 1);
        assert_eq!(ForestSubtree::offset_to_depth_in_subtree(6), 2);
        assert_eq!(ForestSubtree::offset_to_depth_in_subtree(7), 3);
        assert_eq!(ForestSubtree::offset_to_depth_in_subtree(15), 4);
        assert_eq!(ForestSubtree::offset_to_depth_in_subtree(31), 5);
    }

    #[test]
    fn set_bit_get_bit() {
        let mut bitmask = vec![0b01010101];
        ForestSubtree::set_bit(&mut bitmask, 7);
        assert_eq!(bitmask, vec![0b11010101]);
        assert!(!ForestSubtree::get_bit(&bitmask, 5));
    }
}
