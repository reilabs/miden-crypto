use winter_utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable};

use super::{LeafIndex, SMT_DEPTH};
use crate::{
    EMPTY_WORD, Word,
    hash::rpo::Rpo256,
    merkle::{
        InnerNodeInfo, MerkleError, NodeIndex, SparseMerklePath,
        smt::{InnerNode, InnerNodes, Leaves, Smt, SmtLeaf, SmtProof, SparseMerkleTree},
    },
};

#[cfg(test)]
mod tests;

/// A partial version of an [`Smt`].
///
/// This type can track a subset of the key-value pairs of a full [`Smt`] and allows for updating
/// those pairs to compute the new root of the tree, as if the updates had been done on the full
/// tree. This is useful so that not all leaves have to be present and loaded into memory to compute
/// an update.
///
/// A key is considered "tracked" if either:
/// 1. Its merkle path was explicitly added to the tree (via [`PartialSmt::add_path`] or
///    [`PartialSmt::add_proof`]), or
/// 2. A merkle path can be computed for it from the existing inner nodes in the partial SMT, and
///    that path resolves to the current root.
///
/// The second condition allows updating keys in empty subtrees for which merkle paths exist,
/// even if those keys were not explicitly added.
///
/// An important caveat is that only tracked keys can be updated. Attempting to update an
/// untracked key will result in an error. See [`PartialSmt::insert`] for more details.
///
/// Once a partial SMT has been constructed, its root is set in stone. All subsequently added proofs
/// or merkle paths must match that root, otherwise an error is returned.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct PartialSmt(Smt);

impl PartialSmt {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Constructs a [`PartialSmt`] from a root.
    ///
    /// All subsequently added proofs or paths must have the same root.
    pub fn new(root: Word) -> Self {
        let mut partial_smt = Self(Smt::default());

        partial_smt.0.set_root(root);

        partial_smt
    }

    /// Instantiates a new [`PartialSmt`] by calling [`PartialSmt::add_proof`] for all [`SmtProof`]s
    /// in the provided iterator.
    ///
    /// If the provided iterator is empty, an empty [`PartialSmt`] is returned.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the roots of the provided proofs are not the same.
    pub fn from_proofs<I>(proofs: I) -> Result<Self, MerkleError>
    where
        I: IntoIterator<Item = SmtProof>,
    {
        let mut proofs = proofs.into_iter();

        let Some(first_proof) = proofs.next() else {
            return Ok(Self::default());
        };

        // Add the first path to an empty partial SMT without checking that the existing root
        // matches the new one. This sets the expected root to the root of the first proof and all
        // subsequently added proofs must match it.
        let mut partial_smt = Self::default();
        let (path, leaf) = first_proof.into_parts();
        let path_root = partial_smt.add_path_unchecked(leaf, path);
        partial_smt.0.set_root(path_root);

        for proof in proofs {
            partial_smt.add_proof(proof)?;
        }

        Ok(partial_smt)
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the root of the tree.
    pub fn root(&self) -> Word {
        self.0.root()
    }

    /// Returns an opening of the leaf associated with `key`. Conceptually, an opening is a Merkle
    /// path to the leaf, as well as the leaf itself.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the key is not tracked by this partial SMT.
    pub fn open(&self, key: &Word) -> Result<SmtProof, MerkleError> {
        if !self.is_leaf_tracked(key) {
            return Err(MerkleError::UntrackedKey(*key));
        }

        Ok(self.0.open(key))
    }

    /// Returns the leaf to which `key` maps
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the key is not tracked by this partial SMT.
    pub fn get_leaf(&self, key: &Word) -> Result<SmtLeaf, MerkleError> {
        if !self.is_leaf_tracked(key) {
            return Err(MerkleError::UntrackedKey(*key));
        }

        Ok(self.0.get_leaf(key))
    }

    /// Returns the value associated with `key`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the key is not tracked by this partial SMT.
    pub fn get_value(&self, key: &Word) -> Result<Word, MerkleError> {
        if !self.is_leaf_tracked(key) {
            return Err(MerkleError::UntrackedKey(*key));
        }

        Ok(self.0.get_value(key))
    }

    // STATE MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Inserts a value at the specified key, returning the previous value associated with that key.
    /// Recall that by definition, any key that hasn't been updated is associated with
    /// [`Smt::EMPTY_VALUE`].
    ///
    /// This also recomputes all hashes between the leaf (associated with the key) and the root,
    /// updating the root itself.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the key and its merkle path were not previously added (using [`PartialSmt::add_path`]) to
    ///   this [`PartialSmt`], which means it is almost certainly incorrect to update its value. If
    ///   an error is returned the tree is in the same state as before.
    /// - inserting the key-value pair would exceed [`super::MAX_LEAF_ENTRIES`] (1024 entries) in
    ///   the leaf.
    pub fn insert(&mut self, key: Word, value: Word) -> Result<Word, MerkleError> {
        if !self.is_leaf_tracked(&key) {
            return Err(MerkleError::UntrackedKey(key));
        }

        let previous_value = self.0.insert(key, value)?;

        // If the value was removed the SmtLeaf was removed as well by the underlying Smt
        // implementation. However, we still want to consider that leaf tracked so it can be
        // read and written to, so we reinsert an empty SmtLeaf.
        if value == EMPTY_WORD {
            let leaf_index = Smt::key_to_leaf_index(&key);
            self.0.leaves.insert(leaf_index.value(), SmtLeaf::Empty(leaf_index));
        }

        Ok(previous_value)
    }

    /// Adds an [`SmtProof`] to this [`PartialSmt`].
    ///
    /// This is a convenience method which calls [`Self::add_path`] on the proof. See its
    /// documentation for details on errors.
    pub fn add_proof(&mut self, proof: SmtProof) -> Result<(), MerkleError> {
        let (path, leaf) = proof.into_parts();
        self.add_path(leaf, path)
    }

    /// Adds a leaf and its sparse merkle path to this [`PartialSmt`].
    ///
    /// If this function was called, any key that is part of the `leaf` can subsequently be updated
    /// to a new value and produce a correct new tree root.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the new root after the insertion of the leaf and the path does not match the existing
    ///   root. If an error is returned, the tree is left in an inconsistent state.
    pub fn add_path(&mut self, leaf: SmtLeaf, path: SparseMerklePath) -> Result<(), MerkleError> {
        let path_root = self.add_path_unchecked(leaf, path);

        // Check if the newly added merkle path is consistent with the existing tree. If not, the
        // merkle path was invalid or computed against another tree.
        if self.root() != path_root {
            return Err(MerkleError::ConflictingRoots {
                expected_root: self.root(),
                actual_root: path_root,
            });
        }

        Ok(())
    }

    /// Returns an iterator over the inner nodes of the [`PartialSmt`].
    pub fn inner_nodes(&self) -> impl Iterator<Item = InnerNodeInfo> + '_ {
        self.0.inner_nodes()
    }

    /// Returns an iterator over the [`InnerNode`] and the respective [`NodeIndex`] of the
    /// [`PartialSmt`].
    pub fn inner_node_indices(&self) -> impl Iterator<Item = (NodeIndex, InnerNode)> + '_ {
        self.0.inner_node_indices()
    }

    /// Returns an iterator over the tracked, non-empty leaves of the [`PartialSmt`] in arbitrary
    /// order.
    pub fn leaves(&self) -> impl Iterator<Item = (LeafIndex<SMT_DEPTH>, &SmtLeaf)> {
        // The partial SMT also contains empty leaves, so we have to filter them out.
        self.0.leaves().filter_map(
            |(leaf_idx, leaf)| {
                if leaf.is_empty() { None } else { Some((leaf_idx, leaf)) }
            },
        )
    }

    /// Returns an iterator over the tracked leaves of the [`PartialSmt`] in arbitrary order.
    ///
    /// Note that this includes empty leaves.
    pub fn tracked_leaves(&self) -> impl Iterator<Item = (LeafIndex<SMT_DEPTH>, &SmtLeaf)> {
        self.0.leaves()
    }

    /// Returns an iterator over the tracked, non-empty key-value pairs of the [`PartialSmt`] in
    /// arbitrary order.
    pub fn entries(&self) -> impl Iterator<Item = &(Word, Word)> {
        self.0.entries()
    }

    /// Returns the number of tracked leaves in this tree, which includes empty ones.
    ///
    /// Note that this may return a different value from [Self::num_entries()] as a single leaf may
    /// contain more than one key-value pair.
    pub fn num_leaves(&self) -> usize {
        self.0.num_leaves()
    }

    /// Returns the number of tracked, non-empty key-value pairs in this tree.
    ///
    /// Note that this may return a different value from [Self::num_leaves()] as a single leaf may
    /// contain more than one key-value pair.
    pub fn num_entries(&self) -> usize {
        self.0.num_entries()
    }

    /// Returns a boolean value indicating whether the [`PartialSmt`] tracks any leaves.
    ///
    /// Note that if a partial SMT does not track leaves, its root is not necessarily the empty SMT
    /// root, since it could have been constructed from a different root but without tracking any
    /// leaves.
    pub fn tracks_leaves(&self) -> bool {
        !self.0.leaves.is_empty()
    }

    // PRIVATE HELPERS
    // --------------------------------------------------------------------------------------------

    /// Adds a leaf and its sparse merkle path to this [`PartialSmt`] and returns the root of the
    /// inserted path.
    ///
    /// This does not check that the path root matches the existing root of the tree and if so, the
    /// tree is left in an inconsistent state. This state can be made consistent again by setting
    /// the root of the SMT to the path root.
    fn add_path_unchecked(&mut self, leaf: SmtLeaf, path: SparseMerklePath) -> Word {
        let mut current_index = leaf.index().index;

        let mut node_hash_at_current_index = leaf.hash();

        // We insert directly into the leaves for two reasons:
        // - We can directly insert the leaf as it is without having to loop over its entries to
        //   call Smt::perform_insert.
        // - If the leaf is SmtLeaf::Empty, we will also insert it, which means this leaf is
        //   considered tracked by the partial SMT as it is part of the leaves map. When calling
        //   PartialSmt::insert, this will not error for such empty leaves whose merkle path was
        //   added, but will error for otherwise non-existent leaves whose paths were not added,
        //   which is what we want.
        let prev_entries = self
            .0
            .leaves
            .get(&current_index.value())
            .map(|leaf| leaf.num_entries())
            .unwrap_or(0);
        let current_entries = leaf.num_entries();
        self.0.leaves.insert(current_index.value(), leaf);

        // Guaranteed not to over/underflow. All variables are <= MAX_LEAF_ENTRIES and result > 0.
        self.0.num_entries = self.0.num_entries + current_entries - prev_entries;

        for sibling_hash in path {
            // Find the index of the sibling node and compute whether it is a left or right child.
            let is_sibling_right = current_index.sibling().is_value_odd();

            // Move the index up so it points to the parent of the current index and the sibling.
            current_index.move_up();

            // Construct the new parent node from the child that was updated and the sibling from
            // the merkle path.
            let new_parent_node = if is_sibling_right {
                InnerNode {
                    left: node_hash_at_current_index,
                    right: sibling_hash,
                }
            } else {
                InnerNode {
                    left: sibling_hash,
                    right: node_hash_at_current_index,
                }
            };

            self.0.insert_inner_node(current_index, new_parent_node);

            node_hash_at_current_index = self.0.get_inner_node(current_index).hash();
        }

        node_hash_at_current_index
    }

    /// Returns true if the key's merkle path was previously added to this partial SMT and can be
    /// sensibly updated to a new value.
    ///
    /// A key is considered tracked if:
    /// 1. It was explicitly added via `add_path` or `add_proof`, or
    /// 2. The leaf is empty and a valid merkle path can be computed for it from existing inner
    ///    nodes (e.g., keys in empty subtrees where sibling paths exist).
    fn is_leaf_tracked(&self, key: &Word) -> bool {
        // Check if the leaf was explicitly added
        let leaf_index = Smt::key_to_leaf_index(key);
        if self.0.leaves.contains_key(&leaf_index.value()) {
            return true;
        }

        // Check if a valid merkle path exists
        let leaf = self.0.get_leaf(key);
        let leaf_hash = Smt::hash_leaf(&leaf);
        self.compute_root_if_path_is_consistent(leaf_index.into(), leaf_hash)
            .is_some_and(|root| root == self.root())
    }

    /// Walks from the given index to the root, computing the root hash while checking
    /// consistency with the tree at each level.
    ///
    /// Returns `Some(root)` if the path is consistent, or `None` if a mismatch is detected.
    fn compute_root_if_path_is_consistent(
        &self,
        mut index: NodeIndex,
        node_hash: Word,
    ) -> Option<Word> {
        let mut current_hash = node_hash;

        while index.depth() > 0 {
            // Check consistency: does our computed hash match what the tree says?
            if current_hash != self.0.get_node_hash(index) {
                return None;
            }

            // Compute parent hash
            let sibling_hash = self.0.get_node_hash(index.sibling());
            let input = index.build_node(current_hash, sibling_hash);
            index.move_up();
            current_hash = Rpo256::merge(&input);
        }

        Some(current_hash)
    }
}

impl Default for PartialSmt {
    /// Returns a new, empty [`PartialSmt`].
    ///
    /// All leaves in the returned tree are set to [`Smt::EMPTY_VALUE`].
    fn default() -> Self {
        Self::new(Smt::EMPTY_ROOT)
    }
}

// CONVERSIONS
// ================================================================================================

impl From<Smt> for PartialSmt {
    fn from(smt: Smt) -> Self {
        PartialSmt(smt)
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for PartialSmt {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write(self.root());
        target.write_usize(self.0.leaves.len());
        for (i, leaf) in &self.0.leaves {
            target.write_u64(*i);
            target.write(leaf);
        }
        target.write_usize(self.0.inner_nodes.len());
        for (idx, node) in &self.0.inner_nodes {
            target.write(idx);
            target.write(node);
        }
    }
}

impl Deserializable for PartialSmt {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let root: Word = source.read()?;

        let mut leaves = Leaves::default();
        for _ in 0..source.read_usize()? {
            let pos: u64 = source.read()?;
            let leaf: SmtLeaf = source.read()?;
            leaves.insert(pos, leaf);
        }

        let mut nodes = InnerNodes::default();
        for _ in 0..source.read_usize()? {
            let idx: NodeIndex = source.read()?;
            let node: InnerNode = source.read()?;
            nodes.insert(idx, node);
        }

        // If the leaves are empty, the set root may not match the root of the inner nodes, which
        // causes from_raw_parts to panic. In this case, we bypass this check by constructing the
        // SMT with the expected root and overwriting it afterward.
        let smt = if leaves.is_empty() {
            let inner_node_root =
                nodes.get(&NodeIndex::root()).map(InnerNode::hash).unwrap_or(Smt::EMPTY_ROOT);
            let mut smt = Smt::from_raw_parts(nodes, leaves, inner_node_root);
            smt.set_root(root);
            smt
        } else {
            // If the leaves are not empty, the root should match.
            Smt::from_raw_parts(nodes, leaves, root)
        };

        Ok(PartialSmt(smt))
    }
}
