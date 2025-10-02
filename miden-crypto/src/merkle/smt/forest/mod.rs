use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};

use super::{EmptySubtreeRoots, MerkleError, NodeIndex, SmtLeaf, SmtProof, Word};
use crate::{
    Map,
    merkle::{MerkleStore, SmtLeafError, SmtProofError, SparseMerklePath, smt::SMT_DEPTH},
};

#[cfg(test)]
mod tests;

// SPARSE MERKLE TREE FOREST
// ================================================================================================

/// An in-memory data collection of sparse Merkle trees (SMTs).
///
/// Each SMT in the forest is identified by its root hash. The forest stores all leaves of all SMTs
/// in the forest, as well as all Merkle paths required to prove membership of any leaf in any SMT.
///
///
/// Example usage:
///
/// ```rust
/// use miden_crypto::{
///     Felt, Map, ONE, WORD_SIZE, ZERO,
///     merkle::{
///         forest::{EmptySubtreeRoots, SmtForest, Word},
///         int_to_node,
///         smt::{MAX_LEAF_ENTRIES, SMT_DEPTH},
///     },
/// };
/// // // Create a new SMT forest
/// let mut forest = SmtForest::new();
///
/// // Insert a key-value pair into an SMT with an empty root
/// let empty_tree_root = *EmptySubtreeRoots::entry(SMT_DEPTH, 0);
/// let key = Word::new([ZERO; WORD_SIZE]);
/// let value = Word::new([ONE; WORD_SIZE]);
/// let new_root = forest.insert(empty_tree_root, key, value).unwrap();
///
/// // Insert multiple key-value pairs
/// let mut entries = Map::new();
/// for i in 0..MAX_LEAF_ENTRIES {
///     let key = Word::new([Felt::new(i as u64); WORD_SIZE]);
///     let value = Word::new([Felt::new((i + 1) as u64); WORD_SIZE]);
///     entries.insert(key, value);
/// }
/// let new_root = forest.batch_insert(new_root, &entries).unwrap();
///
/// // Open a proof for the inserted key
/// let proof = forest.open(new_root, key).unwrap();
/// ```
#[derive(Debug, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct SmtForest {
    /// Roots of all SMTs in this forest. Any time an SMT in this forest is updated, we add a new
    /// root to this set.
    roots: BTreeSet<Word>,

    /// Stores Merkle paths for all SMTs in this forest.
    store: MerkleStore,

    /// Leaves of all SMTs stored in this forest
    leaves: BTreeMap<u64, SmtLeaf>,
}

impl Default for SmtForest {
    fn default() -> Self {
        Self::new()
    }
}

impl SmtForest {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates an empty `SmtForest` instance.
    pub fn new() -> SmtForest {
        let store = MerkleStore::new();
        let mut roots = BTreeSet::new();
        let empty_tree_root = *EmptySubtreeRoots::entry(SMT_DEPTH, 0);
        roots.insert(empty_tree_root);
        let leaves: BTreeMap<u64, SmtLeaf> = BTreeMap::new();
        SmtForest { store, roots, leaves }
    }

    // DATA EXTRACTORS
    // --------------------------------------------------------------------------------------------

    /// Returns an opening for the specified key in the SMT with the specified root.
    ///
    /// Returns an error if an SMT with this root is not in the forest, or if the forest does
    /// not have sufficient data to provide an opening for the specified key.
    pub fn open(&self, root: Word, key: Word) -> Result<SmtProof, MerkleError> {
        if !self.roots.contains(&root) {
            return Err(MerkleError::RootNotInStore(root));
        }

        let index = key[3].as_int();
        let node_index = NodeIndex::new(SMT_DEPTH, index)?;
        let path: SparseMerklePath = self.store.get_path(root, node_index)?.path.try_into()?;

        let leaf = match self.leaves.get(&index) {
            Some(leaf) => leaf.clone(),
            None => return Err(MerkleError::UntrackedKey(key)),
        };

        Ok(match SmtProof::new(path, leaf) {
            Ok(proof) => proof,
            Err(err) => match err {
                SmtProofError::InvalidMerklePathLength(depth) => {
                    return Err(MerkleError::InvalidPathLength(depth));
                },
            },
        })
    }

    // STATE MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Inserts the specified key-value pair into an SMT with the specified root. This would also
    /// add a new root to the forest.
    ///
    /// Returns an error if an SMT with the specified root is not in the forest, these is not
    /// enough data in the forest to perform the insert, or if the insert would create a leaf
    /// with too many entries.
    pub fn insert(&mut self, root: Word, key: Word, value: Word) -> Result<Word, MerkleError> {
        if !self.roots.contains(&root) {
            return Err(MerkleError::RootNotInStore(root));
        }

        let index = key[3].as_int();
        let node_index = NodeIndex::new(SMT_DEPTH, index)?;

        let leaf_hash = match self.leaves.get_mut(&index) {
            // Leaf for this key already exists; update it and return its hash.
            // If the leaf was LeafSingle, it gets promoted to LeafMultiple.
            Some(leaf) => {
                leaf.insert(key, value).map_err(to_merkle_error)?;
                leaf.hash()
            },
            // No leaf for this key exists; create a new one and return its hash.
            None => {
                let leaf = SmtLeaf::new_single(key, value);
                let leaf_hash = leaf.hash();
                self.leaves.insert(index, leaf);
                leaf_hash
            },
        };

        let new_root = self.store.set_node(root, node_index, leaf_hash)?.root;
        self.roots.insert(new_root);

        Ok(new_root)
    }

    /// Inserts the specified key-value pairs into an SMT with the specified root. This would also
    /// add a new root to the forest.
    ///
    /// Returns an error if an SMT with the specified root is not in the forest, these is not
    /// enough data in the forest to perform the insert, or if the insert would create a leaf
    /// with too many entries.
    pub fn batch_insert(
        &mut self,
        root: Word,
        entries: &Map<Word, Word>,
    ) -> Result<Word, MerkleError> {
        if !self.roots.contains(&root) {
            return Err(MerkleError::RootNotInStore(root));
        }

        // calculate new key-value pairs for the leaves
        let mut new_leaves = BTreeMap::<u64, SmtLeaf>::new();
        for (key, value) in entries {
            let index = key[3].as_int();
            if let Some(leaf) = new_leaves.get_mut(&index) {
                leaf.insert(*key, *value).map_err(to_merkle_error)?;
            } else if let Some(leaf) = self.leaves.get(&index) {
                let mut new_leaf = leaf.clone();
                new_leaf.insert(*key, *value).map_err(to_merkle_error)?;
                new_leaves.insert(index, new_leaf);
            } else {
                let new_leaf = SmtLeaf::new_single(*key, *value);
                new_leaves.insert(index, new_leaf);
            }
        }
        let new_leaves = new_leaves
            .iter()
            .map(|(index, leaf)| (NodeIndex::new(SMT_DEPTH, *index).unwrap(), leaf.hash()))
            .collect::<Vec<_>>();

        std::println!("new leaves {new_leaves:?}");

        self.store.set_nodes(root, new_leaves)
    }
}

fn to_merkle_error(err: SmtLeafError) -> MerkleError {
    match err {
        SmtLeafError::TooManyLeafEntries { actual } => MerkleError::TooManyLeafEntries { actual },
        _ => unreachable!("other SmtLeafError variants should not be possible here"),
    }
}
