//! Large-scale Sparse Merkle Tree backed by pluggable storage.
//!
//! `LargeSmt` stores the top of the tree (depths 0–23) in memory and persists the lower
//! depths (24–64) in storage as fixed-size subtrees. This hybrid layout scales beyond RAM
//! while keeping common operations fast. With the `rocksdb` feature enabled, the lower
//! subtrees and leaves are stored in RocksDB. On reopen, the in-memory top is reconstructed
//! from cached depth-24 subtree roots.
//!
//! Examples below require the `rocksdb` feature.
//!
//! Open an existing RocksDB-backed tree:
//! ```no_run
//! use miden_crypto::merkle::{LargeSmt, RocksDbConfig, RocksDbStorage};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let storage = RocksDbStorage::open(RocksDbConfig::new("/path/to/db"))?;
//! let smt = LargeSmt::new(storage)?; // reconstructs in-memory top if data exists
//! let _root = smt.root()?;
//! # Ok(())
//! # }
//! ```
//!
//! Initialize an empty RocksDB-backed tree and bulk-load entries:
//! ```no_run
//! use miden_crypto::{
//!     Felt, Word,
//!     merkle::{LargeSmt, RocksDbConfig, RocksDbStorage},
//! };
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let path = "/path/to/new-db";
//! if std::path::Path::new(path).exists() {
//!     std::fs::remove_dir_all(path)?;
//! }
//! std::fs::create_dir_all(path)?;
//!
//! let storage = RocksDbStorage::open(RocksDbConfig::new(path))?;
//! let mut smt = LargeSmt::new(storage)?; // empty tree
//!
//! // Prepare initial entries
//! let entries = vec![
//!     (
//!         Word::new([Felt::new(1), Felt::new(0), Felt::new(0), Felt::new(0)]),
//!         Word::new([Felt::new(10), Felt::new(20), Felt::new(30), Felt::new(40)]),
//!     ),
//!     (
//!         Word::new([Felt::new(2), Felt::new(0), Felt::new(0), Felt::new(0)]),
//!         Word::new([Felt::new(11), Felt::new(22), Felt::new(33), Felt::new(44)]),
//!     ),
//! ];
//!
//! // Bulk insert entries (faster than compute_mutations + apply_mutations)
//! smt.insert_batch(entries)?;
//! # Ok(())
//! # }
//! ```
//!
//! Apply batch updates (insertions and deletions):
//! ```no_run
//! use miden_crypto::{
//!     EMPTY_WORD, Felt, Word,
//!     merkle::{LargeSmt, RocksDbConfig, RocksDbStorage},
//! };
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let storage = RocksDbStorage::open(RocksDbConfig::new("/path/to/db"))?;
//! let mut smt = LargeSmt::new(storage)?;
//!
//! let k1 = Word::new([Felt::new(101), Felt::new(0), Felt::new(0), Felt::new(0)]);
//! let v1 = Word::new([Felt::new(1), Felt::new(2), Felt::new(3), Felt::new(4)]);
//! let k2 = Word::new([Felt::new(202), Felt::new(0), Felt::new(0), Felt::new(0)]);
//! let k3 = Word::new([Felt::new(303), Felt::new(0), Felt::new(0), Felt::new(0)]);
//! let v3 = Word::new([Felt::new(7), Felt::new(7), Felt::new(7), Felt::new(7)]);
//!
//! // EMPTY_WORD marks deletions
//! let updates = vec![(k1, v1), (k2, EMPTY_WORD), (k3, v3)];
//! smt.insert_batch(updates)?;
//! # Ok(())
//! # }
//! ```
//!
//! Quick initialization with `with_entries` (best for modest datasets/tests):
//! ```no_run
//! use miden_crypto::{
//!     Felt, Word,
//!     merkle::{LargeSmt, RocksDbConfig, RocksDbStorage},
//! };
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Note: `with_entries` expects an EMPTY storage and performs an all-at-once build.
//! // Prefer `insert_batch` for large bulk loads.
//! let path = "/path/to/new-db";
//! if std::path::Path::new(path).exists() {
//!     std::fs::remove_dir_all(path)?;
//! }
//! std::fs::create_dir_all(path)?;
//!
//! let storage = RocksDbStorage::open(RocksDbConfig::new(path))?;
//! let entries = vec![
//!     (
//!         Word::new([Felt::new(1), Felt::new(0), Felt::new(0), Felt::new(0)]),
//!         Word::new([Felt::new(10), Felt::new(20), Felt::new(30), Felt::new(40)]),
//!     ),
//!     (
//!         Word::new([Felt::new(2), Felt::new(0), Felt::new(0), Felt::new(0)]),
//!         Word::new([Felt::new(11), Felt::new(22), Felt::new(33), Felt::new(44)]),
//!     ),
//! ];
//! let _smt = LargeSmt::with_entries(storage, entries)?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Performance and Memory Considerations
//!
//! The `apply_mutations()` and `apply_mutations_with_reversion()` methods use batched
//! operations: they preload all affected subtrees and leaves before applying changes
//! atomically. This approach reduces I/O at the cost of higher temporary memory usage.
//!
//! ### Memory Usage
//!
//! Peak memory is proportional to:
//! - The number of mutated leaves
//! - The number of distinct storage subtrees touched by those mutations
//!
//! This memory is temporary and released immediately after the batch commits.
//!
//! ### Locality Matters
//!
//! Memory usage scales with how dispersed updates are, not just their count:
//! - **Localized updates**: Keys with shared high-order bits fall into the same storage subtrees
//! - **Scattered updates**: Keys spread across many storage subtrees require loading more distinct
//!   subtrees
//!
//! ### Guidelines
//!
//! For typical batches (up to ~10,000 updates) with reasonable locality, the working set
//! is modest. Very large or highly scattered batches will use more
//! memory proportionally.
//!
//! To optimize memory and I/O: group updates by key locality so that keys sharing
//! high-order bits are processed together.

use alloc::vec::Vec;
use core::mem;

use rayon::prelude::*;

use super::{
    EMPTY_WORD, EmptySubtreeRoots, InnerNode, InnerNodeInfo, InnerNodes, LeafIndex, MerkleError,
    NodeIndex, Rpo256, SMT_DEPTH, Smt, SmtLeaf, SmtLeafError, SmtProof, SparseMerklePath,
    SparseMerkleTree, Word,
};
use crate::merkle::smt::{
    Map,
    full::concurrent::{
        MutatedSubtreeLeaves, PairComputations, SUBTREE_DEPTH, SubtreeLeaf, SubtreeLeavesIter,
        build_subtree,
    },
};

mod error;
pub use error::LargeSmtError;

#[cfg(test)]
mod tests;

mod subtree;
pub use subtree::{Subtree, SubtreeError};

mod storage;
pub use storage::{MemoryStorage, SmtStorage, StorageError, StorageUpdateParts, StorageUpdates};
#[cfg(feature = "rocksdb")]
pub use storage::{RocksDbConfig, RocksDbStorage};

mod iter;
pub use iter::LargeSmtInnerNodeIterator;

mod utils;
use utils::{is_empty_parent, to_memory_index};

mod batch_ops;

// CONSTANTS
// ================================================================================================

/// Number of levels of the tree that are stored in memory
const IN_MEMORY_DEPTH: u8 = 24;

/// Number of nodes that are stored in memory (including the unused index 0)
const NUM_IN_MEMORY_NODES: usize = 1 << (IN_MEMORY_DEPTH + 1);

/// Number of subtree levels below in-memory depth (24-64 in steps of 8)
const NUM_SUBTREE_LEVELS: usize = 5;

/// How many subtrees we buffer before flushing them to storage **during the
/// SMT construction phase**.
///
/// * This constant is **only** used while building a fresh tree; incremental updates use their own
///   per-batch sizing.
/// * Construction is all-or-nothing: if the write fails we abort and rebuild from scratch, so we
///   allow larger batches that maximise I/O throughput instead of fine-grained rollback safety.
const CONSTRUCTION_SUBTREE_BATCH_SIZE: usize = 10_000;

// TYPES
// ================================================================================================

type Leaves = super::Leaves<SmtLeaf>;

/// Result of loading leaves from storage: (leaf indices, map of leaf index to leaf).
type LoadedLeaves = (Vec<u64>, Map<u64, Option<SmtLeaf>>);

/// Result of processing key-value pairs into mutated leaves for subtree building:
/// - `MutatedSubtreeLeaves`: Leaves organized for parallel subtree building
/// - `Map<u64, SmtLeaf>`: Map of leaf index to mutated leaf node (for storage updates)
/// - `Map<Word, Word>`: Changed key-value pairs
/// - `isize`: Leaf count delta
/// - `isize`: Entry count delta
type MutatedLeaves = (MutatedSubtreeLeaves, Map<u64, SmtLeaf>, Map<Word, Word>, isize, isize);

/// Represents a storage update for a subtree after processing mutations.
#[derive(Debug)]
enum SubtreeUpdate {
    /// No storage update needed (in-memory or unchanged).
    None,
    /// Store the modified subtree at the given index.
    Store { index: NodeIndex, subtree: Subtree },
    /// Delete the subtree at the given index (became empty).
    Delete { index: NodeIndex },
}

// LargeSmt
// ================================================================================================

/// A large-scale Sparse Merkle tree mapping 256-bit keys to 256-bit values, backed by pluggable
/// storage. Both keys and values are represented by 4 field elements.
///
/// Unlike the regular `Smt`, this implementation is designed for very large trees by using external
/// storage (such as RocksDB) for the bulk of the tree data, while keeping only the upper levels (up
/// to depth 24) in memory. This hybrid approach allows the tree to scale beyond memory limitations
/// while maintaining good performance for common operations.
///
/// All leaves sit at depth 64. The most significant element of the key is used to identify the leaf
/// to which the key maps.
///
/// A leaf is either empty, or holds one or more key-value pairs. An empty leaf hashes to the empty
/// word. Otherwise, a leaf hashes to the hash of its key-value pairs, ordered by key first, value
/// second.
///
/// The tree structure:
/// - Depths 0-23: Stored in memory as a flat array for fast access
/// - Depths 24-64: Stored in external storage organized as subtrees for efficient batch operations
#[derive(Debug)]
pub struct LargeSmt<S: SmtStorage> {
    storage: S,
    /// Flat vector representation of in-memory nodes.
    /// Index 0 is unused; index 1 is root.
    /// For node at index i: left child at 2*i, right child at 2*i+1.
    in_memory_nodes: Vec<Word>,
}

impl<S: SmtStorage> LargeSmt<S> {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------
    /// The default value used to compute the hash of empty leaves.
    pub const EMPTY_VALUE: Word = <Self as SparseMerkleTree<SMT_DEPTH>>::EMPTY_VALUE;

    /// Subtree depths for the subtrees stored in storage.
    pub const SUBTREE_DEPTHS: [u8; 5] = [56, 48, 40, 32, 24];

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Returns a new [LargeSmt] backed by the provided storage.
    ///
    /// The SMT's root is fetched from the storage backend. If the storage is empty the SMT is
    /// initialized with the root of an empty tree. Otherwise, materializes in-memory nodes from
    /// the top subtrees.
    ///
    /// # Errors
    /// Returns an error if fetching the root or initial in-memory nodes from the storage fails.
    pub fn new(storage: S) -> Result<Self, LargeSmtError> {
        let root = storage.get_root()?.unwrap_or(*EmptySubtreeRoots::entry(SMT_DEPTH, 0));

        let is_empty = !storage.has_leaves()?;

        // Initialize in-memory nodes
        let mut in_memory_nodes: Vec<Word> = vec![EMPTY_WORD; NUM_IN_MEMORY_NODES];

        for depth in 0..IN_MEMORY_DEPTH {
            let child_empty_hash = *EmptySubtreeRoots::entry(SMT_DEPTH, depth + 1);
            let start = 2 * (1 << depth);
            let end = 2 * (1 << (depth + 1));
            in_memory_nodes[start..end].fill(child_empty_hash);
        }

        // No leaves, return empty tree
        if is_empty {
            return Ok(Self { storage, in_memory_nodes });
        }

        let subtree_roots = storage.get_depth24()?;

        // convert subtree roots to SubtreeLeaf
        let mut leaf_subtrees: Vec<SubtreeLeaf> = subtree_roots
            .into_iter()
            .map(|(index, hash)| SubtreeLeaf { col: index, hash })
            .collect();
        leaf_subtrees.sort_by_key(|leaf| leaf.col);

        let mut subtree_leaves: Vec<Vec<SubtreeLeaf>> =
            SubtreeLeavesIter::from_leaves(&mut leaf_subtrees).collect();

        // build in-memory top of the tree
        for current_depth in (SUBTREE_DEPTH..=IN_MEMORY_DEPTH).step_by(SUBTREE_DEPTH as usize).rev()
        {
            let (nodes, mut subtree_roots): (Vec<Map<_, _>>, Vec<SubtreeLeaf>) = subtree_leaves
                .into_par_iter()
                .map(|subtree| {
                    debug_assert!(subtree.is_sorted());
                    debug_assert!(!subtree.is_empty());
                    let (nodes, subtree_root) = build_subtree(subtree, SMT_DEPTH, current_depth);
                    (nodes, subtree_root)
                })
                .unzip();
            subtree_leaves = SubtreeLeavesIter::from_leaves(&mut subtree_roots).collect();
            debug_assert!(!subtree_leaves.is_empty());

            for subtree_nodes in nodes {
                for (index, node) in subtree_nodes {
                    let memory_index = to_memory_index(&index);
                    // Store left and right children in flat layout
                    in_memory_nodes[memory_index * 2] = node.left;
                    in_memory_nodes[memory_index * 2 + 1] = node.right;
                }
            }
        }

        // Check that the calculated root matches the root in storage
        // Root is at index 1, with children at indices 2 and 3
        let calculated_root = Rpo256::merge(&[in_memory_nodes[2], in_memory_nodes[3]]);
        assert_eq!(calculated_root, root, "Tree reconstruction failed - root mismatch");

        Ok(Self { storage, in_memory_nodes })
    }

    /// Returns a new [Smt] instantiated with leaves set as specified by the provided entries.
    ///
    /// If the `concurrent` feature is enabled, this function uses a parallel implementation to
    /// process the entries efficiently, otherwise it defaults to the sequential implementation.
    ///
    /// All leaves omitted from the entries list are set to [Self::EMPTY_VALUE].
    ///
    /// # Errors
    /// Returns an error if the provided entries contain multiple values for the same key.
    pub fn with_entries(
        storage: S,
        entries: impl IntoIterator<Item = (Word, Word)>,
    ) -> Result<Self, LargeSmtError> {
        let entries: Vec<(Word, Word)> = entries.into_iter().collect();

        if storage.has_leaves()? {
            return Err(StorageError::Unsupported(
                "Cannot create SMT with non-empty storage".into(),
            )
            .into());
        }
        let mut tree = LargeSmt::new(storage)?;
        if entries.is_empty() {
            return Ok(tree);
        }
        tree.build_subtrees(entries)?;
        Ok(tree)
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the depth of the tree
    pub const fn depth(&self) -> u8 {
        SMT_DEPTH
    }

    /// Returns the root of the tree
    pub fn root(&self) -> Result<Word, LargeSmtError> {
        Ok(self.storage.get_root()?.unwrap_or(Self::EMPTY_ROOT))
    }

    /// Returns the number of non-empty leaves in this tree.
    ///
    /// Note that this may return a different value from [Self::num_entries()] as a single leaf may
    /// contain more than one key-value pair.
    ///
    /// # Errors
    /// Returns an error if there is a storage error when retrieving the leaf count.
    pub fn num_leaves(&self) -> Result<usize, LargeSmtError> {
        Ok(self.storage.leaf_count()?)
    }

    /// Returns the number of key-value pairs with non-default values in this tree.
    ///
    /// Note that this may return a different value from [Self::num_leaves()] as a single leaf may
    /// contain more than one key-value pair.
    ///
    /// Also note that this is currently an expensive operation is counting the number of entries
    /// requires iterating over all leaves of the tree.
    ///
    /// # Errors
    /// Returns an error if there is a storage error when retrieving the entry count.
    pub fn num_entries(&self) -> Result<usize, LargeSmtError> {
        Ok(self.storage.entry_count()?)
    }

    /// Returns the leaf to which `key` maps
    pub fn get_leaf(&self, key: &Word) -> SmtLeaf {
        <Self as SparseMerkleTree<SMT_DEPTH>>::get_leaf(self, key)
    }

    /// Returns the value associated with `key`
    pub fn get_value(&self, key: &Word) -> Word {
        <Self as SparseMerkleTree<SMT_DEPTH>>::get_value(self, key)
    }

    /// Returns an opening of the leaf associated with `key`. Conceptually, an opening is a Merkle
    /// path to the leaf, as well as the leaf itself.
    pub fn open(&self, key: &Word) -> SmtProof {
        <Self as SparseMerkleTree<SMT_DEPTH>>::open(self, key)
    }

    /// Returns a boolean value indicating whether the SMT is empty.
    ///
    /// # Errors
    /// Returns an error if there is a storage error when retrieving the root or leaf count.
    pub fn is_empty(&self) -> Result<bool, LargeSmtError> {
        let root = self.storage.get_root()?.unwrap_or(Self::EMPTY_ROOT);
        debug_assert_eq!(self.num_leaves()? == 0, root == Self::EMPTY_ROOT);
        Ok(root == Self::EMPTY_ROOT)
    }

    // ITERATORS
    // --------------------------------------------------------------------------------------------

    /// Returns an iterator over the leaves of this [Smt].
    /// Note: This iterator returns owned SmtLeaf values.
    ///
    /// # Errors
    /// Returns an error if the storage backend fails to create the iterator.
    pub fn leaves(
        &self,
    ) -> Result<impl Iterator<Item = (LeafIndex<SMT_DEPTH>, SmtLeaf)>, LargeSmtError> {
        let iter = self.storage.iter_leaves()?;
        Ok(iter.map(|(idx, leaf)| (LeafIndex::new_max_depth(idx), leaf)))
    }

    /// Returns an iterator over the key-value pairs of this [Smt].
    /// Note: This iterator returns owned (Word, Word) tuples.
    ///
    /// # Errors
    /// Returns an error if the storage backend fails to create the iterator.
    pub fn entries(&self) -> Result<impl Iterator<Item = (Word, Word)>, LargeSmtError> {
        let leaves_iter = self.leaves()?;
        Ok(leaves_iter.flat_map(|(_, leaf)| {
            // Collect the (Word, Word) tuples into an owned Vec
            // This ensures they outlive the 'leaf' from which they are derived.
            let owned_entries: Vec<(Word, Word)> = leaf.entries().to_vec();
            // Return an iterator over this owned Vec
            owned_entries.into_iter()
        }))
    }

    /// Returns an iterator over the inner nodes of this [Smt].
    ///
    /// # Errors
    /// Returns an error if the storage backend fails during iteration setup.
    pub fn inner_nodes(&self) -> Result<impl Iterator<Item = InnerNodeInfo> + '_, LargeSmtError> {
        // Pre-validate that storage is accessible
        let _ = self.storage.iter_subtrees()?;
        Ok(LargeSmtInnerNodeIterator::new(self))
    }

    // STATE MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Inserts a value at the specified key, returning the previous value associated with that key.
    /// Recall that by definition, any key that hasn't been updated is associated with
    /// [`Self::EMPTY_VALUE`].
    ///
    /// This also recomputes all hashes between the leaf (associated with the key) and the root,
    /// updating the root itself.
    ///
    /// # Errors
    /// Returns an error if inserting the key-value pair would exceed
    /// [`MAX_LEAF_ENTRIES`](super::MAX_LEAF_ENTRIES) (1024 entries) in the leaf.
    pub fn insert(&mut self, key: Word, value: Word) -> Result<Word, MerkleError> {
        <Self as SparseMerkleTree<SMT_DEPTH>>::insert(self, key, value)
    }

    // HELPERS
    // --------------------------------------------------------------------------------------------

    /// Helper to get an in-memory node if not empty.
    ///
    /// # Panics
    /// With debug assertions on, panics if `index.depth() >= IN_MEMORY_DEPTH`.
    fn get_non_empty_inner_node(&self, index: NodeIndex) -> Option<InnerNode> {
        debug_assert!(index.depth() < IN_MEMORY_DEPTH, "Only for in-memory nodes");

        let memory_index = to_memory_index(&index);

        let left = self.in_memory_nodes[memory_index * 2];
        let right = self.in_memory_nodes[memory_index * 2 + 1];

        // Check if both children are empty
        let child_depth = index.depth() + 1;
        if is_empty_parent(left, right, child_depth) {
            None
        } else {
            Some(InnerNode { left, right })
        }
    }

    fn build_subtrees(&mut self, mut entries: Vec<(Word, Word)>) -> Result<(), MerkleError> {
        entries.par_sort_unstable_by_key(|item| {
            let index = Self::key_to_leaf_index(&item.0);
            index.value()
        });
        self.build_subtrees_from_sorted_entries(entries)?;
        Ok(())
    }

    fn build_subtrees_from_sorted_entries(
        &mut self,
        entries: Vec<(Word, Word)>,
    ) -> Result<(), MerkleError> {
        let PairComputations {
            leaves: mut leaf_subtrees,
            nodes: initial_leaves,
        } = Smt::sorted_pairs_to_leaves(entries)?;

        if initial_leaves.is_empty() {
            return Ok(());
        }

        // Store the initial leaves
        self.storage.set_leaves(initial_leaves).expect("Failed to store initial leaves");

        // build deep (disk-backed) subtrees
        leaf_subtrees = std::thread::scope(|scope| {
            let (sender, receiver) = flume::bounded(CONSTRUCTION_SUBTREE_BATCH_SIZE);
            let storage: &S = &self.storage;

            scope.spawn(move || -> Result<(), MerkleError> {
                let mut subtrees: Vec<Subtree> =
                    Vec::with_capacity(CONSTRUCTION_SUBTREE_BATCH_SIZE);
                for subtree in receiver.iter() {
                    subtrees.push(subtree);
                    if subtrees.len() == CONSTRUCTION_SUBTREE_BATCH_SIZE {
                        let subtrees_clone = mem::take(&mut subtrees);
                        storage
                            .set_subtrees(subtrees_clone)
                            .expect("Writer thread failed to set subtrees");
                    }
                }
                storage.set_subtrees(subtrees).expect("Writer thread failed to set subtrees");
                Ok(())
            });

            for bottom_depth in (IN_MEMORY_DEPTH + SUBTREE_DEPTH..=SMT_DEPTH)
                .step_by(SUBTREE_DEPTH as usize)
                .rev()
            {
                let mut subtree_roots: Vec<SubtreeLeaf> = leaf_subtrees
                    .into_par_iter()
                    .map(|subtree_leaves| {
                        debug_assert!(subtree_leaves.is_sorted());
                        debug_assert!(!subtree_leaves.is_empty());
                        let (nodes, subtree_root) =
                            build_subtree(subtree_leaves, SMT_DEPTH, bottom_depth);

                        let subtree_root_index =
                            NodeIndex::new(bottom_depth - SUBTREE_DEPTH, subtree_root.col).unwrap();
                        let mut subtree = Subtree::new(subtree_root_index);
                        for (index, node) in nodes {
                            subtree.insert_inner_node(index, node);
                        }
                        sender.send(subtree).expect("Flume channel disconnected unexpectedly");
                        subtree_root
                    })
                    .collect();
                leaf_subtrees = SubtreeLeavesIter::from_leaves(&mut subtree_roots).collect();
                debug_assert!(!leaf_subtrees.is_empty());
            }

            drop(sender);
            leaf_subtrees
        });

        // build top of the tree (in-memory only, normal insert)
        for bottom_depth in (SUBTREE_DEPTH..=IN_MEMORY_DEPTH).step_by(SUBTREE_DEPTH as usize).rev()
        {
            let (nodes, mut subtree_roots): (Vec<Map<_, _>>, Vec<SubtreeLeaf>) = leaf_subtrees
                .into_par_iter()
                .map(|subtree| {
                    debug_assert!(subtree.is_sorted());
                    debug_assert!(!subtree.is_empty());
                    let (nodes, subtree_root) = build_subtree(subtree, SMT_DEPTH, bottom_depth);
                    (nodes, subtree_root)
                })
                .unzip();
            leaf_subtrees = SubtreeLeavesIter::from_leaves(&mut subtree_roots).collect();
            debug_assert!(!leaf_subtrees.is_empty());

            for subtree_nodes in nodes {
                self.insert_inner_nodes_batch(subtree_nodes.into_iter());
            }
        }
        self.set_root(self.get_inner_node(NodeIndex::root()).hash());
        Ok(())
    }

    // STORAGE
    // --------------------------------------------------------------------------------------------

    // Inserts batch of upper inner nodes
    fn insert_inner_nodes_batch(
        &mut self,
        nodes: impl IntoIterator<Item = (NodeIndex, InnerNode)>,
    ) {
        for (index, node) in nodes {
            if index.depth() < IN_MEMORY_DEPTH {
                let memory_index = to_memory_index(&index);
                // Store in flat layout: left at 2*i, right at 2*i+1
                self.in_memory_nodes[memory_index * 2] = node.left;
                self.in_memory_nodes[memory_index * 2 + 1] = node.right;
            }
        }
    }

    // TEST HELPERS
    // --------------------------------------------------------------------------------------------

    #[cfg(test)]
    pub(crate) fn in_memory_nodes(&self) -> &Vec<Word> {
        &self.in_memory_nodes
    }
}

impl<S: SmtStorage> SparseMerkleTree<SMT_DEPTH> for LargeSmt<S> {
    type Key = Word;
    type Value = Word;
    type Leaf = SmtLeaf;
    type Opening = SmtProof;

    const EMPTY_VALUE: Self::Value = EMPTY_WORD;
    const EMPTY_ROOT: Word = *EmptySubtreeRoots::entry(SMT_DEPTH, 0);

    fn from_raw_parts(
        _inner_nodes: InnerNodes,
        _leaves: Leaves,
        _root: Word,
    ) -> Result<Self, MerkleError> {
        // This method is not supported
        panic!("LargeSmt::from_raw_parts is not supported");
    }

    fn root(&self) -> Word {
        self.storage.get_root().ok().flatten().unwrap_or(Self::EMPTY_ROOT)
    }

    fn set_root(&mut self, root: Word) {
        self.storage.set_root(root).expect("Failed to set root");
    }

    fn get_inner_node(&self, index: NodeIndex) -> InnerNode {
        if index.depth() < IN_MEMORY_DEPTH {
            let memory_index = to_memory_index(&index);
            // Reconstruct InnerNode from flat layout: left at 2*i, right at 2*i+1
            return InnerNode {
                left: self.in_memory_nodes[memory_index * 2],
                right: self.in_memory_nodes[memory_index * 2 + 1],
            };
        }

        self.storage
            .get_inner_node(index)
            .expect("Failed to get inner node")
            .unwrap_or_else(|| EmptySubtreeRoots::get_inner_node(SMT_DEPTH, index.depth()))
    }

    fn insert_inner_node(&mut self, index: NodeIndex, inner_node: InnerNode) -> Option<InnerNode> {
        if index.depth() < IN_MEMORY_DEPTH {
            let i = to_memory_index(&index);
            // Get the old node before replacing
            let old_left = self.in_memory_nodes[i * 2];
            let old_right = self.in_memory_nodes[i * 2 + 1];

            // Store new node in flat layout
            self.in_memory_nodes[i * 2] = inner_node.left;
            self.in_memory_nodes[i * 2 + 1] = inner_node.right;

            // Check if the old node was empty
            if is_empty_parent(old_left, old_right, index.depth() + 1) {
                return None;
            }

            return Some(InnerNode { left: old_left, right: old_right });
        }
        self.storage
            .set_inner_node(index, inner_node)
            .expect("Failed to store inner node")
    }

    fn remove_inner_node(&mut self, index: NodeIndex) -> Option<InnerNode> {
        if index.depth() < IN_MEMORY_DEPTH {
            let memory_index = to_memory_index(&index);
            // Get the old node before replacing with empty hashes
            let old_left = self.in_memory_nodes[memory_index * 2];
            let old_right = self.in_memory_nodes[memory_index * 2 + 1];

            // Replace with empty hashes
            let child_depth = index.depth() + 1;
            let empty_hash = *EmptySubtreeRoots::entry(SMT_DEPTH, child_depth);
            self.in_memory_nodes[memory_index * 2] = empty_hash;
            self.in_memory_nodes[memory_index * 2 + 1] = empty_hash;

            // Return the old node if it wasn't already empty
            if is_empty_parent(old_left, old_right, child_depth) {
                return None;
            }

            return Some(InnerNode { left: old_left, right: old_right });
        }
        self.storage.remove_inner_node(index).expect("Failed to remove inner node")
    }

    fn insert(&mut self, key: Self::Key, value: Self::Value) -> Result<Self::Value, MerkleError> {
        let old_value = self.get_value(&key);
        // if the old value and new value are the same, there is nothing to update
        if value == old_value {
            return Ok(value);
        }

        let mutations = self
            .compute_mutations([(key, value)])
            .expect("Failed to compute mutations in insert");
        self.apply_mutations(mutations).expect("Failed to apply mutations in insert");

        Ok(old_value)
    }

    fn insert_value(
        &mut self,
        key: Self::Key,
        value: Self::Value,
    ) -> Result<Option<Self::Value>, MerkleError> {
        // inserting an `EMPTY_VALUE` is equivalent to removing any value associated with `key`
        let index = Self::key_to_leaf_index(&key).value();
        if value != Self::EMPTY_VALUE {
            match self.storage.insert_value(index, key, value) {
                Ok(prev) => Ok(prev),
                Err(StorageError::Leaf(SmtLeafError::TooManyLeafEntries { actual })) => {
                    Err(MerkleError::TooManyLeafEntries { actual })
                },
                Err(_) => {
                    panic!("Storage error during insert_value");
                },
            }
        } else {
            Ok(self.storage.remove_value(index, key).expect("Failed to remove value"))
        }
    }

    fn get_value(&self, key: &Self::Key) -> Self::Value {
        let leaf_pos = LeafIndex::<SMT_DEPTH>::from(*key);
        match self.storage.get_leaf(leaf_pos.value()) {
            Ok(Some(leaf)) => leaf.get_value(key).unwrap_or_default(),
            Ok(None) => EMPTY_WORD,
            Err(_) => {
                panic!("Storage error during get_leaf in get_value");
            },
        }
    }

    fn get_leaf(&self, key: &Word) -> Self::Leaf {
        let leaf_pos = LeafIndex::<SMT_DEPTH>::from(*key).value();
        match self.storage.get_leaf(leaf_pos) {
            Ok(Some(leaf)) => leaf,
            Ok(None) => SmtLeaf::new_empty((*key).into()),
            Err(_) => {
                panic!("Storage error during get_leaf in get_leaf");
            },
        }
    }

    fn hash_leaf(leaf: &Self::Leaf) -> Word {
        leaf.hash()
    }

    fn construct_prospective_leaf(
        &self,
        mut existing_leaf: SmtLeaf,
        key: &Word,
        value: &Word,
    ) -> Result<SmtLeaf, SmtLeafError> {
        debug_assert_eq!(existing_leaf.index(), Self::key_to_leaf_index(key));

        match existing_leaf {
            SmtLeaf::Empty(_) => Ok(SmtLeaf::new_single(*key, *value)),
            _ => {
                if *value != EMPTY_WORD {
                    existing_leaf.insert(*key, *value)?;
                } else {
                    existing_leaf.remove(*key);
                }

                Ok(existing_leaf)
            },
        }
    }

    fn open(&self, key: &Self::Key) -> Self::Opening {
        let leaf = self.get_leaf(key);

        let mut idx: NodeIndex = LeafIndex::from(*key).into();

        let subtree_roots: Vec<NodeIndex> = (0..NUM_SUBTREE_LEVELS)
            .scan(idx.parent(), |cursor, _| {
                let subtree_root = Subtree::find_subtree_root(*cursor);
                *cursor = subtree_root.parent();
                Some(subtree_root)
            })
            .collect();
        // cache subtrees in memory
        let mut cache = Map::<NodeIndex, Subtree>::new();
        for &root in &subtree_roots {
            let subtree =
                match self.storage.get_subtree(root).expect("storage error fetching subtree") {
                    Some(st) => st,
                    None => Subtree::new(root),
                };
            cache.insert(root, subtree);
        }
        let mut path = Vec::with_capacity(idx.depth() as usize);
        while idx.depth() > 0 {
            let is_right = idx.is_value_odd();
            idx = idx.parent();

            let sibling_hash = if idx.depth() < IN_MEMORY_DEPTH {
                // top levels in memory
                let InnerNode { left, right } = self.get_inner_node(idx);
                if is_right { left } else { right }
            } else {
                // deep levels come from our 5 preloaded subtrees
                let root = Subtree::find_subtree_root(idx);
                let subtree = &cache[&root];
                let InnerNode { left, right } = subtree
                    .get_inner_node(idx)
                    .unwrap_or_else(|| EmptySubtreeRoots::get_inner_node(SMT_DEPTH, idx.depth()));
                if is_right { left } else { right }
            };

            path.push(sibling_hash);
        }

        let merkle_path =
            SparseMerklePath::from_sized_iter(path).expect("failed to convert to SparseMerklePath");
        Self::path_and_leaf_to_opening(merkle_path, leaf)
    }

    fn key_to_leaf_index(key: &Word) -> LeafIndex<SMT_DEPTH> {
        let most_significant_felt = key[3];
        LeafIndex::new_max_depth(most_significant_felt.as_int())
    }

    fn path_and_leaf_to_opening(path: SparseMerklePath, leaf: SmtLeaf) -> SmtProof {
        SmtProof::new_unchecked(path, leaf)
    }
}

impl<S: SmtStorage> PartialEq for LargeSmt<S> {
    /// Compares two LargeSmt instances based on their root hash and metadata.
    ///
    /// Note: This comparison only checks the root hash and counts, not the underlying
    /// storage contents. Two SMTs with the same root should be cryptographically
    /// equivalent, but this doesn't verify the storage backends are identical.
    fn eq(&self, other: &Self) -> bool {
        self.root().unwrap() == other.root().unwrap()
            && self.num_leaves().unwrap() == other.num_leaves().unwrap()
            && self.num_entries().unwrap() == other.num_entries().unwrap()
    }
}

impl<S: SmtStorage> Eq for LargeSmt<S> {}

// Note: Clone is intentionally not implemented for LargeSmt because:
// 1. Cloning would only clone the in-memory portion and share storage via Arc
// 2. This doesn't actually clone the underlying disk data, which is misleading
// 3. Users should be explicit about sharing LargeSmt instances via Arc if needed
