//! A high-performance sparse merkle tree forest backed by pluggable storage.
//!
//! # Semantic Layout
//!
//! Much like [`super::SparseMerkleTree`], the forest stores trees of depth 64 that use the compact
//! leaf optimization to uniquely store 256-bit elements. This reduces both the size of a merkle
//! path, and the computational work necessary to perform queries into the trees.
//!
//! # Storing Trees and Versions
//!
//! The usage of an SMT forest is conceptually split into two parts: a collection that is able to
//! store **multiple, unrelated trees**, and a container for **multiple versions of those trees**.
//! Both of these use-cases are supported by the forest, but have an explicit delineation between
//! them in both the API and the implementation. This has two impacts that a client of the forest
//! must understand.
//!
//! - While, when using a [`Storage`] that can persist data, **only the current full tree state is
//!   persisted**, while **the historical data will not be**. This is designed into the structure of
//!   the forest, and does not depend on the choice of storage backend.
//! - It is more expensive to query a given tree at an older point in its history than it is to
//!   query it at a newer point, and querying at the current tree will always be the fastest.
//!
//! # Data Storage
//!
//! In order to help with the query performance for the more latency-prone kinds of [`Storage`]
//! implementation, the forest splits the data into two portions:
//!
//! 1. The **top of each tree** is explicitly **stored in memory**, regardless of the [`Storage`]
//!    backend. This makes the common tree prefix much more performant to query, and relies on the
//!    backend to store sufficient data to _reconstruct_ that prefix at forest rebuild.
//! 2. The **rest of each tree** is managed by the [`Storage`] itself, and makes no guarantees as to
//!    where that data is stored. Depending on the storage backend chosen, queries into this portion
//!    may have varied performance characteristics.
//!
//! The split between these numbers of levels is configured when initially constructing the forest,
//! and will be verified at runtime for forests that are instead reloaded from persistent state.

mod error;
mod operation;
mod prefix;
mod property_tests;
mod storage;
mod tests;
mod utils;

pub use error::{LargeSmtForestError, Result};
pub use operation::{ForestBatch, ForestOp, TreeBatch};
pub use storage::{
    Storage, StorageError, StoredTreeHandle,
    memory::{InMemoryStorage, InMemoryTreeView},
};
pub use utils::SubtreeLevels;

use crate::{
    Map, Set, Word,
    merkle::{
        EmptySubtreeRoots,
        smt::{History, SMT_DEPTH, SmtProof, large_forest::prefix::InMemoryPrefix},
    },
};

// SPARSE MERKLE TREE FOREST
// ================================================================================================

/// A high-performance forest of sparse merkle trees with pluggable storage.
///
/// # Current and Frozen Trees
///
/// Trees in the forest fall into two categories:
///
/// 1. **Current:** These trees represent the latest version of their 'tree lineage' and can be
///    modified to generate a new tree version in the forest.
/// 2. **Frozen:** These are historical versions of trees that are no longer current, and are
///    considered 'frozen' and hence cannot be modified to generate a new tree version in the
///    forest. This is because being able to do so would effectively create a "fork" in the history,
///    and hence allow the forest to yield potentially invalid responses with regard to the
///    blockchain history.
///
/// If an attempt is made to modify a frozen tree, the method in question will yield an
/// [`LargeSmtForestError::InvalidModification`] error as doing so represents a programmer bug.
///
/// # Performance
///
/// The performance characteristics of this forest depend heavily on the choice of underlying
/// [`Storage`] implementation. Where something more specific can be said about a particular method
/// call, the documentation for that method will state it.
#[allow(dead_code)] // Temporary, while the tree gets built.
#[derive(Debug)]
pub struct LargeSmtForest<S: Storage> {
    /// The underlying data storage for the portion of the tree that is not guaranteed to be in
    /// memory. It **must not be exposed** to any client of this struct's API to ensure
    /// correctness.
    storage: S,

    /// The number of levels of each tree that are kept in memory by the forest.
    in_memory_depth: SubtreeLevels,

    /// The container for the in-memory prefixes of each tree stored in the forest, identified by
    /// their current root.
    ///
    /// This must be kept up to date with the prefixes of all trees in the forest actively.
    prefixes: Map<Word, InMemoryPrefix>,

    /// The container for the historical versions of each tree stored in the forest, identified by
    /// the current root.
    histories: Map<Word, History>,
}

// CONSTRUCTION AND BASIC QUERIES
// ================================================================================================

/// These functions deal with the creation of new forest instances, and hence rely on the ability to
/// query storage to do so.
///
/// # Performance
///
/// All the methods in this impl block require access to the underlying [`Storage`] instance to
/// return results. This means that their performance will depend heavily on the specific instance
/// with which the forest was constructed.
///
/// Where anything more specific can be said about performance, the method documentation will
/// contain more detail.
impl<S: Storage> LargeSmtForest<S> {
    /// Constructs a new forest backed by the provided `storage`.
    ///
    /// The constructor will treat whatever state is contained within the provided `storage` as the
    /// starting state for the forest. This means that if you pass a newly-initialized storage the
    /// forest will start in an empty state, while if you pass a `storage` that already contains
    /// some data (e.g. loaded from disk), then the forest will start in _that_ form instead.
    ///
    /// # Errors
    ///
    /// - [`LargeSmtForestError::StorageError`] if the forest cannot be started up correctly from
    ///   storage.
    pub fn new(_storage: S) -> Result<Self> {
        todo!("LargeSmtForest::new")
    }
}

/// These methods provide the ability to perform basic queries on the forest without the need to
/// access the underlying tree storage.
///
/// # Performance
///
/// All of these methods can be performed fully in-memory, and hence their performance is
/// predictable on a given machine regardless of the choice of [`Storage`] instance for the forest.
impl<S: Storage> LargeSmtForest<S> {
    /// Returns a set of all the roots that the forest knows about, including those of all
    /// versions.
    pub fn roots(&self) -> Set<Word> {
        let mut roots: Set<Word> = self.prefixes.keys().cloned().collect();
        self.histories.values().for_each(|h| roots.extend(h.roots()));
        roots
    }

    /// Returns the number of trees in the forest.
    pub fn tree_count(&self) -> usize {
        // History::num_versions does not account for the 'current version' so we add one to each of
        // those counts, and then we add one overall to account for the "phantom empty tree".
        self.histories.values().map(|h| h.num_versions() + 1).sum::<usize>() + 1
    }

    /// Returns `true` if the provided `root` points to a tree that can be modified to yield a new
    /// version, and `false` otherwise.
    pub fn is_modifiable(&self, root: Word) -> bool {
        self.prefixes.contains_key(&root) || *EmptySubtreeRoots::entry(SMT_DEPTH, 0) == root
    }

    /// Returns `true` if the provided `root` points to a tree that is 'frozen', meaning that it
    /// cannot be modified to yield a new version, and `false` otherwise.
    pub fn is_frozen(&self, root: Word) -> bool {
        !self.is_modifiable(root)
    }
}

// QUERIES
// ================================================================================================

/// These methods pertain to non-mutating queries about the data stored in the forest. They differ
/// from the simple queries in the previous block by requiring access to storage to function.
///
/// # Performance
///
/// All the methods in this impl block require access to the underlying [`Storage`] instance to
/// return results. This means that their performance will depend heavily on the specific instance
/// with which the forest was constructed.
///
/// Where anything more specific can be said about performance, the method documentation will
/// contain more detail.
impl<S: Storage> LargeSmtForest<S> {
    /// Returns an opening for the specified `key` in the SMT with the specified `root`.
    ///
    /// # Errors
    ///
    /// - [`LargeSmtForestError::StorageError`] if an error occurs when trying to read from storage.
    /// - [`LargeSmtForestError::MerkleError`] if no tree with the provided `root` exists in the
    ///   forest, or if the forest does not contain sufficient data to provide an opening for `key`.
    pub fn open(&self, _root: Word, _key: Word) -> Result<SmtProof> {
        todo!("LargeSmtForest::open")
    }

    /// Returns `true` if the forest contains the provided `root`, and `false` otherwise.
    pub fn contains_root(&self, root: Word) -> bool {
        // As we're only returning the boolean we can do this lazily for better performance.
        let is_known_root = self.prefixes.keys().any(|r| {
            r == &root || self.histories.get(r).map(|h| h.knows_root(root)).unwrap_or(false)
        });

        // It can also be the empty tree root, which is always semantically present in the forest.
        is_known_root || *EmptySubtreeRoots::entry(SMT_DEPTH, 0) == root
    }
}

// SINGLE-TREE MODIFIERS
// ================================================================================================

/// These methods pertain to modifications that can be made to a single tree in the forest. They
/// exploit parallelism within the single target tree wherever possible.
///
/// # Performance
///
/// All the methods in this impl block require access to the underlying [`Storage`] instance to
/// return results. This means that their performance will depend heavily on the specific instance
/// with which the forest was constructed.
///
/// Where anything more specific can be said about performance, the method documentation will
/// contain more detail.
impl<S: Storage> LargeSmtForest<S> {
    /// Inserts the specified `key`, `value` pair into the tree in the forest with the specified
    /// `root`, returning the new root of that tree.
    ///
    /// Any insertion operation where `root` is equal to the root of the empty tree will generate a
    /// new unique tree in the forest, rather than adding history to an existing tree.
    ///
    /// # Errors
    ///
    /// - [`LargeSmtForestError::StorageError`] if an error occurs when trying to access storage.
    pub fn insert(&mut self, _root: Word, _key: Word, _proof: SmtProof) -> Result<Word> {
        todo!("LargeSmtForest::insert")
    }

    /// Inserts the specified `entries` into the tree in the forest with the specified `root`,
    /// adding a single new root to the forest for the entire batch and returning that root.
    ///
    /// Any insertion operation where `root` is equal to the root of the empty tree will generate a
    /// new unique tree in the forest, rather than adding history to an existing tree.
    ///
    /// # Errors
    ///
    /// - [`LargeSmtForestError::StorageError`] if an error occurs when trying to access storage.
    pub fn batch_insert(
        &mut self,
        _root: Word,
        _entries: impl IntoIterator<Item = (Word, Word)> + Clone,
    ) -> Result<Word> {
        todo!("LargeSmtForest::batch_insert")
    }

    /// Removes the `key` and its associated value from the tree specified by `root`, returning the
    /// new root of the tree after performing that modification.
    ///
    /// Note that if `key` does not exist in the tree with the provided `root`, then `root` will be
    /// returned unchanged and no new tree will be allocated.
    ///
    /// # Errors
    ///
    /// - [`LargeSmtForestError::StorageError`] if an error occurs when trying to access storage.
    pub fn remove(&mut self, _root: Word, _key: Word) -> Result<Word> {
        todo!("LargeSmtForest::remove")
    }

    /// Removes the associated `entries` from the tree with the provided `root`, adding a single new
    /// root to the forest for the entire batch and returning that root.
    ///
    /// Note that if all `entries` do not exist in the tree with the provided `root`, then `root`
    /// will be returned unchanged and no new tree will be allocated.
    ///
    /// # Errors
    ///
    /// - [`LargeSmtForestError::StorageError`] if an error occurs when trying to access storage.
    pub fn batch_remove(
        &mut self,
        _root: Word,
        _entries: impl IntoIterator<Item = Word> + Clone,
    ) -> Result<Word> {
        todo!("LargeSmtForest::batch_remove")
    }

    /// Performs the provided `operations` on the tree with the provided `root`, adding a single new
    /// root to the forest for the entire batch and returning that root.
    ///
    /// If applying the `operations` results in no changes to the tree, then `root` will be returned
    /// unchanged and no new tree will be allocated.
    ///
    /// # Errors
    ///
    /// - [`LargeSmtForestError::StorageError`] if an error occurs when trying to access storage.
    pub fn batch_modify(&mut self, _root: Word, _operations: TreeBatch) -> Result<Word> {
        todo!("LargeSmtForest::batch_modify")
    }
}

// MULTI-TREE MODIFIERS
// ================================================================================================

/// These methods pertain to modifications that can be made to multiple trees in the forest at once.
/// They exploit parallelism both between trees and within trees wherever possible.
///
/// # Performance
///
/// All the methods in this impl block require access to the underlying [`Storage`] instance to
/// return results. This means that their performance will depend heavily on the specific instance
/// with which the forest was constructed.
///
/// Where anything more specific can be said about performance, the method documentation will
/// contain more detail.
impl<S: Storage> LargeSmtForest<S> {
    /// Performs the provided `operations` on the forest, adding at most one new root to the forest
    /// for each target root in `operations`, returning a mapping from old root to new root.
    ///
    /// If applying the associated batch to any given tree in the forest results in no changes to
    /// the tree, the initial root will be returned and no new tree will be allocated.
    ///
    /// # Errors
    ///
    /// - [`LargeSmtForestError::StorageError`] if an error occurs when trying to access storage.
    pub fn forest_batch_modify(&mut self, _operations: ForestBatch) -> Result<Map<Word, Word>> {
        todo!("LargeSmtForest::forest_batch_modify")
    }
}
