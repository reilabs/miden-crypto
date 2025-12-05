//! This module contains the non-parallel in-memory storage for the SMT forest.
//!
//! This **non-persistent** storage provides high throughput for all forest operations due to its
//! in-memory nature. It is, however, fundamentally limited by the amount of memory that is
//! available to the forest when it comes to determining how much data it can store.
//!
//! You should **choose this storage** if:
//!
//! - You only need to store _small amounts of data_.
//! - Your data is _ephemeral and/or easily recreated_.
//!
//! For use-cases requiring persistence or the ability to store huge amounts of data, the disk
//! storage layer may be more appropriate. TODO Link to it when available.
//!
//! # Memory Usage
//!
//! The amount of memory used by a forest using this storage will grow **proportionally to the
//! amount of data** stored in the forest. This storage implementation performs no spilling to disk
//! or similar operations to reduce memory pressure.
//!
//! # Non-Persistence
//!
//! This storage implementation offers no persistence of data. This means that any data stored
//! within the forest will be lost if the process is shut down for any reason. This makes it ripe
//! for experimentation, or for use with data that is ephemeral or can be rebuilt without much
//! effort.

use alloc::{boxed::Box, sync::Arc, vec::Vec};

use super::error::Result;
use crate::{
    Map, Word,
    hash::rpo::Rpo256,
    merkle::{
        EmptySubtreeRoots, NodeIndex,
        smt::{
            ForestSubtree, InnerNode, SMT_DEPTH, SmtLeaf, StorageError, StoredTreeHandle,
            SubtreeLevels, large_forest::Storage,
        },
    },
};
// IN-MEMORY STORAGE
// ================================================================================================

/// The in-memory storage layer for the smt forest, providing high-throughput without persistence.
///
/// # Write Behavior
///
/// Due to its lack of persistence, this storage layer will eagerly perform writes when requested
/// to, as there is no risk of data corruption due to a process shutdown as all data is lost
/// regardless.
#[derive(Debug)]
pub struct InMemoryStorage {
    data: Arc<InMemoryStorageSharedData>,
}

impl InMemoryStorage {
    /// Creates a new, empty, in-memory storage instance.
    ///
    /// # Arguments
    ///
    /// - `in_memory_depth`: The number of non-root tree levels that must be kept in memory by a
    ///   forest configured with this storage.
    pub fn new(in_memory_depth: SubtreeLevels) -> Self {
        let data = Arc::new(InMemoryStorageSharedData::new(in_memory_depth));
        Self { data }
    }
}

impl Storage for InMemoryStorage {
    type TransactionHandle = ();
    type TreeDataHandle = InMemoryTreeHandle;

    fn in_memory_depth(&self) -> Result<SubtreeLevels> {
        Ok(self.data.in_memory_depth)
    }

    fn tree_count(&self) -> Result<usize> {
        Ok(self.data.metadata.keys().len())
    }

    fn roots(&self) -> Result<Vec<Word>> {
        Ok(self.data.metadata.keys().copied().collect())
    }

    fn begin(&self) -> Result<Self::TransactionHandle> {
        Ok(())
    }

    fn commit(&self, _: Self::TransactionHandle) -> Result<()> {
        Ok(())
    }

    fn tree(&self, root: Word) -> Result<Self::TreeDataHandle> {
        InMemoryTreeHandle::new(root, self.data.clone())
    }
}

// IN-MEMORY TREE HANDLE
// ================================================================================================

/// A handle to a specific tree in the forest's in-memory storage.
#[allow(dead_code)] // Temporary
#[derive(Debug)]
pub struct InMemoryTreeHandle {
    /// The root of the tree that this is a handle to.
    root: Word,

    /// The underlying storage data.
    data: Arc<InMemoryStorageSharedData>,
}

impl InMemoryTreeHandle {
    /// Constructs a new tree handle providing a view onto a tree with the provided `root` in the
    /// provided `storage.
    ///
    /// # Errors
    ///
    /// - [`StorageError::NotInStorage`] if the `storage` does not contain a tree with the provided
    ///   `root`.
    fn new(root: Word, data: Arc<InMemoryStorageSharedData>) -> Result<Self> {
        if data.trees.get(&root).is_none() {
            return Err(StorageError::NotInStorage(format!(
                "The root {root} is not in this storage"
            )));
        }

        Ok(Self { root, data })
    }
}

impl StoredTreeHandle for InMemoryTreeHandle {
    fn root(&self) -> Result<Word> {
        Ok(self.root)
    }

    fn set_root(&self, _root: Word) -> Result<Word> {
        todo!()
    }

    fn leaf_count(&self) -> Result<usize> {
        todo!()
    }

    fn set_leaf_count(&self, _leaf_count: usize) -> Result<()> {
        todo!()
    }

    fn entry_count(&self) -> Result<Word> {
        todo!()
    }

    fn set_entry_count(&self, _entry: Word) -> Result<()> {
        todo!()
    }

    fn insert_value(&self, _key: Word, _value: Word) -> Result<Option<Word>> {
        todo!()
    }

    fn get_value(&self, _key: Word) -> Result<Option<Word>> {
        todo!()
    }

    fn remove_value(&self, _key: Word) -> Result<Option<Word>> {
        todo!()
    }

    fn has_leaves(&self) -> Result<bool> {
        todo!()
    }

    fn get_leaf(&self, _index: u64) -> Result<Option<SmtLeaf>> {
        todo!()
    }

    fn set_leaf(&self, _index: u64, _leaf: SmtLeaf) -> Result<Option<SmtLeaf>> {
        todo!()
    }

    fn remove_leaf(&self, _index: u64) -> Result<Option<SmtLeaf>> {
        todo!()
    }

    fn get_leaves(&self, _indices: &[u64]) -> Result<Vec<Option<SmtLeaf>>> {
        todo!()
    }

    fn set_leaves(&self, _leaves: Vec<(u64, SmtLeaf)>) -> Result<Vec<Option<SmtLeaf>>> {
        todo!()
    }

    fn remove_leaves(&self, _indices: &[u64]) -> Result<Vec<Option<SmtLeaf>>> {
        todo!()
    }

    fn get_subtree(&self, _index: NodeIndex) -> Result<Option<ForestSubtree>> {
        todo!()
    }

    fn set_subtree(
        &self,
        _index: NodeIndex,
        _subtree: ForestSubtree,
    ) -> Result<Option<ForestSubtree>> {
        todo!()
    }

    fn remove_subtree(&self, _index: &NodeIndex) -> Result<Option<ForestSubtree>> {
        todo!()
    }

    fn get_subtrees(&self, _indices: &[NodeIndex]) -> Result<Vec<Option<ForestSubtree>>> {
        todo!()
    }

    fn set_subtrees(
        &self,
        _subtrees: Vec<(NodeIndex, ForestSubtree)>,
    ) -> Result<Vec<Option<ForestSubtree>>> {
        todo!()
    }

    fn remove_subtrees(&self, _indices: &[NodeIndex]) -> Result<Vec<Option<ForestSubtree>>> {
        todo!()
    }

    fn get_node(&self, _index: NodeIndex) -> Result<Option<InnerNode>> {
        todo!()
    }

    fn set_node(&self, _index: NodeIndex, _node: InnerNode) -> Result<Option<InnerNode>> {
        todo!()
    }

    fn remove_node(&self, _index: NodeIndex) -> Result<Option<InnerNode>> {
        todo!()
    }

    fn iter_leaves(&self) -> Result<Box<dyn Iterator<Item = (u64, SmtLeaf)> + '_>> {
        todo!()
    }

    fn iter_nodes(&self) -> Result<Box<dyn Iterator<Item = (NodeIndex, Word)> + '_>> {
        todo!()
    }

    fn iter_subtrees(&self) -> Result<Box<dyn Iterator<Item = (NodeIndex, ForestSubtree)> + '_>> {
        todo!()
    }

    fn restoration_data(&self) -> Result<Vec<Word>> {
        todo!()
    }
}

// TREE DATA
// ================================================================================================

/// The data for a single tree in the forest's in-memory storage.
#[derive(Clone, Debug, Eq, PartialEq)]
struct InMemoryStorageTreeData {
    /// The root of the tree.
    pub root: Word,

    /// The number of populated nodes in the tree.
    pub node_count: usize,

    /// The number of populated leaves in the tree.
    pub leaf_count: usize,

    /// The number of populated entries in the tree.
    pub entry_count: usize,

    /// The non-leaf nodes of the tree.
    pub nodes: Map<Word, InMemoryNode>,

    /// The compact leaves of the tree.
    pub leaves: Map<Word, SmtLeaf>,
}
impl InMemoryStorageTreeData {
    /// Constructs a new tree data instance, with all fields defaulted.
    pub fn new() -> Self {
        let root = *EmptySubtreeRoots::entry(SMT_DEPTH, 0);
        let node_count = 0;
        let leaf_count = 0;
        let entry_count = 0;
        let nodes = Map::new();
        let leaves = Map::new();

        Self {
            root,
            node_count,
            leaf_count,
            entry_count,
            nodes,
            leaves,
        }
    }
}

// SHARED DATA
// ================================================================================================

#[derive(Clone, Debug, Eq, PartialEq)]
struct InMemoryStorageSharedData {
    /// The number of tree levels to be stored in memory by a forest configured with this storage.
    in_memory_depth: SubtreeLevels,

    /// The trees in the storage, associated with their roots.
    trees: Map<Word, InMemoryStorageTreeData>,
}

impl InMemoryStorageSharedData {
    /// Creates a new, empty, storage shared data instance, with `in_memory_depth` levels kept in
    /// memory.
    fn new(in_memory_depth: SubtreeLevels) -> Self {
        let trees = Map::new();
        Self { in_memory_depth, trees }
    }
}

// INNER NODE
// ================================================================================================

/// A non-leaf node in the storage.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InMemoryNode {
    left: Word,
    right: Word,
}
#[allow(dead_code)] // Temporary
impl InMemoryNode {
    /// Computes the hash of the two children of the node.
    pub fn hash(&self) -> Word {
        Rpo256::merge(&[self.left, self.right])
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod test {}
