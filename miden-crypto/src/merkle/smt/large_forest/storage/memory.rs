//! This module contains the in-memory storage for the SMT forest.
//!
//! This **non-persistent** storage provides high throughput for all forest operations due to its
//! in-memory nature and exploitation of concurrency potential wherever possible. It is, however,
//! fundamentally limited by the amount of memory that is available to the forest in how much data
//! it can store.
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

use std::prelude::rust_2015::{Box, Vec};

use super::error::Result;
use crate::{
    Map, Set, Word,
    hash::rpo::Rpo256,
    merkle::{
        NodeIndex,
        smt::{
            InnerNode, SmtLeaf, StoredTreeHandle, Subtree, SubtreeLevels, large_forest::Storage,
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
    /// The number of tree levels to be stored in memory by a forest configured with this storage.
    in_memory_depth: SubtreeLevels,

    /// The roots of all full trees the forest.
    ///
    /// Any time that one of these trees is updated, a root is replaced here with the new root.
    roots: Set<Word>,

    /// The non-leaf nodes in the tree.
    nodes: Map<Word, InMemoryNode>,

    /// The leaves of all trees stored in this forest.
    leaves: Map<Word, SmtLeaf>,
}

impl InMemoryStorage {
    /// Creates a new, empty, in-memory storage instance.
    ///
    /// # Arguments
    ///
    /// - `in_memory_depth`: The number of non-root tree levels that must be kept in memory by a
    ///   forest configured with this storage.
    pub fn new(in_memory_depth: SubtreeLevels) -> Result<Self> {
        let roots = Set::new();
        let nodes = Map::new();
        let leaves = Map::new();
        Ok(Self { in_memory_depth, roots, nodes, leaves })
    }
}

impl Storage for InMemoryStorage {
    type TransactionHandle = ();
    type TreeDataHandle = InMemoryTreeView;

    fn in_memory_depth(&self) -> Result<SubtreeLevels> {
        Ok(self.in_memory_depth)
    }

    fn tree_count(&self) -> Result<usize> {
        todo!()
    }

    fn roots(&self) -> Result<Vec<Word>> {
        todo!()
    }

    fn begin(&self) -> Result<Self::TransactionHandle> {
        Ok(())
    }

    fn commit(&self, _: Self::TransactionHandle) -> Result<()> {
        Ok(())
    }

    fn tree(&self, _root: Word) -> Result<Self::TreeDataHandle> {
        todo!()
    }
}

// IN-MEMORY TREE VIEW
// ================================================================================================

#[derive(Debug)]
pub struct InMemoryTreeView {}

impl StoredTreeHandle for InMemoryTreeView {
    fn root(&self) -> Result<Word> {
        todo!()
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

    fn get_subtree(&self, _index: NodeIndex) -> Result<Option<Subtree>> {
        todo!()
    }

    fn set_subtree(&self, _index: NodeIndex, _subtree: Subtree) -> Result<Option<Subtree>> {
        todo!()
    }

    fn remove_subtree(&self, _index: &NodeIndex) -> Result<Option<Subtree>> {
        todo!()
    }

    fn get_subtrees(&self, _indices: &[NodeIndex]) -> Result<Vec<Option<Subtree>>> {
        todo!()
    }

    fn set_subtrees(&self, _subtrees: Vec<(NodeIndex, Subtree)>) -> Result<Vec<Option<Subtree>>> {
        todo!()
    }

    fn remove_subtrees(&self, _indices: &[NodeIndex]) -> Result<Vec<Option<Subtree>>> {
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

    fn iter_subtrees(&self) -> Result<Box<dyn Iterator<Item = (NodeIndex, Subtree)> + '_>> {
        todo!()
    }

    fn restoration_data(&self) -> Result<Vec<Word>> {
        todo!()
    }
}

// INNER NODE
// ================================================================================================

/// A non-leaf node in the storage.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InMemoryNode {
    left: Word,
    right: Word,
    rc: usize,
}
impl InMemoryNode {
    /// Computes the hash of the two children of the node.
    pub fn hash(&self) -> Word {
        Rpo256::merge(&[self.left, self.right])
    }
}
