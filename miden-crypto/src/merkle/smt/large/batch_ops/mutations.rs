use alloc::vec::Vec;
use core::mem;

use num::Integer;
use rayon::prelude::*;

use super::super::{
    IN_MEMORY_DEPTH, LargeSmt, LargeSmtError, SMT_DEPTH, SmtStorage, StorageUpdates, Subtree,
};
use crate::{
    Word,
    merkle::{
        EmptySubtreeRoots, MerkleError, MutationSet, NodeIndex, SmtLeaf,
        smt::{
            Map, NodeMutation, NodeMutations, SparseMerkleTree,
            full::concurrent::{SUBTREE_DEPTH, SubtreeLeaf, SubtreeLeavesIter, fetch_sibling_pair},
        },
    },
};

// TYPES
// ================================================================================================

/// Prepared mutations loaded from storage, ready to be applied.
pub(crate) struct PreparedMutations {
    pub(super) old_root: Word,
    pub(super) new_root: Word,
    pub(super) sorted_node_mutations: Vec<(NodeIndex, NodeMutation)>,
    pub(super) loaded_subtrees: Map<NodeIndex, Option<Subtree>>,
    pub(super) new_pairs: Map<Word, Word>,
    pub(super) leaf_map: Map<u64, Option<SmtLeaf>>,
}

// BATCH MUTATIONS
// ================================================================================================

/// Implementation block for batch mutation operations on `LargeSmt`.
///
/// This module handles the compute-and-apply pattern for mutations, allowing validation
/// before committing changes to the tree.
impl<S: SmtStorage> LargeSmt<S> {
    /// Computes what changes are necessary to insert the specified key-value pairs into this Merkle
    /// tree, allowing for validation before applying those changes.
    ///
    /// This method returns a [`MutationSet`], which contains all the information for inserting
    /// `kv_pairs` into this Merkle tree already calculated, including the new root hash, which can
    /// be queried with [`MutationSet::root()`]. Once a mutation set is returned,
    /// [`Smt::apply_mutations()`] can be called in order to commit these changes to the Merkle
    /// tree, or [`drop()`] to discard them.
    ///
    /// # Example
    /// ```
    /// # use miden_crypto::{Felt, Word};
    /// # use miden_crypto::merkle::{Smt, EmptySubtreeRoots, SMT_DEPTH};
    /// let mut smt = Smt::new();
    /// let pair = (Word::default(), Word::default());
    /// let mutations = smt.compute_mutations(vec![pair]).expect("compute_mutations ok");
    /// assert_eq!(mutations.root(), *EmptySubtreeRoots::entry(SMT_DEPTH, 0));
    /// smt.apply_mutations(mutations);
    /// assert_eq!(smt.root(), *EmptySubtreeRoots::entry(SMT_DEPTH, 0));
    /// ```
    pub fn compute_mutations(
        &self,
        kv_pairs: impl IntoIterator<Item = (Word, Word)>,
    ) -> Result<MutationSet<SMT_DEPTH, Word, Word>, LargeSmtError>
    where
        Self: Sized + Sync,
    {
        // Collect and sort key-value pairs by their corresponding leaf index
        let mut sorted_kv_pairs: Vec<_> = kv_pairs.into_iter().collect();
        sorted_kv_pairs
            .par_sort_unstable_by_key(|(key, _)| LargeSmt::<S>::key_to_leaf_index(key).value());

        // Load leaves from storage using helper (from insertion module)
        let (_leaf_indices, leaf_map) = self.load_leaves_for_pairs(&sorted_kv_pairs)?;

        // Convert sorted pairs into mutated leaves and capture any new pairs
        let (mut leaves, _mutated_leaf_nodes, new_pairs, _leaf_count_delta, _entry_count_delta) =
            self.sorted_pairs_to_mutated_leaves_with_preloaded_leaves(sorted_kv_pairs, &leaf_map);

        // If no mutations, return an empty mutation set
        let old_root = SparseMerkleTree::<SMT_DEPTH>::root(self);
        if leaves.is_empty() {
            return Ok(MutationSet {
                old_root,
                new_root: old_root,
                node_mutations: NodeMutations::default(),
                new_pairs,
            });
        }

        let mut node_mutations = NodeMutations::default();

        // Process each depth level in reverse, stepping by the subtree depth
        for subtree_root_depth in
            (0..=SMT_DEPTH - SUBTREE_DEPTH).step_by(SUBTREE_DEPTH as usize).rev()
        {
            // Parallel processing of each subtree to generate mutations and roots
            let (mutations_per_subtree, mut subtree_roots): (Vec<_>, Vec<_>) = leaves
                .into_par_iter()
                .map(|subtree_leaves| {
                    let subtree_opt = if subtree_root_depth < IN_MEMORY_DEPTH {
                        None
                    } else {
                        // Compute subtree root index
                        let subtree_root_index = NodeIndex::new_unchecked(
                            subtree_root_depth,
                            subtree_leaves[0].col >> SUBTREE_DEPTH,
                        );
                        self.storage
                            .get_subtree(subtree_root_index)
                            .expect("Storage error getting subtree in compute_mutations")
                    };
                    debug_assert!(subtree_leaves.is_sorted() && !subtree_leaves.is_empty());
                    self.build_subtree_mutations(
                        subtree_leaves,
                        SMT_DEPTH,
                        subtree_root_depth,
                        subtree_opt.as_ref(),
                    )
                })
                .unzip();

            // Prepare leaves for the next depth level
            leaves = SubtreeLeavesIter::from_leaves(&mut subtree_roots).collect();

            // Aggregate all node mutations
            node_mutations.extend(mutations_per_subtree.into_iter().flatten());

            debug_assert!(!leaves.is_empty());
        }

        let new_root = leaves[0][0].hash;

        // Create mutation set
        let mutation_set = MutationSet {
            old_root: SparseMerkleTree::<SMT_DEPTH>::root(self),
            new_root,
            node_mutations,
            new_pairs,
        };

        // There should be mutations and new pairs at this point
        debug_assert!(
            !mutation_set.node_mutations().is_empty() && !mutation_set.new_pairs().is_empty()
        );

        Ok(mutation_set)
    }

    /// Applies the prospective mutations computed with [`Smt::compute_mutations()`] to this tree.
    ///
    /// # Errors
    /// If `mutations` was computed on a tree with a different root than this one, returns
    /// [`MerkleError::ConflictingRoots`] with a two-item [`Vec`]. The first item is the root hash
    /// the `mutations` were computed against, and the second item is the actual current root of
    /// this tree.
    pub fn apply_mutations(
        &mut self,
        mutations: MutationSet<SMT_DEPTH, Word, Word>,
    ) -> Result<(), LargeSmtError> {
        let prepared = self.prepare_mutations(mutations)?;
        self.apply_prepared_mutations(prepared)?;
        Ok(())
    }

    /// Applies the prospective mutations computed with [`Smt::compute_mutations()`] to this tree
    /// and returns the reverse mutation set.
    ///
    /// Applying the reverse mutation sets to the updated tree will revert the changes.
    ///
    /// # Errors
    /// If `mutations` was computed on a tree with a different root than this one, returns
    /// [`MerkleError::ConflictingRoots`] with a two-item [`Vec`]. The first item is the root hash
    /// the `mutations` were computed against, and the second item is the actual current root of
    /// this tree.
    pub fn apply_mutations_with_reversion(
        &mut self,
        mutations: MutationSet<SMT_DEPTH, Word, Word>,
    ) -> Result<MutationSet<SMT_DEPTH, Word, Word>, LargeSmtError>
    where
        Self: Sized,
    {
        use NodeMutation::*;

        let prepared = self.prepare_mutations(mutations)?;
        let (old_root, new_root) = (prepared.old_root, prepared.new_root);

        // Collect reverse mutations: for each mutation, capture the old node state
        let reverse_mutations: NodeMutations = prepared
            .sorted_node_mutations
            .iter()
            .filter_map(|(index, mutation)| {
                let old_node = if index.depth() < IN_MEMORY_DEPTH {
                    self.get_non_empty_inner_node(*index)
                } else {
                    let subtree_root = Subtree::find_subtree_root(*index);
                    prepared
                        .loaded_subtrees
                        .get(&subtree_root)
                        .and_then(|opt| opt.as_ref())
                        .and_then(|subtree| subtree.get_inner_node(*index))
                };

                // Map (index, mutation, old_node) to the reverse mutation
                match (mutation, old_node) {
                    (Removal, Some(node)) => Some((*index, Addition(node))),
                    (Addition(_), Some(node)) => Some((*index, Addition(node))),
                    (Addition(_), None) => Some((*index, Removal)),
                    (Removal, None) => None,
                }
            })
            .collect();

        // Collect reverse pairs: for each key, capture the old value
        let reverse_pairs: Map<Word, Word> = prepared
            .new_pairs
            .keys()
            .map(|key| {
                let leaf_idx = LargeSmt::<S>::key_to_leaf_index(key).value();
                let old_value = prepared
                    .leaf_map
                    .get(&leaf_idx)
                    .and_then(|opt| opt.as_ref())
                    .and_then(|leaf| leaf.get_value(key))
                    .unwrap_or(LargeSmt::<S>::EMPTY_VALUE);
                (*key, old_value)
            })
            .collect();

        // Apply the mutations
        self.apply_prepared_mutations(prepared)?;

        Ok(MutationSet {
            old_root: new_root,
            node_mutations: reverse_mutations,
            new_pairs: reverse_pairs,
            new_root: old_root,
        })
    }

    /// Computes the node mutations and the root of a subtree.
    ///
    /// This helper is used by both `compute_mutations` and `process_subtree_for_depth` (from
    /// insertion module).
    pub(crate) fn build_subtree_mutations(
        &self,
        mut leaves: Vec<SubtreeLeaf>,
        tree_depth: u8,
        subtree_root_depth: u8,
        subtree: Option<&Subtree>,
    ) -> (NodeMutations, SubtreeLeaf) {
        let bottom_depth = subtree_root_depth + SUBTREE_DEPTH;

        debug_assert!(bottom_depth <= tree_depth);
        debug_assert!(Integer::is_multiple_of(&bottom_depth, &SUBTREE_DEPTH));
        debug_assert!(leaves.len() <= usize::pow(2, SUBTREE_DEPTH as u32));

        let mut node_mutations: NodeMutations = Default::default();
        let mut next_leaves: Vec<SubtreeLeaf> = Vec::with_capacity(leaves.len() / 2);

        for current_depth in (subtree_root_depth..bottom_depth).rev() {
            debug_assert!(current_depth <= bottom_depth);

            let next_depth = current_depth + 1;
            let mut iter = leaves.drain(..).peekable();

            while let Some(first_leaf) = iter.next() {
                // This constructs a valid index because next_depth will never exceed the depth of
                // the tree.
                let parent_index = NodeIndex::new_unchecked(next_depth, first_leaf.col).parent();
                let parent_node = if let Some(sub) = subtree {
                    sub.get_inner_node(parent_index).unwrap_or_else(|| {
                        EmptySubtreeRoots::get_inner_node(SMT_DEPTH, parent_index.depth())
                    })
                } else if subtree_root_depth >= IN_MEMORY_DEPTH {
                    EmptySubtreeRoots::get_inner_node(SMT_DEPTH, parent_index.depth())
                } else {
                    self.get_inner_node(parent_index)
                };
                let combined_node = fetch_sibling_pair(&mut iter, first_leaf, parent_node);
                let combined_hash = combined_node.hash();

                let &empty_hash = EmptySubtreeRoots::entry(tree_depth, current_depth);

                // Add the parent node even if it is empty for proper upward updates
                next_leaves.push(SubtreeLeaf {
                    col: parent_index.value(),
                    hash: combined_hash,
                });

                node_mutations.insert(
                    parent_index,
                    if combined_hash != empty_hash {
                        NodeMutation::Addition(combined_node)
                    } else {
                        NodeMutation::Removal
                    },
                );
            }
            drop(iter);
            leaves = mem::take(&mut next_leaves);
        }

        debug_assert_eq!(leaves.len(), 1);
        let root_leaf = leaves.pop().unwrap();
        (node_mutations, root_leaf)
    }

    /// Prepares mutations by loading necessary data from storage.
    pub(crate) fn prepare_mutations(
        &self,
        mutations: MutationSet<SMT_DEPTH, Word, Word>,
    ) -> Result<PreparedMutations, LargeSmtError> {
        let MutationSet {
            old_root,
            node_mutations,
            new_pairs,
            new_root,
        } = mutations;

        // Guard against accidentally trying to apply mutations that were computed against a
        // different tree, including a stale version of this tree.
        let expected_root = SparseMerkleTree::<SMT_DEPTH>::root(self);
        if old_root != expected_root {
            return Err(LargeSmtError::Merkle(MerkleError::ConflictingRoots {
                expected_root,
                actual_root: old_root,
            }));
        }

        // Sort mutations
        let mut sorted_mutations: Vec<_> = Vec::from_iter(node_mutations);
        sorted_mutations.par_sort_unstable_by_key(|(index, _)| Subtree::find_subtree_root(*index));

        // Collect all unique subtree root indexes needed
        let mut subtree_roots_indices: Vec<NodeIndex> = sorted_mutations
            .iter()
            .filter_map(|(index, _)| {
                if index.depth() < IN_MEMORY_DEPTH {
                    None
                } else {
                    Some(Subtree::find_subtree_root(*index))
                }
            })
            .collect();
        subtree_roots_indices.dedup();

        // Read all subtrees at once
        let subtrees_from_storage = self.storage.get_subtrees(&subtree_roots_indices)?;

        // Map the subtrees
        let loaded_subtrees: Map<NodeIndex, Option<Subtree>> = subtree_roots_indices
            .into_iter()
            .zip(subtrees_from_storage)
            .map(|(root_index, subtree_opt)| {
                (root_index, Some(subtree_opt.unwrap_or_else(|| Subtree::new(root_index))))
            })
            .collect();

        // Collect and sort key-value pairs by their corresponding leaf index
        let mut sorted_kv_pairs: Vec<_> = new_pairs.iter().map(|(k, v)| (*k, *v)).collect();
        sorted_kv_pairs.par_sort_by_key(|(key, _)| LargeSmt::<S>::key_to_leaf_index(key).value());

        // Collect the unique leaf indices
        let mut leaf_indices: Vec<u64> = sorted_kv_pairs
            .iter()
            .map(|(key, _)| LargeSmt::<S>::key_to_leaf_index(key).value())
            .collect();
        leaf_indices.par_sort_unstable();
        leaf_indices.dedup();

        // Get leaves from storage
        let leaves = self.storage.get_leaves(&leaf_indices)?;

        // Map leaf indices to their corresponding leaves
        let leaf_map: Map<u64, Option<SmtLeaf>> = leaf_indices.into_iter().zip(leaves).collect();

        Ok(PreparedMutations {
            old_root,
            new_root,
            sorted_node_mutations: sorted_mutations,
            loaded_subtrees,
            new_pairs,
            leaf_map,
        })
    }

    /// Applies prepared mutations to the tree, updating storage.
    pub(crate) fn apply_prepared_mutations(
        &mut self,
        prepared: PreparedMutations,
    ) -> Result<(), LargeSmtError> {
        use NodeMutation::*;

        let PreparedMutations {
            old_root: _,
            new_root,
            sorted_node_mutations,
            mut loaded_subtrees,
            new_pairs,
            mut leaf_map,
        } = prepared;

        // Process node mutations
        for (index, mutation) in sorted_node_mutations {
            if index.depth() < IN_MEMORY_DEPTH {
                match mutation {
                    Removal => {
                        SparseMerkleTree::<SMT_DEPTH>::remove_inner_node(self, index);
                    },
                    Addition(node) => {
                        SparseMerkleTree::<SMT_DEPTH>::insert_inner_node(self, index, node);
                    },
                };
            } else {
                let subtree_root_index = Subtree::find_subtree_root(index);
                let subtree = loaded_subtrees
                    .get_mut(&subtree_root_index)
                    .expect("Subtree map entry must exist")
                    .as_mut()
                    .expect("Subtree must exist as it was either fetched or created");

                match mutation {
                    Removal => {
                        subtree.remove_inner_node(index);
                    },
                    Addition(node) => {
                        subtree.insert_inner_node(index, node);
                    },
                };
            }
        }

        // Go through subtrees, see if any are empty, and if so remove them
        for (_index, subtree) in loaded_subtrees.iter_mut() {
            if subtree.as_ref().is_some_and(|s| s.is_empty()) {
                *subtree = None;
            }
        }

        // Process leaf mutations
        let mut leaf_count_delta = 0isize;
        let mut entry_count_delta = 0isize;

        for (key, value) in new_pairs {
            let idx = LargeSmt::<S>::key_to_leaf_index(&key).value();
            let entry = leaf_map.entry(idx).or_insert(None);

            // New value is empty, handle deletion
            if value == LargeSmt::<S>::EMPTY_VALUE {
                if let Some(leaf) = entry {
                    // Leaf exists, handle deletion
                    if leaf.remove(key).1 {
                        // Key had previous value, decrement entry count
                        entry_count_delta -= 1;
                        if leaf.is_empty() {
                            // Leaf is now empty, remove it and decrement leaf count
                            *entry = None;
                            leaf_count_delta -= 1;
                        }
                    }
                }
            } else {
                // New value is not empty, handle update or create
                match entry {
                    Some(leaf) => {
                        // Leaf exists, handle update
                        if leaf.insert(key, value).expect("Failed to insert value").is_none() {
                            // Key had no previous value, increment entry count
                            entry_count_delta += 1;
                        }
                    },
                    None => {
                        // Leaf does not exist, create it
                        *entry = Some(SmtLeaf::Single((key, value)));
                        // Increment both entry and leaf count
                        entry_count_delta += 1;
                        leaf_count_delta += 1;
                    },
                }
            }
        }

        let updates = StorageUpdates::from_parts(
            leaf_map,
            loaded_subtrees,
            new_root,
            leaf_count_delta,
            entry_count_delta,
        );
        self.storage.apply(updates)?;
        Ok(())
    }
}
