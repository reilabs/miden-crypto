use alloc::vec::Vec;

use rayon::prelude::*;

use super::super::{
    IN_MEMORY_DEPTH, LargeSmt, LargeSmtError, LoadedLeaves, MutatedLeaves, SMT_DEPTH, SmtStorage,
    StorageUpdates, Subtree, SubtreeUpdate,
};
use crate::{
    Word,
    merkle::{
        LeafIndex, NodeIndex, SmtLeaf,
        smt::{
            Map, NodeMutation, NodeMutations, SparseMerkleTree,
            full::concurrent::{SUBTREE_DEPTH, SubtreeLeaf, SubtreeLeavesIter},
        },
    },
};

// BATCH INSERTION
// ================================================================================================

/// Implementation block for batch insertion operations on `LargeSmt`.
impl<S: SmtStorage> LargeSmt<S> {
    /// Inserts multiple key-value pairs into the tree in a single batch operation.
    ///
    /// This is the recommended method for bulk insertions, updates, and deletions. It efficiently
    /// processes all changes by loading each subtree and leaf only once, applying all mutations
    /// in-place, and leveraging parallel hashing throughout.
    ///
    /// To delete entries, pass [`EMPTY_WORD`](crate::EMPTY_WORD) as the value.
    ///
    /// # Returns
    /// Returns the new root hash of the tree after applying all changes.
    ///
    /// # Errors
    /// Returns an error if:
    /// - Any leaf would exceed [`MAX_LEAF_ENTRIES`](super::super::MAX_LEAF_ENTRIES) (1024 entries)
    /// - Storage operations fail
    ///
    /// # Example
    /// ```no_run
    /// use miden_crypto::{
    ///     EMPTY_WORD, Felt, Word,
    ///     merkle::{LargeSmt, RocksDbConfig, RocksDbStorage},
    /// };
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let storage = RocksDbStorage::open(RocksDbConfig::new("/path/to/db"))?;
    /// let mut smt = LargeSmt::new(storage)?;
    ///
    /// let entries = vec![
    ///     // Insert new entries
    ///     (
    ///         Word::new([Felt::new(1), Felt::new(0), Felt::new(0), Felt::new(0)]),
    ///         Word::new([Felt::new(10), Felt::new(20), Felt::new(30), Felt::new(40)]),
    ///     ),
    ///     (
    ///         Word::new([Felt::new(2), Felt::new(0), Felt::new(0), Felt::new(0)]),
    ///         Word::new([Felt::new(11), Felt::new(22), Felt::new(33), Felt::new(44)]),
    ///     ),
    ///     // Delete an entry
    ///     (Word::new([Felt::new(3), Felt::new(0), Felt::new(0), Felt::new(0)]), EMPTY_WORD),
    /// ];
    ///
    /// let new_root = smt.insert_batch(entries)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn insert_batch(
        &mut self,
        kv_pairs: impl IntoIterator<Item = (Word, Word)>,
    ) -> Result<Word, LargeSmtError>
    where
        Self: Sized + Sync,
    {
        // Sort key-value pairs by leaf index
        let mut sorted_kv_pairs: Vec<_> = kv_pairs.into_iter().collect();
        sorted_kv_pairs.par_sort_by_key(|(key, _)| Self::key_to_leaf_index(key).value());

        // Load leaves from storage
        let (_leaf_indices, leaf_map) = self.load_leaves_for_pairs(&sorted_kv_pairs)?;

        // Process leaves in parallel to get mutated leaves for tree building AND deltas
        let (mut leaves, mutated_leaf_nodes, _new_pairs, leaf_count_delta, entry_count_delta) =
            self.sorted_pairs_to_mutated_leaves_with_preloaded_leaves(sorted_kv_pairs, &leaf_map);

        // Early return if no mutations
        let old_root = self.root()?;
        if leaves.is_empty() {
            return Ok(old_root);
        }

        let mut loaded_subtrees: Map<NodeIndex, Option<Subtree>> = Map::new();

        // Process each depth level in reverse, stepping by the subtree depth
        for subtree_root_depth in
            (0..=SMT_DEPTH - SUBTREE_DEPTH).step_by(SUBTREE_DEPTH as usize).rev()
        {
            // Build mutations and apply them to loaded subtrees
            let subtree_count = leaves.len();
            let is_in_memory = subtree_root_depth < IN_MEMORY_DEPTH;
            let mutations_capacity = if is_in_memory {
                subtree_count * SUBTREE_DEPTH as usize
            } else {
                0
            };
            let updates_capacity = if is_in_memory { 0 } else { subtree_count };

            let (in_memory_mutations, mut subtree_roots, modified_subtrees) = leaves
                .into_par_iter()
                .map(|subtree_leaves| {
                    self.process_subtree_for_depth(subtree_leaves, subtree_root_depth)
                })
                .fold(
                    || {
                        (
                            Vec::with_capacity(mutations_capacity),
                            Vec::with_capacity(subtree_count),
                            Vec::with_capacity(updates_capacity),
                        )
                    },
                    |(mut muts, mut roots, mut subtrees), (mem_muts, root, subtree_update)| {
                        muts.extend(mem_muts);
                        roots.push(root);
                        if !matches!(subtree_update, SubtreeUpdate::None) {
                            subtrees.push(subtree_update);
                        }
                        (muts, roots, subtrees)
                    },
                )
                .reduce(
                    || (Vec::new(), Vec::new(), Vec::new()),
                    |(mut m1, mut r1, mut s1), (m2, r2, s2)| {
                        m1.extend(m2);
                        r1.extend(r2);
                        s1.extend(s2);
                        (m1, r1, s1)
                    },
                );

            // Apply in-memory mutations
            for (index, mutation) in in_memory_mutations {
                match mutation {
                    NodeMutation::Removal => self.remove_inner_node(index),
                    NodeMutation::Addition(node) => self.insert_inner_node(index, node),
                };
            }

            // Convert SubtreeUpdate to storage format
            for update in modified_subtrees {
                match update {
                    SubtreeUpdate::None => {},
                    SubtreeUpdate::Store { index, subtree } => {
                        loaded_subtrees.insert(index, Some(subtree));
                    },
                    SubtreeUpdate::Delete { index } => {
                        loaded_subtrees.insert(index, None);
                    },
                }
            }

            // Prepare leaves for the next depth level
            leaves = SubtreeLeavesIter::from_leaves(&mut subtree_roots).collect();

            debug_assert!(!leaves.is_empty());
        }

        let new_root = leaves[0][0].hash;

        // Build leaf updates for storage (convert Empty to None for deletion)
        let mut leaf_update_map = leaf_map;

        for (idx, mutated_leaf) in mutated_leaf_nodes {
            let leaf_opt = match mutated_leaf {
                // Delete from storage
                SmtLeaf::Empty(_) => None,
                _ => Some(mutated_leaf),
            };
            leaf_update_map.insert(idx, leaf_opt);
        }

        // Atomic update to storage
        let updates = StorageUpdates::from_parts(
            leaf_update_map,
            loaded_subtrees,
            new_root,
            leaf_count_delta,
            entry_count_delta,
        );
        self.storage.apply(updates)?;

        Ok(new_root)
    }

    /// Processes one set of `subtree_leaves` at a given `subtree_root_depth` and returns:
    /// - node mutations to apply to in-memory nodes (empty if handled in subtree),
    /// - the computed subtree root leaf, and
    /// - a storage update instruction for the subtree.
    fn process_subtree_for_depth(
        &self,
        subtree_leaves: Vec<SubtreeLeaf>,
        subtree_root_depth: u8,
    ) -> (NodeMutations, SubtreeLeaf, SubtreeUpdate) {
        debug_assert!(subtree_leaves.is_sorted() && !subtree_leaves.is_empty());

        let subtree_root_index =
            NodeIndex::new_unchecked(subtree_root_depth, subtree_leaves[0].col >> SUBTREE_DEPTH);

        // Load subtree from storage if below in-memory horizon; otherwise use in-memory nodes
        let mut subtree_opt = if subtree_root_depth < IN_MEMORY_DEPTH {
            None
        } else {
            Some(
                self.storage
                    .get_subtree(subtree_root_index)
                    .expect("Storage error getting subtree in insert_batch")
                    .unwrap_or_else(|| Subtree::new(subtree_root_index)),
            )
        };

        // Build mutations for the subtree (using helper from mutations module)
        let (mutations, root) = self.build_subtree_mutations(
            subtree_leaves,
            SMT_DEPTH,
            subtree_root_depth,
            subtree_opt.as_ref(),
        );

        let (in_memory_mutations, subtree_update) = if subtree_root_depth < IN_MEMORY_DEPTH {
            // In-memory nodes: return mutations for direct application
            (mutations, SubtreeUpdate::None)
        } else {
            // Storage nodes: apply mutations to loaded subtree and determine storage action
            let modified = !mutations.is_empty();
            if let Some(subtree) = subtree_opt.as_mut() {
                for (index, mutation) in mutations {
                    match mutation {
                        NodeMutation::Removal => {
                            subtree.remove_inner_node(index);
                        },
                        NodeMutation::Addition(node) => {
                            subtree.insert_inner_node(index, node);
                        },
                    }
                }
            }

            let update = if !modified {
                SubtreeUpdate::None
            } else if let Some(subtree) = subtree_opt
                && !subtree.is_empty()
            {
                SubtreeUpdate::Store { index: subtree_root_index, subtree }
            } else {
                SubtreeUpdate::Delete { index: subtree_root_index }
            };

            (NodeMutations::default(), update)
        };

        (in_memory_mutations, root, subtree_update)
    }

    /// Helper function to load leaves from storage for a set of key-value pairs.
    /// Returns the deduplicated leaf indices and a map of loaded leaves.
    ///
    /// This is a shared helper used by both `insert_batch` and `compute_mutations`.
    pub(crate) fn load_leaves_for_pairs(
        &self,
        sorted_kv_pairs: &[(Word, Word)],
    ) -> Result<LoadedLeaves, LargeSmtError> {
        // Collect the unique leaf indices
        let mut leaf_indices: Vec<u64> = sorted_kv_pairs
            .iter()
            .map(|(key, _)| Self::key_to_leaf_index(key).value())
            .collect();
        leaf_indices.dedup();
        leaf_indices.par_sort_unstable();

        // Get leaves from storage
        let leaves_from_storage = self.storage.get_leaves(&leaf_indices)?;

        // Map leaf indices to their corresponding leaves
        let leaf_map: Map<u64, Option<SmtLeaf>> = leaf_indices
            .iter()
            .zip(leaves_from_storage)
            .map(|(index, maybe_leaf)| (*index, maybe_leaf))
            .collect();

        Ok((leaf_indices, leaf_map))
    }

    /// Computes leaves from a set of key-value pairs and current leaf values.
    ///
    /// Returns: (leaves for tree building, map of mutated leaf nodes, changed key-value pairs,
    /// leaf_delta, entry_delta)
    ///
    /// This is a shared helper used by both `insert_batch` and `compute_mutations`.
    pub(crate) fn sorted_pairs_to_mutated_leaves_with_preloaded_leaves(
        &self,
        pairs: Vec<(Word, Word)>,
        leaf_map: &Map<u64, Option<SmtLeaf>>,
    ) -> MutatedLeaves {
        use crate::merkle::smt::full::concurrent::process_sorted_pairs_to_leaves;

        // Map to track new key-value pairs for mutated leaves
        let mut new_pairs = Map::new();
        let mut leaf_count_delta = 0isize;
        let mut entry_count_delta = 0isize;

        let accumulator = process_sorted_pairs_to_leaves(pairs, |leaf_pairs| {
            let leaf_index = LeafIndex::<SMT_DEPTH>::from(leaf_pairs[0].0);
            let old_leaf_opt = leaf_map.get(&leaf_index.value()).and_then(|opt| opt.as_ref());
            let old_entry_count = old_leaf_opt.map(|leaf| leaf.entries().len()).unwrap_or(0);

            let mut leaf = old_leaf_opt
                .cloned()
                .unwrap_or_else(|| SmtLeaf::new_empty(leaf_pairs[0].0.into()));

            let mut leaf_changed = false;
            for (key, value) in leaf_pairs {
                // Check if the value has changed
                let old_value = new_pairs.get(&key).cloned().unwrap_or_else(|| {
                    // Safe to unwrap: `leaf_pairs` contains keys all belonging to this leaf.
                    // `SmtLeaf::get_value()` only returns `None` if the key does not belong to the
                    // leaf, which cannot happen due to the sorting/grouping
                    // logic in `process_sorted_pairs_to_leaves()`.
                    leaf.get_value(&key).unwrap()
                });

                if value != old_value {
                    // Update the leaf and track the new key-value pair
                    leaf = self
                        .construct_prospective_leaf(leaf, &key, &value)
                        .expect("Failed to construct prospective leaf");
                    new_pairs.insert(key, value);
                    leaf_changed = true;
                }
            }

            if leaf_changed {
                // Calculate deltas
                let new_entry_count = leaf.entries().len();

                match (&leaf, old_leaf_opt) {
                    (SmtLeaf::Empty(_), Some(_)) => {
                        // Leaf was deleted
                        leaf_count_delta -= 1;
                        entry_count_delta -= old_entry_count as isize;
                    },
                    (SmtLeaf::Empty(_), None) => {
                        // Was empty, still empty (shouldn't happen with leaf_changed=true)
                        unreachable!("Leaf was empty, but leaf_changed=true");
                    },
                    (_, None) => {
                        // New leaf created
                        leaf_count_delta += 1;
                        entry_count_delta += new_entry_count as isize;
                    },
                    (_, Some(_)) => {
                        // Leaf updated (not empty)
                        entry_count_delta += new_entry_count as isize - old_entry_count as isize;
                    },
                }

                // Only return the leaf if it actually changed
                Ok(Some(leaf))
            } else {
                // Return None if leaf hasn't changed
                Ok(None)
            }
        });
        // The closure is the only possible source of errors.
        // Since it never returns an error - only `Ok(Some(_))` or `Ok(None)` - we can safely assume
        // `accumulator` is always `Ok(_)`.
        let accumulator = accumulator.expect("process_sorted_pairs_to_leaves never fails");
        (
            accumulator.leaves,
            accumulator.nodes,
            new_pairs,
            leaf_count_delta,
            entry_count_delta,
        )
    }
}
