use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};

use rand::{prelude::IteratorRandom, thread_rng, Rng};

use super::{
    build_subtree, InnerNode, LeafIndex, NodeIndex, NodeMutations, PairComputations, SmtLeaf,
    SparseMerkleTree, SubtreeLeaf, SubtreeLeavesIter, COLS_PER_SUBTREE, SUBTREE_DEPTH,
};
use crate::{
    hash::rpo::RpoDigest,
    merkle::{smt::UnorderedMap, Smt, SMT_DEPTH},
    Felt, Word, EMPTY_WORD, ONE,
};

fn smtleaf_to_subtree_leaf(leaf: &SmtLeaf) -> SubtreeLeaf {
    SubtreeLeaf {
        col: leaf.index().index.value(),
        hash: leaf.hash(),
    }
}

#[test]
#[cfg(feature = "concurrent")]
fn test_sorted_pairs_to_leaves() {
    let entries: Vec<(RpoDigest, Word)> = vec![
        // Subtree 0.
        (RpoDigest::new([ONE, ONE, ONE, Felt::new(16)]), [ONE; 4]),
        (RpoDigest::new([ONE, ONE, ONE, Felt::new(17)]), [ONE; 4]),
        // Leaf index collision.
        (RpoDigest::new([ONE, ONE, Felt::new(10), Felt::new(20)]), [ONE; 4]),
        (RpoDigest::new([ONE, ONE, Felt::new(20), Felt::new(20)]), [ONE; 4]),
        // Subtree 1. Normal single leaf again.
        (RpoDigest::new([ONE, ONE, ONE, Felt::new(400)]), [ONE; 4]), // Subtree boundary.
        (RpoDigest::new([ONE, ONE, ONE, Felt::new(401)]), [ONE; 4]),
        // Subtree 2. Another normal leaf.
        (RpoDigest::new([ONE, ONE, ONE, Felt::new(1024)]), [ONE; 4]),
    ];

    let control = Smt::with_entries_sequential(entries.clone()).unwrap();

    let control_leaves: Vec<SmtLeaf> = {
        let mut entries_iter = entries.iter().cloned();
        let mut next_entry = || entries_iter.next().unwrap();
        let control_leaves = vec![
            // Subtree 0.
            SmtLeaf::Single(next_entry()),
            SmtLeaf::Single(next_entry()),
            SmtLeaf::new_multiple(vec![next_entry(), next_entry()]).unwrap(),
            // Subtree 1.
            SmtLeaf::Single(next_entry()),
            SmtLeaf::Single(next_entry()),
            // Subtree 2.
            SmtLeaf::Single(next_entry()),
        ];
        assert_eq!(entries_iter.next(), None);
        control_leaves
    };

    let control_subtree_leaves: Vec<Vec<SubtreeLeaf>> = {
        let mut control_leaves_iter = control_leaves.iter();
        let mut next_leaf = || control_leaves_iter.next().unwrap();

        let control_subtree_leaves: Vec<Vec<SubtreeLeaf>> = [
            // Subtree 0.
            vec![next_leaf(), next_leaf(), next_leaf()],
            // Subtree 1.
            vec![next_leaf(), next_leaf()],
            // Subtree 2.
            vec![next_leaf()],
        ]
        .map(|subtree| subtree.into_iter().map(smtleaf_to_subtree_leaf).collect())
        .to_vec();
        assert_eq!(control_leaves_iter.next(), None);
        control_subtree_leaves
    };

    let subtrees: PairComputations<u64, SmtLeaf> = Smt::sorted_pairs_to_leaves(entries);
    // This will check that the hashes, columns, and subtree assignments all match.
    assert_eq!(subtrees.leaves, control_subtree_leaves);

    // Flattening and re-separating out the leaves into subtrees should have the same result.
    let mut all_leaves: Vec<SubtreeLeaf> = subtrees.leaves.clone().into_iter().flatten().collect();
    let re_grouped: Vec<Vec<_>> = SubtreeLeavesIter::from_leaves(&mut all_leaves).collect();
    assert_eq!(subtrees.leaves, re_grouped);

    // Then finally we might as well check the computed leaf nodes too.
    let control_leaves: BTreeMap<u64, SmtLeaf> = control
        .leaves()
        .map(|(index, value)| (index.index.value(), value.clone()))
        .collect();

    for (column, test_leaf) in subtrees.nodes {
        if test_leaf.is_empty() {
            continue;
        }
        let control_leaf = control_leaves
            .get(&column)
            .unwrap_or_else(|| panic!("no leaf node found for column {column}"));
        assert_eq!(control_leaf, &test_leaf);
    }
}

// Helper for the below tests.
fn generate_entries(pair_count: u64) -> Vec<(RpoDigest, Word)> {
    (0..pair_count)
        .map(|i| {
            let leaf_index = ((i as f64 / pair_count as f64) * (pair_count as f64)) as u64;
            let key = RpoDigest::new([ONE, ONE, Felt::new(i), Felt::new(leaf_index)]);
            let value = [ONE, ONE, ONE, Felt::new(i)];
            (key, value)
        })
        .collect()
}

fn generate_updates(entries: Vec<(RpoDigest, Word)>, updates: usize) -> Vec<(RpoDigest, Word)> {
    const REMOVAL_PROBABILITY: f64 = 0.2;
    let mut rng = thread_rng();

    // Assertion to ensure input keys are unique
    assert!(
        entries
            .iter()
            .map(|(key, _)| key)
            .collect::<BTreeSet<_>>()
            .len()
            == entries.len(),
        "Input entries contain duplicate keys!"
    );

    let mut sorted_entries: Vec<(RpoDigest, Word)> = entries
        .into_iter()
        .choose_multiple(&mut rng, updates)
        .into_iter()
        .map(|(key, _)| {
            let value = if rng.gen_bool(REMOVAL_PROBABILITY) {
                EMPTY_WORD
            } else {
                [ONE, ONE, ONE, Felt::new(rng.gen())]
            };

            (key, value)
        })
        .collect();
    sorted_entries.sort_by_key(|(key, _)| Smt::key_to_leaf_index(key).value());
    sorted_entries
}

#[test]
#[cfg(feature = "concurrent")]
fn test_single_subtree() {
    // A single subtree's worth of leaves.
    const PAIR_COUNT: u64 = COLS_PER_SUBTREE;

    let entries = generate_entries(PAIR_COUNT);

    let control = Smt::with_entries_sequential(entries.clone()).unwrap();

    // `entries` should already be sorted by nature of how we constructed it.
    let leaves = Smt::sorted_pairs_to_leaves(entries).leaves;
    let leaves = leaves.into_iter().next().unwrap();

    let (first_subtree, subtree_root) = build_subtree(leaves, SMT_DEPTH, SMT_DEPTH);
    assert!(!first_subtree.is_empty());

    // The inner nodes computed from that subtree should match the nodes in our control tree.
    for (index, node) in first_subtree.into_iter() {
        let control = control.get_inner_node(index);
        assert_eq!(
            control, node,
            "subtree-computed node at index {index:?} does not match control",
        );
    }

    // The root returned should also match the equivalent node in the control tree.
    let control_root_index =
        NodeIndex::new(SMT_DEPTH - SUBTREE_DEPTH, subtree_root.col).expect("Valid root index");
    let control_root_node = control.get_inner_node(control_root_index);
    let control_hash = control_root_node.hash();
    assert_eq!(
        control_hash, subtree_root.hash,
        "Subtree-computed root at index {control_root_index:?} does not match control"
    );
}

// Test that not just can we compute a subtree correctly, but we can feed the results of one
// subtree into computing another. In other words, test that `build_subtree()` is correctly
// composable.
#[test]
#[cfg(feature = "concurrent")]
fn test_two_subtrees() {
    // Two subtrees' worth of leaves.
    const PAIR_COUNT: u64 = COLS_PER_SUBTREE * 2;

    let entries = generate_entries(PAIR_COUNT);

    let control = Smt::with_entries_sequential(entries.clone()).unwrap();

    let PairComputations { leaves, .. } = Smt::sorted_pairs_to_leaves(entries);
    // With two subtrees' worth of leaves, we should have exactly two subtrees.
    let [first, second]: [Vec<_>; 2] = leaves.try_into().unwrap();
    assert_eq!(first.len() as u64, PAIR_COUNT / 2);
    assert_eq!(first.len(), second.len());

    let mut current_depth = SMT_DEPTH;
    let mut next_leaves: Vec<SubtreeLeaf> = Default::default();

    let (first_nodes, first_root) = build_subtree(first, SMT_DEPTH, current_depth);
    next_leaves.push(first_root);

    let (second_nodes, second_root) = build_subtree(second, SMT_DEPTH, current_depth);
    next_leaves.push(second_root);

    // All new inner nodes + the new subtree-leaves should be 512, for one depth-cycle.
    let total_computed = first_nodes.len() + second_nodes.len() + next_leaves.len();
    assert_eq!(total_computed as u64, PAIR_COUNT);

    // Verify the computed nodes of both subtrees.
    let computed_nodes = first_nodes.clone().into_iter().chain(second_nodes);
    for (index, test_node) in computed_nodes {
        let control_node = control.get_inner_node(index);
        assert_eq!(
            control_node, test_node,
            "subtree-computed node at index {index:?} does not match control",
        );
    }

    current_depth -= SUBTREE_DEPTH;

    let (nodes, root_leaf) = build_subtree(next_leaves, SMT_DEPTH, current_depth);
    assert_eq!(nodes.len(), SUBTREE_DEPTH as usize);
    assert_eq!(root_leaf.col, 0);

    for (index, test_node) in nodes {
        let control_node = control.get_inner_node(index);
        assert_eq!(
            control_node, test_node,
            "subtree-computed node at index {index:?} does not match control",
        );
    }

    let index = NodeIndex::new(current_depth - SUBTREE_DEPTH, root_leaf.col).unwrap();
    let control_root = control.get_inner_node(index).hash();
    assert_eq!(control_root, root_leaf.hash, "Root mismatch");
}

#[test]
#[cfg(feature = "concurrent")]
fn test_singlethreaded_subtrees() {
    const PAIR_COUNT: u64 = COLS_PER_SUBTREE * 64;

    let entries = generate_entries(PAIR_COUNT);

    let control = Smt::with_entries_sequential(entries.clone()).unwrap();

    let mut accumulated_nodes: BTreeMap<NodeIndex, InnerNode> = Default::default();

    let PairComputations {
        leaves: mut leaf_subtrees,
        nodes: test_leaves,
    } = Smt::sorted_pairs_to_leaves(entries);

    for current_depth in (SUBTREE_DEPTH..=SMT_DEPTH).step_by(SUBTREE_DEPTH as usize).rev() {
        // There's no flat_map_unzip(), so this is the best we can do.
        let (nodes, mut subtree_roots): (Vec<UnorderedMap<_, _>>, Vec<SubtreeLeaf>) = leaf_subtrees
            .into_iter()
            .enumerate()
            .map(|(i, subtree)| {
                // Pre-assertions.
                assert!(
                    subtree.is_sorted(),
                    "subtree {i} at bottom-depth {current_depth} is not sorted",
                );
                assert!(
                    !subtree.is_empty(),
                    "subtree {i} at bottom-depth {current_depth} is empty!",
                );

                // Do actual things.
                let (nodes, subtree_root) = build_subtree(subtree, SMT_DEPTH, current_depth);

                // Post-assertions.
                for (&index, test_node) in nodes.iter() {
                    let control_node = control.get_inner_node(index);
                    assert_eq!(
                        test_node, &control_node,
                        "depth {} subtree {}: test node does not match control at index {:?}",
                        current_depth, i, index,
                    );
                }

                (nodes, subtree_root)
            })
            .unzip();

        // Update state between each depth iteration.

        leaf_subtrees = SubtreeLeavesIter::from_leaves(&mut subtree_roots).collect();
        accumulated_nodes.extend(nodes.into_iter().flatten());

        assert!(!leaf_subtrees.is_empty(), "on depth {current_depth}");
    }

    // Make sure the true leaves match, first checking length and then checking each individual
    // leaf.
    let control_leaves: BTreeMap<_, _> = control.leaves().collect();
    let control_leaves_len = control_leaves.len();
    let test_leaves_len = test_leaves.len();
    assert_eq!(test_leaves_len, control_leaves_len);
    for (col, ref test_leaf) in test_leaves {
        let index = LeafIndex::new_max_depth(col);
        let &control_leaf = control_leaves.get(&index).unwrap();
        assert_eq!(test_leaf, control_leaf, "test leaf at column {col} does not match control");
    }

    // Make sure the inner nodes match, checking length first and then each individual leaf.
    let control_nodes_len = control.inner_nodes().count();
    let test_nodes_len = accumulated_nodes.len();
    assert_eq!(test_nodes_len, control_nodes_len);
    for (index, test_node) in accumulated_nodes.clone() {
        let control_node = control.get_inner_node(index);
        assert_eq!(test_node, control_node, "test node does not match control at {index:?}");
    }

    // After the last iteration of the above for loop, we should have the new root node actually
    // in two places: one in `accumulated_nodes`, and the other as the "next leaves" return from
    // `build_subtree()`. So let's check both!

    let control_root = control.get_inner_node(NodeIndex::root());

    // That for loop should have left us with only one leaf subtree...
    let [leaf_subtree]: [Vec<_>; 1] = leaf_subtrees.try_into().unwrap();
    // which itself contains only one 'leaf'...
    let [root_leaf]: [SubtreeLeaf; 1] = leaf_subtree.try_into().unwrap();
    // which matches the expected root.
    assert_eq!(control.root(), root_leaf.hash);

    // Likewise `accumulated_nodes` should contain a node at the root index...
    assert!(accumulated_nodes.contains_key(&NodeIndex::root()));
    // and it should match our actual root.
    let test_root = accumulated_nodes.get(&NodeIndex::root()).unwrap();
    assert_eq!(control_root, *test_root);
    // And of course the root we got from each place should match.
    assert_eq!(control.root(), root_leaf.hash);
}

/// The parallel version of `test_singlethreaded_subtree()`.
#[test]
#[cfg(feature = "concurrent")]
fn test_multithreaded_subtrees() {
    use rayon::prelude::*;

    const PAIR_COUNT: u64 = COLS_PER_SUBTREE * 64;

    let entries = generate_entries(PAIR_COUNT);

    let control = Smt::with_entries_sequential(entries.clone()).unwrap();

    let mut accumulated_nodes: BTreeMap<NodeIndex, InnerNode> = Default::default();

    let PairComputations {
        leaves: mut leaf_subtrees,
        nodes: test_leaves,
    } = Smt::sorted_pairs_to_leaves(entries);

    for current_depth in (SUBTREE_DEPTH..=SMT_DEPTH).step_by(SUBTREE_DEPTH as usize).rev() {
        let (nodes, mut subtree_roots): (Vec<UnorderedMap<_, _>>, Vec<SubtreeLeaf>) = leaf_subtrees
            .into_par_iter()
            .enumerate()
            .map(|(i, subtree)| {
                // Pre-assertions.
                assert!(
                    subtree.is_sorted(),
                    "subtree {i} at bottom-depth {current_depth} is not sorted",
                );
                assert!(
                    !subtree.is_empty(),
                    "subtree {i} at bottom-depth {current_depth} is empty!",
                );

                let (nodes, subtree_root) = build_subtree(subtree, SMT_DEPTH, current_depth);

                // Post-assertions.
                for (&index, test_node) in nodes.iter() {
                    let control_node = control.get_inner_node(index);
                    assert_eq!(
                        test_node, &control_node,
                        "depth {} subtree {}: test node does not match control at index {:?}",
                        current_depth, i, index,
                    );
                }

                (nodes, subtree_root)
            })
            .unzip();

        leaf_subtrees = SubtreeLeavesIter::from_leaves(&mut subtree_roots).collect();
        accumulated_nodes.extend(nodes.into_iter().flatten());

        assert!(!leaf_subtrees.is_empty(), "on depth {current_depth}");
    }

    // Make sure the true leaves match, checking length first and then each individual leaf.
    let control_leaves: BTreeMap<_, _> = control.leaves().collect();
    let control_leaves_len = control_leaves.len();
    let test_leaves_len = test_leaves.len();
    assert_eq!(test_leaves_len, control_leaves_len);
    for (col, ref test_leaf) in test_leaves {
        let index = LeafIndex::new_max_depth(col);
        let &control_leaf = control_leaves.get(&index).unwrap();
        assert_eq!(test_leaf, control_leaf);
    }

    // Make sure the inner nodes match, checking length first and then each individual leaf.
    let control_nodes_len = control.inner_nodes().count();
    let test_nodes_len = accumulated_nodes.len();
    assert_eq!(test_nodes_len, control_nodes_len);
    for (index, test_node) in accumulated_nodes.clone() {
        let control_node = control.get_inner_node(index);
        assert_eq!(test_node, control_node, "test node does not match control at {index:?}");
    }

    // After the last iteration of the above for loop, we should have the new root node actually
    // in two places: one in `accumulated_nodes`, and the other as the "next leaves" return from
    // `build_subtree()`. So let's check both!

    let control_root = control.get_inner_node(NodeIndex::root());

    // That for loop should have left us with only one leaf subtree...
    let [leaf_subtree]: [_; 1] = leaf_subtrees.try_into().unwrap();
    // which itself contains only one 'leaf'...
    let [root_leaf]: [_; 1] = leaf_subtree.try_into().unwrap();
    // which matches the expected root.
    assert_eq!(control.root(), root_leaf.hash);

    // Likewise `accumulated_nodes` should contain a node at the root index...
    assert!(accumulated_nodes.contains_key(&NodeIndex::root()));
    // and it should match our actual root.
    let test_root = accumulated_nodes.get(&NodeIndex::root()).unwrap();
    assert_eq!(control_root, *test_root);
    // And of course the root we got from each place should match.
    assert_eq!(control.root(), root_leaf.hash);
}

#[test]
#[cfg(feature = "concurrent")]
fn test_with_entries_parallel() {
    const PAIR_COUNT: u64 = COLS_PER_SUBTREE * 64;

    let entries = generate_entries(PAIR_COUNT);

    let control = Smt::with_entries_sequential(entries.clone()).unwrap();

    let smt = Smt::with_entries(entries.clone()).unwrap();
    assert_eq!(smt.root(), control.root());
    assert_eq!(smt, control);
}

#[test]
#[cfg(feature = "concurrent")]
fn test_singlethreaded_subtree_mutations() {
    const PAIR_COUNT: u64 = COLS_PER_SUBTREE * 64;

    let entries = generate_entries(PAIR_COUNT);
    let updates = generate_updates(entries.clone(), 1000);

    let tree = Smt::with_entries_sequential(entries.clone()).unwrap();
    let control = tree.compute_mutations_sequential(updates.clone());

    let mut node_mutations = NodeMutations::default();

    let (mut subtree_leaves, new_pairs) = tree.sorted_pairs_to_mutated_subtree_leaves(updates);

    for current_depth in (SUBTREE_DEPTH..=SMT_DEPTH).step_by(SUBTREE_DEPTH as usize).rev() {
        // There's no flat_map_unzip(), so this is the best we can do.
        let (mutations_per_subtree, mut subtree_roots): (Vec<_>, Vec<_>) = subtree_leaves
            .into_iter()
            .enumerate()
            .map(|(i, subtree)| {
                // Pre-assertions.
                assert!(
                    subtree.is_sorted(),
                    "subtree {i} at bottom-depth {current_depth} is not sorted",
                );
                assert!(
                    !subtree.is_empty(),
                    "subtree {i} at bottom-depth {current_depth} is empty!",
                );

                // Calculate the mutations for this subtree.
                let (mutations_per_subtree, subtree_root) =
                    tree.build_subtree_mutations(subtree, SMT_DEPTH, current_depth);

                // Check that the mutations match the control tree.
                for (&index, mutation) in mutations_per_subtree.iter() {
                    let control_mutation = control.node_mutations().get(&index).unwrap();
                    assert_eq!(
                        control_mutation, mutation,
                        "depth {} subtree {}: mutation does not match control at index {:?}",
                        current_depth, i, index,
                    );
                }

                (mutations_per_subtree, subtree_root)
            })
            .unzip();

        subtree_leaves = SubtreeLeavesIter::from_leaves(&mut subtree_roots).collect();
        node_mutations.extend(mutations_per_subtree.into_iter().flatten());

        assert!(!subtree_leaves.is_empty(), "on depth {current_depth}");
    }

    let [subtree]: [Vec<_>; 1] = subtree_leaves.try_into().unwrap();
    let [root_leaf]: [SubtreeLeaf; 1] = subtree.try_into().unwrap();
    // Check that the new root matches the control.
    assert_eq!(control.new_root, root_leaf.hash);

    // Check that the node mutations match the control.
    assert_eq!(control.node_mutations().len(), node_mutations.len());
    for (&index, mutation) in control.node_mutations().iter() {
        let test_mutation = node_mutations.get(&index).unwrap();
        assert_eq!(test_mutation, mutation);
    }
    // Check that the new pairs match the control
    assert_eq!(control.new_pairs.len(), new_pairs.len());
    for (&key, &value) in control.new_pairs.iter() {
        let test_value = new_pairs.get(&key).unwrap();
        assert_eq!(test_value, &value);
    }
}

#[test]
#[cfg(feature = "concurrent")]
fn test_compute_mutations_parallel() {
    const PAIR_COUNT: u64 = COLS_PER_SUBTREE * 64;

    let entries = generate_entries(PAIR_COUNT);
    let tree = Smt::with_entries(entries.clone()).unwrap();

    let updates = generate_updates(entries, 1000);

    let control = tree.compute_mutations_sequential(updates.clone());
    let mutations = tree.compute_mutations(updates);

    assert_eq!(mutations.root(), control.root());
    assert_eq!(mutations.old_root(), control.old_root());
    assert_eq!(mutations.node_mutations(), control.node_mutations());
    assert_eq!(mutations.new_pairs(), control.new_pairs());
}
