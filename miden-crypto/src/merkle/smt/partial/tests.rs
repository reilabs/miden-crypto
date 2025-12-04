use alloc::collections::{BTreeMap, BTreeSet};

use assert_matches::assert_matches;
use rand_utils::{rand_array, rand_value};
use winter_math::fields::f64::BaseElement as Felt;

use super::*;
use crate::{EMPTY_WORD, ONE, ZERO, merkle::EmptySubtreeRoots};

/// Tests that a partial SMT constructed from a root is well behaved and returns expected
/// values.
#[test]
fn partial_smt_new_with_no_entries() {
    let key0 = Word::from(rand_array::<Felt, 4>());
    let value0 = Word::from(rand_array::<Felt, 4>());
    let full = Smt::with_entries([(key0, value0)]).unwrap();

    let partial_smt = PartialSmt::new(full.root());

    assert!(!partial_smt.tracks_leaves());
    assert_eq!(partial_smt.num_entries(), 0);
    assert_eq!(partial_smt.num_leaves(), 0);
    assert_eq!(partial_smt.entries().count(), 0);
    assert_eq!(partial_smt.tracked_leaves().count(), 0);
    assert_eq!(partial_smt.root(), full.root());
}

/// Tests that a basic PartialSmt can be built from a full one and that inserting or removing
/// values whose merkle path were added to the partial SMT results in the same root as the
/// equivalent update in the full tree.
#[test]
fn partial_smt_insert_and_remove() {
    let key0 = Word::from(rand_array::<Felt, 4>());
    let key1 = Word::from(rand_array::<Felt, 4>());
    let key2 = Word::from(rand_array::<Felt, 4>());
    // A key for which we won't add a value so it will be empty.
    let key_empty = Word::from(rand_array::<Felt, 4>());

    let value0 = Word::from(rand_array::<Felt, 4>());
    let value1 = Word::from(rand_array::<Felt, 4>());
    let value2 = Word::from(rand_array::<Felt, 4>());

    let mut kv_pairs = vec![(key0, value0), (key1, value1), (key2, value2)];

    // Add more random leaves.
    kv_pairs.reserve(1000);
    for _ in 0..1000 {
        let key = Word::from(rand_array::<Felt, 4>());
        let value = Word::from(rand_array::<Felt, 4>());
        kv_pairs.push((key, value));
    }

    let mut full = Smt::with_entries(kv_pairs).unwrap();

    // Constructing a partial SMT from proofs succeeds.
    // ----------------------------------------------------------------------------------------

    let proof0 = full.open(&key0);
    let proof2 = full.open(&key2);
    let proof_empty = full.open(&key_empty);

    assert!(proof_empty.leaf().is_empty());

    let mut partial = PartialSmt::from_proofs([proof0, proof2, proof_empty]).unwrap();

    assert_eq!(full.root(), partial.root());
    assert_eq!(partial.get_value(&key0).unwrap(), value0);
    let error = partial.get_value(&key1).unwrap_err();
    assert_matches!(error, MerkleError::UntrackedKey(_));
    assert_eq!(partial.get_value(&key2).unwrap(), value2);

    // Insert new values for added keys with empty and non-empty values.
    // ----------------------------------------------------------------------------------------

    let new_value0 = Word::from(rand_array::<Felt, 4>());
    let new_value2 = Word::from(rand_array::<Felt, 4>());
    // A non-empty value for the key that was previously empty.
    let new_value_empty_key = Word::from(rand_array::<Felt, 4>());

    full.insert(key0, new_value0).unwrap();
    full.insert(key2, new_value2).unwrap();
    full.insert(key_empty, new_value_empty_key).unwrap();

    partial.insert(key0, new_value0).unwrap();
    partial.insert(key2, new_value2).unwrap();
    // This updates a key whose value was previously empty.
    partial.insert(key_empty, new_value_empty_key).unwrap();

    assert_eq!(full.root(), partial.root());
    assert_eq!(partial.get_value(&key0).unwrap(), new_value0);
    assert_eq!(partial.get_value(&key2).unwrap(), new_value2);
    assert_eq!(partial.get_value(&key_empty).unwrap(), new_value_empty_key);

    // Remove an added key.
    // ----------------------------------------------------------------------------------------

    full.insert(key0, EMPTY_WORD).unwrap();
    partial.insert(key0, EMPTY_WORD).unwrap();

    assert_eq!(full.root(), partial.root());
    assert_eq!(partial.get_value(&key0).unwrap(), EMPTY_WORD);

    // Check if returned openings are the same in partial and full SMT.
    // ----------------------------------------------------------------------------------------

    // This is a key whose value is empty since it was removed.
    assert_eq!(full.open(&key0), partial.open(&key0).unwrap());
    // This is a key whose value is non-empty.
    assert_eq!(full.open(&key2), partial.open(&key2).unwrap());

    // Attempting to update a key whose merkle path was not added is an error.
    // ----------------------------------------------------------------------------------------

    let error = partial.clone().insert(key1, Word::from(rand_array::<Felt, 4>())).unwrap_err();
    assert_matches!(error, MerkleError::UntrackedKey(_));

    let error = partial.insert(key1, EMPTY_WORD).unwrap_err();
    assert_matches!(error, MerkleError::UntrackedKey(_));
}

/// Test that we can add an SmtLeaf::Multiple variant to a partial SMT.
#[test]
fn partial_smt_multiple_leaf_success() {
    // key0 and key1 have the same felt at index 3 so they will be placed in the same leaf.
    let key0 = Word::from([ZERO, ZERO, ZERO, ONE]);
    let key1 = Word::from([ONE, ONE, ONE, ONE]);
    let key2 = Word::from(rand_array::<Felt, 4>());

    let value0 = Word::from(rand_array::<Felt, 4>());
    let value1 = Word::from(rand_array::<Felt, 4>());
    let value2 = Word::from(rand_array::<Felt, 4>());

    let full = Smt::with_entries([(key0, value0), (key1, value1), (key2, value2)]).unwrap();

    // Make sure our assumption about the leaf being a multiple is correct.
    let SmtLeaf::Multiple(_) = full.get_leaf(&key0) else {
        panic!("expected full tree to produce multiple leaf")
    };

    let proof0 = full.open(&key0);
    let proof2 = full.open(&key2);

    let partial = PartialSmt::from_proofs([proof0, proof2]).unwrap();

    assert_eq!(partial.root(), full.root());

    assert_eq!(partial.get_leaf(&key0).unwrap(), full.get_leaf(&key0));
    // key1 is present in the partial tree because it is part of the proof of key0.
    assert_eq!(partial.get_leaf(&key1).unwrap(), full.get_leaf(&key1));
    assert_eq!(partial.get_leaf(&key2).unwrap(), full.get_leaf(&key2));
}

/// Tests that adding proofs to a partial SMT whose roots are not the same will result in an
/// error.
///
/// This test uses only empty values in the partial SMT.
#[test]
fn partial_smt_root_mismatch_on_empty_values() {
    let key0 = Word::from(rand_array::<Felt, 4>());
    let key1 = Word::from(rand_array::<Felt, 4>());
    let key2 = Word::from(rand_array::<Felt, 4>());

    let value0 = EMPTY_WORD;
    let value1 = Word::from(rand_array::<Felt, 4>());
    let value2 = EMPTY_WORD;

    let kv_pairs = vec![(key0, value0)];

    let mut full = Smt::with_entries(kv_pairs).unwrap();

    // This proof will become stale after the tree is modified.
    let stale_proof = full.open(&key2);

    // Insert a non-empty value so the root actually changes.
    full.insert(key1, value1).unwrap();
    full.insert(key2, value2).unwrap();

    // Construct a partial SMT against the latest root.
    let mut partial = PartialSmt::new(full.root());

    // Adding the stale proof should fail as its root is different.
    let err = partial.add_proof(stale_proof).unwrap_err();
    assert_matches!(err, MerkleError::ConflictingRoots { .. });
}

/// Tests that adding proofs to a partial SMT whose roots are not the same will result in an
/// error.
///
/// This test uses only non-empty values in the partial SMT.
#[test]
fn partial_smt_root_mismatch_on_non_empty_values() {
    let key0 = Word::new(rand_array());
    let key1 = Word::new(rand_array());
    let key2 = Word::new(rand_array());

    let value0 = Word::new(rand_array());
    let value1 = Word::new(rand_array());
    let value2 = Word::new(rand_array());

    let kv_pairs = vec![(key0, value0), (key1, value1)];

    let mut full = Smt::with_entries(kv_pairs).unwrap();

    // This proof will become stale after the tree is modified.
    let stale_proof = full.open(&key0);

    // Insert a value so the root changes.
    full.insert(key2, value2).unwrap();

    // Construct a partial SMT against the latest root.
    let mut partial = PartialSmt::new(full.root());

    // Adding the stale proof should fail as its root is different.
    let err = partial.add_proof(stale_proof).unwrap_err();
    assert_matches!(err, MerkleError::ConflictingRoots { .. });
}

/// Tests that from_proofs fails when the proofs roots do not match.
#[test]
fn partial_smt_from_proofs_fails_on_root_mismatch() {
    let key0 = Word::new(rand_array());
    let key1 = Word::new(rand_array());

    let value0 = Word::new(rand_array());
    let value1 = Word::new(rand_array());

    let mut full = Smt::with_entries([(key0, value0)]).unwrap();

    // This proof will become stale after the tree is modified.
    let stale_proof = full.open(&key0);

    // Insert a value so the root changes.
    full.insert(key1, value1).unwrap();

    // Construct a partial SMT against the latest root.
    let err = PartialSmt::from_proofs([full.open(&key1), stale_proof]).unwrap_err();
    assert_matches!(err, MerkleError::ConflictingRoots { .. });
}

/// Tests that a basic PartialSmt's iterator APIs return the expected values.
#[test]
fn partial_smt_iterator_apis() {
    let key0 = Word::new(rand_array());
    let key1 = Word::new(rand_array());
    let key2 = Word::new(rand_array());
    // A key for which we won't add a value so it will be empty.
    let key_empty = Word::new(rand_array());

    let value0 = Word::new(rand_array());
    let value1 = Word::new(rand_array());
    let value2 = Word::new(rand_array());

    let mut kv_pairs = vec![(key0, value0), (key1, value1), (key2, value2)];

    // Add more random leaves.
    kv_pairs.reserve(1000);
    for _ in 0..1000 {
        let key = Word::new(rand_array());
        let value = Word::new(rand_array());
        kv_pairs.push((key, value));
    }

    let full = Smt::with_entries(kv_pairs).unwrap();

    // Construct a partial SMT from proofs.
    // ----------------------------------------------------------------------------------------

    let proof0 = full.open(&key0);
    let proof2 = full.open(&key2);
    let proof_empty = full.open(&key_empty);

    assert!(proof_empty.leaf().is_empty());

    let proofs = [proof0, proof2, proof_empty];
    let partial = PartialSmt::from_proofs(proofs.clone()).unwrap();

    assert!(partial.tracks_leaves());
    assert_eq!(full.root(), partial.root());
    // There should be 2 non-empty entries.
    assert_eq!(partial.num_entries(), 2);
    // There should be 3 leaves, including the empty one.
    assert_eq!(partial.num_leaves(), 3);

    // The leaves API should only return tracked but non-empty leaves.
    // ----------------------------------------------------------------------------------------

    // Construct the sorted vector of leaves that should be yielded by the partial SMT.
    let expected_leaves: BTreeMap<_, _> =
        [SmtLeaf::new_single(key0, value0), SmtLeaf::new_single(key2, value2)]
            .into_iter()
            .map(|leaf| (leaf.index(), leaf))
            .collect();

    let actual_leaves = partial
        .leaves()
        .map(|(idx, leaf)| (idx, leaf.clone()))
        .collect::<BTreeMap<_, _>>();

    assert_eq!(actual_leaves.len(), expected_leaves.len());
    assert_eq!(actual_leaves, expected_leaves);

    // The tracked_leaves API should return all tracked leaves, including empty ones.
    // ----------------------------------------------------------------------------------------

    let mut expected_tracked_leaves = expected_leaves;
    let empty_leaf = SmtLeaf::new_empty(LeafIndex::from(key_empty));
    expected_tracked_leaves.insert(empty_leaf.index(), empty_leaf);

    let actual_tracked_leaves = partial
        .tracked_leaves()
        .map(|(idx, leaf)| (idx, leaf.clone()))
        .collect::<BTreeMap<_, _>>();

    assert_eq!(actual_tracked_leaves.len(), expected_tracked_leaves.len());
    assert_eq!(actual_tracked_leaves, expected_tracked_leaves);

    // The entries of the merkle paths from the proofs should exist as children of inner nodes
    // in the partial SMT.
    // ----------------------------------------------------------------------------------------

    let partial_inner_nodes: BTreeSet<_> =
        partial.inner_nodes().flat_map(|node| [node.left, node.right]).collect();
    let empty_subtree_roots: BTreeSet<_> = (0..SMT_DEPTH)
        .map(|depth| *EmptySubtreeRoots::entry(SMT_DEPTH, depth))
        .collect();

    for merkle_path in proofs.into_iter().map(|proof| proof.into_parts().0) {
        for (idx, digest) in merkle_path.into_iter().enumerate() {
            assert!(
                partial_inner_nodes.contains(&digest) || empty_subtree_roots.contains(&digest),
                "failed at idx {idx}"
            );
        }
    }
}

/// Test that the default partial SMT's tracks_leaves method returns `false`.
#[test]
fn partial_smt_tracks_leaves() {
    assert!(!PartialSmt::default().tracks_leaves());
}

/// `PartialSmt` serde round-trip when constructed from just a root.
#[test]
fn partial_smt_with_empty_leaves_serialization_roundtrip() {
    let partial_smt = PartialSmt::new(rand_value());
    assert_eq!(partial_smt, PartialSmt::read_from_bytes(&partial_smt.to_bytes()).unwrap());
}

/// `PartialSmt` serde round-trip. Also tests conversion from SMT.
#[test]
fn partial_smt_serialization_roundtrip() {
    let key = rand_value();
    let val = rand_value();

    let key_1 = rand_value();
    let val_1 = rand_value();

    let key_2 = rand_value();
    let val_2 = rand_value();

    let smt: Smt = Smt::with_entries([(key, val), (key_1, val_1), (key_2, val_2)]).unwrap();

    let partial_smt = PartialSmt::from_proofs([smt.open(&key)]).unwrap();

    assert_eq!(partial_smt.root(), smt.root());
    assert_matches!(partial_smt.open(&key_1), Err(MerkleError::UntrackedKey(_)));
    assert_matches!(partial_smt.open(&key), Ok(_));

    let bytes = partial_smt.to_bytes();
    let decoded = PartialSmt::read_from_bytes(&bytes).unwrap();

    assert_eq!(partial_smt, decoded);
}

/// Tests that add_path correctly updates num_entries for increasing entry counts.
///
/// Note that decreasing counts are not possible with the current API.
#[test]
fn partial_smt_add_proof_num_entries() {
    // key0 and key1 have the same felt at index 3 so they will be placed in the same leaf.
    let key0 = Word::from([ZERO, ZERO, ZERO, ONE]);
    let key1 = Word::from([ONE, ONE, ONE, ONE]);
    let key2 = Word::from([ONE, ONE, ONE, Felt::new(5)]);
    let value0 = Word::from(rand_array::<Felt, 4>());
    let value1 = Word::from(rand_array::<Felt, 4>());
    let value2 = Word::from(rand_array::<Felt, 4>());

    let full = Smt::with_entries([(key0, value0), (key1, value1), (key2, value2)]).unwrap();
    let mut partial = PartialSmt::new(full.root());

    // Add the multi-entry leaf
    partial.add_proof(full.open(&key0)).unwrap();
    assert_eq!(partial.num_entries(), 2);

    // Add the single-entry leaf
    partial.add_proof(full.open(&key2)).unwrap();
    assert_eq!(partial.num_entries(), 3);

    // Setting a value to the empty word removes decreases the number of entries.
    partial.insert(key0, Word::empty()).unwrap();
    assert_eq!(partial.num_entries(), 2);
}

/// Tests that a partial SMT can update keys in empty subtrees for which merkle paths exist,
/// even if those keys were not explicitly added. This verifies the new tracking definition.
#[test]
fn partial_smt_update_empty_subtree() {
    let key0 = Word::from([ZERO, ZERO, ZERO, ONE]);
    let value0 = Word::from(rand_array::<Felt, 4>());
    let kv_pairs = vec![(key0, value0)];

    let mut full = Smt::with_entries(kv_pairs).unwrap();

    let proof0 = full.open(&key0);

    let mut partial = PartialSmt::from_proofs([proof0]).unwrap();

    // The key we added is in the left subtree, so we expect the right child of the root to be
    // an empty subtree. In the partial SMT then, we can update any value in the right subtree
    // since they are all empty.
    let empty_subtree_root_depth_1 = EmptySubtreeRoots::entry(SMT_DEPTH, 1);
    assert_eq!(
        *empty_subtree_root_depth_1,
        partial.0.get_inner_node(NodeIndex::root().right_child()).hash()
    );

    // Construct a key in the right subtree (high bit set means right child at root level).
    let key1 = Word::from([ZERO, ZERO, ZERO, Felt::new(1 << (SMT_DEPTH - 1))]);
    let value1 = Word::from(rand_array::<Felt, 4>());

    full.insert(key1, value1).unwrap();
    partial.insert(key1, value1).unwrap();

    assert_eq!(full.root(), partial.root());
}

/// Tests that tracking one leaf does NOT allow updating a non-empty sibling leaf.
/// `proof0` contains `key1`'s non-empty leaf hash as a sibling in the merkle path,
/// so when we try to verify `key1` using an empty leaf hash, the roots don't match.
#[test]
fn partial_smt_cannot_update_nonempty_sibling_leaf() {
    // key0 and key1 are siblings at the leaf level (their leaf indices differ by 1)
    let key0 = Word::from([ZERO, ZERO, ZERO, Felt::new(0)]);
    let key1 = Word::from([ZERO, ZERO, ZERO, Felt::new(1)]);

    let value0 = Word::from(rand_array::<Felt, 4>());
    let value1 = Word::from(rand_array::<Felt, 4>());

    // Create full SMT with both keys so key1's leaf is NOT empty
    let full = Smt::with_entries([(key0, value0), (key1, value1)]).unwrap();

    // Only track key0 in the partial SMT
    let proof0 = full.open(&key0);
    let mut partial = PartialSmt::from_proofs([proof0]).unwrap();

    // Attempting to update key1 fails because its leaf is not tracked.
    let new_value1 = Word::from(rand_array::<Felt, 4>());
    let result = partial.insert(key1, new_value1);

    assert_matches!(result, Err(MerkleError::UntrackedKey(_)));
}
