use super::{
    super::{MerkleError, RpoDigest, SimpleSmt},
    NodeIndex,
};
use crate::{
    hash::rpo::Rpo256,
    merkle::{
        digests_to_words, int_to_leaf, int_to_node, smt::SparseMerkleTree, EmptySubtreeRoots,
        InnerNodeInfo, LeafIndex, MerkleTree,
    },
    Word, EMPTY_WORD,
};
use alloc::vec::Vec;

// TEST DATA
// ================================================================================================

const KEYS4: [u64; 4] = [0, 1, 2, 3];
const KEYS8: [u64; 8] = [0, 1, 2, 3, 4, 5, 6, 7];

const VALUES4: [RpoDigest; 4] = [int_to_node(1), int_to_node(2), int_to_node(3), int_to_node(4)];

const VALUES8: [RpoDigest; 8] = [
    int_to_node(1),
    int_to_node(2),
    int_to_node(3),
    int_to_node(4),
    int_to_node(5),
    int_to_node(6),
    int_to_node(7),
    int_to_node(8),
];

const ZERO_VALUES8: [Word; 8] = [int_to_leaf(0); 8];

// TESTS
// ================================================================================================

#[test]
fn build_empty_tree() {
    // tree of depth 3
    let smt = SimpleSmt::<3>::new().unwrap();
    let mt = MerkleTree::new(ZERO_VALUES8).unwrap();
    assert_eq!(mt.root(), smt.root());
}

#[test]
fn build_sparse_tree() {
    const DEPTH: u8 = 3;
    let mut smt = SimpleSmt::<DEPTH>::new().unwrap();
    let mut values = ZERO_VALUES8.to_vec();

    assert_eq!(smt.num_leaves(), 0);

    // insert single value
    let key = 6;
    let new_node = int_to_leaf(7);
    values[key as usize] = new_node;
    let old_value = smt.insert(LeafIndex::<DEPTH>::new(key).unwrap(), new_node);
    let mt2 = MerkleTree::new(values.clone()).unwrap();
    assert_eq!(mt2.root(), smt.root());
    assert_eq!(
        mt2.get_path(NodeIndex::make(3, 6)).unwrap(),
        smt.open(&LeafIndex::<3>::new(6).unwrap()).path
    );
    assert_eq!(old_value, EMPTY_WORD);
    assert_eq!(smt.num_leaves(), 1);

    // insert second value at distinct leaf branch
    let key = 2;
    let new_node = int_to_leaf(3);
    values[key as usize] = new_node;
    let old_value = smt.insert(LeafIndex::<DEPTH>::new(key).unwrap(), new_node);
    let mt3 = MerkleTree::new(values).unwrap();
    assert_eq!(mt3.root(), smt.root());
    assert_eq!(
        mt3.get_path(NodeIndex::make(3, 2)).unwrap(),
        smt.open(&LeafIndex::<3>::new(2).unwrap()).path
    );
    assert_eq!(old_value, EMPTY_WORD);
    assert_eq!(smt.num_leaves(), 2);
}

/// Tests that [`SimpleSmt::with_contiguous_leaves`] works as expected
#[test]
fn build_contiguous_tree() {
    let tree_with_leaves =
        SimpleSmt::<2>::with_leaves([0, 1, 2, 3].into_iter().zip(digests_to_words(&VALUES4)))
            .unwrap();

    let tree_with_contiguous_leaves =
        SimpleSmt::<2>::with_contiguous_leaves(digests_to_words(&VALUES4)).unwrap();

    assert_eq!(tree_with_leaves, tree_with_contiguous_leaves);
}

#[test]
fn test_depth2_tree() {
    let tree =
        SimpleSmt::<2>::with_leaves(KEYS4.into_iter().zip(digests_to_words(&VALUES4))).unwrap();

    // check internal structure
    let (root, node2, node3) = compute_internal_nodes();
    assert_eq!(root, tree.root());
    assert_eq!(node2, tree.get_node(NodeIndex::make(1, 0)).unwrap());
    assert_eq!(node3, tree.get_node(NodeIndex::make(1, 1)).unwrap());

    // check get_node()
    assert_eq!(VALUES4[0], tree.get_node(NodeIndex::make(2, 0)).unwrap());
    assert_eq!(VALUES4[1], tree.get_node(NodeIndex::make(2, 1)).unwrap());
    assert_eq!(VALUES4[2], tree.get_node(NodeIndex::make(2, 2)).unwrap());
    assert_eq!(VALUES4[3], tree.get_node(NodeIndex::make(2, 3)).unwrap());

    // check get_path(): depth 2
    assert_eq!(vec![VALUES4[1], node3], *tree.open(&LeafIndex::<2>::new(0).unwrap()).path);
    assert_eq!(vec![VALUES4[0], node3], *tree.open(&LeafIndex::<2>::new(1).unwrap()).path);
    assert_eq!(vec![VALUES4[3], node2], *tree.open(&LeafIndex::<2>::new(2).unwrap()).path);
    assert_eq!(vec![VALUES4[2], node2], *tree.open(&LeafIndex::<2>::new(3).unwrap()).path);
}

#[test]
fn test_inner_node_iterator() -> Result<(), MerkleError> {
    let tree =
        SimpleSmt::<2>::with_leaves(KEYS4.into_iter().zip(digests_to_words(&VALUES4))).unwrap();

    // check depth 2
    assert_eq!(VALUES4[0], tree.get_node(NodeIndex::make(2, 0)).unwrap());
    assert_eq!(VALUES4[1], tree.get_node(NodeIndex::make(2, 1)).unwrap());
    assert_eq!(VALUES4[2], tree.get_node(NodeIndex::make(2, 2)).unwrap());
    assert_eq!(VALUES4[3], tree.get_node(NodeIndex::make(2, 3)).unwrap());

    // get parent nodes
    let root = tree.root();
    let l1n0 = tree.get_node(NodeIndex::make(1, 0))?;
    let l1n1 = tree.get_node(NodeIndex::make(1, 1))?;
    let l2n0 = tree.get_node(NodeIndex::make(2, 0))?;
    let l2n1 = tree.get_node(NodeIndex::make(2, 1))?;
    let l2n2 = tree.get_node(NodeIndex::make(2, 2))?;
    let l2n3 = tree.get_node(NodeIndex::make(2, 3))?;

    let nodes: Vec<InnerNodeInfo> = tree.inner_nodes().collect();
    let expected = vec![
        InnerNodeInfo { value: root, left: l1n0, right: l1n1 },
        InnerNodeInfo { value: l1n0, left: l2n0, right: l2n1 },
        InnerNodeInfo { value: l1n1, left: l2n2, right: l2n3 },
    ];
    assert_eq!(nodes, expected);

    Ok(())
}

#[test]
fn test_insert() {
    const DEPTH: u8 = 3;
    let mut tree =
        SimpleSmt::<DEPTH>::with_leaves(KEYS8.into_iter().zip(digests_to_words(&VALUES8))).unwrap();
    assert_eq!(tree.num_leaves(), 8);

    // update one value
    let key = 3;
    let new_node = int_to_leaf(9);
    let mut expected_values = digests_to_words(&VALUES8);
    expected_values[key] = new_node;
    let expected_tree = MerkleTree::new(expected_values.clone()).unwrap();

    let old_leaf = tree.insert(LeafIndex::<DEPTH>::new(key as u64).unwrap(), new_node);
    assert_eq!(expected_tree.root(), tree.root);
    assert_eq!(old_leaf, *VALUES8[key]);
    assert_eq!(tree.num_leaves(), 8);

    // update another value
    let key = 6;
    let new_node = int_to_leaf(10);
    expected_values[key] = new_node;
    let expected_tree = MerkleTree::new(expected_values.clone()).unwrap();

    let old_leaf = tree.insert(LeafIndex::<DEPTH>::new(key as u64).unwrap(), new_node);
    assert_eq!(expected_tree.root(), tree.root);
    assert_eq!(old_leaf, *VALUES8[key]);
    assert_eq!(tree.num_leaves(), 8);

    // set a leaf to empty value
    let key = 5;
    let new_node = EMPTY_WORD;
    expected_values[key] = new_node;
    let expected_tree = MerkleTree::new(expected_values.clone()).unwrap();

    let old_leaf = tree.insert(LeafIndex::<DEPTH>::new(key as u64).unwrap(), new_node);
    assert_eq!(expected_tree.root(), tree.root);
    assert_eq!(old_leaf, *VALUES8[key]);
    assert_eq!(tree.num_leaves(), 7);
}

#[test]
fn small_tree_opening_is_consistent() {
    //        ____k____
    //       /         \
    //     _i_         _j_
    //    /   \       /   \
    //   e     f     g     h
    //  / \   / \   / \   / \
    // a   b 0   0 c   0 0   d

    let z = EMPTY_WORD;

    let a = Word::from(Rpo256::merge(&[z.into(); 2]));
    let b = Word::from(Rpo256::merge(&[a.into(); 2]));
    let c = Word::from(Rpo256::merge(&[b.into(); 2]));
    let d = Word::from(Rpo256::merge(&[c.into(); 2]));

    let e = Rpo256::merge(&[a.into(), b.into()]);
    let f = Rpo256::merge(&[z.into(), z.into()]);
    let g = Rpo256::merge(&[c.into(), z.into()]);
    let h = Rpo256::merge(&[z.into(), d.into()]);

    let i = Rpo256::merge(&[e, f]);
    let j = Rpo256::merge(&[g, h]);

    let k = Rpo256::merge(&[i, j]);

    let entries = vec![(0, a), (1, b), (4, c), (7, d)];
    let tree = SimpleSmt::<3>::with_leaves(entries).unwrap();

    assert_eq!(tree.root(), k);

    let cases: Vec<(u64, Vec<RpoDigest>)> = vec![
        (0, vec![b.into(), f, j]),
        (1, vec![a.into(), f, j]),
        (4, vec![z.into(), h, i]),
        (7, vec![z.into(), g, i]),
    ];

    for (key, path) in cases {
        let opening = tree.open(&LeafIndex::<3>::new(key).unwrap());

        assert_eq!(path, *opening.path);
    }
}

#[test]
fn test_simplesmt_fail_on_duplicates() {
    let values = [
        // same key, same value
        (int_to_leaf(1), int_to_leaf(1)),
        // same key, different values
        (int_to_leaf(1), int_to_leaf(2)),
        // same key, set to zero
        (EMPTY_WORD, int_to_leaf(1)),
        // same key, re-set to zero
        (int_to_leaf(1), EMPTY_WORD),
        // same key, set to zero twice
        (EMPTY_WORD, EMPTY_WORD),
    ];

    for (first, second) in values.iter() {
        // consecutive
        let entries = [(1, *first), (1, *second)];
        let smt = SimpleSmt::<64>::with_leaves(entries);
        assert_eq!(smt.unwrap_err(), MerkleError::DuplicateValuesForIndex(1));

        // not consecutive
        let entries = [(1, *first), (5, int_to_leaf(5)), (1, *second)];
        let smt = SimpleSmt::<64>::with_leaves(entries);
        assert_eq!(smt.unwrap_err(), MerkleError::DuplicateValuesForIndex(1));
    }
}

#[test]
fn with_no_duplicates_empty_node() {
    let entries = [(1_u64, int_to_leaf(0)), (5, int_to_leaf(2))];
    let smt = SimpleSmt::<64>::with_leaves(entries);
    assert!(smt.is_ok());
}

#[test]
fn test_simplesmt_with_leaves_nonexisting_leaf() {
    // TESTING WITH EMPTY WORD
    // --------------------------------------------------------------------------------------------

    // Depth 1 has 2 leaf. Position is 0-indexed, position 2 doesn't exist.
    let leaves = [(2, EMPTY_WORD)];
    let result = SimpleSmt::<1>::with_leaves(leaves);
    assert!(result.is_err());

    // Depth 2 has 4 leaves. Position is 0-indexed, position 4 doesn't exist.
    let leaves = [(4, EMPTY_WORD)];
    let result = SimpleSmt::<2>::with_leaves(leaves);
    assert!(result.is_err());

    // Depth 3 has 8 leaves. Position is 0-indexed, position 8 doesn't exist.
    let leaves = [(8, EMPTY_WORD)];
    let result = SimpleSmt::<3>::with_leaves(leaves);
    assert!(result.is_err());

    // TESTING WITH A VALUE
    // --------------------------------------------------------------------------------------------
    let value = int_to_node(1);

    // Depth 1 has 2 leaves. Position is 0-indexed, position 2 doesn't exist.
    let leaves = [(2, *value)];
    let result = SimpleSmt::<1>::with_leaves(leaves);
    assert!(result.is_err());

    // Depth 2 has 4 leaves. Position is 0-indexed, position 4 doesn't exist.
    let leaves = [(4, *value)];
    let result = SimpleSmt::<2>::with_leaves(leaves);
    assert!(result.is_err());

    // Depth 3 has 8 leaves. Position is 0-indexed, position 8 doesn't exist.
    let leaves = [(8, *value)];
    let result = SimpleSmt::<3>::with_leaves(leaves);
    assert!(result.is_err());
}

#[test]
fn test_simplesmt_set_subtree() {
    // Final Tree:
    //
    //        ____k____
    //       /         \
    //     _i_         _j_
    //    /   \       /   \
    //   e     f     g     h
    //  / \   / \   / \   / \
    // a   b 0   0 c   0 0   d

    let z = EMPTY_WORD;

    let a = Word::from(Rpo256::merge(&[z.into(); 2]));
    let b = Word::from(Rpo256::merge(&[a.into(); 2]));
    let c = Word::from(Rpo256::merge(&[b.into(); 2]));
    let d = Word::from(Rpo256::merge(&[c.into(); 2]));

    let e = Rpo256::merge(&[a.into(), b.into()]);
    let f = Rpo256::merge(&[z.into(), z.into()]);
    let g = Rpo256::merge(&[c.into(), z.into()]);
    let h = Rpo256::merge(&[z.into(), d.into()]);

    let i = Rpo256::merge(&[e, f]);
    let j = Rpo256::merge(&[g, h]);

    let k = Rpo256::merge(&[i, j]);

    // subtree:
    //   g
    //  / \
    // c   0
    let subtree = {
        let entries = vec![(0, c)];
        SimpleSmt::<1>::with_leaves(entries).unwrap()
    };

    // insert subtree
    const TREE_DEPTH: u8 = 3;
    let tree = {
        let entries = vec![(0, a), (1, b), (7, d)];
        let mut tree = SimpleSmt::<TREE_DEPTH>::with_leaves(entries).unwrap();

        tree.set_subtree(2, subtree).unwrap();

        tree
    };

    assert_eq!(tree.root(), k);
    assert_eq!(tree.get_leaf(&LeafIndex::<TREE_DEPTH>::new(4).unwrap()), c);
    assert_eq!(tree.get_inner_node(NodeIndex::new_unchecked(2, 2)).hash(), g);
}

/// Ensures that an invalid input node index into `set_subtree()` incurs no mutation of the tree
#[test]
fn test_simplesmt_set_subtree_unchanged_for_wrong_index() {
    // Final Tree:
    //
    //        ____k____
    //       /         \
    //     _i_         _j_
    //    /   \       /   \
    //   e     f     g     h
    //  / \   / \   / \   / \
    // a   b 0   0 c   0 0   d

    let z = EMPTY_WORD;

    let a = Word::from(Rpo256::merge(&[z.into(); 2]));
    let b = Word::from(Rpo256::merge(&[a.into(); 2]));
    let c = Word::from(Rpo256::merge(&[b.into(); 2]));
    let d = Word::from(Rpo256::merge(&[c.into(); 2]));

    // subtree:
    //   g
    //  / \
    // c   0
    let subtree = {
        let entries = vec![(0, c)];
        SimpleSmt::<1>::with_leaves(entries).unwrap()
    };

    let mut tree = {
        let entries = vec![(0, a), (1, b), (7, d)];
        SimpleSmt::<3>::with_leaves(entries).unwrap()
    };
    let tree_root_before_insertion = tree.root();

    // insert subtree
    assert!(tree.set_subtree(500, subtree).is_err());

    assert_eq!(tree.root(), tree_root_before_insertion);
}

/// We insert an empty subtree that has the same depth as the original tree
#[test]
fn test_simplesmt_set_subtree_entire_tree() {
    // Initial Tree:
    //
    //        ____k____
    //       /         \
    //     _i_         _j_
    //    /   \       /   \
    //   e     f     g     h
    //  / \   / \   / \   / \
    // a   b 0   0 c   0 0   d

    let z = EMPTY_WORD;

    let a = Word::from(Rpo256::merge(&[z.into(); 2]));
    let b = Word::from(Rpo256::merge(&[a.into(); 2]));
    let c = Word::from(Rpo256::merge(&[b.into(); 2]));
    let d = Word::from(Rpo256::merge(&[c.into(); 2]));

    // subtree: E3
    const DEPTH: u8 = 3;
    let subtree = { SimpleSmt::<DEPTH>::with_leaves(Vec::new()).unwrap() };
    assert_eq!(subtree.root(), *EmptySubtreeRoots::entry(DEPTH, 0));

    // insert subtree
    let mut tree = {
        let entries = vec![(0, a), (1, b), (4, c), (7, d)];
        SimpleSmt::<3>::with_leaves(entries).unwrap()
    };

    tree.set_subtree(0, subtree).unwrap();

    assert_eq!(tree.root(), *EmptySubtreeRoots::entry(DEPTH, 0));
}

/// Tests that we can correctly calculate leaf hashes before actually inserting them.
#[test]
fn test_prospective_hash() {
    const DEPTH: u8 = 3;
    type SimpleSmt = super::SimpleSmt::<DEPTH>;
    const EMPTY: Word = SimpleSmt::EMPTY_VALUE;
    let mut smt = SimpleSmt::new().unwrap();

    let key = |num: u64| LeafIndex::<DEPTH>::new(num).unwrap();

    let key_1 = key(3);
    let value_1 = int_to_leaf(9);

    let key_2 = key(4);
    let value_2 = int_to_leaf(12);

    let key_3 = key(5);
    let value_3 = int_to_leaf(15);
    let value_3_2 = int_to_leaf(20);

    // Prospective hashes before insertion should be equal to actual hashes
    // after insertion.
    {
        // That includes inserting empty values on an empty tree.
        let prospective_empty = smt.hash_prospective_leaf(&key_1, &EMPTY);
        smt.insert(key_1, EMPTY);
        assert_eq!(SimpleSmt::hash_leaf(&smt.get_leaf(&key_1)), prospective_empty);

        let prospective = smt.hash_prospective_leaf(&key_1, &value_1);
        smt.insert(key_1, value_1);
        assert_eq!(SimpleSmt::hash_leaf(&smt.get_leaf(&key_1)), prospective);
    }

    {
        let prospective = smt.hash_prospective_leaf(&key_2, &value_2);
        smt.insert(key_2, value_2);
        assert_eq!(SimpleSmt::hash_leaf(&smt.get_leaf(&key_2)), prospective);
    }

    {
        let prospective = smt.hash_prospective_leaf(&key_3, &value_3);
        smt.insert(key_3, value_3);
        assert_eq!(SimpleSmt::hash_leaf(&smt.get_leaf(&key_3)), prospective);

        let prospective_multi = smt.hash_prospective_leaf(&key_3, &value_3_2);
        smt.insert(key_3, value_3_2);
        assert_eq!(SimpleSmt::hash_leaf(&smt.get_leaf(&key_3)), prospective_multi);
    }

    // Prospective hashes after removal should be equal to actual hashes
    // before removal, and prospective hashes *for* the removal should be
    // equal to actual hashes after the removal.
    {
        let prospective_empty = smt.hash_prospective_leaf(&key_3, &EMPTY);
        let old_hash = SimpleSmt::hash_leaf(&smt.get_leaf(&key_3));
        smt.insert(key_3, EMPTY);
        assert_eq!(old_hash, smt.hash_prospective_leaf(&key_3, &value_3_2));
        assert_eq!(SimpleSmt::hash_leaf(&smt.get_leaf(&key_3)), prospective_empty);

        let prospective_empty_2 = smt.hash_prospective_leaf(&key_3, &EMPTY);
        let old_hash_2 = SimpleSmt::hash_leaf(&smt.get_leaf(&key_3));
        assert_ne!(old_hash, old_hash_2);
        assert_eq!(SimpleSmt::hash_leaf(&smt.get_leaf(&key_3)), prospective_empty_2);
        smt.insert(key_3, EMPTY);
        assert_eq!(old_hash_2, smt.hash_prospective_leaf(&key_3, &EMPTY));
    }

    {
        let prospective_empty = smt.hash_prospective_leaf(&key_2, &EMPTY);
        let old_hash = SimpleSmt::hash_leaf(&smt.get_leaf(&key_2));
        smt.insert(key_2, EMPTY);
        assert_eq!(old_hash, smt.hash_prospective_leaf(&key_2, &value_2));
        assert_eq!(SimpleSmt::hash_leaf(&smt.get_leaf(&key_2)), prospective_empty);
    }

    {
        let prospective_empty = smt.hash_prospective_leaf(&key_1, &EMPTY);
        let old_hash = SimpleSmt::hash_leaf(&smt.get_leaf(&key_1));
        smt.insert(key_1, EMPTY);
        assert_eq!(old_hash, smt.hash_prospective_leaf(&key_1, &value_1));
        assert_eq!(SimpleSmt::hash_leaf(&smt.get_leaf(&key_1)), prospective_empty);
    }
}

// HELPER FUNCTIONS
// --------------------------------------------------------------------------------------------

fn compute_internal_nodes() -> (RpoDigest, RpoDigest, RpoDigest) {
    let node2 = Rpo256::merge(&[VALUES4[0], VALUES4[1]]);
    let node3 = Rpo256::merge(&[VALUES4[2], VALUES4[3]]);
    let root = Rpo256::merge(&[node2, node3]);

    (root, node2, node3)
}
