use assert_matches::assert_matches;

use super::{EmptySubtreeRoots, MerkleError, SmtForest, Word};
use crate::{
    Felt, Map, ONE, WORD_SIZE, ZERO,
    merkle::{int_to_node, smt::SMT_DEPTH},
};

// TESTS
// ================================================================================================

#[test]
fn test_insert_root_not_in_store() -> Result<(), MerkleError> {
    let mut forest = SmtForest::new();
    let word = Word::new([ONE; WORD_SIZE]);
    assert_matches!(
        forest.insert(word, word, word),
        Err(MerkleError::RootNotInStore(_)),
        "The forest is empty, so only empty root is valid"
    );

    Ok(())
}

#[test]
fn test_insert_root_empty() -> Result<(), MerkleError> {
    let mut forest = SmtForest::new();
    let empty_tree_root = *EmptySubtreeRoots::entry(SMT_DEPTH, 0);
    let key = Word::new([ZERO; WORD_SIZE]);
    let value = Word::new([ONE; WORD_SIZE]);
    assert_eq!(
        forest.insert(empty_tree_root, key, value)?,
        Word::new([
            Felt::new(10376354645124572258),
            Felt::new(13808228093617896354),
            Felt::new(4835829334388921262),
            Felt::new(2144113770050911180)
        ]),
    );
    Ok(())
}

#[test]
fn test_insert_multiple_values() -> Result<(), MerkleError> {
    let mut forest = SmtForest::new();

    let empty_tree_root = *EmptySubtreeRoots::entry(SMT_DEPTH, 0);
    let key = Word::new([ZERO; WORD_SIZE]);
    let value = Word::new([ONE; WORD_SIZE]);
    let new_root = forest.insert(empty_tree_root, key, value)?;
    assert_eq!(
        new_root,
        Word::new([
            Felt::new(10376354645124572258),
            Felt::new(13808228093617896354),
            Felt::new(4835829334388921262),
            Felt::new(2144113770050911180)
        ]),
    );

    let new_root = forest.insert(new_root, key, value)?;
    assert_eq!(
        new_root,
        Word::new([
            Felt::new(10376354645124572258),
            Felt::new(13808228093617896354),
            Felt::new(4835829334388921262),
            Felt::new(2144113770050911180)
        ]),
    );

    let key2 = Word::new([ZERO, ONE, ZERO, ONE]);
    let new_root = forest.insert(new_root, key2, value)?;
    assert_eq!(
        new_root,
        Word::new([
            Felt::new(1600265794710932756),
            Felt::new(4102884415474859847),
            Felt::new(7916203901318401823),
            Felt::new(9187865964280213047)
        ])
    );

    Ok(())
}

#[test]
fn test_batch_insert() -> Result<(), MerkleError> {
    let mut forest = SmtForest::new();

    let empty_tree_root = *EmptySubtreeRoots::entry(SMT_DEPTH, 0);

    let values = Map::<Word, Word>::from_iter([
        (Word::new([ZERO; WORD_SIZE]), Word::new([ONE; WORD_SIZE])),
        (Word::new([ZERO; WORD_SIZE]), Word::new([ONE; WORD_SIZE])),
        (Word::new([ZERO, ONE, ZERO, ONE]), Word::new([ONE; WORD_SIZE])),
    ]);

    let new_root = forest.batch_insert(empty_tree_root, &values)?;
    assert_eq!(
        new_root,
        Word::new([
            Felt::new(1600265794710932756),
            Felt::new(4102884415474859847),
            Felt::new(7916203901318401823),
            Felt::new(9187865964280213047)
        ])
    );

    Ok(())
}

#[test]
fn test_open_root_not_in_store() -> Result<(), MerkleError> {
    let forest = SmtForest::new();
    let word = Word::new([ONE; WORD_SIZE]);
    assert_matches!(
        forest.open(word, word),
        Err(MerkleError::RootNotInStore(_)),
        "The forest is empty, so only empty root is valid"
    );

    Ok(())
}

#[test]
fn test_open_root_in_store() -> Result<(), MerkleError> {
    let mut forest = SmtForest::new();

    let root = *EmptySubtreeRoots::entry(SMT_DEPTH, 0);
    let root = forest.insert(
        root,
        Word::new([Felt::new(0), Felt::new(0), Felt::new(0), Felt::new(0)]),
        int_to_node(1),
    )?;
    let root = forest.insert(
        root,
        Word::new([Felt::new(0), Felt::new(0), Felt::new(0), Felt::new(1)]),
        int_to_node(2),
    )?;
    let root = forest.insert(
        root,
        Word::new([Felt::new(0), Felt::new(0), Felt::new(0), Felt::new(2)]),
        int_to_node(3),
    )?;

    let proof =
        forest.open(root, Word::new([Felt::new(0), Felt::new(0), Felt::new(0), Felt::new(2)]))?;
    assert_eq!(
        proof.verify_membership(
            &Word::new([Felt::new(0), Felt::new(0), Felt::new(0), Felt::new(2)]),
            &int_to_node(3),
            &root
        ),
        true
    );

    Ok(())
}
