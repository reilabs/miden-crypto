//! This module contains the error types and helpers for working with errors from the large SMT
//! forest.

use thiserror::Error;

use crate::merkle::{smt::large_forest::storage, MerkleError};

/// The type of errors returned by operations on the large SMT forest.
#[derive(Debug, Error)]
pub enum LargeSmtForestError {
    #[error(transparent)]
    HistoryError(#[from] history::HistoryError),

    #[error(transparent)]
    MerkleError(#[from] MerkleError),

    #[error(transparent)]
    StorageError(#[from] storage::StorageError),
}

/// The result type for use within the large SMT forest portion of the library.
pub type Result<T> = std::result::Result<T, LargeSmtForestError>;

pub mod history {
    use thiserror::Error;

    use crate::Word;

    /// The type of errors returned by the history subsystem of the large SMT forest.
    #[derive(Debug, Error, PartialEq)]
    pub enum HistoryError {
        #[error("The root {0} had no corresponding history version")]
        NoSuchVersion(Word),

        #[error("The history contains no deltas")]
        NothingToRemove,
    }

    /// The result type for use within the history subsystem of the large SMT forest.
    pub type Result<T> = std::result::Result<T, HistoryError>;
}
