//! This module contains the error types and helpers for working with errors from the large SMT
//! forest.

use thiserror::Error;

use crate::merkle::{
    MerkleError,
    smt::{history::error::HistoryError, large_forest::storage},
};

/// The type of errors returned by operations on the large SMT forest.
#[derive(Debug, Error)]
pub enum LargeSmtForestError {
    #[error(transparent)]
    HistoryError(#[from] HistoryError),

    #[error(transparent)]
    MerkleError(#[from] MerkleError),

    #[error(transparent)]
    StorageError(#[from] storage::StorageError),
}

/// The result type for use within the large SMT forest portion of the library.
#[allow(dead_code)] // Temporary: this is code being merged incrementally
pub type Result<T> = std::result::Result<T, LargeSmtForestError>;
