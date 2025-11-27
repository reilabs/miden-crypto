//! This module contains the error types and helpers for working with errors from the large SMT
//! forest.

use thiserror::Error;

/// The type of errors returned by operations on the large SMT forest.
#[derive(Debug, Error)]
pub enum StorageError {}

/// The result type for use within the large SMT forest portion of the library.
#[allow(dead_code)] // TODO temporary
pub type Result<T> = std::result::Result<T, StorageError>;
