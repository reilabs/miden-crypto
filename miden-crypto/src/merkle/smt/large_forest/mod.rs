//! A high-performance sparse merkle tree forest backed by pluggable storage.
//!
//! TODO A description of the basics of it incl. enabling persistence, and overlays.
//! TODO A description of the assumptions.
//! TODO Examples of usage (open, create new, apply updates, quit init, in-memory vs rocksdb), see
//!      LargeSMT.
//! TODO Memory usage/residency
//! TODO Performance concerns
//! TODO Usage guidelines

mod error;
mod history;
mod storage;

pub use error::{history::HistoryError, LargeSmtForestError, Result};
#[cfg(feature = "concurrent")]
pub use storage::MemoryStorage;
#[cfg(feature = "rocksdb")]
pub use storage::RocksDBStorage;
pub use storage::{Storage, StorageError};

/// The persistent sparse merkle tree, backed by the provided storage type `S`.
///
/// See the module documentation for detailed descriptions and usage guidelines.
#[allow(dead_code)] // TODO temporary
#[derive(Debug)]
pub struct LargeSmtForest<S: Storage> {
    storage: S,
}

/// These functions deal with the creation, loading, and storage of the forest.
impl<S: Storage> LargeSmtForest<S> {
    /// Creates a new instance of the forest that is in the default state and contains no leaves.
    pub fn new() -> Result<Self> {
        todo!("New")
    }
}

/// These functions deal with the manipulation of the forest, allowing the user to perform
/// operations on the data stored within.
impl<S: Storage> LargeSmtForest<S> {}
