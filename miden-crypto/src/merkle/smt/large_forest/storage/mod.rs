//! This module contains the definition of [`Storage`], the backing data store for use in the
//! large SMT forest.
//!
//! It is intended to allow the forest itself to be storage agnostic, and provides the minimum set
//! of operations for interacting with the storage backend. Very little logic should reside in the
//! storage itself; in other words, it should mostly act as a **dumb container** for data with the
//! necessary shape.
//!
//! # Performance
//!
//! Having an arbitrary `S: Storage` does not give you any performance guarantees about the forest
//! itself. To that end, reasoning about performance should always be done in the context of a
//! concrete instance of the forest storage.

use core::fmt::Debug;

pub mod error;
pub mod memory;
#[cfg(feature = "rocksdb")]
pub mod rocksdb;

pub use error::{Result, StorageError};
pub use memory::MemoryStorage;
#[cfg(feature = "rocksdb")]
pub use rocksdb::RocksDBStorage;

/// The backing storage for the large SMT forest, providing the necessary methods for reading
/// from and writing to a variety of storage types while allowing the tree itself to be storage
/// agnostic.
///
/// ## Object Safety
///
/// Note that this trait is not intended to be object safe. Being able to construct a type using
/// `dyn Storage` is rife with performance pitfalls, and is explicitly disallowed as a result.
pub trait Storage
where
    Self: Debug,
{
    /// This type
    type View;
}
