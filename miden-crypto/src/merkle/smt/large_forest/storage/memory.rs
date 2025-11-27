//! This module contains an in-memory storage layer for the large SMT forest.
//!
//! This storage layer offers no persistence, but allows the forest to be used even in scenarios
//! where persistent storage is used. It operates purely in-memory and offers no atomicity.
//!
//! TODO Performance details

pub struct MemoryStorage {}
