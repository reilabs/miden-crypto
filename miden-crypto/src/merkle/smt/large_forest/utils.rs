//! This module contains a variety of useful functions and type aliases that do not really have any
//! other place to live.

use core::num::NonZeroU8;

/// The number of levels in a tree.
///
/// Any instance of this type should see that the following properties hold:
///
/// - The root is a level of its own. This is level 0, to follow the convention used by
///   [`crate::merkle::smt::NodeIndex`]. This means that if the level count begins at the top of the
///   tree, it should include the root level. By way of example, a tree with 8 leaves has _4_ levels
///   in this counting.
/// - You cannot have a zero number of levels, which is enforced by construction.
pub type NumLevels = NonZeroU8;
