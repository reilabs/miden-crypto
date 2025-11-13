mod insertion;
mod mutations;

// The public API methods (insert_batch, compute_mutations, apply_mutations, etc.)
// are implemented in the insertion.rs and mutations.rs modules via impl blocks
// for LargeSmt<S>, so they're automatically available.
