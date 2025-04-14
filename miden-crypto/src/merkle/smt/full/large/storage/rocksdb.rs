use alloc::string::ToString;
use alloc::vec::Vec;
use rayon::prelude::*;
use super::{SmtStorage, StorageError, StorageUpdates};
use crate::merkle::{InnerNode, NodeIndex, RpoDigest, SmtLeaf};
use crate::merkle::smt::full::large::{subtree::Subtree, IN_MEMORY_DEPTH};
use crate::merkle::smt::UnorderedMap;
use rocksdb::{BlockBasedOptions, Cache, ColumnFamilyDescriptor, DB, DBCompressionType, Options, WriteBatch};
use std::path::PathBuf;
use std::sync::Arc;
use winter_utils::{Deserializable, Serializable};

const LEAVES_CF: &str = "leaves";
const SUBTREES_CF: &str = "subtrees";
const UPPER_NODES_CF: &str = "upper_nodes";
const METADATA_CF: &str = "metadata";

const ROOT_KEY: &[u8] = b"smt_root";
const LEAF_COUNT_KEY: &[u8] = b"leaf_count";
const ENTRY_COUNT_KEY: &[u8] = b"entry_count";


#[derive(Debug, Clone)]
pub struct RocksDbStorage {
    db: Arc<DB>,
}

impl RocksDbStorage {
    pub fn open(path: &PathBuf) -> Result<Self, StorageError> {
        let mut db_opts = Options::default();
        db_opts.create_if_missing(true);
        db_opts.create_missing_column_families(true);
        db_opts.increase_parallelism(rayon::current_num_threads() as i32);
        db_opts.set_max_open_files(512);

        let cache = Cache::new_lru_cache(1024 * 1024 * 1024);

        let mut leaves_table_opts = BlockBasedOptions::default();
        leaves_table_opts.set_block_cache(&cache);
        let mut leaves_opts = Options::default();
        leaves_opts.set_block_based_table_factory(&leaves_table_opts);
        //leaves_opts.set_compression_type(DBCompressionType::Lz4);

        let mut subtrees_table_opts = BlockBasedOptions::default();
        subtrees_table_opts.set_block_cache(&cache);
        let mut subtrees_opts = Options::default();
        subtrees_opts.set_block_based_table_factory(&subtrees_table_opts);
        //subtrees_opts.set_compression_type(DBCompressionType::Lz4);

        let mut upper_nodes_table_opts = BlockBasedOptions::default();
        upper_nodes_table_opts.set_block_cache(&cache);
        let mut upper_nodes_opts = Options::default();
        upper_nodes_opts.set_block_based_table_factory(&upper_nodes_table_opts);
        //upper_nodes_opts.set_compression_type(DBCompressionType::Lz4);

        let metadata_table_opts = BlockBasedOptions::default();
        let mut metadata_opts = Options::default();
        metadata_opts.set_block_based_table_factory(&metadata_table_opts);
        metadata_opts.set_compression_type(DBCompressionType::None);

        let cfs = vec![
            ColumnFamilyDescriptor::new(LEAVES_CF, leaves_opts),
            ColumnFamilyDescriptor::new(SUBTREES_CF, subtrees_opts),
            ColumnFamilyDescriptor::new(UPPER_NODES_CF, upper_nodes_opts),
            ColumnFamilyDescriptor::new(METADATA_CF, metadata_opts),
        ];

        let db = DB::open_cf_descriptors(&db_opts, &path, cfs)
            .map_err(|e| StorageError::BackendError(format!("Failed to open DB: {}", e)))?;

        Ok(Self { db: Arc::new(db) })
    }

    #[inline(always)]
    fn leaf_db_key(index: u64) -> [u8; 8] { index.to_be_bytes() }

    #[inline(always)]
    fn subtree_db_key(index: NodeIndex) -> [u8; 9] { Subtree::subtree_key(index) }

    #[inline(always)]
    fn upper_node_db_key(index: NodeIndex) -> [u8; 9] {
        let mut key = [0u8; 9];
        key[0] = index.depth();
        key[1..].copy_from_slice(&index.value().to_be_bytes());
        key
    }

    fn cf_handle(&self, name: &str) -> Result<&rocksdb::ColumnFamily, StorageError> {
        self.db.cf_handle(name).ok_or_else(|| StorageError::BackendError(format!("CF '{}' missing", name)))
    }
}

impl SmtStorage for RocksDbStorage {
    fn get_root(&self) -> Result<Option<RpoDigest>, StorageError> {
        let cf = self.cf_handle(METADATA_CF)?;
        match self.db.get_cf(cf, ROOT_KEY).map_err(|e| StorageError::BackendError(e.to_string()))? {
            Some(bytes) => {
                let digest = RpoDigest::read_from_bytes(&bytes)
                    .map_err(|e| StorageError::DeserializationError(e.to_string()))?;
                Ok(Some(digest))
            }
            None => Ok(None),
        }
    }

    fn get_leaf_count(&self) -> Result<usize, StorageError> {
        let cf = self.cf_handle(METADATA_CF)?;
        match self.db.get_cf(cf, LEAF_COUNT_KEY).map_err(|e| StorageError::BackendError(e.to_string()))? {
            Some(bytes) => {
                if bytes.len() == 8 {
                    Ok(usize::from_be_bytes(bytes.try_into().unwrap()))
                } else {
                    Err(StorageError::DeserializationError("Invalid byte length for leaf count".to_string()))
                }
            }
            None => Ok(0),
        }
    }

    fn get_entry_count(&self) -> Result<usize, StorageError> {
         let cf = self.cf_handle(METADATA_CF)?;
         match self.db.get_cf(cf, ENTRY_COUNT_KEY).map_err(|e| StorageError::BackendError(e.to_string()))? {
             Some(bytes) => {
                 if bytes.len() == 8 {
                     Ok(usize::from_be_bytes(bytes.try_into().unwrap()))
                 } else {
                     Err(StorageError::DeserializationError("Invalid byte length for entry count".to_string()))
                 }
             }
             None => Ok(0),
         }
    }

    fn get_leaf(&self, index: u64) -> Result<Option<SmtLeaf>, StorageError> {
        let cf = self.cf_handle(LEAVES_CF)?;
        let key = Self::leaf_db_key(index);
        match self.db.get_cf(cf, &key).map_err(|e| StorageError::BackendError(e.to_string()))? {
            Some(bytes) => {
                 let leaf = SmtLeaf::read_from_bytes(&bytes)
                      .map_err(|e| StorageError::DeserializationError(e.to_string()))?;
                  Ok(Some(leaf))
             },
             None => Ok(None),
         }
    }

    fn set_leaf(&self, index: u64, leaf: &SmtLeaf) -> Result<Option<SmtLeaf>, StorageError> {
        let cf = self.cf_handle(LEAVES_CF)?;
        let key = Self::leaf_db_key(index);
        let old_bytes = self.db.get_cf(cf, &key).ok().flatten();
        let value = leaf.to_bytes();
        self.db
            .put_cf(cf, &key, &value)
            .map_err(|e| StorageError::BackendError(e.to_string()))?;
        Ok(old_bytes
            .map(|bytes| SmtLeaf::read_from_bytes(&bytes).expect("failed to deserialize leaf")))
    }

    fn set_leaves(&self, leaves: UnorderedMap<u64, SmtLeaf>) -> Result<(), StorageError> {
        let cf = self.cf_handle(LEAVES_CF)?;
        let mut batch = WriteBatch::default();
        for (idx, leaf) in leaves {
            let key = Self::leaf_db_key(idx);
            let value = leaf.to_bytes();
            batch.put_cf(cf, &key, &value);
        }
        self.db.write(batch).map_err(|e| StorageError::BackendError(e.to_string()))?;
        Ok(())
    }

    fn remove_leaf(&self, index: u64) -> Result<Option<SmtLeaf>, StorageError> {
        let key = Self::leaf_db_key(index);
        let cf = self.cf_handle(LEAVES_CF)?;
        let old_bytes = self.db.get_cf(cf, &key).ok().flatten();
        self.db.delete_cf(cf, &key).map_err(|e| StorageError::BackendError(e.to_string()))?;
        Ok(old_bytes.map(|bytes| SmtLeaf::read_from_bytes(&bytes).expect("failed to deserialize leaf")))
    }

    fn get_leaves(&self, indices: &[u64]) -> Result<Vec<Option<SmtLeaf>>, StorageError> {
        let cf = self.cf_handle(LEAVES_CF)?;
        let db_keys: Vec<[u8; 8]> = indices.iter().map(|&idx| Self::leaf_db_key(idx)).collect();
        let results = self.db.multi_get_cf(db_keys.iter().map(|k| (cf, k.as_ref())));

        results.into_iter().map(|result| {
            match result {
                Ok(Some(bytes)) => SmtLeaf::read_from_bytes(&bytes)
                                    .map(Some)
                                    .map_err(|e| StorageError::DeserializationError(e.to_string())),
                Ok(None) => Ok(None),
                Err(e) => Err(StorageError::BackendError(e.to_string())),
            }
        }).collect()
    }

    fn get_subtree(&self, index: NodeIndex) -> Result<Option<Subtree>, StorageError> {
        let cf = self.cf_handle(SUBTREES_CF)?;
        let key = Self::subtree_db_key(index);
         match self.db.get_cf(cf, &key).map_err(|e| StorageError::BackendError(e.to_string()))? {
             Some(bytes) => {
                  let subtree = Subtree::from_vec(index, &bytes)
                       .map_err(|e| StorageError::DeserializationError(e.to_string()))?;
                   Ok(Some(subtree))
              },
              None => Ok(None),
          }
    }

    fn get_subtrees(&self, indices: &[NodeIndex]) -> Result<Vec<Option<Subtree>>, StorageError> {
        let cf = self.cf_handle(SUBTREES_CF)?;
        let db_keys: Vec<[u8; 9]> = indices.iter().map(|&idx| Self::subtree_db_key(idx)).collect();
        let results = self.db.multi_get_cf(db_keys.iter().map(|k| (cf, k)));

        results.into_iter().zip(indices).map(|(result, index)| {
            match result {
                Ok(Some(bytes)) => {
                    Subtree::from_vec(*index, &bytes)
                        .map(Some)
                        .map_err(|e| StorageError::DeserializationError(e.to_string()))
                },
                Ok(None) => Ok(None),
                Err(e) => Err(StorageError::BackendError(e.to_string())),
            }
        }).collect()
    }

    fn set_subtree(&self, subtree: &Subtree) -> Result<(), StorageError> {
        let cf = self.cf_handle(SUBTREES_CF)?;
        let key = Self::subtree_db_key(subtree.root_index);
        self.db.put_cf(cf, &key, subtree.to_vec()).map_err(|e| StorageError::BackendError(e.to_string()))?;
        Ok(())
    }

    fn set_subtrees(&self, subtrees: Vec<Subtree>) -> Result<(), StorageError> {
        let cf = self.cf_handle(SUBTREES_CF)?;
        let mut batch = WriteBatch::default();
        let serialized: Vec<([u8; 9], Vec<u8>)> = subtrees
        .into_par_iter()
        .map(|subtree| {
            let key = Self::subtree_db_key(subtree.root_index);
            let value = subtree.to_vec();
            (key, value)
        })
        .collect();
        for (key, value) in serialized {
            batch.put_cf(cf, &key, value);
        }
        self.db.write(batch).map_err(|e| StorageError::BackendError(e.to_string()))?;
        Ok(())
    }

    fn remove_subtree(&self, index: NodeIndex) -> Result<(), StorageError> {
        let cf = self.cf_handle(SUBTREES_CF)?;
        let key = Self::subtree_db_key(index);
        self.db.delete_cf(cf, &key).map_err(|e| StorageError::BackendError(e.to_string()))?;
        Ok(())
    }

    fn get_inner_node(&self, index: NodeIndex) -> Result<Option<InnerNode>, StorageError> {
        if index.depth() <= IN_MEMORY_DEPTH {
            let cf = self.cf_handle(UPPER_NODES_CF)?;
            let key = Self::upper_node_db_key(index);
            match self.db.get_cf(cf, &key).map_err(|e| StorageError::BackendError(e.to_string()))? {
                Some(bytes) => {
                    let node = InnerNode::read_from_bytes(&bytes)
                        .map_err(|e| StorageError::DeserializationError(e.to_string()))?;
                    return Ok(Some(node));
                },
                None => return Ok(None),
            }
        }
        let subtree_root_index = Subtree::find_subtree_root(index);
        let subtree = self.get_subtree(subtree_root_index).expect("failed to get subtree");
        if let Some(subtree) = subtree {
            Ok(subtree.get_inner_node(index))
        } else {
            Ok(None)
        }
    }   

    fn get_upper_nodes(&self, indices: &[NodeIndex]) -> Result<Vec<Option<InnerNode>>, StorageError> {
        let cf = self.cf_handle(UPPER_NODES_CF)?;
        let db_keys: Vec<[u8; 9]> = indices.iter().map(|&idx| Self::upper_node_db_key(idx)).collect();
        let results = self.db.multi_get_cf(db_keys.iter().map(|k| (cf, k)));
        results.into_iter().map(|result| {
            match result {
                Ok(Some(bytes)) => InnerNode::read_from_bytes(&bytes)
                                    .map(Some)
                                    .map_err(|e| StorageError::DeserializationError(e.to_string())),
                Ok(None) => Ok(None),
                Err(e) => Err(StorageError::BackendError(e.into_string())),
            }
        }).collect()
    }

    fn set_inner_node(&self, index: NodeIndex, node: InnerNode) -> Result<Option<InnerNode>, StorageError> {
        if index.depth() <= IN_MEMORY_DEPTH {
            let cf = self.cf_handle(UPPER_NODES_CF)?;
            let key = Self::upper_node_db_key(index);
            let old_bytes = self.db.get_cf(cf, &key).ok().flatten();
            let value = node.to_bytes();
            self.db
                .put_cf(cf, &key, &value)
                .map_err(|e| StorageError::BackendError(e.to_string()))?;
            Ok(old_bytes.map(|bytes| {
                InnerNode::read_from_bytes(&bytes).expect("failed to deserialize inner node")
            }))
        } else {
            let subtree_root_index = Subtree::find_subtree_root(index);
            let mut subtree = self
                .get_subtree(subtree_root_index)?
                .unwrap_or_else(|| Subtree::new(subtree_root_index));
            let old_node = subtree.insert_inner_node(index, node);
            self.set_subtree(&subtree)?;
            Ok(old_node)
        }
    }

    fn remove_inner_node(&self, index: NodeIndex) -> Result<Option<InnerNode>, StorageError> {
        if index.depth() <= IN_MEMORY_DEPTH {
            let cf = self.cf_handle(UPPER_NODES_CF)?;
            let key = Self::upper_node_db_key(index);
            let old_bytes = self.db.get_cf(cf, &key).ok().flatten();
            self.db
                .delete_cf(cf, &key)
                .map_err(|e| StorageError::BackendError(e.to_string()))?;
            Ok(old_bytes.map(|bytes| {
                InnerNode::read_from_bytes(&bytes).expect("failed to deserialize inner node")
            }))
        } else {
            let subtree_root_index = Subtree::find_subtree_root(index);
            if let Some(mut subtree) = self.get_subtree(subtree_root_index)? {
                let old_node = subtree.remove_inner_node(index);
                if subtree.is_empty() {
                    self.remove_subtree(subtree_root_index)?;
                } else {
                    self.set_subtree(&subtree)?;
                }
                Ok(old_node)
            } else {
                // Subtree not found, so the node within it is also not found.
                Ok(None)
            }
        }
    }

    fn apply_batch(&self, updates: StorageUpdates) -> Result<(), StorageError> {
        let mut batch = WriteBatch::default();

        let leaves_cf = self.cf_handle(LEAVES_CF)?;
        let subtrees_cf = self.cf_handle(SUBTREES_CF)?;
        let upper_nodes_cf = self.cf_handle(UPPER_NODES_CF)?;
        let metadata_cf = self.cf_handle(METADATA_CF)?;

        for (index, maybe_leaf) in updates.leaf_updates {
            let key = Self::leaf_db_key(index);
            match maybe_leaf {
                Some(leaf) => {
                    let bytes = leaf.to_bytes();
                    batch.put_cf(leaves_cf, &key, bytes);
                },
                None => batch.delete_cf(leaves_cf, &key),
            }
        }

        for (index, maybe_subtree) in updates.subtree_updates {
             let key = Self::subtree_db_key(index);
             match maybe_subtree {
                 Some(subtree) => {
                     let bytes = subtree.to_vec();
                     batch.put_cf(subtrees_cf, &key, bytes);
                 },
                 None => batch.delete_cf(subtrees_cf, &key),
             }
        }

        for (index, maybe_node) in updates.upper_node_updates {
            let key = Self::upper_node_db_key(index);
            match maybe_node {
                Some(node) => {
                    let bytes = node.to_bytes();
                    batch.put_cf(upper_nodes_cf, &key, bytes);
                }
                None => batch.delete_cf(upper_nodes_cf, &key),
            }
        }

        if updates.leaf_count_delta != 0 || updates.entry_count_delta != 0 {
            let current_leaf_count = self.get_leaf_count()?;
            let current_entry_count = self.get_entry_count()?;

            let new_leaf_count = current_leaf_count.saturating_add_signed(updates.leaf_count_delta);
            let new_entry_count = current_entry_count.saturating_add_signed(updates.entry_count_delta);

            batch.put_cf(metadata_cf, LEAF_COUNT_KEY, &new_leaf_count.to_be_bytes());
            batch.put_cf(metadata_cf, ENTRY_COUNT_KEY, &new_entry_count.to_be_bytes());
        }

        batch.put_cf(metadata_cf, ROOT_KEY, updates.new_root.to_bytes());

        self.db.write(batch).map_err(|e| StorageError::BackendError(e.to_string()))?;
        Ok(())
    }
}