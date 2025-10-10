use std::hint;

use criterion::{Criterion, criterion_group, criterion_main};
use miden_crypto::{
    Word,
    merkle::{LargeSmt, RocksDbConfig, RocksDbStorage},
};

mod common;
use common::*;

use crate::{
    common::data::{generate_smt_entries_sequential, generate_test_keys_sequential},
    config::{DEFAULT_MEASUREMENT_TIME, DEFAULT_SAMPLE_SIZE},
};

benchmark_with_setup_data! {
    large_smt_open,
    DEFAULT_MEASUREMENT_TIME,
    DEFAULT_SAMPLE_SIZE,
    "open",
    || {
        let entries = generate_smt_entries_sequential(256);
        let keys = generate_test_keys_sequential(10);
        let temp_dir = tempfile::TempDir::new().unwrap();
        let storage = RocksDbStorage::open(RocksDbConfig::new(temp_dir.path())).unwrap();
        let smt = LargeSmt::with_entries(storage, entries).unwrap();
        (smt, keys, temp_dir)
    },
    |b: &mut criterion::Bencher, (smt, keys, _temp_dir): &(LargeSmt<RocksDbStorage>, Vec<Word>, tempfile::TempDir)| {
        b.iter(|| {
            for key in keys {
                hint::black_box(smt.open(key));
            }
        })
    },
}

benchmark_with_setup_data! {
    large_smt_compute_mutations,
    DEFAULT_MEASUREMENT_TIME,
    DEFAULT_SAMPLE_SIZE,
    "compute_mutations",
    || {
        let entries = generate_smt_entries_sequential(256);
        let temp_dir = tempfile::TempDir::new().unwrap();
        let storage = RocksDbStorage::open(RocksDbConfig::new(temp_dir.path())).unwrap();
        let smt = LargeSmt::with_entries(storage, entries).unwrap();
        let new_entries = generate_smt_entries_sequential(10_000);
        (smt, new_entries, temp_dir)
    },
    |b: &mut criterion::Bencher, (smt, new_entries, _temp_dir): &(LargeSmt<RocksDbStorage>, Vec<(Word, Word)>, tempfile::TempDir)| {
        b.iter(|| {
            hint::black_box(smt.compute_mutations(new_entries.clone()).unwrap());
        })
    },
}

benchmark_batch! {
    large_smt_apply_mutations,
    &[1, 16, 32, 64, 128],
    |b: &mut criterion::Bencher, mutation_count: usize| {
        let base_entries = generate_smt_entries_sequential(256);
        let temp_dir = tempfile::TempDir::new().unwrap();
        let storage = RocksDbStorage::open(RocksDbConfig::new(temp_dir.path())).unwrap();
        let mut smt = LargeSmt::with_entries(storage, base_entries).unwrap();

        b.iter(|| {
            for _ in 0..mutation_count {
                let new_entries = generate_smt_entries_sequential(10_000);
                let mutations = smt.compute_mutations(new_entries).unwrap();
                smt.apply_mutations(mutations).unwrap();
            }
        })
    },
    |size| Some(criterion::Throughput::Elements(size as u64))
}

benchmark_batch! {
    large_smt_insert_batch,
    &[1, 16, 32, 64, 128],
    |b: &mut criterion::Bencher, mutation_count: usize| {
        let base_entries = generate_smt_entries_sequential(256);
        let temp_dir = tempfile::TempDir::new().unwrap();
        let storage = RocksDbStorage::open(RocksDbConfig::new(temp_dir.path())).unwrap();
        let mut smt = LargeSmt::with_entries(storage, base_entries).unwrap();

        b.iter(|| {
            for _ in 0..mutation_count {
                let new_entries = generate_smt_entries_sequential(10_000);
                smt.insert_batch(new_entries).unwrap();
            }
        })
    },
    |size| Some(criterion::Throughput::Elements(size as u64))
}

// Compute/apply vs insert_batch
fn large_smt_mutation_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("large_smt_mutation_comparison");
    
    // Setup: create base SMT with some entries
    let base_entries = generate_smt_entries_sequential(256);
    let new_entries = generate_smt_entries_sequential(10_000);
    
    // Benchmark the two-step flow
    group.bench_function("compute_mutations_apply_mutations", |b| {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let storage = RocksDbStorage::open(RocksDbConfig::new(temp_dir.path())).unwrap();
        let mut smt = LargeSmt::with_entries(storage, base_entries.clone()).unwrap();
        
        b.iter(|| {
            let mutations = smt.compute_mutations(new_entries.clone()).unwrap();
            smt.apply_mutations(mutations).unwrap();
        });
    });
    
    // Benchmark the optimized insert_batch
    group.bench_function("insert_batch", |b| {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let storage = RocksDbStorage::open(RocksDbConfig::new(temp_dir.path())).unwrap();
        let mut smt = LargeSmt::with_entries(storage, base_entries.clone()).unwrap();
        
        b.iter(|| {
            smt.insert_batch(new_entries.clone()).unwrap();
        });
    });
    
    group.finish();
}

criterion_group!(
    large_smt_benchmark_group,
    large_smt_open,
    large_smt_compute_mutations,
    large_smt_apply_mutations,
    large_smt_insert_batch,
    large_smt_mutation_comparison,
);

criterion_main!(large_smt_benchmark_group);
