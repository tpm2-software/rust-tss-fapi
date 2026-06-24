/* SPDX-License-Identifier: BSD-3-Clause */
/***********************************************************************************************
 * Copyright 2024-2026 Fraunhofer SIT, sponsored by the ELISA and ProSeCA research projects.
 * All rights reserved.
 **********************************************************************************************/

use criterion::{criterion_group, criterion_main};
use rand::{Rng, rng};
use std::{env, sync::Once};
use uuid::Uuid;

use tss2_fapi_rs::{BaseErrorCode, ErrorCode, FapiContext, KeyFlags};

// ==========================================================================
// Benchmarks
// ==========================================================================

const FLAGS_STORAGE: [KeyFlags; 3usize] = [KeyFlags::Decrypt, KeyFlags::Restricted, KeyFlags::NoDA];
const FLAGS_SIGNING: [KeyFlags; 2usize] = [KeyFlags::Sign, KeyFlags::NoDA];

mod bench_fapi {
    use super::{FLAGS_SIGNING, FapiContext, TpmManager};
    use criterion::{BenchmarkGroup, Criterion, SamplingMode, measurement::Measurement};
    use std::{
        hint::black_box,
        num::NonZeroUsize,
        sync::atomic::{AtomicUsize, Ordering},
        time::Duration,
    };

    /// Benchmark #1: Get random
    /// ------------------------
    /// This benchmark measures the performance of the [`FapiContext::get_random()`] function.
    fn get_random<M: Measurement>(group: &mut BenchmarkGroup<M>) {
        // Initialize TPM
        let mut manager = TpmManager::new();

        // Measurement!
        let counter: AtomicUsize = AtomicUsize::new(0usize);
        group.bench_function("get_random", |b| b.iter(|| _get_random(&mut manager.0, black_box(counter.fetch_add(1usize, Ordering::Relaxed)))));
    }

    fn _get_random(context: &mut FapiContext, _n: usize) {
        let length = unsafe { NonZeroUsize::new(32usize).unwrap_unchecked() };
        let _buffer = black_box(context.get_random(length).expect("Failed to get random data!"));
    }

    /// Benchmark #2: Create key
    /// ------------------------
    /// This benchmark measures the performance of the [`FapiContext::create_key()`] function.
    fn create_key<M: Measurement>(group: &mut BenchmarkGroup<M>) {
        // Initialize TPM
        let mut manager = TpmManager::new();

        // Measurement!
        let counter: AtomicUsize = AtomicUsize::new(0usize);
        group.bench_function("create_key", |b| b.iter(|| _create_key(&mut manager.0, &manager.1, black_box(counter.fetch_add(1usize, Ordering::Relaxed)))));
    }

    fn _create_key(context: &mut FapiContext, parent_path: &str, n: usize) {
        context.create_key(&format!("{}/key_{}", parent_path, n), Some(&FLAGS_SIGNING), None, None).expect("Failed to create key!")
    }

    /// Benchmark #3: Sign
    /// ------------------
    /// This benchmark measures the performance of the [`FapiContext::sign()`] function.
    fn sign<M: Measurement>(group: &mut BenchmarkGroup<M>) {
        // Initialize TPM
        let mut manager = TpmManager::new();

        // Create siging key
        let sign_key_path = format!("{}/sign_key", &manager.1);
        manager.0.create_key(&sign_key_path, Some(&FLAGS_SIGNING), None, None).expect("Failed to create sign key!");

        // Measurement!
        let counter: AtomicUsize = AtomicUsize::new(0usize);
        group.bench_function("sign", |b| b.iter(|| _sign(&mut manager.0, &sign_key_path, black_box(counter.fetch_add(1usize, Ordering::Relaxed)))));
    }

    fn _sign(context: &mut FapiContext, sign_key_path: &str, n: usize) {
        let mut digest = [0u8; 32usize];
        digest[..size_of::<usize>()].copy_from_slice(&n.to_be_bytes());
        let _signature = black_box(context.sign(sign_key_path, None, &digest, false, false).expect("Failed to sign message!"));
    }

    /// Benchmark #4: Verify signature
    /// ------------------------------
    /// This benchmark measures the performance of the [`FapiContext::verify_signature()`] function.
    fn verify_signature<M: Measurement>(group: &mut BenchmarkGroup<M>) {
        // Initialize TPM
        let mut manager = TpmManager::new();

        // Create siging key
        let sign_key_path = format!("{}/sign_key", &manager.1);
        manager.0.create_key(&sign_key_path, Some(&FLAGS_SIGNING), None, None).expect("Failed to create sign key!");

        // Sign message
        let digest = [0u8; 32usize];
        let signature = manager.0.sign(&sign_key_path, None, &digest, false, false).expect("Failed to sign message!");

        // Measurement!
        group.bench_function("verify_signature", |b| {
            b.iter(|| _verify_signature(&mut manager.0, &sign_key_path, black_box(&digest), &black_box(&signature).sign_value))
        });
    }

    fn _verify_signature(context: &mut FapiContext, sign_key_path: &str, digest: &[u8], signature: &[u8]) {
        let result = black_box(context.verify_signature(sign_key_path, digest, signature).expect("Failed to verify signature!"));
        assert!(result);
    }

    /// FAPI benchmarks runner
    /// ----------------------
    /// This is the entry point for running the `fapi_rs` benchmarks
    pub fn run(c: &mut Criterion) {
        let mut group = c.benchmark_group("fapi_rs");
        group.sampling_mode(SamplingMode::Flat).warm_up_time(Duration::from_secs(12)).measurement_time(Duration::from_secs(30));

        // Run benchmarks
        get_random(&mut group);
        create_key(&mut group);
        sign(&mut group);
        verify_signature(&mut group);

        // Finish benchmark
        group.finish();
    }
}

// ==========================================================================
// Utility functions
// ==========================================================================

struct TpmManager(pub FapiContext, pub String);

impl TpmManager {
    pub fn new() -> Self {
        let parent_path = format!("HS/SRK/{}", Self::random_uuid(&mut rng()));

        // Make sure that TSS2_FAPICONF is set
        if env::var("TSS2_FAPICONF").ok().is_none_or(|str| str.trim_ascii().is_empty()) {
            panic!("Environment variable TSS2_FAPICONF must be set!");
        }

        // Create a new FAPI context
        let mut context = FapiContext::new().expect("Failed to create context!");

        // Perform the provisioning, if it has not been done yet
        static PROVISION_TPM: Once = Once::new();
        PROVISION_TPM.call_once(|| match context.provision(None, None, None) {
            Ok(_) => (),
            Err(ErrorCode::FapiError(BaseErrorCode::AlreadyProvisioned)) => (),
            Err(error) => panic!("Provisioning has failed: {:?}", error),
        });

        // Create our storage key
        if let Err(error) = context.create_key(&parent_path, Some(&FLAGS_STORAGE), None, None) {
            panic!("Failed to create parent key: {:?}", error);
        }

        Self(context, parent_path)
    }

    fn clean_up(context: &mut FapiContext, parent_path: &str) -> Result<(), ErrorCode> {
        match context.delete(parent_path) {
            Ok(_) => Ok(()),
            Err(ErrorCode::FapiError(BaseErrorCode::BadPath | BaseErrorCode::PathNotFound | BaseErrorCode::KeyNotFound)) => Ok(()),
            Err(error) => Err(error),
        }
    }

    fn random_uuid(random: &mut impl Rng) -> Uuid {
        Uuid::from_u64_pair(random.next_u64(), random.next_u64())
    }
}

impl Drop for TpmManager {
    fn drop(&mut self) {
        if let Err(error) = Self::clean_up(&mut self.0, &self.1) {
            eprintln!("Failed to delete key: {:?}", error);
        }
    }
}

// ==========================================================================
// Main
// ==========================================================================

criterion_group!(benches, bench_fapi::run);
criterion_main!(benches);
