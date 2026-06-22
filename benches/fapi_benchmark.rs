/* SPDX-License-Identifier: BSD-3-Clause */
/***********************************************************************************************
 * Copyright 2024-2026 Fraunhofer SIT, sponsored by the ELISA and ProSeCA research projects.
 * All rights reserved.
 **********************************************************************************************/

use criterion::{Criterion, criterion_group, criterion_main};
use std::{
    hint::black_box,
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};
use tss2_fapi_rs::{BaseErrorCode, ErrorCode, FapiContext, KeyFlags};

const BASE_KEY_PATH: &str = "HS/SRK/bench";
const SIGN_KEY_PATH: &str = "HS/SRK/sign_key";

// ==========================================================================
// Bench #1: Create key
// ==========================================================================

fn bench_create_key(c: &mut Criterion) {
    // Create a new FAPI context
    let mut context = FapiContext::new().expect("Failed to create context!");

    // Perform the provisioning, if it has not been done yet
    match context.provision(None, None, None) {
        Ok(_) => (),
        Err(ErrorCode::FapiError(BaseErrorCode::AlreadyProvisioned)) => (),
        Err(error) => panic!("Provisioning has failed: {:?}", error),
    }

    // Delete existing storage key
    match context.delete(BASE_KEY_PATH) {
        Ok(_) => (),
        Err(ErrorCode::FapiError(BaseErrorCode::BadPath)) => (),
        Err(ErrorCode::FapiError(BaseErrorCode::PathNotFound)) => (),
        Err(error) => panic!("Failed to delete: {:?}", error),
    }

    // Create storage key
    context.create_key(BASE_KEY_PATH, Some(&[KeyFlags::Decrypt, KeyFlags::Restricted, KeyFlags::NoDA]), None, None).expect("Failed to create parent key!");

    // Create the siging keys
    let counter: AtomicUsize = AtomicUsize::new(0usize);
    c.bench_function("create_key", |b| b.iter(|| _create_key(&mut context, black_box(counter.fetch_add(1usize, Ordering::Relaxed)))));
}

fn _create_key(context: &mut FapiContext, n: usize) {
    const MY_KEYFLAG: &[KeyFlags] = &[KeyFlags::Sign, KeyFlags::NoDA];
    context.create_key(&format!("{}/key_{}", BASE_KEY_PATH, n), Some(MY_KEYFLAG), None, None).expect("Failed to create key!")
}

// ==========================================================================
// Bench #2: Sign
// ==========================================================================

fn bench_sign(c: &mut Criterion) {
    // Create a new FAPI context
    let mut context = FapiContext::new().expect("Failed to create context!");

    // Perform the provisioning, if it has not been done yet
    match context.provision(None, None, None) {
        Ok(_) => (),
        Err(ErrorCode::FapiError(BaseErrorCode::AlreadyProvisioned)) => (),
        Err(error) => panic!("Provisioning has failed: {:?}", error),
    }

    // Delete existing key
    match context.delete(SIGN_KEY_PATH) {
        Ok(_) => (),
        Err(ErrorCode::FapiError(BaseErrorCode::BadPath)) => (),
        Err(ErrorCode::FapiError(BaseErrorCode::PathNotFound)) => (),
        Err(error) => panic!("Failed to delete: {:?}", error),
    }

    // Create siging key
    context.create_key(SIGN_KEY_PATH, Some(&[KeyFlags::Sign, KeyFlags::NoDA]), None, None).expect("Failed to create sign key!");

    // Sign message
    let counter: AtomicUsize = AtomicUsize::new(0usize);
    c.bench_function("sign", |b| b.iter(|| _sign(&mut context, black_box(counter.fetch_add(1usize, Ordering::Relaxed)))));
}

fn _sign(context: &mut FapiContext, n: usize) {
    let mut digest = [0u8; 32usize];
    digest[..size_of::<usize>()].copy_from_slice(&n.to_be_bytes());
    let _signature = context.sign(SIGN_KEY_PATH, None, &digest, false, false).expect("Failed to sign message!");
}

// ==========================================================================
// Bench #3: Verify
// ==========================================================================

fn bench_verify_signature(c: &mut Criterion) {
    // Create a new FAPI context
    let mut context = FapiContext::new().expect("Failed to create context!");

    // Perform the provisioning, if it has not been done yet
    match context.provision(None, None, None) {
        Ok(_) => (),
        Err(ErrorCode::FapiError(BaseErrorCode::AlreadyProvisioned)) => (),
        Err(error) => panic!("Provisioning has failed: {:?}", error),
    }

    // Delete existing key
    match context.delete(SIGN_KEY_PATH) {
        Ok(_) => (),
        Err(ErrorCode::FapiError(BaseErrorCode::BadPath)) => (),
        Err(ErrorCode::FapiError(BaseErrorCode::PathNotFound)) => (),
        Err(error) => panic!("Failed to delete: {:?}", error),
    }

    // Create siging key
    context.create_key(SIGN_KEY_PATH, Some(&[KeyFlags::Sign, KeyFlags::NoDA]), None, None).expect("Failed to create sign key!");

    // Sign message
    let digest = [0u8; 32usize];
    let signature = context.sign(SIGN_KEY_PATH, None, &digest, false, false).expect("Failed to sign message!");

    // Verify signature
    c.bench_function("verify_signature", |b| b.iter(|| _verify_signature(&mut context, black_box(&digest), &black_box(&signature).sign_value)));
}

fn _verify_signature(context: &mut FapiContext, digest: &[u8], signature: &[u8]) {
    let result = context.verify_signature(SIGN_KEY_PATH, digest, signature).expect("Failed to verify signature!");
    assert!(result);
}

// ==========================================================================
// Main
// ==========================================================================

fn create_config() -> Criterion {
    Criterion::default().warm_up_time(Duration::from_secs(15)).measurement_time(Duration::from_secs(30)).noise_threshold(0.1).without_plots()
}

criterion_group!(name = benches; config = create_config(); targets = bench_create_key, bench_sign, bench_verify_signature);
criterion_main!(benches);
