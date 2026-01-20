/* SPDX-License-Identifier: BSD-3-Clause */
/***********************************************************************************************
 * Copyright 2024-2026 Fraunhofer SIT, sponsored by the ELISA and ProSeCA research projects.
 * All rights reserved.
 **********************************************************************************************/

pub mod common;

use common::{
    callback::MyCallbacks,
    crypto::{KeyType, get_key_type},
    param::PASSWORD,
    random::create_seed,
    setup::TestConfiguration,
    utils::my_tpm_finalizer,
};
use function_name::named;
use log::{debug, trace};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaChaRng;
use serial_test::serial;
use sha2::{Digest, Sha256};
use std::{
    sync::{Arc, Barrier, Mutex},
    thread,
};
use tss2_fapi_rs::{FapiContext, KeyFlags, PaddingFlags};

const KEY_FLAGS_SIGN: &[KeyFlags] = &[KeyFlags::NoDA, KeyFlags::Sign];
const PADDING_RSAPSS: &[PaddingFlags] = &[PaddingFlags::RsaPss];

const THREAD_COUNT: usize = 4usize;

// ==========================================================================
// Test cases
// ==========================================================================

/// Test access to the same "shared" FAPI context from multiple concurrent threads to sign some random data
#[test]
#[serial]
#[named]
fn test_multiple_threads() {
    let configuration = TestConfiguration::with_finalizer(|| my_tpm_finalizer(PASSWORD));

    repeat_test!(|i| {
        let key_path = &format!("HS/SRK/mySigKey{}", i);

        // Initialize RNG
        let rng = ChaChaRng::from_seed(create_seed(i));

        // Create FAPI context
        let mut context = match FapiContext::new() {
            Ok(fpai_ctx) => fpai_ctx,
            Err(error) => panic!("Failed to create context: {:?}", error),
        };

        // Initialize TPM, if not already initialized
        tpm_initialize!(context, PASSWORD, MyCallbacks::new(PASSWORD, None));

        // Create new key, if not already created
        match context.create_key(key_path, Some(KEY_FLAGS_SIGN), None, Some(PASSWORD)) {
            Ok(_) => debug!("Key created."),
            Err(error) => panic!("Key creation has failed: {:?}", error),
        }

        // Select padding algorithm
        let padding_algo = get_padding_algorithm(&configuration);
        trace!("Padding algorithm: {:?}", padding_algo);

        // Wrap the context in a Arc/Mutex so that it can be shared between threads
        let shared_context = Arc::new(Mutex::new(context));

        // Create a list and the barrier for the thread that will be spawned
        let mut thread_list = Vec::with_capacity(THREAD_COUNT);
        let barrier = Arc::new(Barrier::new(THREAD_COUNT));

        // Start multiple threads to perform signing operations in parallel
        for _n in 0..THREAD_COUNT {
            let thread_keypath = key_path.clone();
            let mut thread_rng = rng.clone();
            let thread_context = shared_context.clone();
            let thread_barrier = barrier.clone();

            // Spawn a new thread
            thread_list.push(thread::spawn(move || {
                // Get unique thread id
                let tid = thread::current().id();

                // Repeat the following operations n times (per thread)
                for _k in 0..THREAD_COUNT {
                    // Make sure that all threads have reached this point, before we go on!
                    thread_barrier.wait();

                    // Compute digest to be signed
                    let digest = Sha256::digest(format!("{:?}\\{:08X}", tid, thread_rng.next_u64()).as_bytes());
                    debug!("Digest to be signed: {}", hex::encode(&digest[..]));

                    // Lock the mutex and create the signature
                    let signature = {
                        let mut mutex_guard = thread_context.lock().unwrap();
                        match mutex_guard.sign(&thread_keypath, padding_algo, &digest, false, false) {
                            Ok(value) => value,
                            Err(error) => panic!("Failed to create the signature: {:?}", error),
                        }
                    };

                    // Print the signature
                    let signature_data: &[u8] = signature.sign_value.as_ref();
                    assert!(signature_data.len() >= 32usize);
                    debug!("Signature value: {}", hex::encode(signature_data));

                    // Lock the mutex (again) and verify the signature
                    let verify_result = {
                        let mut mutex_guard = thread_context.lock().unwrap();
                        match mutex_guard.verify_signature(&thread_keypath, &digest, &signature.sign_value[..]) {
                            Ok(value) => value,
                            Err(error) => panic!("Failed to verify the signature: {:?}", error),
                        }
                    };

                    // Check result
                    debug!("Signature valid: {:?}", verify_result);
                    assert!(verify_result);
                }
            }));
        }

        // Wait for all threads
        for thread in thread_list.drain(..) {
            thread.join().unwrap();
        }

        // Finished
        debug!("All threads have finished!");
    });
}

// ==========================================================================
// Helper functions
// ==========================================================================

fn get_padding_algorithm(config: &TestConfiguration) -> Option<&'static [PaddingFlags]> {
    match get_key_type(config.prof_name()) {
        Some(KeyType::RsaKey) => Some(PADDING_RSAPSS),
        _ => None,
    }
}
