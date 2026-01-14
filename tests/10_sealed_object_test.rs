/* SPDX-License-Identifier: BSD-3-Clause */
/***********************************************************************************************
 * Copyright 2024-2026 Fraunhofer SIT, sponsored by the ELISA and ProSeCA research projects.
 * All rights reserved.
 **********************************************************************************************/

pub mod common;

use common::{
    param::PASSWORD,
    random::{create_seed, generate_bytes},
    setup::TestConfiguration,
};
use function_name::named;
use log::debug;
use rand::SeedableRng;
use rand_chacha::ChaChaRng;
use serial_test::serial;
use std::num::NonZeroUsize;
use tss2_fapi_rs::{FapiContext, SealFlags};

mk_auth_callback!(my_auth_callback, PASSWORD);
mk_tpm_finalizer!(my_tpm_finalizer, my_auth_callback);

const SEAL_TYPE_FLAGS: &[SealFlags] = &[SealFlags::NoDA];

// ==========================================================================
// Test cases
// ==========================================================================

/// Test the `create_seal()` function to create a new sealed object
#[test]
#[serial]
#[named]
fn test_create_seal() {
    let _configuration = TestConfiguration::with_finalizer(my_tpm_finalizer);

    repeat_test!(|i| {
        let key_path = &format!("/HS/SRK/mySealObj{}", i);

        // Create FAPI context
        let mut context = match FapiContext::new() {
            Ok(fpai_ctx) => fpai_ctx,
            Err(error) => panic!("Failed to create context: {:?}", error),
        };

        // Initialize TPM, if not already initialized
        tpm_initialize!(context, PASSWORD, my_auth_callback);

        // Create new seal, if not already created
        match context.create_seal(key_path, Some(SEAL_TYPE_FLAGS), NonZeroUsize::new(32usize).unwrap(), None, None, None) {
            Ok(_) => debug!("Seal created."),
            Err(error) => panic!("Seal creation has failed: {:?}", error),
        }
    });
}

/// Test the `unseal()` function to unseal an object that was sealed via the `create_seal()` function
#[test]
#[serial]
#[named]
fn test_unseal() {
    let _configuration = TestConfiguration::with_finalizer(my_tpm_finalizer);

    repeat_test!(|i| {
        let key_path = &format!("/HS/SRK/mySealData{}", i);

        // Initialize RNG
        let mut rng = ChaChaRng::from_seed(create_seed(i));

        // Create FAPI context
        let mut context = match FapiContext::new() {
            Ok(fpai_ctx) => fpai_ctx,
            Err(error) => panic!("Failed to create context: {:?}", error),
        };

        // Initialize TPM, if not already initialized
        tpm_initialize!(context, PASSWORD, my_auth_callback);

        // Generate plain-text
        let original_data: [u8; 128usize] = generate_bytes(&mut rng);

        // Create new seal, if not already created
        match context.create_seal(key_path, Some(SEAL_TYPE_FLAGS), NonZeroUsize::new(original_data.len()).unwrap(), None, None, Some(&original_data[..])) {
            Ok(_) => debug!("Seal created."),
            Err(error) => panic!("Seal creation has failed: {:?}", error),
        }

        // Unseal data
        let unsealed_data = match context.unseal(key_path) {
            Ok(data) => data,
            Err(error) => panic!("Unseal operation has failed: {:?}", error),
        };

        // Validate the result
        debug!("Original data: {}", hex::encode(&original_data[..]));
        debug!("Unsealed data: {}", hex::encode(&unsealed_data[..]));

        // Verify
        assert!(unsealed_data[..].eq(&original_data[..]));
    });
}
