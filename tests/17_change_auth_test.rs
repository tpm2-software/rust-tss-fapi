/* SPDX-License-Identifier: BSD-3-Clause */
/***********************************************************************************************
 * Copyright 2024-2026 Fraunhofer SIT, sponsored by the ELISA and ProSeCA research projects.
 * All rights reserved.
 **********************************************************************************************/

pub mod common;

use common::{
    param::PASSWORD,
    random::{create_seed, generate_string},
    setup::TestConfiguration,
};
use function_name::named;
use log::debug;
use rand::SeedableRng;
use rand_chacha::ChaChaRng;
use serial_test::serial;
use tss2_fapi_rs::{FapiContext, KeyFlags};

mk_auth_callback!(my_auth_callback, PASSWORD);
mk_tpm_finalizer!(my_tpm_finalizer, my_auth_callback);

const KEY_FLAGS: &[KeyFlags] = &[KeyFlags::NoDA, KeyFlags::Decrypt];

// ==========================================================================
// Test cases
// ==========================================================================

/// Test the `change_auth()` function to change the auth value (password) for an existing key
#[test]
#[serial]
#[named]
fn test_change_auth() {
    let _configuration = TestConfiguration::with_finalizer(my_tpm_finalizer);

    repeat_test!(|i| {
        let key_path = &format!("HS/SRK/myTestKey{}", i);

        // Initialize RNG
        let mut rng = ChaChaRng::from_seed(create_seed(i));

        // Create FAPI context
        let mut context = match FapiContext::new() {
            Ok(fpai_ctx) => fpai_ctx,
            Err(error) => panic!("Failed to create context: {:?}", error),
        };

        // Initialize TPM, if not already initialized
        tpm_initialize!(context, PASSWORD, my_auth_callback);

        // Create the key, if not already created
        match context.create_key(key_path, Some(KEY_FLAGS), None, Some(PASSWORD)) {
            Ok(_) => debug!("Key created successfully."),
            Err(error) => panic!("Key creation has failed: {:?}", error),
        }

        // Generate password
        let new_password = generate_string::<12usize>(&mut rng);

        // Change auth value
        match context.change_auth(key_path, Some(&new_password[..])) {
            Ok(_) => debug!("Auth value changed successfully."),
            Err(error) => panic!("Changing the auth value has failed: {:?}", error),
        }
    });
}

/// Test the `change_auth()` function to remove the auth value (password) from an existing key
#[test]
#[serial]
#[named]
fn test_remove_auth() {
    let _configuration = TestConfiguration::with_finalizer(my_tpm_finalizer);

    repeat_test!(|i| {
        let key_path = &format!("HS/SRK/myTestKey{}", i);

        // Create FAPI context
        let mut context = match FapiContext::new() {
            Ok(fpai_ctx) => fpai_ctx,
            Err(error) => panic!("Failed to create context: {:?}", error),
        };

        // Initialize TPM, if not already initialized
        tpm_initialize!(context, PASSWORD, my_auth_callback);

        // Create the key, if not already created
        match context.create_key(key_path, Some(KEY_FLAGS), None, Some(PASSWORD)) {
            Ok(_) => debug!("Key created successfully."),
            Err(error) => panic!("Key creation has failed: {:?}", error),
        }

        // Change auth value
        match context.change_auth(key_path, None) {
            Ok(_) => debug!("Auth value removed."),
            Err(error) => panic!("Removing the auth value has failed: {:?}", error),
        }
    });
}
