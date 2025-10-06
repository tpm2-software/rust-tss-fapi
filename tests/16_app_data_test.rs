/* SPDX-License-Identifier: BSD-3-Clause */
/***********************************************************************************************
 * Copyright 2024-2025 Fraunhofer SIT, sponsored by the ELISA and ProSeCA research projects.
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
use tss2_fapi_rs::{FapiContext, KeyFlags};

mk_auth_callback!(my_auth_callback, PASSWORD);
mk_tpm_finalizer!(my_tpm_finalizer, my_auth_callback);

const KEY_FLAGS: &[KeyFlags] = &[KeyFlags::NoDA, KeyFlags::Decrypt];

// ==========================================================================
// Test cases
// ==========================================================================

/// Test the `set_app_data()` function to associate some application-specific data with an existing key
#[test]
#[serial]
#[named]
fn test_set_appdata() {
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

        // Generate data
        let app_data = generate_bytes::<128usize>(&mut rng);

        // Set application data
        match context.set_app_data(key_path, Some(&app_data[..])) {
            Ok(_) => debug!("Data set successfully."),
            Err(error) => panic!("Setting application-specific data has failed: {:?}", error),
        }
    });
}

/// Test the `get_app_data()` function to read back the application-specific data that was previously set via the `set_app_data()` function
#[test]
#[serial]
#[named]
fn test_get_appdata() {
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

        // Generate data
        let app_data = generate_bytes::<128usize>(&mut rng);

        // Set application data
        match context.set_app_data(key_path, Some(&app_data[..])) {
            Ok(_) => debug!("Data set successfully."),
            Err(error) => panic!("Setting application-specific data has failed: {:?}", error),
        }

        // Get the application data
        let recovered_data = match context.get_app_data(key_path) {
            Ok(cert_data) => cert_data,
            Err(error) => panic!("Getting application-specific data has failed: {:?}", error),
        };

        // Verify
        debug!("Application data: {}", recovered_data.as_ref().map(|data| hex::encode(&data[..])).unwrap_or_else(|| "(None)".to_owned()));
        assert!(recovered_data.expect("No application-specific data avialble!")[..].eq_ignore_ascii_case(&app_data[..]))
    });
}

/// Test the `set_app_data()` function to erase the application-specific data that was previously set via the `set_app_data()` function
#[test]
#[serial]
#[named]
fn test_remove_appdata() {
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

        // Generate data
        let app_data = generate_bytes::<128usize>(&mut rng);

        // Set application data
        match context.set_app_data(key_path, Some(&app_data[..])) {
            Ok(_) => debug!("Data set successfully."),
            Err(error) => panic!("Setting application-specific data has failed: {:?}", error),
        }

        // Get the application data
        let recovered_data = match context.get_app_data(key_path) {
            Ok(cert_data) => cert_data,
            Err(error) => panic!("Getting application-specific data has failed: {:?}", error),
        };

        // Verify
        assert!(recovered_data.is_some());

        // Erase application data
        match context.set_app_data(key_path, None) {
            Ok(_) => debug!("Data erased."),
            Err(error) => panic!("Setting application-specific data has failed: {:?}", error),
        }

        // Get the application data (again)
        let recovered_data = match context.get_app_data(key_path) {
            Ok(cert_data) => cert_data,
            Err(error) => panic!("Getting application-specific data has failed: {:?}", error),
        };

        // Verify
        assert!(recovered_data.is_none());
    });
}
