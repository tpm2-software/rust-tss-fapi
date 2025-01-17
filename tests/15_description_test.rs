/* SPDX-License-Identifier: BSD-3-Clause */
/*******************************************************************************
 * Copyright 2024, Fraunhofer SIT sponsored by the ELISA research project
 * All rights reserved.
 ******************************************************************************/

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

/// Test the `set_description()` function to set up a description for an existing key
#[test]
#[serial]
#[named]
fn test_set_description() {
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

        // Generate description
        let desciption = generate_string::<64usize>(&mut rng);

        // Set description
        match context.set_description(key_path, Some(&desciption)) {
            Ok(_) => debug!("Description set successfully."),
            Err(error) => panic!("Setting description data has failed: {:?}", error),
        }
    });
}

/// Test the `get_description()` function to read back the description that was previosuly set via the `set_description()` function
#[test]
#[serial]
#[named]
fn test_get_description() {
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

        // Generate description
        let desciption = generate_string::<64usize>(&mut rng);

        // Set description
        match context.set_description(key_path, Some(&desciption)) {
            Ok(_) => debug!("Description set successfully."),
            Err(error) => panic!("Setting description data has failed: {:?}", error),
        }

        // Get the description data
        let recovered_descr = match context.get_description(key_path) {
            Ok(cert_data) => cert_data,
            Err(error) => panic!("Getting description has failed: {:?}", error),
        };

        // Verify
        debug!("Description: {:?}", &recovered_descr);
        assert!(recovered_descr.expect("No description avialble!").trim()[..].eq(desciption.trim()))
    });
}

/// Test the `set_description()` function to remove the description that was previosuly set via the `set_description()` function
#[test]
#[serial]
#[named]
fn test_remove_description() {
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

        // Generate description
        let desciption = generate_string::<64usize>(&mut rng);

        // Set description
        match context.set_description(key_path, Some(&desciption)) {
            Ok(_) => debug!("Description set successfully."),
            Err(error) => panic!("Setting description data has failed: {:?}", error),
        }

        // Get the description data
        let recovered_descr = match context.get_description(key_path) {
            Ok(cert_data) => cert_data,
            Err(error) => panic!("Getting description has failed: {:?}", error),
        };

        // Verify
        assert!(recovered_descr.is_some());

        // Erase the description
        match context.set_description(key_path, None) {
            Ok(_) => debug!("Description erased."),
            Err(error) => panic!("Setting application-specific data has failed: {:?}", error),
        }

        // Get the description data
        let recovered_descr = match context.get_description(key_path) {
            Ok(cert_data) => cert_data,
            Err(error) => panic!("Getting description has failed: {:?}", error),
        };

        // Verify
        assert!(recovered_descr.is_none());
    });
}
