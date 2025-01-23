/* SPDX-License-Identifier: BSD-3-Clause */
/***********************************************************************************************
 * Copyright 2024-2025 Fraunhofer SIT, sponsored by the ELISA and ProSeCA research projects.
 * All rights reserved.
 **********************************************************************************************/

pub mod common;

use common::{
    crypto::{get_key_type, load_public_key},
    param::PASSWORD,
    setup::TestConfiguration,
};
use function_name::named;
use log::debug;
use serial_test::serial;
use std::collections::HashSet;
use tss2_fapi_rs::{BaseErrorCode, ErrorCode, FapiContext, KeyFlags};

mk_auth_callback!(my_auth_callback, PASSWORD);
mk_tpm_finalizer!(my_tpm_finalizer, my_auth_callback);

const KEY_FLAGS: &[KeyFlags] = &[KeyFlags::NoDA];

// ==========================================================================
// Test cases
// ==========================================================================

/// Test the `create_key()` function
#[test]
#[serial]
#[named]
fn test_create_key() {
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

        // Create new key, if not already created
        match context.create_key(key_path, Some(KEY_FLAGS), None, Some(PASSWORD)) {
            Ok(_) => debug!("Key created successfully."),
            Err(error) => panic!("Key creation has failed: {:?}", error),
        }
    });
}

/// Test the `list()` function after a key has been created via the `create_key()` function
#[test]
#[serial]
#[named]
fn test_list_keys() {
    let _configuration = TestConfiguration::with_finalizer(my_tpm_finalizer);

    repeat_test!(|i| {
        let key_paths = [&format!("HS/SRK/myTestKey{}a", i), &format!("HS/SRK/myTestKey{}b", i)];

        // Create FAPI context
        let mut context = match FapiContext::new() {
            Ok(fpai_ctx) => fpai_ctx,
            Err(error) => panic!("Failed to create context: {:?}", error),
        };

        // Initialize TPM, if not already initialized
        tpm_initialize!(context, PASSWORD, my_auth_callback);

        // Create new key, if not already created
        for key_path in key_paths {
            match context.create_key(key_path, Some(KEY_FLAGS), None, Some(PASSWORD)) {
                Ok(_) => debug!("Key created successfully."),
                Err(error) => panic!("Key creation has failed: {:?}", error),
            }
        }

        // Enumerate keys
        let mut key_list = match context.list("HS/SRK") {
            Ok(list) => list,
            Err(error) => panic!("Failed to enumerate the keys: {:?}", error),
        };

        // Check if all keys are present
        let mut pending_keys = HashSet::from(key_paths.map(|elem| format!("/{}", elem)));
        for list_entry in key_list.drain(..) {
            debug!("KeyList entry: \"{}\"", list_entry);
            pending_keys.retain(|elem| !list_entry.ends_with(elem));
        }

        // All found?
        assert_eq!(0usize, pending_keys.len());
    });
}

/// Test the `export_key()` function after a key has been created via the `create_key()` function
#[test]
#[serial]
#[named]
fn test_export_key() {
    let configuration = TestConfiguration::with_finalizer(my_tpm_finalizer);

    repeat_test!(|i| {
        let key_path = &format!("HS/SRK/myTestKey{}", i);

        // Create FAPI context
        let mut context = match FapiContext::new() {
            Ok(fpai_ctx) => fpai_ctx,
            Err(error) => panic!("Failed to create context: {:?}", error),
        };

        // Initialize TPM, if not already initialized
        tpm_initialize!(context, PASSWORD, my_auth_callback);

        // Create new key, if not already created
        match context.create_key(key_path, Some(KEY_FLAGS), None, Some(PASSWORD)) {
            Ok(_) => debug!("Key created successfully."),
            Err(error) => panic!("Key creation has failed: {:?}", error),
        }

        // Export the key from TPM
        let key_data_json = match context.export_key(key_path, None) {
            Ok(data) => data,
            Err(error) => panic!("Key export has failed: {:?}", error),
        };

        // Get public key in PEM format from JSON data
        assert!(!key_data_json.is_empty());
        let pem_data = key_data_json["pem_ext_public"].as_str().expect("Failed to extract public key from JSON data!");
        debug!("PEM data: {:?}", pem_data);

        // Load public key from PEM data
        let loaded_public_key = get_key_type(configuration.prof_name()).map(|key_type| load_public_key(pem_data, key_type));
        assert!(loaded_public_key.is_some());
        debug!("Public key: {:?}", loaded_public_key);
    });
}

/// Test the `delete()` function after a key has been created via the `create_key()` function
#[test]
#[serial]
#[named]
fn test_delete() {
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

        // Create new key, if not already created
        match context.create_key(key_path, Some(KEY_FLAGS), None, Some(PASSWORD)) {
            Ok(_) => debug!("Key created successfully."),
            Err(error) => panic!("Key creation has failed: {:?}", error),
        }

        // Delete the key
        match context.delete(key_path) {
            Ok(_) => debug!("Key deleted successfully."),
            Err(error) => panic!("The key could not be deleted: {:?}", error),
        };

        // Try delete the key again (expected to fail!)
        match context.delete(key_path) {
            Err(ErrorCode::FapiError(BaseErrorCode::BadPath)) => (),
            Ok(_) => panic!("Key was deleted again!"),
            Err(error) => panic!("The key could not be deleted: {:?}", error),
        };
    });
}

/// Test the `get_tpm_blobs()` function after a key has been created via the `create_key()` function
#[test]
#[serial]
#[named]
fn test_get_tpm_blobs() {
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

        // Create new key, if not already created
        match context.create_key(key_path, Some(KEY_FLAGS), None, Some(PASSWORD)) {
            Ok(_) => debug!("Key created successfully."),
            Err(error) => panic!("Key creation has failed: {:?}", error),
        }

        // Fetch public/private key data
        let blobs = match context.get_tpm_blobs(key_path, true, false, false) {
            Ok(value) => value,
            Err(error) => panic!("Failed to obtain TPM blobs: {:?}", error),
        };

        // Verify public key
        let pub_key = blobs.0.expect("No public key data has been returned!");
        assert!(pub_key.len() >= 32usize);
        debug!("Public key: {}", hex::encode(pub_key));

        // Verify private key
        assert!(blobs.1.is_none());
        assert!(blobs.2.is_none());
    });
}

/// Test the `get_tpm_blobs()` function after a key has been created via the `create_key()` function
#[test]
#[serial]
#[named]
fn test_get_tpm_blobs_with_private() {
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

        // Create new key, if not already created
        match context.create_key(key_path, Some(KEY_FLAGS), None, Some(PASSWORD)) {
            Ok(_) => debug!("Key created successfully."),
            Err(error) => panic!("Key creation has failed: {:?}", error),
        }

        // Fetch public/private key data
        let blobs = match context.get_tpm_blobs(key_path, true, true, true) {
            Ok(value) => value,
            Err(error) => panic!("Failed to obtain TPM blobs: {:?}", error),
        };

        // Verify public key
        let pub_key = blobs.0.expect("No public key data has been returned!");
        assert!(pub_key.len() >= 32usize);
        debug!("Public key: {}", hex::encode(pub_key));

        // Verify private key
        let sec_key = blobs.1.expect("No private key data has been returned!");
        assert!(sec_key.len() >= 32usize);
        debug!("Private key: {}", hex::encode(sec_key));

        // Print the policy, if any:
        assert!(blobs.2.as_ref().map_or(true, |policy| !policy.is_empty()));
        debug!("Policy: {:?}", blobs.2)
    });
}

/// Test the `get_esys_blob()` function after a key has been created via the `create_key()` function
#[test]
#[serial]
#[named]
fn test_get_esys_blob() {
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

        // Create new key, if not already created
        match context.create_key(key_path, Some(KEY_FLAGS), None, Some(PASSWORD)) {
            Ok(_) => debug!("Key created successfully."),
            Err(error) => panic!("Key creation has failed: {:?}", error),
        }

        // Fetch ESAPI blob
        let esys_blob = match context.get_esys_blob(key_path) {
            Ok(value) => value,
            Err(error) => panic!("Failed to obtain ESAPI blob: {:?}", error),
        };

        // Verify public key
        debug!("ESAPI blob type: {:?}", esys_blob.0);
        debug!("ESAPI blob data: {}", hex::encode(&esys_blob.1[..]));

        //Check result
        assert!(esys_blob.1.len() >= 32usize);
    });
}
