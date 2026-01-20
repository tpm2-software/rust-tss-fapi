/* SPDX-License-Identifier: BSD-3-Clause */
/***********************************************************************************************
 * Copyright 2024-2026 Fraunhofer SIT, sponsored by the ELISA and ProSeCA research projects.
 * All rights reserved.
 **********************************************************************************************/

pub mod common;

use common::{
    callback::MyCallbacks,
    crypto::{KeyType, PrivateKey, load_private_key},
    param::PASSWORD,
    random::{create_seed, generate_bytes},
    setup::TestConfiguration,
    utils::my_tpm_finalizer,
};
use function_name::named;
use log::debug;
use rand::SeedableRng;
use rand_chacha::ChaChaRng;
use serial_test::serial;
use sha2::{Digest, Sha256};
use std::{any::Any, fs, path::Path};
use tss2_fapi_rs::{FapiContext, ImportData, KeyFlags, json::JsonValue};

const KEY_FLAGS_SIGN: &[KeyFlags] = &[KeyFlags::NoDA, KeyFlags::Sign];

// ==========================================================================
// Test cases
// ==========================================================================

/// Test the `import()` and `set_sign_callback()` functions to import and use a `POLICYSIGNED` policy containing an RSA key
#[test]
#[serial]
#[named]
fn test_policy_signed_rsa() {
    let configuration = TestConfiguration::with_finalizer(|| my_tpm_finalizer(PASSWORD));

    repeat_test!(|i| {
        let key_path = &format!("HS/SRK/myPolKeyRsa{}", i);
        let pol_name = &format!("/policy/pol_signed_rsa{}", i);

        // Initialize RNG
        let mut rng = ChaChaRng::from_seed(create_seed(i));

        // Create FAPI context

        let mut context = match FapiContext::new() {
            Ok(fpai_ctx) => fpai_ctx,
            Err(error) => panic!("Failed to create context: {:?}", error),
        };

        // Read policy from file
        let policy_json = read_policy(configuration.data_path(), "pol_signed_rsa").expect("Failed to read policy!");

        // Read the private key
        let private_key = read_private_key(configuration.data_path(), KeyType::RsaKey, "key_rsa_2048").expect("Failed to load RSA private key!");

        // Initialize TPM, if not already initialized
        tpm_initialize!(context, PASSWORD, MyCallbacks::new(PASSWORD, Some(private_key)));

        // Import policy
        match context.import(pol_name, ImportData::from_json(&policy_json).unwrap()) {
            Ok(_) => debug!("Policy imported."),
            Err(error) => panic!("Failed to import policy: {:?}", error),
        };

        // Create new key, if not already created
        match context.create_key(key_path, Some(KEY_FLAGS_SIGN), Some(pol_name), Some(PASSWORD)) {
            Ok(_) => debug!("Key created with policy."),
            Err(error) => panic!("Key creation has failed: {:?}", error),
        }

        // Compute digest to be signed
        let digest = Sha256::digest(&generate_bytes::<256usize>(&mut rng)[..]);
        debug!("Digest to be signed: {}", hex::encode(&digest[..]));

        // Create the signature
        let _signature = match context.sign(key_path, None, &digest, false, false) {
            Ok(value) => value,
            Err(error) => panic!("Failed to create the signature: {:?}", error),
        };
    });
}

/// Test the `import()` and `set_sign_callback()` functions to import and use a `POLICYSIGNED` policy containing an ECC key
#[test]
#[serial]
#[named]
fn test_policy_signed_ecc() {
    let configuration = TestConfiguration::with_finalizer(|| my_tpm_finalizer(PASSWORD));

    repeat_test!(|i| {
        let key_path = &format!("HS/SRK/myPolKeyEcc{}", i);
        let pol_name = &format!("/policy/pol_signed_ecc{}", i);

        // Initialize RNG
        let mut rng = ChaChaRng::from_seed(create_seed(i));

        // Create FAPI context
        let mut context = match FapiContext::new() {
            Ok(fpai_ctx) => fpai_ctx,
            Err(error) => panic!("Failed to create context: {:?}", error),
        };

        // Read policy from file
        let policy_json = read_policy(configuration.data_path(), "pol_signed_ecc").expect("Failed to read policy!");

        // Read the private key
        let private_key = read_private_key(configuration.data_path(), KeyType::EccKey, "key_ecc_256").expect("Failed to load ECC private key!");

        // Initialize TPM, if not already initialized
        tpm_initialize!(context, PASSWORD, MyCallbacks::new(PASSWORD, Some(private_key)));

        // Import policy
        match context.import(pol_name, ImportData::from_json(&policy_json).unwrap()) {
            Ok(_) => debug!("Policy imported."),
            Err(error) => panic!("Failed to import policy: {:?}", error),
        };

        // Create new key, if not already created
        match context.create_key(key_path, Some(KEY_FLAGS_SIGN), Some(pol_name), Some(PASSWORD)) {
            Ok(_) => debug!("Key created with policy."),
            Err(error) => panic!("Key creation has failed: {:?}", error),
        }

        // Compute digest to be signed
        let digest = Sha256::digest(&generate_bytes::<256usize>(&mut rng)[..]);
        debug!("Digest to be signed: {}", hex::encode(&digest[..]));

        // Create the signature
        let _signature = match context.sign(key_path, None, &digest, false, false) {
            Ok(value) => value,
            Err(error) => panic!("Failed to create the signature: {:?}", error),
        };
    });
}

/// Test the `import()` and `set_branch_callback()` functions to import and use a `POLICYOR` policy
#[test]
#[serial]
#[named]
fn test_policy_or() {
    let configuration = TestConfiguration::with_finalizer(|| my_tpm_finalizer(PASSWORD));

    repeat_test!(|i| {
        let key_path = &format!("HS/SRK/myPolKeyOr{}", i);
        let pol_name = &format!("/policy/pol_or{}", i);

        // Initialize RNG
        let mut rng = ChaChaRng::from_seed(create_seed(i));

        // Create FAPI context
        let mut context = match FapiContext::new() {
            Ok(fpai_ctx) => fpai_ctx,
            Err(error) => panic!("Failed to create context: {:?}", error),
        };

        // Read policy from file
        let policy_json = read_policy(configuration.data_path(), "pol_or").expect("Failed to read policy!");

        // Read the private key
        let private_key = read_private_key(configuration.data_path(), KeyType::RsaKey, "key_rsa_2048").expect("Failed to load RSA private key!");

        // Initialize TPM, if not already initialized
        tpm_initialize!(context, PASSWORD, MyCallbacks::new(PASSWORD, Some(private_key)));

        // Import policy
        match context.import(pol_name, ImportData::from_json(&policy_json).unwrap()) {
            Ok(_) => debug!("Policy imported."),
            Err(error) => panic!("Failed to import policy: {:?}", error),
        };

        // Create new key, if not already created
        match context.create_key(key_path, Some(KEY_FLAGS_SIGN), Some(pol_name), Some(PASSWORD)) {
            Ok(_) => debug!("Key created with policy."),
            Err(error) => panic!("Key creation has failed: {:?}", error),
        }

        // Compute digest to be signed
        let digest = Sha256::digest(&generate_bytes::<256usize>(&mut rng)[..]);
        debug!("Digest to be signed: {}", hex::encode(&digest[..]));

        // Create the signature
        let _signature = match context.sign(key_path, None, &digest, false, false) {
            Ok(value) => value,
            Err(error) => panic!("Failed to create the signature: {:?}", error),
        };

        // Check retrieved branches
        let callbacks: Box<MyCallbacks> = downcast(context.clear_callbacks().expect("Failed to clear!").expect("No callbacks!")).expect("Downcast has failed!");
        let branches = callbacks.get_branches();
        assert_eq!(branches.len(), 2);
        assert!(branches[0].eq_ignore_ascii_case("#0,PolicySignedRSA"));
        assert!(branches[1].eq_ignore_ascii_case("#1,PolicySignedECC"));
    });
}

/// Test the `import()` and `set_policy_action_callback()` functions to import and use a `POLICYACTION` policy
#[test]
#[serial]
#[named]
fn test_policy_action() {
    let configuration = TestConfiguration::with_finalizer(|| my_tpm_finalizer(PASSWORD));

    repeat_test!(|i| {
        let key_path = &format!("HS/SRK/myPolKeyAction{}", i);
        let pol_name = &format!("/policy/pol_action{}", i);

        // Initialize RNG
        let mut rng = ChaChaRng::from_seed(create_seed(i));

        // Create FAPI context
        let mut context = match FapiContext::new() {
            Ok(fpai_ctx) => fpai_ctx,
            Err(error) => panic!("Failed to create context: {:?}", error),
        };

        // Read policy from file
        let policy_json = read_policy(configuration.data_path(), "pol_action").expect("Failed to read policy!");

        // Initialize TPM, if not already initialized
        tpm_initialize!(context, PASSWORD, MyCallbacks::new(PASSWORD, None));

        // Import policy
        match context.import(pol_name, ImportData::from_json(&policy_json).unwrap()) {
            Ok(_) => debug!("Policy imported."),
            Err(error) => panic!("Failed to import policy: {:?}", error),
        };

        // Create new key, if not already created
        match context.create_key(key_path, Some(KEY_FLAGS_SIGN), Some(pol_name), Some(PASSWORD)) {
            Ok(_) => debug!("Key created with policy."),
            Err(error) => panic!("Key creation has failed: {:?}", error),
        }

        // Compute digest to be signed
        let digest = Sha256::digest(&generate_bytes::<256usize>(&mut rng)[..]);
        debug!("Digest to be signed: {}", hex::encode(&digest[..]));

        // Create the signature
        let _signature = match context.sign(key_path, None, &digest, false, false) {
            Ok(value) => value,
            Err(error) => panic!("Failed to create the signature: {:?}", error),
        };

        // Check retrieved actions
        let callbacks: Box<MyCallbacks> = downcast(context.clear_callbacks().expect("Failed to clear!").expect("No callbacks!")).expect("Downcast has failed!");
        let actions = callbacks.get_actions();
        assert!(!actions.is_empty());
        assert!(actions[0].eq_ignore_ascii_case("myaction"));
    });
}

// ==========================================================================
// Helper functions
// ==========================================================================

/// Read policy from file
fn read_policy(data_path: &Path, policy_name: &str) -> Option<JsonValue> {
    let policy_file = data_path.join("policies").join(format!("{}.json", policy_name));
    fs::read_to_string(policy_file).ok().and_then(|policy_data| json::parse(&policy_data[..]).ok())
}

/// Read private key from file
fn read_private_key(data_path: &Path, key_type: KeyType, key_name: &str) -> Option<PrivateKey> {
    let pem_file = data_path.join("keys").join(format!("{}.pem", key_name));
    fs::read_to_string(pem_file).ok().and_then(|pem_data| load_private_key(&pem_data[..], key_type))
}

/// Downcast helper
fn downcast<T: 'static>(boxed: Box<dyn Any>) -> Option<Box<T>> {
    boxed.downcast().ok()
}
