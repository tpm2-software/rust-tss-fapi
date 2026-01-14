/* SPDX-License-Identifier: BSD-3-Clause */
/***********************************************************************************************
 * Copyright 2024-2025 Fraunhofer SIT, sponsored by the ELISA and ProSeCA research projects.
 * All rights reserved.
 **********************************************************************************************/

pub mod common;

use common::{
    crypto::{KeyType, PrivateKey, create_signature, load_private_key},
    param::PASSWORD,
    random::{create_seed, generate_bytes},
    setup::TestConfiguration,
};
use function_name::named;
use json::JsonValue;
use log::{debug, trace, warn};
use rand::SeedableRng;
use rand_chacha::ChaChaRng;
use serial_test::serial;
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::Path,
    sync::{Arc, Mutex},
};
use tss2_fapi_rs::{ActnCallback, ActnCallbackParam, BranCallback, BranCallbackParam, FapiContext, ImportData, KeyFlags, SignCallback, SignCallbackParam};

mk_auth_callback!(my_auth_callback, PASSWORD);
mk_tpm_finalizer!(my_tpm_finalizer, my_auth_callback);

const KEY_FLAGS_SIGN: &[KeyFlags] = &[KeyFlags::NoDA, KeyFlags::Sign];

// ==========================================================================
// Test cases
// ==========================================================================

/// Test the `import()` and `set_sign_callback()` functions to import and use a `POLICYSIGNED` policy containing an RSA key
#[test]
#[serial]
#[named]
fn test_policy_signed_rsa() {
    let configuration = TestConfiguration::with_finalizer(my_tpm_finalizer);

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

        // Initialize TPM, if not already initialized
        tpm_initialize!(context, PASSWORD, my_auth_callback);

        // Read policy from file
        let policy_json = read_policy(configuration.data_path(), "pol_signed_rsa").expect("Failed to read policy!");

        // Read the private key
        let private_key = read_private_key(configuration.data_path(), KeyType::RsaKey, "key_rsa_2048").expect("Failed to load RSA private key!");

        // Set up callback
        match context.set_sign_callback(SignCallback::with_data(my_sign_callback, private_key)) {
            Ok(_) => debug!("Sign callback installed."),
            Err(error) => panic!("Failed to set up sign callback: {:?}", error),
        }

        // Import policy
        match context.import(pol_name, ImportData::from(&policy_json)) {
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
    let configuration = TestConfiguration::with_finalizer(my_tpm_finalizer);

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

        // Initialize TPM, if not already initialized
        tpm_initialize!(context, PASSWORD, my_auth_callback);

        // Read policy from file
        let policy_json = read_policy(configuration.data_path(), "pol_signed_ecc").expect("Failed to read policy!");

        // Read the private key
        let private_key = read_private_key(configuration.data_path(), KeyType::EccKey, "key_ecc_256").expect("Failed to load ECC private key!");

        // Set up callback
        match context.set_sign_callback(SignCallback::with_data(my_sign_callback, private_key)) {
            Ok(_) => debug!("Sign callback installed."),
            Err(error) => panic!("Failed to set up sign callback: {:?}", error),
        }

        // Import policy
        match context.import(pol_name, ImportData::from(&policy_json)) {
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
    let configuration = TestConfiguration::with_finalizer(my_tpm_finalizer);

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

        // Initialize TPM, if not already initialized
        tpm_initialize!(context, PASSWORD, my_auth_callback);

        // Read policy from file
        let policy_json = read_policy(configuration.data_path(), "pol_or").expect("Failed to read policy!");

        // Read the private key
        let private_key = read_private_key(configuration.data_path(), KeyType::RsaKey, "key_rsa_2048").expect("Failed to load RSA private key!");

        // Set up callback
        let branches: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        match context.set_branch_callback(BranCallback::with_data(my_bran_callback, branches.clone())) {
            Ok(_) => debug!("Branch callback installed."),
            Err(error) => panic!("Failed to set up sign callback: {:?}", error),
        }

        // Set up callback
        match context.set_sign_callback(SignCallback::with_data(my_sign_callback, private_key)) {
            Ok(_) => debug!("Sign callback installed."),
            Err(error) => panic!("Failed to set up sign callback: {:?}", error),
        }

        // Import policy
        match context.import(pol_name, ImportData::from(&policy_json)) {
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
        let branches_ref = branches.try_lock().expect("Failed to borrow the result value!");
        assert_eq!(branches_ref.len(), 2);
        assert!(branches_ref[0].eq_ignore_ascii_case("#0,PolicySignedRSA"));
        assert!(branches_ref[1].eq_ignore_ascii_case("#1,PolicySignedECC"));
    });
}

/// Test the `import()` and `set_policy_action_callback()` functions to import and use a `POLICYACTION` policy
#[test]
#[serial]
#[named]
fn test_policy_action() {
    let configuration = TestConfiguration::with_finalizer(my_tpm_finalizer);

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

        // Initialize TPM, if not already initialized
        tpm_initialize!(context, PASSWORD, my_auth_callback);

        // Read policy from file
        let policy_json = read_policy(configuration.data_path(), "pol_action").expect("Failed to read policy!");

        // Set up callback
        let actions: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        match context.set_policy_action_callback(ActnCallback::with_data(my_actn_callback, actions.clone())) {
            Ok(_) => debug!("Action callback installed."),
            Err(error) => panic!("Failed to set up sign callback: {:?}", error),
        }

        // Import policy
        match context.import(pol_name, ImportData::from(&policy_json)) {
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
        let actions_ref = actions.try_lock().expect("Failed to borrow the result value!");
        assert!(!actions_ref.is_empty());
        assert!(actions_ref[0].eq_ignore_ascii_case("myaction"));
    });
}

// ==========================================================================
// Callback functions
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

/// The "sign" callback implementation used for testing
fn my_sign_callback(param: SignCallbackParam, private_key: &PrivateKey) -> Option<Vec<u8>> {
    debug!("(SIGN_CB) Signature for {:?} has been requested!", param.object_path);
    trace!("(SIGN_CB) Parameters: {:?}", param);

    let signature_value = create_signature(private_key, &param.hash_algo, param.challenge);

    if let Some(signature_bytes) = signature_value.as_ref() {
        debug!("(SIGN_CB) Computed signature value: {}", hex::encode(&signature_bytes[..]));
    } else {
        warn!("(SIGN_CB) Failed to generate the signature!");
    }

    signature_value
}

/// The "branch" callback implementation used for testing
fn my_bran_callback(param: BranCallbackParam, branches: &Arc<Mutex<Vec<String>>>) -> Option<usize> {
    debug!("(BRAN_CB) Branch for {:?} has been requested!", param.object_path);
    trace!("(BRAN_CB) Parameters: {:?}", param);

    if let Ok(mut branches) = branches.try_lock() {
        branches.clear();
        for name in param.branches.iter().enumerate() {
            branches.push(format!("#{},{}", name.0, name.1.trim()));
        }
    }

    Some(0usize)
}

/// The "action" callback implementation used for testing
fn my_actn_callback(param: ActnCallbackParam, actions: &Arc<Mutex<Vec<String>>>) -> bool {
    debug!("(ACTN_CB) Action for {:?} has been requested!", param.object_path);
    trace!("(ACTN_CB) Parameters: {:?}", param);

    if let Ok(mut actions) = actions.try_lock() {
        if let Some(action) = param.action {
            actions.push(action.trim().to_owned());
        }
    }

    param.action.is_some()
}
