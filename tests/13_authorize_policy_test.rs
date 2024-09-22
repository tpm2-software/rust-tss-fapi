/* SPDX-License-Identifier: BSD-3-Clause */
/*******************************************************************************
 * Copyright 2024, Fraunhofer SIT sponsored by the ELISA research project
 * All rights reserved.
 ******************************************************************************/

pub mod common;

use common::{
    param::PASSWORD,
    random::{create_seed, generate_bytes},
    setup::TestConfiguration,
};
use function_name::named;
use json::{number::Number, Error as JsonError, JsonValue};
use log::{debug, trace};
use rand::SeedableRng;
use rand_chacha::ChaChaRng;
use serial_test::serial;
use sha2::{Digest, Sha256};
use std::sync::{
    atomic::{AtomicI64, Ordering},
    Arc,
};
use tss2_fapi_rs::{ActnCallback, ActnCallbackParam, FapiContext, KeyFlags};

mk_auth_callback!(my_auth_callback, PASSWORD);
mk_tpm_finalizer!(my_tpm_finalizer, my_auth_callback);

const KEY_FLAGS_SIGN: &[KeyFlags] = &[KeyFlags::NoDA, KeyFlags::Sign];

// ==========================================================================
// Test cases
// ==========================================================================

/// Test `authorize_policy()` with a `POLICYAUTHORIZE` policy that contains a public key (PEM)
#[test]
#[serial]
#[named]
fn test_policy_authorize_pubkey() {
    let _configuration = TestConfiguration::with_finalizer(my_tpm_finalizer);

    repeat_test!(|i| {
        let key_path = [
            &format!("/HS/SRK/myPolicySignKey{}", i),
            &format!("HS/SRK/myTestKey{}", i),
        ];
        let pol_name = [
            &format!("/policy/pol_authorize{}", i),
            &format!("/policy/pol_name_hash{}", i),
        ];

        // Initialize RNG
        let mut rng = ChaChaRng::from_seed(create_seed(i));

        // Create FAPI context
        let mut context = match FapiContext::new() {
            Ok(fpai_ctx) => fpai_ctx,
            Err(error) => panic!("Failed to create context: {:?}", error),
        };

        // Initialize TPM, if not already initialized
        tpm_initialize!(context, PASSWORD, my_auth_callback);

        // Set up "action" callback
        let action_triggered = Arc::new(AtomicI64::new(0i64));
        match context.set_policy_action_callback(ActnCallback::with_data(
            my_actn_callback,
            action_triggered.clone(),
        )) {
            Ok(_) => debug!("Action callback installed."),
            Err(error) => panic!("Failed to set up sign callback: {:?}", error),
        }

        // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        // Step #1: Create the policy siging key [backend]
        // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        // Create policy signing key, if not already created
        match context.create_key(&key_path[0], Some(KEY_FLAGS_SIGN), None, Some(PASSWORD)) {
            Ok(_) => debug!("Key created."),
            Err(error) => panic!("Key creation has failed: {:?}", error),
        }

        // Export the public key from TPM
        let policy_siging_public_key = match context.export_key(&key_path[0], None) {
            Ok(data) => data["pem_ext_public"]
                .as_str()
                .expect("Failed to find the public key!")
                .to_owned(),
            Err(error) => panic!("Key export has failed: {:?}", error),
        };

        // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        // Step #2: Create the user key [frontend]
        // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        // Create the POLICYAUTHORIZE policy with public key
        let policy_authorize_json =
            create_authorize_policy_with_public_key(&policy_siging_public_key[..], None)
                .expect("Failed to create policy!");

        // Import policy
        match context.import(&pol_name[0], &policy_authorize_json) {
            Ok(_) => debug!("Policy imported."),
            Err(error) => panic!("Failed to import policy: {:?}", error),
        };

        // Create the key, if not already created
        match context.create_key(&key_path[1], Some(KEY_FLAGS_SIGN), Some(&pol_name[0]), None) {
            Ok(_) => debug!("Key created with policy."),
            Err(error) => panic!("Key creation has failed: {:?}", error),
        }

        // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        // Step #3: Authorize the new policy [backend]
        // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        // Create the POLICYNAMEHASH policy
        let policy_name_hash_json =
            create_name_hash_policy(key_path[1]).expect("Failed to create policy!");

        // Import new policy
        match context.import(&pol_name[1], &policy_name_hash_json) {
            Ok(_) => debug!("Policy imported."),
            Err(error) => panic!("Failed to import policy: {:?}", error),
        };

        // Authorize new policy
        match context.authorize_policy(&pol_name[1], key_path[0], None) {
            Ok(_) => debug!("Policy authorized."),
            Err(error) => panic!("Failed to authorize policy: {:?}", error),
        }

        // Delete policy signing key from TPM (no longer required!)
        match context.delete(&key_path[0]) {
            Ok(_) => debug!("Policy siging key deleted."),
            Err(error) => panic!("Failed to delete authorized policy: {:?}", error),
        };

        // Export the authorized policy
        let authorized_policy_json = match context.export_policy(&pol_name[1]) {
            Ok(policy) => policy,
            Err(error) => panic!("Failed to export authorized policy: {:?}", error),
        };

        // Print authroized policy
        trace!("{:?}", authorized_policy_json);

        // Delete policy from TPM (for testing purposes!)
        match context.delete(&pol_name[1]) {
            Ok(_) => debug!("Authorized policy deleted."),
            Err(error) => panic!("Failed to delete authorized policy: {:?}", error),
        };

        // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        // Step #4: Import new policy and use key [frontend]
        // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        // Compute digest to be signed
        let digest_tbs = Sha256::digest(&generate_bytes::<256usize>(&mut rng)[..]);
        debug!("Digest to be signed: {}", hex::encode(&digest_tbs[..]));

        // Create the signature (expected to fail!)
        match context.sign(&key_path[1], None, &digest_tbs, false, false) {
            Ok(_) => panic!("Signature was created succesfully *without* an authorized policy!"),
            Err(error) => debug!("Failed to create the signature (expected): {:?}", error),
        };

        // Import authorized policy
        match context.import(&pol_name[1], &authorized_policy_json) {
            Ok(_) => debug!("Authorized policy imported."),
            Err(error) => panic!("Failed to import authorized policy: {:?}", error),
        };

        // Create the signature (this time it is supposed to work!)
        let signature = match context.sign(&key_path[1], None, &digest_tbs, false, false) {
            Ok(value) => value,
            Err(error) => panic!("Failed to create the signature: {:?}", error),
        };

        // Validate signature data
        let signature_data: &[u8] = signature.0.as_ref();
        assert!(signature_data.len() >= 32usize);
        debug!("Signature value: {}", hex::encode(signature_data));
    });
}

/// Test `authorize_policy()` with a `POLICYAUTHORIZE` policy that contains a key path
#[test]
#[serial]
#[named]
fn test_policy_authorize_path() {
    let _configuration = TestConfiguration::with_finalizer(my_tpm_finalizer);

    repeat_test!(|i| {
        let key_path = [
            &format!("/HS/SRK/myPolicySignKey{}", i),
            &format!("HS/SRK/myTestKey{}", i),
        ];
        let pol_name = [
            &format!("/policy/pol_authorize{}", i),
            &format!("/policy/pol_name_hash{}", i),
        ];

        // Initialize RNG
        let mut rng = ChaChaRng::from_seed(create_seed(i));

        // Create FAPI context
        let mut context = match FapiContext::new() {
            Ok(fpai_ctx) => fpai_ctx,
            Err(error) => panic!("Failed to create context: {:?}", error),
        };

        // Initialize TPM, if not already initialized
        tpm_initialize!(context, PASSWORD, my_auth_callback);

        // Set up "action" callback
        let action_triggered = Arc::new(AtomicI64::new(0i64));
        match context.set_policy_action_callback(ActnCallback::with_data(
            my_actn_callback,
            action_triggered.clone(),
        )) {
            Ok(_) => debug!("Action callback installed."),
            Err(error) => panic!("Failed to set up sign callback: {:?}", error),
        }

        // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        // Step #1: Create the policy siging key [backend]
        // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        // Create policy signing key, if not already created
        match context.create_key(&key_path[0], Some(KEY_FLAGS_SIGN), None, Some(PASSWORD)) {
            Ok(_) => debug!("Key created."),
            Err(error) => panic!("Key creation has failed: {:?}", error),
        }

        // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        // Step #2: Create the user key [frontend]
        // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        // Create the POLICYAUTHORIZE policy with key path
        let policy_authorize_json = create_authorize_policy_with_key_path(&key_path[0], None)
            .expect("Failed to create policy!");

        // Import policy
        match context.import(&pol_name[0], &policy_authorize_json) {
            Ok(_) => debug!("Policy imported."),
            Err(error) => panic!("Failed to import policy: {:?}", error),
        };

        // Create the key, if not already created
        match context.create_key(&key_path[1], Some(KEY_FLAGS_SIGN), Some(&pol_name[0]), None) {
            Ok(_) => debug!("Key created with policy."),
            Err(error) => panic!("Key creation has failed: {:?}", error),
        }

        // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        // Step #3: Authorize the new policy [backend]
        // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        // Create the POLICYNAMEHASH policy
        let policy_name_hash_json =
            create_name_hash_policy(key_path[1]).expect("Failed to create policy!");

        // Import new policy
        match context.import(&pol_name[1], &policy_name_hash_json) {
            Ok(_) => debug!("Policy imported."),
            Err(error) => panic!("Failed to import policy: {:?}", error),
        };

        // Authorize new policy
        match context.authorize_policy(&pol_name[1], key_path[0], None) {
            Ok(_) => debug!("Policy authorized."),
            Err(error) => panic!("Failed to authorize policy: {:?}", error),
        }

        // Delete policy signing key from TPM (no longer required!)
        match context.delete(&key_path[0]) {
            Ok(_) => debug!("Policy siging key deleted."),
            Err(error) => panic!("Failed to delete authorized policy: {:?}", error),
        };

        // Export the authorized policy
        let authorized_policy_json = match context.export_policy(&pol_name[1]) {
            Ok(policy) => policy,
            Err(error) => panic!("Failed to export authorized policy: {:?}", error),
        };

        // Print authroized policy
        trace!("{:?}", authorized_policy_json);

        // Delete policy from TPM (for testing purposes!)
        match context.delete(&pol_name[1]) {
            Ok(_) => debug!("Authorized policy deleted."),
            Err(error) => panic!("Failed to delete authorized policy: {:?}", error),
        };

        // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        // Step #4: Import new policy and use key [frontend]
        // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        // Compute digest to be signed
        let digest_tbs = Sha256::digest(&generate_bytes::<256usize>(&mut rng)[..]);
        debug!("Digest to be signed: {}", hex::encode(&digest_tbs[..]));

        // Create the signature (expected to fail!)
        match context.sign(&key_path[1], None, &digest_tbs, false, false) {
            Ok(_) => panic!("Signature was created succesfully *without* an authorized policy!"),
            Err(error) => debug!("Failed to create the signature (expected): {:?}", error),
        };

        // Import authorized policy
        match context.import(&pol_name[1], &authorized_policy_json) {
            Ok(_) => debug!("Authorized policy imported."),
            Err(error) => panic!("Failed to import authorized policy: {:?}", error),
        };

        // Create the signature (this time it is supposed to work!)
        let signature = match context.sign(&key_path[1], None, &digest_tbs, false, false) {
            Ok(value) => value,
            Err(error) => panic!("Failed to create the signature: {:?}", error),
        };

        // Validate signature data
        let signature_data: &[u8] = signature.0.as_ref();
        assert!(signature_data.len() >= 32usize);
        debug!("Signature value: {}", hex::encode(signature_data));
    });
}

// ==========================================================================
// Helper functions
// ==========================================================================

const POLICY_AUTHORIZE_TEMPLATE: &str =
    "{\"description\":\"Description pol_authorize\",\"policy\":[{\"type\":\"POLICYAUTHORIZE\"}]}";
const POLICY_NAME_HASH_TEMPLATE: &str = "{\"description\":\"Description pol_name_hash\",\"policy\":[{\"type\":\"POLICYNAMEHASH\",\"namePaths\":[]},{\"type\":\"POLICYACTION\",\"action\":\"myaction\"}]}";

/// Create new POLICYAUTHORIZE policy with "keyPEM"
fn create_authorize_policy_with_public_key(
    public_key_pem: &str,
    policy_ref: Option<&[u8]>,
) -> Result<JsonValue, JsonError> {
    _create_authorize_policy("keyPEM", public_key_pem, policy_ref)
}

/// Create new POLICYAUTHORIZE policy with "keyPath"
fn create_authorize_policy_with_key_path(
    key_path: &str,
    policy_ref: Option<&[u8]>,
) -> Result<JsonValue, JsonError> {
    _create_authorize_policy("keyPath", key_path, policy_ref)
}

/// Create new POLICYAUTHORIZE policy
fn _create_authorize_policy(
    policy_entry: &str,
    policy_value: &str,
    policy_ref: Option<&[u8]>,
) -> Result<JsonValue, JsonError> {
    let mut policy_json = json::parse(POLICY_AUTHORIZE_TEMPLATE)?;
    policy_json["policy"][0usize]
        .insert(policy_entry, JsonValue::String(policy_value.to_owned()))?;
    if let Some(data) = policy_ref {
        let values = data
            .into_iter()
            .map(|val| JsonValue::Number(Number::from(*val)))
            .collect::<Vec<JsonValue>>();
        policy_json["policy"][0usize].insert("policyRef", JsonValue::Array(values))?;
    }
    Ok(policy_json)
}

/// Create new POLICYNAMEHASH policy
fn create_name_hash_policy(key_path: &str) -> Result<JsonValue, JsonError> {
    let mut policy_json = json::parse(POLICY_NAME_HASH_TEMPLATE)?;
    policy_json["policy"][0usize]["namePaths"].push(JsonValue::String(key_path.to_owned()))?;
    Ok(policy_json)
}

/// The "action" callback implementation to be used for testing
fn my_actn_callback(param: ActnCallbackParam, triggered: &Arc<AtomicI64>) -> bool {
    debug!(
        "(ACTN_CB) Action for {:?} has been requested!",
        param.object_path
    );
    trace!("(ACTN_CB) Parameters: {:?}", param);
    triggered.fetch_add(1i64, Ordering::SeqCst) >= 0i64
}
