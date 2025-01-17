/* SPDX-License-Identifier: BSD-3-Clause */
/*******************************************************************************
 * Copyright 2024-2025 Fraunhofer SIT, sponsored by the ELISA research project.
 * All rights reserved.
 ******************************************************************************/

pub mod common;

use common::{
    crypto::{get_key_type, KeyType},
    param::PASSWORD,
    random::{create_seed, generate_bytes},
    setup::TestConfiguration,
};
use function_name::named;
use log::{debug, trace};
use rand::SeedableRng;
use rand_chacha::ChaChaRng;
use serial_test::serial;
use sha2::{Digest, Sha256};
use tss2_fapi_rs::{FapiContext, KeyFlags, PaddingFlags};

mk_auth_callback!(my_auth_callback, PASSWORD);
mk_tpm_finalizer!(my_tpm_finalizer, my_auth_callback);

const KEY_FLAGS_SIGN: &[KeyFlags] = &[KeyFlags::NoDA, KeyFlags::Sign];
const PADDING_RSAPSS: &[PaddingFlags] = &[PaddingFlags::RsaPss];

// ==========================================================================
// Test cases
// ==========================================================================

/// Test the `sign()` function to sign some random data with a suitable key and the matching padding algorithm
#[test]
#[serial]
#[named]
fn test_sign() {
    let configuration = TestConfiguration::with_finalizer(my_tpm_finalizer);

    repeat_test!(|i| {
        let key_path = &format!("HS/SRK/mySigKey{}", i);

        // Initialize RNG
        let mut rng = ChaChaRng::from_seed(create_seed(i));

        // Create FAPI context
        let mut context = match FapiContext::new() {
            Ok(fpai_ctx) => fpai_ctx,
            Err(error) => panic!("Failed to create context: {:?}", error),
        };

        // Initialize TPM, if not already initialized
        tpm_initialize!(context, PASSWORD, my_auth_callback);

        // Create new key, if not already created
        match context.create_key(key_path, Some(KEY_FLAGS_SIGN), None, Some(PASSWORD)) {
            Ok(_) => debug!("Key created."),
            Err(error) => panic!("Key creation has failed: {:?}", error),
        }

        // Compute digest to be signed
        let digest = Sha256::digest(&generate_bytes::<256usize>(&mut rng)[..]);
        debug!("Digest to be signed: {}", hex::encode(&digest[..]));

        // Select padding algorithm
        let padding_algo = get_padding_algorithm(&configuration);
        trace!("Padding algorithm: {:?}", padding_algo);

        // Create the signature
        let signature = match context.sign(key_path, padding_algo, &digest, false, false) {
            Ok(value) => value,
            Err(error) => panic!("Failed to create the signature: {:?}", error),
        };

        // Validate signature data
        let signature_data: &[u8] = signature.0.as_ref();
        assert!(signature_data.len() >= 32usize);
        debug!("Signature value: {}", hex::encode(signature_data));

        // Verify absent data
        assert!(signature.1.is_none());
        assert!(signature.2.is_none());
    });
}

/// Test the `sign()` function to sign some random data with a suitable key and the matching padding algorithm; also request the signer's private key (and certificate).
#[test]
#[serial]
#[named]
fn test_sign_with_pubkey() {
    let configuration = TestConfiguration::with_finalizer(my_tpm_finalizer);

    repeat_test!(|i| {
        let key_path = &format!("HS/SRK/mySigKey{}", i);

        // Initialize RNG
        let mut rng = ChaChaRng::from_seed(create_seed(i));

        // Create FAPI context
        let mut context = match FapiContext::new() {
            Ok(fpai_ctx) => fpai_ctx,
            Err(error) => panic!("Failed to create context: {:?}", error),
        };

        // Initialize TPM, if not already initialized
        tpm_initialize!(context, PASSWORD, my_auth_callback);

        // Create new key, if not already created
        match context.create_key(key_path, Some(KEY_FLAGS_SIGN), None, Some(PASSWORD)) {
            Ok(_) => debug!("Key created."),
            Err(error) => panic!("Key creation has failed: {:?}", error),
        }

        // Compute digest to be signed
        let digest = Sha256::digest(&generate_bytes::<256usize>(&mut rng)[..]);
        debug!("Digest to be signed: {}", hex::encode(&digest[..]));

        // Select padding algorithm
        let padding_algo = get_padding_algorithm(&configuration);
        trace!("Padding algorithm: {:?}", padding_algo);

        // Create the signature
        let signature = match context.sign(key_path, padding_algo, &digest, true, true) {
            Ok(value) => value,
            Err(error) => panic!("Failed to create the signature: {:?}", error),
        };

        // Validate signature data
        let signature_data: &[u8] = signature.0.as_ref();
        assert!(signature_data.len() >= 32usize);
        debug!("Signature value: {}", hex::encode(signature_data));

        // Print the public key
        assert!(signature.1.as_ref().map_or(false, |pem_data| !pem_data.is_empty()));
        debug!("Public key: \"{}\"", signature.1.unwrap_or_default());

        // Print the certificate, if any:
        debug!("Certificate: \"{}\"", signature.2.unwrap_or_else(String::new).trim());
    });
}

/// Test the `verify_signature()` function with a signature that was created via the `sign()` function
#[test]
#[serial]
#[named]
fn test_verify_signature() {
    let configuration = TestConfiguration::with_finalizer(my_tpm_finalizer);

    repeat_test!(|i| {
        let key_path = &format!("HS/SRK/mySigKey{}", i);

        // Initialize RNG
        let mut rng = ChaChaRng::from_seed(create_seed(i));

        // Create FAPI context
        let mut context = match FapiContext::new() {
            Ok(fpai_ctx) => fpai_ctx,
            Err(error) => panic!("Failed to create context: {:?}", error),
        };

        // Initialize TPM, if not already initialized
        tpm_initialize!(context, PASSWORD, my_auth_callback);

        // Create new key, if not already created
        match context.create_key(key_path, Some(KEY_FLAGS_SIGN), None, Some(PASSWORD)) {
            Ok(_) => debug!("Key created successfully."),
            Err(error) => panic!("Key creation has failed: {:?}", error),
        }

        // Compute digest to be signed
        let digest = Sha256::digest(&generate_bytes::<256usize>(&mut rng)[..]);
        debug!("Digest to be signed: {}", hex::encode(&digest[..]));

        // Select padding algorithm
        let padding_algo = get_padding_algorithm(&configuration);
        trace!("Padding algorithm: {:?}", padding_algo);

        // Create the signature
        let signature = match context.sign(key_path, padding_algo, &digest, false, false) {
            Ok(value) => value,
            Err(error) => panic!("Failed to create the signature: {:?}", error),
        };

        // Print signature data
        debug!("Signature value: {}", hex::encode(&signature.0[..]));

        // Verify the signature
        let verify_result = match context.verify_signature(key_path, &digest, &signature.0[..]) {
            Ok(value) => value,
            Err(error) => panic!("Failed to verify the signature: {:?}", error),
        };

        // Check result
        debug!("Signature valid: {:?}", verify_result);
        assert!(verify_result);

        // Modify signature value
        let signature_mod = increment(&signature.0[..]);

        // Verify the signature (again)
        let verify_result = match context.verify_signature(key_path, &digest, &signature_mod[..]) {
            Ok(value) => value,
            Err(error) => panic!("Failed to verify the signature: {:?}", error),
        };

        // Check result
        debug!("Signature valid: {:?}", verify_result);
        assert!(!verify_result);
    });
}

// ==========================================================================
// Helper functions
// ==========================================================================

fn increment(data: &[u8]) -> Vec<u8> {
    let mut mut_data: Vec<u8> = data.into();
    _increment(mut_data.last_mut().expect("Data must not be empty!"));
    mut_data
}

fn _increment(data: &mut u8) {
    *data = data.wrapping_add(1u8);
}

fn get_padding_algorithm(config: &TestConfiguration) -> Option<&'static [PaddingFlags]> {
    match get_key_type(config.prof_name()) {
        Some(KeyType::RsaKey) => Some(PADDING_RSAPSS),
        _ => None,
    }
}
