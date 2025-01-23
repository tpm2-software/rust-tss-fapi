/* SPDX-License-Identifier: BSD-3-Clause */
/*******************************************************************************
 * Copyright 2024-2025 Fraunhofer SIT, sponsored by the ELISA and ProSeCA research projects.
 * All rights reserved.
 ******************************************************************************/

pub mod common;

use common::{
    param::PASSWORD,
    random::{create_seed, generate_bytes},
    setup::TestConfiguration,
};
use function_name::named;
use log::{debug, warn};
use rand::SeedableRng;
use rand_chacha::ChaChaRng;
use serial_test::serial;
use tss2_fapi_rs::{FapiContext, KeyFlags};

mk_auth_callback!(my_auth_callback, PASSWORD);
mk_tpm_finalizer!(my_tpm_finalizer, my_auth_callback);

const KEY_FLAGS_ENCR: &[KeyFlags] = &[KeyFlags::NoDA, KeyFlags::Decrypt];

// ==========================================================================
// Test cases
// ==========================================================================

/// Test the `encrypt()` function to encrypt a random message with a suitable key
#[test]
#[serial]
#[named]
fn test_encrypt() {
    let configuration = TestConfiguration::with_finalizer(my_tpm_finalizer);
    skip_test_ifeq!(configuration, "ECC");

    repeat_test!(|i| {
        let key_path = &format!("HS/SRK/myEncKey{}", i);

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
        match context.create_key(key_path, Some(KEY_FLAGS_ENCR), None, Some(PASSWORD)) {
            Ok(_) => debug!("Key created."),
            Err(error) => panic!("Key creation has failed: {:?}", error),
        }

        // Generate plain-text
        let plaintext: [u8; 128usize] = generate_bytes(&mut rng);

        // Encrypt the plaintext
        let ciphertext = match context.encrypt(key_path, &plaintext) {
            Ok(value) => value,
            Err(error) => panic!("Failed to encrypt plaintext: {:?}", error),
        };

        // Validate the ciphertext
        debug!("Ciphertext: {}", hex::encode(&ciphertext[..]));
        assert!(ciphertext.len() >= plaintext.len());
    });
}

/// Test the `decrypt()` function on some ciphertext that was created via the `encrypt()` function with a suitable key
#[test]
#[serial]
#[named]
fn test_decrypt() {
    let configuration = TestConfiguration::with_finalizer(my_tpm_finalizer);
    skip_test_ifeq!(configuration, "ECC");

    repeat_test!(|i| {
        let key_path = &format!("HS/SRK/myEncKey{}", i);

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
        match context.create_key(key_path, Some(KEY_FLAGS_ENCR), None, Some(PASSWORD)) {
            Ok(_) => debug!("Key created."),
            Err(error) => panic!("Key creation has failed: {:?}", error),
        }

        // Generate plain-text
        let plaintext: [u8; 128usize] = generate_bytes(&mut rng);

        // Encrypt the plaintext
        let ciphertext = match context.encrypt(key_path, &plaintext[..]) {
            Ok(value) => value,
            Err(error) => panic!("Failed to encrypt plaintext: {:?}", error),
        };

        // Validate ciphertext
        debug!("Ciphertext: {}", hex::encode(&ciphertext[..]));
        assert!(ciphertext.len() >= plaintext.len());

        // Decrypt the plaintext
        let decrypted = match context.decrypt(key_path, &ciphertext) {
            Ok(value) => value,
            Err(error) => panic!("Failed to decrypt ciphertext: {:?}", error),
        };

        // Validate the ciphertext
        debug!("Decrypted: {}", hex::encode(&decrypted[..]));
        assert!(decrypted[..].eq(&plaintext[..]));
    });
}
