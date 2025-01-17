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
use log::debug;
use rand::SeedableRng;
use rand_chacha::ChaChaRng;
use serial_test::serial;
use tss2_fapi_rs::{FapiContext, KeyFlags};

const KEY_FLAGS_RESTRICTED: &[KeyFlags] = &[KeyFlags::NoDA, KeyFlags::Restricted, KeyFlags::Sign];
const PCR_NO: [u32; 8usize] = [8, 9, 10, 11, 12, 13, 14, 15];

mk_auth_callback!(my_auth_callback, PASSWORD);
mk_tpm_finalizer!(my_tpm_finalizer, my_auth_callback);

// ==========================================================================
// Test cases
// ==========================================================================

/// Test the `pcr_extend()` to update a PCR with some random data
#[test]
#[serial]
#[named]
fn test_pcr_extend() {
    let _configuration = TestConfiguration::with_finalizer(my_tpm_finalizer);

    repeat_test!(|i| {
        // Initialize RNG
        let mut rng = ChaChaRng::from_seed(create_seed(i));

        // Create FAPI context
        let mut context = match FapiContext::new() {
            Ok(fpai_ctx) => fpai_ctx,
            Err(error) => panic!("Failed to create context: {:?}", error),
        };

        // Initialize TPM, if not already initialized
        tpm_initialize!(context, PASSWORD, my_auth_callback);

        // Extend PCR with data
        match context.pcr_extend(PCR_NO[i % PCR_NO.len()], &generate_bytes::<128usize>(&mut rng)[..], None) {
            Ok(_) => debug!("PCR extended."),
            Err(error) => panic!("PCR extension has failed: {:?}", error),
        }
    });
}

/// Test the `pcr_read()` function to read back the value of a PCR after it was updated via the `pcr_extend()` function
#[test]
#[serial]
#[named]
fn test_pcr_read() {
    let _configuration = TestConfiguration::with_finalizer(my_tpm_finalizer);

    repeat_test!(|i| {
        // Initialize RNG
        let mut rng = ChaChaRng::from_seed(create_seed(i));

        // Create FAPI context
        let mut context = match FapiContext::new() {
            Ok(fpai_ctx) => fpai_ctx,
            Err(error) => panic!("Failed to create context: {:?}", error),
        };

        // Initialize TPM, if not already initialized
        tpm_initialize!(context, PASSWORD, my_auth_callback);

        // Read current PCR value
        let pcr_value_0 = match context.pcr_read(PCR_NO[i % PCR_NO.len()], false) {
            Ok(data) => data,
            Err(error) => panic!("PCR read has failed: {:?}", error),
        };

        // Print PCR data #0
        assert!(pcr_value_0.0.len() >= 20usize);
        assert!(pcr_value_0.1.is_none());
        debug!("PCR value #0: 0x{}", hex::encode(&pcr_value_0.0[..]));

        // Extend PCR with data
        match context.pcr_extend(
            PCR_NO[i % PCR_NO.len()],
            &generate_bytes::<128usize>(&mut rng)[..],
            Some("{ \"test\": \"1st value\" }"),
        ) {
            Ok(_) => debug!("PCR extended."),
            Err(error) => panic!("PCR extension has failed: {:?}", error),
        }

        // Read current PCR value
        let pcr_value_1 = match context.pcr_read(PCR_NO[i % PCR_NO.len()], false) {
            Ok(data) => data,
            Err(error) => panic!("PCR read has failed: {:?}", error),
        };

        // Print PCR data #1
        assert!(pcr_value_1.0.len() >= 20usize);
        assert!(pcr_value_1.1.is_none());
        debug!("PCR value #1: 0x{}", hex::encode(&pcr_value_1.0[..]));

        // Extend PCR with data
        match context.pcr_extend(
            PCR_NO[i % PCR_NO.len()],
            &generate_bytes::<128usize>(&mut rng)[..],
            Some("{ \"test\": \"2nd value\" }"),
        ) {
            Ok(_) => debug!("PCR extended."),
            Err(error) => panic!("PCR extension has failed: {:?}", error),
        }

        // Read current PCR value
        let pcr_value_2 = match context.pcr_read(PCR_NO[i % PCR_NO.len()], false) {
            Ok(data) => data,
            Err(error) => panic!("PCR read has failed: {:?}", error),
        };

        // Print PCR data #2
        assert!(pcr_value_2.0.len() >= 20usize);
        assert!(pcr_value_2.1.is_none());
        debug!("PCR value #2: 0x{}", hex::encode(&pcr_value_2.0[..]));

        // Verify
        assert_eq!(pcr_value_0.0.len(), pcr_value_1.0.len());
        assert_eq!(pcr_value_1.0.len(), pcr_value_2.0.len());
        assert!(pcr_value_0.0[..].ne(&pcr_value_1.0[..]));
        assert!(pcr_value_1.0[..].ne(&pcr_value_2.0[..]));
        assert!(pcr_value_2.0[..].ne(&pcr_value_0.0[..]));
    });
}

/// Test the `pcr_read()` function to read back the value of a PCR after it was updated via the `pcr_extend()` function *and* request a PCR log
#[test]
#[serial]
#[named]
fn test_pcr_read_with_quote() {
    let _configuration = TestConfiguration::with_finalizer(my_tpm_finalizer);

    repeat_test!(|i| {
        // Initialize RNG
        let mut rng = ChaChaRng::from_seed(create_seed(i));

        // Create FAPI context
        let mut context = match FapiContext::new() {
            Ok(fpai_ctx) => fpai_ctx,
            Err(error) => panic!("Failed to create context: {:?}", error),
        };

        // Initialize TPM, if not already initialized
        tpm_initialize!(context, PASSWORD, my_auth_callback);

        // Extend PCR with data
        match context.pcr_extend(
            PCR_NO[i % PCR_NO.len()],
            &generate_bytes::<128usize>(&mut rng)[..],
            Some("{ \"test\": \"1st value\" }"),
        ) {
            Ok(_) => debug!("PCR extended."),
            Err(error) => panic!("PCR extension has failed: {:?}", error),
        }

        // Read current PCR value
        let pcr_value = match context.pcr_read(PCR_NO[i % PCR_NO.len()], true) {
            Ok(data) => data,
            Err(error) => panic!("PCR read has failed: {:?}", error),
        };

        // Verify
        assert!(pcr_value.0.len() >= 20usize);
        assert!(pcr_value.1.as_ref().map_or(false, |log_data| !log_data.is_empty()));
        debug!("PCR value: 0x{}", hex::encode(&pcr_value.0[..]));
        debug!("PCR log: {:?}", pcr_value.1.unwrap().to_string());
    });
}

/// Test the `quote()` function to create a quote of a set of several PCRs after they have been updated via the `pcr_extend()` function
#[test]
#[serial]
#[named]
fn test_pcr_quote() {
    let _configuration = TestConfiguration::with_finalizer(my_tpm_finalizer);

    repeat_test!(|i| {
        let key_path = &format!("HS/SRK/myTestAK{}", i);

        // Initialize RNG
        let mut rng = ChaChaRng::from_seed(create_seed(i));

        // Create FAPI context
        let mut context = match FapiContext::new() {
            Ok(fpai_ctx) => fpai_ctx,
            Err(error) => panic!("Failed to create context: {:?}", error),
        };

        // Initialize TPM, if not already initialized
        tpm_initialize!(context, PASSWORD, my_auth_callback);

        // Create attestation key, if not already created
        match context.create_key(key_path, Some(KEY_FLAGS_RESTRICTED), None, Some(PASSWORD)) {
            Ok(_) => debug!("Key created successfully."),
            Err(error) => panic!("Key creation has failed: {:?}", error),
        }

        // Extend all PCR's with some data
        for pcr_no in PCR_NO {
            match context.pcr_extend(pcr_no, &generate_bytes::<128usize>(&mut rng)[..], None) {
                Ok(_) => debug!("PCR extended."),
                Err(error) => panic!("PCR extension has failed: {:?}", error),
            }
        }

        // Prepare inputs
        let pcr_list = [
            PCR_NO[i % PCR_NO.len()],
            PCR_NO[(i + 1usize) % PCR_NO.len()],
            PCR_NO[(i + 2usize) % PCR_NO.len()],
        ];
        let qualifying_data = generate_bytes::<32usize>(&mut rng);

        // Create attestation
        let attestation = match context.quote(&pcr_list, None, key_path, Some(&qualifying_data[..]), false, false) {
            Ok(data) => data,
            Err(error) => panic!("Quote operation has failed: {:?}", error),
        };

        // Print attestation
        debug!("QuoteInfo: {:?}", attestation.0);
        debug!("Signature: {:?}", hex::encode(&attestation.1[..]));

        // Verify
        assert!(!attestation.0.is_empty());
        assert!(attestation.1.len() >= 20usize);
        assert!(attestation.2.is_none());
        assert!(attestation.3.is_none());
    });
}

/// Test the `quote()` function to create a quote of a set of several PCRs after they have been updated via the `pcr_extend()` function *and* also request the PCR log
#[test]
#[serial]
#[named]
fn test_pcr_quote_with_log() {
    let _configuration = TestConfiguration::with_finalizer(my_tpm_finalizer);

    repeat_test!(|i| {
        let key_path = &format!("HS/SRK/myTestAK{}", i);

        // Initialize RNG
        let mut rng = ChaChaRng::from_seed(create_seed(i));

        // Create FAPI context
        let mut context = match FapiContext::new() {
            Ok(fpai_ctx) => fpai_ctx,
            Err(error) => panic!("Failed to create context: {:?}", error),
        };

        // Initialize TPM, if not already initialized
        tpm_initialize!(context, PASSWORD, my_auth_callback);

        // Create attestation key, if not already created
        match context.create_key(key_path, Some(KEY_FLAGS_RESTRICTED), None, Some(PASSWORD)) {
            Ok(_) => debug!("Key created successfully."),
            Err(error) => panic!("Key creation has failed: {:?}", error),
        }

        // Extend all PCR's with some data
        for pcr_no in PCR_NO {
            match context.pcr_extend(pcr_no, &generate_bytes::<128usize>(&mut rng)[..], None) {
                Ok(_) => debug!("PCR extended."),
                Err(error) => panic!("PCR extension has failed: {:?}", error),
            }
        }

        // Prepare inputs
        let pcr_list = [
            PCR_NO[i % PCR_NO.len()],
            PCR_NO[(i + 1usize) % PCR_NO.len()],
            PCR_NO[(i + 2usize) % PCR_NO.len()],
        ];
        let qualifying_data = generate_bytes::<32usize>(&mut rng);

        // Create attestation
        let attestation = match context.quote(&pcr_list, None, key_path, Some(&qualifying_data[..]), true, true) {
            Ok(data) => data,
            Err(error) => panic!("Quote operation has failed: {:?}", error),
        };

        // Print attestation
        debug!("QuoteInfo: {:?}", attestation.0);
        debug!("Signature: {:?}", hex::encode(&attestation.1[..]));
        debug!("PCRLogOut: {:?}", attestation.2);
        debug!("CertAsPem: {:?}", attestation.3);

        // Verify
        assert!(!attestation.0.is_empty());
        assert!(attestation.1.len() >= 20usize);
        assert!(attestation.2.map_or(false, |log_data| !log_data.is_empty()));
        assert!(attestation.3.map_or(true, |cert| !cert.is_empty()));
    });
}

/// Test the `verify_quote()` function to verify a quote that was created via the `quote()` function
#[test]
#[serial]
#[named]
fn test_pcr_verify_quote() {
    let _configuration = TestConfiguration::with_finalizer(my_tpm_finalizer);

    repeat_test!(|i| {
        let key_path = &format!("HS/SRK/myTestAK{}", i);

        // Initialize RNG
        let mut rng = ChaChaRng::from_seed(create_seed(i));

        // Create FAPI context
        let mut context = match FapiContext::new() {
            Ok(fpai_ctx) => fpai_ctx,
            Err(error) => panic!("Failed to create context: {:?}", error),
        };

        // Initialize TPM, if not already initialized
        tpm_initialize!(context, PASSWORD, my_auth_callback);

        // Create attestation key, if not already created
        match context.create_key(key_path, Some(KEY_FLAGS_RESTRICTED), None, Some(PASSWORD)) {
            Ok(_) => debug!("Key created successfully."),
            Err(error) => panic!("Key creation has failed: {:?}", error),
        }

        // Extend all PCR's with some data
        for pcr_no in PCR_NO {
            match context.pcr_extend(pcr_no, &generate_bytes::<128usize>(&mut rng)[..], None) {
                Ok(_) => debug!("PCR extended."),
                Err(error) => panic!("PCR extension has failed: {:?}", error),
            }
        }

        // Prepare inputs
        let pcr_list = [
            PCR_NO[i % PCR_NO.len()],
            PCR_NO[(i + 1usize) % PCR_NO.len()],
            PCR_NO[(i + 2usize) % PCR_NO.len()],
        ];
        let qualifying_data = generate_bytes::<32usize>(&mut rng);

        // Create attestation
        let attestation = match context.quote(&pcr_list, None, key_path, Some(&qualifying_data[..]), false, false) {
            Ok(data) => data,
            Err(error) => panic!("Quote operation has failed: {:?}", error),
        };

        // Print attestation
        debug!("QuoteInfo: {:?}", attestation.0);
        debug!("Signature: {:?}", hex::encode(&attestation.1[..]));

        // Verify attestation
        let verify_result = match context.verify_quote(key_path, Some(&qualifying_data[..]), &attestation.0, &attestation.1[..], None) {
            Ok(data) => data,
            Err(error) => panic!("Verification of quote has failed: {:?}", error),
        };

        // Check result
        debug!("Quote valid: {:?}", verify_result);
        assert!(verify_result);

        // Modify signature value
        let signature_mod = increment(&attestation.1[..]);

        // Verify attestation (again)
        let verify_result = match context.verify_quote(key_path, Some(&qualifying_data[..]), &attestation.0, &signature_mod[..], None) {
            Ok(data) => data,
            Err(error) => panic!("Verification of quote has failed: {:?}", error),
        };

        // Check result
        debug!("Quote valid: {:?}", verify_result);
        assert!(!verify_result);

        // Modify qualifying data
        let qualifying_mod = increment(&qualifying_data[..]);

        // Verify attestation (again)
        let verify_result = match context.verify_quote(key_path, Some(&qualifying_mod[..]), &attestation.0, &attestation.1[..], None) {
            Ok(data) => data,
            Err(error) => panic!("Verification of quote has failed: {:?}", error),
        };

        // Check result
        debug!("Quote valid: {:?}", verify_result);
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
