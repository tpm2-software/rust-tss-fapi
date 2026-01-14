/* SPDX-License-Identifier: BSD-3-Clause */
/***********************************************************************************************
 * Copyright 2024-2026 Fraunhofer SIT, sponsored by the ELISA and ProSeCA research projects.
 * All rights reserved.
 **********************************************************************************************/

pub mod common;

use common::{
    crypto::{KeyType, get_key_type},
    param::PASSWORD,
    setup::TestConfiguration,
    tempfile::TempFile,
};
use function_name::named;
use json::JsonValue;
use log::{debug, warn};
use serial_test::serial;
use std::{
    fs,
    process::{Command, Stdio},
};
use tss2_fapi_rs::{BaseErrorCode, ErrorCode, FapiContext, KeyFlags};

mk_auth_callback!(my_auth_callback, PASSWORD);
mk_tpm_finalizer!(my_tpm_finalizer, my_auth_callback);

const KEY_FLAGS: &[KeyFlags] = &[KeyFlags::NoDA, KeyFlags::Decrypt];

// ==========================================================================
// Test cases
// ==========================================================================

/// Test the `export_key()` and `set_certificate()` functions to generate and import a certificate for an existing key
#[test]
#[serial]
#[named]
fn test_set_certificate() {
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

        // Create the key, if not already created
        match context.create_key(key_path, Some(KEY_FLAGS), None, Some(PASSWORD)) {
            Ok(_) => debug!("Key created successfully."),
            Err(error) => panic!("Key creation has failed: {:?}", error),
        }

        // Export public key
        let json_public_key = match context.export_key(key_path, None) {
            Ok(exported) => exported,
            Err(error) => panic!("Key export (public) has failed: {:?}", error),
        };

        // Create the certificate
        let pem_data = generate_certificate(&configuration, json_public_key, &format!("User {}", i)).expect("Failed to generate certificate!");
        debug!("Certificate: {:?}", pem_data);

        // Set the certificate
        match context.set_certificate(key_path, Some(&pem_data[..])) {
            Ok(_) => debug!("Certificate set successfully."),
            Err(error) => panic!("Setting certificate has failed: {:?}", error),
        }
    });
}

/// Test the `get_certificate()` function to read back the certificate that was previosuly set via the `set_certificate()` function
#[test]
#[serial]
#[named]
fn test_get_certificate() {
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

        // Create the key, if not already created
        match context.create_key(key_path, Some(KEY_FLAGS), None, Some(PASSWORD)) {
            Ok(_) => debug!("Key created successfully."),
            Err(error) => panic!("Key creation has failed: {:?}", error),
        }

        // Export public key
        let json_public_key = match context.export_key(key_path, None) {
            Ok(exported) => exported,
            Err(error) => panic!("Key export (public) has failed: {:?}", error),
        };

        // Create the certificate
        let pem_data = generate_certificate(&configuration, json_public_key, &format!("User {}", i)).expect("Failed to generate certificate!");
        debug!("Certificate: {:?}", pem_data);

        // Set the certificate
        match context.set_certificate(key_path, Some(&pem_data[..])) {
            Ok(_) => debug!("Certificate set successfully."),
            Err(error) => panic!("Setting certificate has failed: {:?}", error),
        }

        // Get the certificate
        let recovered_cert = match context.get_certificate(key_path) {
            Ok(cert_data) => cert_data,
            Err(error) => panic!("Getting certificate has failed: {:?}", error),
        };

        // Verify
        debug!("Certificate: {:?}", recovered_cert);
        assert!(recovered_cert.expect("No certificate data avialble!").trim().eq_ignore_ascii_case(pem_data.trim()))
    });
}

/// Test the `set_certificate()` function to remove the certificate that was previosuly set via the `set_certificate()` function
#[test]
#[serial]
#[named]
fn test_remove_certificate() {
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

        // Create the key, if not already created
        match context.create_key(key_path, Some(KEY_FLAGS), None, Some(PASSWORD)) {
            Ok(_) => debug!("Key created successfully."),
            Err(error) => panic!("Key creation has failed: {:?}", error),
        }

        // Export public key
        let json_public_key = match context.export_key(key_path, None) {
            Ok(exported) => exported,
            Err(error) => panic!("Key export (public) has failed: {:?}", error),
        };

        // Create the certificate
        let pem_data = generate_certificate(&configuration, json_public_key, &format!("User {}", i)).expect("Failed to generate certificate!");
        debug!("Certificate: {:?}", pem_data);

        // Set the certificate
        match context.set_certificate(key_path, Some(&pem_data[..])) {
            Ok(_) => debug!("Certificate set successfully."),
            Err(error) => panic!("Setting certificate has failed: {:?}", error),
        }

        // Get the certificate
        let recovered_cert = match context.get_certificate(key_path) {
            Ok(cert_data) => cert_data,
            Err(error) => panic!("Getting certificate has failed: {:?}", error),
        };

        // Verify
        assert!(recovered_cert.is_some());

        // Remove the certificate
        match context.set_certificate(key_path, None) {
            Ok(_) => debug!("Certificate removed."),
            Err(error) => panic!("Removing certificate has failed: {:?}", error),
        }

        // Get the certificate (again)
        let recovered_cert = match context.get_certificate(key_path) {
            Ok(cert_data) => cert_data,
            Err(ErrorCode::FapiError(BaseErrorCode::NoCert)) => None,
            Err(error) => panic!("Getting certificate has failed: {:?}", error),
        };

        // Verify
        assert!(recovered_cert.is_none());
    });
}

/// Test the `get_platform_certificates()` function to retrieve the platform certificates
#[test]
#[serial]
#[named]
fn test_get_platform_certificates() {
    let _configuration = TestConfiguration::with_finalizer(my_tpm_finalizer);

    repeat_test!(|_i| {
        // Create FAPI context
        let mut context = match FapiContext::new() {
            Ok(fpai_ctx) => fpai_ctx,
            Err(error) => panic!("Failed to create context: {:?}", error),
        };

        // Initialize TPM, if not already initialized
        tpm_initialize!(context, PASSWORD, my_auth_callback);

        // Get the certificate
        let platform_certs = match context.get_platform_certificates() {
            Ok(cert_data) => cert_data,
            Err(error) => panic!("Getting certificate has failed: {:?}", error),
        };

        // Verify
        match platform_certs {
            Some(cert_data) => debug!("Certificate: {}", hex::encode(&cert_data[..])),
            None => warn!("No platform certificates available."),
        }
    });
}

// ==========================================================================
// Helper functions
// ==========================================================================

fn generate_certificate(config: &TestConfiguration, public_key: JsonValue, common_name: &str) -> Option<String> {
    let common_name = common_name.trim();
    assert!(!common_name.is_empty() && common_name.chars().all(|c| char::is_ascii_alphanumeric(&c) || c == '\x20'));

    let key_suffix = get_key_suffix(config).expect("Failed to determine key type!");
    let public_key = public_key["pem_ext_public"].as_str()?;
    let tmp_pubkey = TempFile::with_suffix(config.work_path(), "pem")?;

    fs::write(tmp_pubkey.path(), public_key).ok()?;

    let cert_data = Command::new("openssl")
        .arg("x509")
        .arg("-new")
        .arg("-CA")
        .arg(config.data_path().join("keys").join(format!("ca_key_{}.pem", key_suffix)))
        .arg("-force_pubkey")
        .arg(tmp_pubkey.path())
        .arg("-subj")
        .arg(format!("/CN={}", common_name))
        .stderr(Stdio::null())
        .stdout(Stdio::piped())
        .output()
        .ok()?;

    match cert_data.status.success() {
        true => String::from_utf8(cert_data.stdout).ok(),
        _ => None,
    }
}

fn get_key_suffix(config: &TestConfiguration) -> Option<&'static str> {
    match get_key_type(config.prof_name()) {
        Some(KeyType::RsaKey) => Some("rsa"),
        Some(KeyType::EccKey) => Some("ecc"),
        _ => None,
    }
}
