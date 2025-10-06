/* SPDX-License-Identifier: BSD-3-Clause */
/***********************************************************************************************
 * Copyright 2024-2025 Fraunhofer SIT, sponsored by the ELISA and ProSeCA research projects.
 * All rights reserved.
 **********************************************************************************************/

use env_logger::Builder as EnvLogger;
use log::{LevelFilter, debug, info, warn};
use sha2::{Digest, Sha256};
use tss2_fapi_rs::{BaseErrorCode, ErrorCode, FapiContext, KeyFlags};

const MY_KEYFLAG: &[KeyFlags] = &[KeyFlags::Sign, KeyFlags::NoDA];
const MY_KEYPATH: &str = "HS/SRK/mySignKey";
const MY_MESSAGE: &str = "The quick brown fox jumps over the lazy dog.";

/// # tss2-fapi-rs example #2 — sign() and verify_signature()
///
/// This example demonstrates how to create a signing key in the TMP and then use that TPM-resident key to sign a message as well as how to verify the generated signature.
///
/// ### Remarks
///
/// Please note that this example requires that a valid FAPI configuration has already been set up!
///
/// The environment variable `TSS2_FAPICONF` can be used to control the path of the FAPI configuration file. Otherwise it defaults to `/etc/tpm2-tss/fapi-config.json`.
///
/// A template for creating a valid FAPI configuration is provided in the `data` sub-directory.
fn main() {
    // Initialize the logger
    EnvLogger::new().filter_level(LevelFilter::Info).init();

    // Print logo
    info!("TSS2 FAPI Wrapper - Example #2");

    // Create a new FAPI context
    info!("Creating FAPI context, please wait...");
    let mut context = match FapiContext::new() {
        Ok(fpai_ctx) => fpai_ctx,
        Err(error) => panic!("Failed to create context: {:?}", error),
    };

    // Print result
    info!("FAPI context created. ({})", context);

    // Perform the provisioning, if it has not been done yet
    info!("Provisioning, please wait...");
    match context.provision(None, None, None) {
        Ok(_) => info!("Success."),
        Err(ErrorCode::FapiError(BaseErrorCode::AlreadyProvisioned)) => {
            warn!("TPM already provisioned -> skipping!")
        }
        Err(error) => panic!("Provisioning has failed: {:?}", error),
    }

    // Create the siging key
    info!("Creating key, please wait...");
    match context.create_key(MY_KEYPATH, Some(MY_KEYFLAG), None, None) {
        Ok(_) => info!("Success."),
        Err(ErrorCode::FapiError(BaseErrorCode::PathAlreadyExists)) => {
            debug!("Key already created -> skipping!")
        }
        Err(error) => panic!("Key creation has failed: {:?}", error),
    };

    // Compute digest to be signed (using the "sha2" crate)
    let digest = Sha256::digest(MY_MESSAGE);
    debug!("Digest to be signed: {}", hex::encode(&digest[..]));

    // Create the signature
    info!("Computing signature, please wait...");
    let mut signature = match context.sign(MY_KEYPATH, None, &digest, false, false) {
        Ok(value) => value,
        Err(error) => panic!("Failed to create the signature: {:?}", error),
    };

    // Print signature value
    info!("Signature: {}", hex::encode(&signature.0[..]));

    // Simulate an attack on the siganture value!
    if !option_env!("ATTACK").unwrap_or_default().is_empty() {
        warn!("Disturbing the digest value !!!");
        *signature.0.last_mut().unwrap() = signature.0.last().unwrap().wrapping_add(1u8);
    }

    // Verify the signature
    let verify_result = match context.verify_signature(MY_KEYPATH, &digest, &signature.0[..]) {
        Ok(value) => value,
        Err(error) => panic!("Failed to verify the signature: {:?}", error),
    };

    // Print verification result
    info!("Result: {}", if verify_result { "valid \u{2714}" } else { "invalid \u{274C}" });

    // Exit
    info!("Shutting down...");
}
