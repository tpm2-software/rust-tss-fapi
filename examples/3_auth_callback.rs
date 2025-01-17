/* SPDX-License-Identifier: BSD-3-Clause */
/*******************************************************************************
 * Copyright 2024-2025 Fraunhofer SIT, sponsored by the ELISA research project.
 * All rights reserved.
 ******************************************************************************/

use env_logger::Builder as EnvLogger;
use log::{debug, info, warn, LevelFilter};
use std::borrow::Cow;
use tss2_fapi_rs::{AuthCallback, AuthCallbackParam, BaseErrorCode, ErrorCode, FapiContext, KeyFlags};

const MY_KEYFLAG: &[KeyFlags] = &[KeyFlags::Sign, KeyFlags::NoDA];
const MY_KEYPATH: &str = "HS/SRK/myTestKey";
const MY_AUTHVAL: &str = "OrpheanBeholderScryDoubt";

/// # tss2-fapi-rs example #3 — set_auth_callback()
///
/// This example demonstrates how to create a key that is protected by an auth value (password) and how to register the required authorization callback.
///
/// The callback function will be called, by the FAPI, in order to request the auth value (password) from the application when the key is used.
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
    info!("TSS2 FAPI Wrapper - Example #3");

    // Create a new FAPI context
    info!("Creating FAPI context, please wait...");
    let mut context = match FapiContext::new() {
        Ok(fpai_ctx) => fpai_ctx,
        Err(error) => panic!("Failed to create context: {:?}", error),
    };

    // Print result
    info!("FAPI context created. ({})", context);

    // Add authorization callback function
    match context.set_auth_callback(AuthCallback::new(my_auth_callback)) {
        Ok(_) => info!("Success."),
        Err(error) => panic!("Failed to set up AUTH callback function: {:?}", error),
    }

    // Perform the provisioning, if it has not been done yet
    info!("Provisioning, please wait...");
    match context.provision(None, None, None) {
        Ok(_) => info!("Success."),
        Err(ErrorCode::FapiError(BaseErrorCode::AlreadyProvisioned)) => {
            warn!("TPM already provisioned -> skipping!")
        }
        Err(error) => panic!("Provisioning has failed: {:?}", error),
    }

    // Create the key and set up auth value (password)
    info!("Creating key, please wait...");
    match context.create_key(MY_KEYPATH, Some(MY_KEYFLAG), None, Some(MY_AUTHVAL)) {
        Ok(_) => info!("Success."),
        Err(ErrorCode::FapiError(BaseErrorCode::PathAlreadyExists)) => {
            debug!("Key already created -> skipping!")
        }
        Err(error) => panic!("Key creation has failed: {:?}", error),
    };

    // Create the signature
    info!("Computing signature, please wait...");
    let signature = match context.sign(MY_KEYPATH, None, &[0u8; 32], false, false) {
        Ok(value) => value,
        Err(error) => panic!("Failed to create the signature: {:?}", error),
    };

    // Print signature value
    info!("Signature: {}", hex::encode(&signature.0[..]));

    // Exit
    info!("Shutting down...");
}

/// This function will be called by FAPI in order to request authorization values from the application.
///
/// *Note:* For simplicity, in this example, the callback function always returns our password, regardless of the requested object path.
fn my_auth_callback(auth_param: AuthCallbackParam) -> Option<Cow<'static, str>> {
    info!("Authorization for object at {:?} has been requested.", auth_param.object_path);
    Some(Cow::from(MY_AUTHVAL))
}
