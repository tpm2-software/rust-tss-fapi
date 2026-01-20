/* SPDX-License-Identifier: BSD-3-Clause */
/***********************************************************************************************
 * Copyright 2024-2026 Fraunhofer SIT, sponsored by the ELISA and ProSeCA research projects.
 * All rights reserved.
 **********************************************************************************************/

use env_logger::Builder as EnvLogger;
use log::{LevelFilter, error, info, warn};
use std::{num::NonZeroUsize, panic};
use tss2_fapi_rs::{BaseErrorCode, ErrorCode, FapiContext};

/// # tss2-fapi-rs example #1 — get_random()
///
/// This example demonstrates how to generate cryptographically secure random bytes using the TPM.
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
    info!("TSS2 FAPI Wrapper - Example #1");

    // Print library version
    let version = tss2_fapi_rs::get_version();
    info!("Using tss2-fapi-rs package version: {}, built with native FAPI library version: {}", version.package, version.library);

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

    // Generate random
    info!("Generating random data...");
    for _i in 0..8 {
        match context.get_random(NonZeroUsize::new(32).unwrap()) {
            Ok(random) => info!("Random data: {}", hex::encode(&random[..])),
            Err(error) => error!("get_random() failed: {:?}", error),
        }
    }

    // Exit
    info!("Shutting down...");
}
