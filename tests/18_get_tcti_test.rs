/* SPDX-License-Identifier: BSD-3-Clause */
/***********************************************************************************************
 * Copyright 2024-2026 Fraunhofer SIT, sponsored by the ELISA and ProSeCA research projects.
 * All rights reserved.
 **********************************************************************************************/

pub mod common;

use common::{callback::MyCallbacks, param::PASSWORD, setup::TestConfiguration, utils::my_tpm_finalizer};
use function_name::named;
use log::debug;
use serial_test::serial;
use tss2_fapi_rs::FapiContext;

// ==========================================================================
// Test cases
// ==========================================================================

/// Test the `get_tcti()` function to retrieve the TCTI context
#[test]
#[serial]
#[named]
fn test_get_tcti() {
    let _configuration = TestConfiguration::with_finalizer(|| my_tpm_finalizer(PASSWORD));

    repeat_test!(|_i| {
        // Create FAPI context
        let mut context = match FapiContext::new() {
            Ok(fpai_ctx) => fpai_ctx,
            Err(error) => panic!("Failed to create context: {:?}", error),
        };

        // Initialize TPM, if not already initialized
        tpm_initialize!(context, PASSWORD, MyCallbacks::new(PASSWORD, None));

        // Get TCTI context
        let tcti_context = match context.get_tcti() {
            Ok(tcti_ctx) => tcti_ctx,
            Err(error) => panic!("Failed to obtain TCTI context: {:?}", error),
        };

        // Print value
        debug!("TCTI: {:?}", tcti_context);

        // Verify
        assert!(!tcti_context.is_null())
    });
}
