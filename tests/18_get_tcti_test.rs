/* SPDX-License-Identifier: BSD-3-Clause */
/*******************************************************************************
 * Copyright 2024, Fraunhofer SIT sponsored by the ELISA research project
 * All rights reserved.
 ******************************************************************************/

pub mod common;

use std::ptr;

use common::{param::PASSWORD, setup::TestConfiguration};
use function_name::named;
use log::debug;
use serial_test::serial;
use tss2_fapi_rs::FapiContext;

mk_auth_callback!(my_auth_callback, PASSWORD);
mk_tpm_finalizer!(my_tpm_finalizer, my_auth_callback);

// ==========================================================================
// Test cases
// ==========================================================================

/// Test the `get_tcti()` function to retrieve the TCTI context
#[test]
#[serial]
#[named]
fn test_get_tcti() {
    let _configuration = TestConfiguration::with_finalizer(my_tpm_finalizer);

    repeat_test!(|_i| {
        // Create FAPI context
        let mut context = match FapiContext::new() {
            Ok(fpai_ctx) => fpai_ctx,
            Err(error) => panic!("Failed to create context: {:?}", error),
        };

        // Initialize TPM, if not already initialized
        tpm_initialize!(context, PASSWORD, my_auth_callback);

        // Get TCTI context
        let tcti_context = match context.get_tcti() {
            Ok(tcti_ctx) => tcti_ctx,
            Err(error) => panic!("Failed to obtain TCTI context: {:?}", error),
        };

        // Print value
        debug!("TCTI: {:?}", tcti_context);

        // Verify
        assert!(tcti_context != ptr::null_mut())
    });
}
