/* SPDX-License-Identifier: BSD-3-Clause */
/***********************************************************************************************
 * Copyright 2024-2026 Fraunhofer SIT, sponsored by the ELISA and ProSeCA research projects.
 * All rights reserved.
 **********************************************************************************************/

pub mod common;

use common::{callback::MyCallbacks, param::PASSWORD, setup::TestConfiguration, utils::my_tpm_finalizer};
use function_name::named;
use serial_test::serial;
use tss2_fapi_rs::{ErrorCode, FapiContext, InternalError};

// ==========================================================================
// Test cases
// ==========================================================================

/// Test the `get_poll_handles()` function (which is **not** currently implemented)
#[test]
#[serial]
#[named]
fn test_get_poll_handles() {
    let _configuration = TestConfiguration::with_finalizer(|| my_tpm_finalizer(PASSWORD));

    repeat_test!(|_i| {
        // Create FAPI context
        let mut context = match FapiContext::new() {
            Ok(fpai_ctx) => fpai_ctx,
            Err(error) => panic!("Failed to create context: {:?}", error),
        };

        // Initialize TPM, if not already initialized
        tpm_initialize!(context, PASSWORD, MyCallbacks::new(PASSWORD, None));

        // Try to acquire the poll handles (this is expected to fail!)
        let result = context.get_poll_handles();
        assert!(matches!(result, Err(ErrorCode::InternalError(InternalError::NotImplemented))));
    });
}
