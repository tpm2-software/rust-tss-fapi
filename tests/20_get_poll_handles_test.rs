/* SPDX-License-Identifier: BSD-3-Clause */
/***********************************************************************************************
 * Copyright 2024-2026 Fraunhofer SIT, sponsored by the ELISA and ProSeCA research projects.
 * All rights reserved.
 **********************************************************************************************/

pub mod common;

use common::{callback::MyCallbacks, param::PASSWORD, setup::TestConfiguration, utils::my_tpm_finalizer};
use function_name::named;
use serial_test::serial;
use tss2_fapi_rs::{ErrorCode, FapiContext, FapiPollHandle, InternalError};

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
        let result: Result<Vec<FapiPollHandle>, _> = context.get_poll_handles();
        assert!(matches!(result, Err(ErrorCode::InternalError(InternalError::NotImplemented))));

        // Check the handles
        if let Ok(poll_handles) = result {
            for handle in poll_handles {
                check_poll_handle(&handle);
            }
        }
    });
}

// ==========================================================================
// Helper functions
// ==========================================================================

#[inline(always)]
fn check_poll_handle(handle: &FapiPollHandle) {
    _ = std::hint::black_box(handle);
}
