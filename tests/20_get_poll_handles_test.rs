/* SPDX-License-Identifier: BSD-3-Clause */
/***********************************************************************************************
 * Copyright 2024-2026 Fraunhofer SIT, sponsored by the ELISA and ProSeCA research projects.
 * All rights reserved.
 **********************************************************************************************/

pub mod common;

use common::{callback::MyCallbacks, param::PASSWORD, setup::TestConfiguration, utils::my_tpm_finalizer};
use function_name::named;
use serial_test::serial;
use std::hint::black_box;
use tss2_fapi_rs::{BaseErrorCode, ErrorCode, FapiContext, FapiPollHandle};

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

        // Try to acquire the poll handles
        let result: Result<Vec<FapiPollHandle>, _> = context.get_poll_handles();

        // Expect `BadSequence` error here, because poll handles are only available while in the middle of an asynchronious I/O operation!
        assert!(matches!(result, Err(ErrorCode::FapiError(BaseErrorCode::BadSequence))));

        // Verify handles
        if let Ok(handles) = result {
            handles.into_iter().for_each(|handle| _ = black_box(handle.0));
        }
    });
}
