/* SPDX-License-Identifier: BSD-3-Clause */
/***********************************************************************************************
 * Copyright 2024-2026 Fraunhofer SIT, sponsored by the ELISA and ProSeCA research projects.
 * All rights reserved.
 **********************************************************************************************/

pub mod common;

use common::{param::PASSWORD, setup::TestConfiguration};
use function_name::named;
use log::debug;
use serial_test::serial;
use std::num::NonZeroUsize;
use tss2_fapi_rs::FapiContext;

use crate::common::{callback::MyCallbacks, utils::my_tpm_finalizer};

// ==========================================================================
// Test cases
// ==========================================================================

/// Test the `test_get_random()` function
#[test]
#[serial]
#[named]
fn test_get_random() {
    let _configuration = TestConfiguration::with_finalizer(|| my_tpm_finalizer(PASSWORD));

    repeat_test!(|_i| {
        // Create FAPI context
        let mut context = match FapiContext::new() {
            Ok(fpai_ctx) => fpai_ctx,
            Err(error) => panic!("Failed to create context: {:?}", error),
        };

        // Initialize TPM, if not already initialized
        let (callbacks, _logger) = MyCallbacks::new(PASSWORD, None);
        tpm_initialize!(context, PASSWORD, callbacks);

        // Fetch random data
        let random_data = match context.get_random(NonZeroUsize::new(128usize).unwrap()) {
            Ok(data) => data,
            Err(error) => panic!("Generating random data failed: {:?}", error),
        };

        // Verify random data
        assert_eq!(random_data.len(), 128usize);
        debug!("random_data: {}", hex::encode(random_data));
    });
}
