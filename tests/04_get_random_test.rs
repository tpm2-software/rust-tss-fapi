/* SPDX-License-Identifier: BSD-3-Clause */
/*******************************************************************************
 * Copyright 2024-2025 Fraunhofer SIT, sponsored by the ELISA and ProSeCA research projects.
 * All rights reserved.
 ******************************************************************************/

pub mod common;

use common::{param::PASSWORD, setup::TestConfiguration};
use function_name::named;
use log::debug;
use serial_test::serial;
use std::num::NonZeroUsize;
use tss2_fapi_rs::FapiContext;

mk_auth_callback!(my_auth_callback, PASSWORD);
mk_tpm_finalizer!(my_tpm_finalizer, my_auth_callback);

// ==========================================================================
// Test cases
// ==========================================================================

/// Test the `test_get_random()` function
#[test]
#[serial]
#[named]
fn test_get_random() {
    let _configuration = TestConfiguration::with_finalizer(my_tpm_finalizer);

    repeat_test!(|_i| {
        // Create FAPI context
        let mut context = match FapiContext::new() {
            Ok(fpai_ctx) => fpai_ctx,
            Err(error) => panic!("Failed to create context: {:?}", error),
        };

        // Initialize TPM, if not already initialized
        tpm_initialize!(context, PASSWORD, my_auth_callback);

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
