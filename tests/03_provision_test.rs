/* SPDX-License-Identifier: BSD-3-Clause */
/***********************************************************************************************
 * Copyright 2024-2026 Fraunhofer SIT, sponsored by the ELISA and ProSeCA research projects.
 * All rights reserved.
 **********************************************************************************************/

pub mod common;

use common::{param::PASSWORD, setup::TestConfiguration};
use function_name::named;
use log::{Level, debug, info};
use memory_stats::memory_stats;
use serial_test::serial;
use std::time::Instant;
use tss2_fapi_rs::FapiContext;

mk_auth_callback!(my_auth_callback, PASSWORD);
mk_tpm_finalizer!(my_tpm_finalizer, my_auth_callback);

// ==========================================================================
// Test cases
// ==========================================================================

/// Test the `provision()` function with a password (auth value) for the storage hierarchy
#[test]
#[serial]
#[named]
fn test_provision() {
    let _configuration = TestConfiguration::with_finalizer(my_tpm_finalizer);

    repeat_test!(|_i| {
        // Create FAPI context
        let mut context = match FapiContext::new() {
            Ok(fpai_ctx) => fpai_ctx,
            Err(error) => panic!("Failed to create context: {:?}", error),
        };

        // Set up auth callback
        if let Err(error) = context.set_auth_callback(tss2_fapi_rs::AuthCallback::new(my_auth_callback)) {
            panic!("Setting up the callback has failed: {:?}", error)
        }

        // Initialize TPM, if not already initialized
        match context.provision(None, Some(PASSWORD), None) {
            Ok(_) => log::debug!("Provisioned."),
            Err(tss2_fapi_rs::ErrorCode::FapiError(tss2_fapi_rs::BaseErrorCode::AlreadyProvisioned)) => log::debug!("TPM already provisioned -> skipping."),
            Err(error) => panic!("Provisioning has failed: {:?}", error),
        }
    });
}

/// Test for possible memory leaks by calling `get_info()` *many* times in a row and monitoring memory usage
#[test]
#[serial]
#[named]
#[ignore = "tends to fails with the swtpm (socket error)"]
fn test_to_destruction() {
    let _configuration = TestConfiguration::new();

    repeat_test!(|i| {
        // Capture initial memory usage
        let initial_memory_usage = memory_stats().expect("Failed to fetch initial memory stats!");
        debug!("Initial memory usage: {} bytes", initial_memory_usage.virtual_mem);

        // Create context and attempt provision repeatedly to check for possible memory leaks
        const LOOP_COUNT: usize = 99_991_usize;
        let mut previous_update: Option<Instant> = None;
        for j in 0..LOOP_COUNT {
            if log::log_enabled!(Level::Info) && previous_update.is_none_or(|ts| ts.elapsed().as_secs() >= 5u64) {
                output_progress(j, LOOP_COUNT);
                previous_update = Some(Instant::now());
            }
            let mut context = match FapiContext::new() {
                Ok(fpai_ctx) => fpai_ctx,
                Err(error) => panic!("Failed to create context: {:?}", error),
            };
            tpm_initialize!(context, PASSWORD, my_auth_callback);
        }

        // Completed
        output_progress(LOOP_COUNT, LOOP_COUNT);

        // Capture final memory usage
        let final_memory_usage = memory_stats().expect("Failed to fetch final memory stats!");
        debug!("Final memory usage: {} bytes", final_memory_usage.virtual_mem);

        // Detect number of "leaked" bytes
        let leaked_bytes = final_memory_usage.virtual_mem.saturating_sub(initial_memory_usage.virtual_mem);
        log::debug!("Leaked bytes: {}", leaked_bytes);
        if i > 0_usize {
            assert!(leaked_bytes < 4096_usize, "Memory leak detected! ({} bytes leaked)", leaked_bytes);
        }
    });
}

// ==========================================================================
// Helper functions
// ==========================================================================

fn output_progress(current: usize, total: usize) {
    info!("Progress: {:5} of {:5} completed. ({:5.1}%)", current, total, (current as f64) / (total as f64) * 100_f64);
}
