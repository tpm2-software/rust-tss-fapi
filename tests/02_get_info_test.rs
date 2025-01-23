/* SPDX-License-Identifier: BSD-3-Clause */
/*******************************************************************************
 * Copyright 2024-2025 Fraunhofer SIT, sponsored by the ELISA and ProSeCA research projects.
 * All rights reserved.
 ******************************************************************************/

pub mod common;

use common::setup::TestConfiguration;
use function_name::named;
use log::{debug, info, trace, Level};
use memory_stats::memory_stats;
use serial_test::serial;
use std::{mem, time::Instant};
use tss2_fapi_rs::FapiContext;

// ==========================================================================
// Test cases
// ==========================================================================

/// Test the `get_info()` function
#[test]
#[serial]
#[named]
fn test_get_info() {
    let _configuration = TestConfiguration::new();

    repeat_test!(|_i| {
        // Create FAPI context
        let mut context = match FapiContext::new() {
            Ok(fpai_ctx) => fpai_ctx,
            Err(error) => panic!("Failed to create context: {:?}", error),
        };

        // Print the context
        let _stringify = format!("{}", context);

        // Fetch TPM info
        let info_json = match context.get_info() {
            Ok(info) => info,
            Err(error) => panic!("Retrieving TPM info has failed: {:?}", error),
        };

        // Verify received TPM info data
        trace!("{:?}", info_json);
        assert!(!info_json.is_empty());
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

        // Create FAPI context
        let mut context = match FapiContext::new() {
            Ok(fpai_ctx) => fpai_ctx,
            Err(error) => panic!("Failed to create context: {:?}", error),
        };

        // Fetch info repeatedly to check for possible memory leaks
        const LOOP_COUNT: usize = 99_991_usize;
        let mut previous_update: Option<Instant> = None;
        for j in 0..LOOP_COUNT {
            if log::log_enabled!(Level::Info) && previous_update.map_or(true, |ts| ts.elapsed().as_secs() >= 5u64) {
                output_progress(j, LOOP_COUNT);
                previous_update = Some(Instant::now());
            }
            match context.get_info() {
                Ok(info) => assert!(!info.is_empty()),
                Err(error) => panic!("Retrieving TPM info has failed: {:?}", error),
            };
        }

        // Completed
        output_progress(LOOP_COUNT, LOOP_COUNT);

        // Explicitely drop the context
        mem::drop(context);

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
    info!(
        "Progress: {:5} of {:5} completed. ({:5.1}%)",
        current,
        total,
        (current as f64) / (total as f64) * 100_f64
    );
}
