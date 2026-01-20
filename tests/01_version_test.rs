/* SPDX-License-Identifier: BSD-3-Clause */
/***********************************************************************************************
 * Copyright 2024-2026 Fraunhofer SIT, sponsored by the ELISA and ProSeCA research projects.
 * All rights reserved.
 **********************************************************************************************/

pub mod common;

use common::setup::TestConfiguration;
use function_name::named;
use log::debug;
use serial_test::serial;
use std::hint::black_box;
use tss2_fapi_rs::get_version;

const CURRENT_PKG_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Test the `get_version()` function
#[test]
#[serial]
#[named]
fn test_version() {
    let _configuration = TestConfiguration::new();

    repeat_test!(|_i| {
        let version_info = get_version();
        debug!("tss2-fapi-rs package version: {}", version_info.package);
        debug!("TSS 2.0 FAPI library version: {}", version_info.library);

        let package = black_box(version_info.package);
        let library = black_box(version_info.library);

        // Verify the package version
        assert_eq!(CURRENT_PKG_VERSION, format!("{}", package));

        // Verify the FAPI version
        assert!((library.major > 3u16) || ((library.major == 3u16) && ((library.minor > 0u16) || (library.patch >= 3u16))));
    });
}
