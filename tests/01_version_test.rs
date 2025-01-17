/* SPDX-License-Identifier: BSD-3-Clause */
/*******************************************************************************
 * Copyright 2024-2025 Fraunhofer SIT, sponsored by the ELISA research project.
 * All rights reserved.
 ******************************************************************************/

pub mod common;

use common::setup::TestConfiguration;
use function_name::named;
use log::debug;
use serial_test::serial;
use tss2_fapi_rs::get_version;

const CURRENT_PKG_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Test the `get_version()` function
#[test]
#[serial]
#[named]
fn test_version() {
    let _configuration = TestConfiguration::new();

    repeat_test!(|_i| {
        let (version_pkg, version_sys) = get_version();
        debug!("tss2-fapi-rs package version: {}", version_pkg);
        debug!("Native FAPI version: {}", version_sys);

        // Verify the package version
        assert_eq!(CURRENT_PKG_VERSION, format!("{}", version_pkg));

        // Verify the FAPI version
        assert!((version_sys.major > 3u16) || ((version_sys.major == 3u16) && ((version_sys.minor > 0u16) || (version_sys.patch >= 3u16))));
    });
}
