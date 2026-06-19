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
use std::{hint::black_box, process::Command};
use tss2_fapi_rs::get_version;

const CURRENT_PKG_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Test the `get_version()` function
#[test]
#[serial]
#[named]
fn test_version() {
    let _configuration = TestConfiguration::new();
    let native_version = detect_native_library_version().expect("Failed to detect native library version!");

    repeat_test!(|_i| {
        let version_info = get_version();
        debug!("tss2-fapi-rs package version: {}", version_info.package);
        debug!("TSS 2.0 FAPI library version: {}", version_info.library);

        let package = black_box(version_info.package);
        let library = black_box(version_info.library);

        // Verify the package version
        assert!(format!("{}", package).eq_ignore_ascii_case(CURRENT_PKG_VERSION));

        // Verify the FAPI version
        assert!((library.major > 3u16) || ((library.major == 3u16) && ((library.minor > 0u16) || (library.patch >= 3u16))));
        assert!(native_version.starts_with(strip_version(&format!("{}", library))));
    });
}

fn detect_native_library_version() -> Option<String> {
    Command::new("pkgconf")
        .args(["--modversion", "tss2-fapi"])
        .output()
        .ok()
        .map(|out| String::from_utf8_lossy(&out.stdout[..]).trim().to_owned())
        .filter(|str| !str.is_empty())
}

fn strip_version(version_string: &str) -> &str {
    version_string.split(['+', '-']).next().unwrap()
}
