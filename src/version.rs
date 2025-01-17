/* SPDX-License-Identifier: BSD-3-Clause */
/*******************************************************************************
 * Copyright 2024, Fraunhofer SIT sponsored by the ELISA research project
 * All rights reserved.
 ******************************************************************************/

use std::{fmt::Display, sync::OnceLock};

static VERSION_INFO_PKG: OnceLock<VersionInfo> = OnceLock::new();
static VERSION_INFO_SYS: OnceLock<VersionInfo> = OnceLock::new();

/// Contains version information.
pub struct VersionInfo {
    /// The *major* version of the software.
    pub major: u16,
    /// The *minor* version of the software.
    pub minor: u16,
    /// The *patch* level of the software.
    pub patch: u16,
}

/// Returns the package version of the **`tss2-fapi-rs`** library.
///
/// Additionally, the version of the "native" FAPI library that was used to build `tss2-fapi-rs` is returned.
///
/// ###### Return Value
///
/// **`(package_version, fapi_library_version)`**
pub fn get_version() -> (&'static VersionInfo, &'static VersionInfo) {
    (
        VERSION_INFO_PKG.get_or_init(|| parse_version(env!("CARGO_PKG_VERSION", "Package version not defined!"))),
        VERSION_INFO_SYS.get_or_init(|| parse_version(crate::fapi_sys::TSS2_FAPI_VERSION)),
    )
}

/// Parse a version string that is in the `"major.minor.patch"` format into a [`VersionInfo`] struct.
fn parse_version(version_string: &str) -> VersionInfo {
    let mut tokens = version_string.split('.').map(|str| str.parse::<u16>().unwrap_or_default());
    VersionInfo {
        major: tokens.next().unwrap_or_default(),
        minor: tokens.next().unwrap_or_default(),
        patch: tokens.next().unwrap_or_default(),
    }
}

/// Convert the `VersionInfo` struct to a string in the `"major.minor.patch"` format
impl Display for VersionInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}
