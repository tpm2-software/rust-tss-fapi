/* SPDX-License-Identifier: BSD-3-Clause */
/***********************************************************************************************
 * Copyright 2024-2026 Fraunhofer SIT, sponsored by the ELISA and ProSeCA research projects.
 * All rights reserved.
 **********************************************************************************************/

use std::{fmt::Display, sync::OnceLock};

static VERSION_INFO_PKG: OnceLock<VersionInfo> = OnceLock::new();
static VERSION_INFO_SYS: OnceLock<VersionInfo> = OnceLock::new();

/// Contains version information.
#[derive(Clone)]
#[non_exhaustive]
pub struct VersionInfo {
    /// The *major* version of the software.
    pub major: u16,
    /// The *minor* version of the software.
    pub minor: u16,
    /// The *patch* level of the software.
    pub patch: u16,
    /// Additional version identifier (e.g. "beta-2")
    pub ident: Option<String>,
}

/// Contains the FAPI version.
#[derive(Clone)]
#[non_exhaustive]
pub struct FapiVersion {
    /// Version of the `tss2-fapi-rs` package (Rust wrapper)
    pub package: VersionInfo,
    /// Versin of the "native" FAPI library that was used to build `tss2-fapi-rs`
    pub library: VersionInfo,
}

/// Returns the package version of the **`tss2-fapi-rs`** library.
///
/// Additionally, the version of the "native" FAPI library that was used to build `tss2-fapi-rs` is returned.
pub fn get_version() -> FapiVersion {
    const PACKAGE_VERSION: &str = env!("CARGO_PKG_VERSION", "Package version is not defined!");
    FapiVersion {
        package: VERSION_INFO_PKG.get_or_init(|| parse_version(PACKAGE_VERSION)).clone(),
        library: VERSION_INFO_SYS.get_or_init(|| parse_version(crate::fapi_sys::TSS2_FAPI_VERSION)).clone(),
    }
}

/// Parse a version string that is in the `"major.minor.patch"` format into a [`VersionInfo`] struct.
fn parse_version(version_string: &str) -> VersionInfo {
    let mut tokens = version_string.splitn(4usize, ['.', '+', '-', '_']).map(str::trim_ascii);
    VersionInfo {
        major: tokens.next().and_then(|str| str.parse::<u16>().ok()).unwrap_or_default(),
        minor: tokens.next().and_then(|str| str.parse::<u16>().ok()).unwrap_or_default(),
        patch: tokens.next().and_then(|str| str.parse::<u16>().ok()).unwrap_or_default(),
        ident: tokens.next().filter(|str| !str.is_empty()).map(str::to_owned),
    }
}

/// Convert the `VersionInfo` struct to a string in the `"major.minor.patch"` format
impl Display for VersionInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(ident_str) = self.ident.as_ref() {
            write!(f, "{}.{}.{}-{}", self.major, self.minor, self.patch, ident_str)
        } else {
            write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
        }
    }
}
