/* SPDX-License-Identifier: BSD-3-Clause */
/***********************************************************************************************
 * Copyright 2024-2025 Fraunhofer SIT, sponsored by the ELISA and ProSeCA research projects.
 * All rights reserved.
 **********************************************************************************************/

use pkg_config::{Config, Error};
use std::{
    env,
    fs::File,
    io::Write,
    path::{Path, PathBuf},
};

/// Library configuration type definition
type LibraryConfig = (Vec<String>, Vec<PathBuf>, Vec<PathBuf>, String);

/// The name of the native TSS 2.0 FPAI library
const LIBRARY_NAME: &str = "tss2-fapi";

/// Minimal required version of the native FAPI library
/// The version specified here is equal to the TSS 2.0 version available in Ubuntu 22.04 LTS
const LIBRARY_MIN_VERSION: &str = "3.2.0";

/// This build scripts is required to detect and link the "native" FAPI library
fn main() {
    // Get the output directory
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());

    // Detect the native TSS 2.0 FAPI library location
    let tss2_fapi = detect_tss2_library();

    // Unwrap pkg-config result
    let tss2_fapi = tss2_fapi.expect("pkg_config: Required library \"tss2-fapi\" not found!");

    // Assert that library information is complete
    assert!(!tss2_fapi.0.is_empty(), "library name is not defined!");
    assert!(!tss2_fapi.1.is_empty(), "link path is not defined!");
    assert!(!tss2_fapi.2.is_empty(), "include path is not defined!");
    assert!(!tss2_fapi.3.is_empty(), "version is not defined!");

    // Add the required libraries to be linked
    for library_name in tss2_fapi.0 {
        assert!(!library_name.is_empty(), "library name is empty!");
        println!("cargo:rustc-link-lib={}", library_name);
    }

    // Add the required linker search paths
    for link_path in tss2_fapi.1 {
        assert!(link_path.is_dir(), "Link path not found: {:?}", link_path);
        println!("cargo:rustc-link-search={}", link_path.to_str().unwrap());
    }

    // Initialize `bindgen` builder with the required include directories
    let mut bindgen_builder = bindgen::Builder::default();
    for inc_path in tss2_fapi.2 {
        assert!(inc_path.is_dir(), "Include path not found: {:?}", inc_path);
        bindgen_builder = bindgen_builder.clang_arg(format!("-I{}", inc_path.to_str().unwrap()));
    }

    // Invoke the `bindgen` for TSS 2.0 FAPI library
    bindgen_builder
        .header_contents("wrapper.h", "#include <tss2_fapi.h>")
        .layout_tests(false)
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("Unable to generate FAPI bindings")
        .write_to_file(out_path.join("tss2_fapi_bindings.rs"))
        .expect("Failed to write FAPI bindings!");

    // Persist the detected library version
    if !write_version_string(&out_path.join("tss2_fapi_versinfo.rs"), &tss2_fapi.3) {
        panic!("Failed to write library version!");
    }
}

/// Detect the native TSS2 FAPI library
///
/// Try to detect the library using **pkg-config**, unless the environment variables `TSS2_INCLUDE_PATH` and `TSS2_LIBRARY_PATH` are defined!
fn detect_tss2_library() -> Result<LibraryConfig, Error> {
    // Check environment variables
    let env_include_path = env::var("TSS2_INCLUDE_PATH").map(PathBuf::from);
    let env_library_path = env::var("TSS2_LIBRARY_PATH").map(PathBuf::from);

    // Shortcut if `TSS2_INCLUDE_PATH` and `TSS2_LIBRARY_PATH` are defined
    if let Ok(include_path) = env_include_path {
        if let Ok(library_path) = env_library_path {
            let library_version = env::var("TSS2_LIBRARY_VERS").unwrap_or_else(|_| LIBRARY_MIN_VERSION.to_owned());
            return Ok((vec![LIBRARY_NAME.to_owned()], vec![library_path], vec![include_path], library_version));
        }
    }

    // Try to detect the TSS 2.0 library by invoking the `pkg-config` utility
    Config::new()
        .cargo_metadata(false)
        .atleast_version(LIBRARY_MIN_VERSION)
        .probe(LIBRARY_NAME)
        .map(|config| (config.libs, config.link_paths, config.include_paths, config.version))
}

/// Persist the version string to output file, so that it can be evaluated in the code at runtime
fn write_version_string(path: &Path, version_string: &str) -> bool {
    // Parse the version string, assuming that is is in the `"major.minor.patch"` format
    let mut tokens = version_string.split('.');
    let vers_major = tokens.next().unwrap_or_default().parse::<u16>().expect("Failed to parse version string!");
    let vers_minor = tokens.next().unwrap_or_default().parse::<u16>().expect("Failed to parse version string!");
    let vers_patch = tokens.next().unwrap_or_default().parse::<u16>().expect("Failed to parse version string!");

    // Try to write the version string to the output file
    let mut file = File::create(path).expect("Failed to create output file for version!");
    writeln!(file, r#"pub const TSS2_FAPI_VERSION: &str = "{}.{}.{}";"#, vers_major, vers_minor, vers_patch).is_ok()
}
