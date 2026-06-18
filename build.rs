/* SPDX-License-Identifier: BSD-3-Clause */
/***********************************************************************************************
 * Copyright 2024-2026 Fraunhofer SIT, sponsored by the ELISA and ProSeCA research projects.
 * All rights reserved.
 **********************************************************************************************/

#[cfg(not(target_family = "unix"))]
compile_error!("Sorry, this project currently only supports the Unix platform.");

use pkg_config::{Config, Error};
use regex::Regex;
use std::{
    env,
    fs::File,
    io::{BufRead, BufReader, Error as IoError, Write},
    path::{Path, PathBuf},
    sync::LazyLock,
};

/// Library configuration type definition
type LibraryConfig = (Vec<String>, Vec<PathBuf>, Vec<PathBuf>, String);

/// The name of the native TSS 2.0 FPAI library
const LIBRARY_NAME: &str = "tss2-fapi";

/// Minimal required version of the native FAPI library
/// The version specified here is equal to the TSS 2.0 version available in Ubuntu 22.04 LTS
const LIBRARY_MIN_VERSION: &str = "3.2.0";

/// Regex to parse public FAPI function name for the 'bindings.rs' file
static REGEX_FUNCTION: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\bpub\s+fn\s+Fapi_([a-zA-Z0-9]+)\b").unwrap());

/// Regex to parse the version string, assuming the `<major>.<minor>.<patch>` format
static REGEX_VERSION: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^(\d+)\.(\d+)\.(\d+)([-+][a-zA-Z0-9.]+)?").unwrap());

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
    let fapi_bindings_rs = out_path.join("tss2_fapi_bindings.rs");
    bindgen_builder
        .header_contents("wrapper.h", "#include <tss2_fapi.h>")
        .layout_tests(false)
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("Unable to generate FAPI bindings")
        .write_to_file(&fapi_bindings_rs)
        .expect("Failed to write FAPI bindings!");

    // Detect all available FAPI functions
    detect_fapi_functions(&fapi_bindings_rs).expect("Failed to detect available functions!");

    // Persist the detected library version
    if let Err(error) = write_version_string(&out_path.join("tss2_fapi_versinfo.rs"), &tss2_fapi.3) {
        panic!("Failed to write library version: {:?}", error);
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

    // Link static TSS 2.0 library?
    let statik: bool = option_env!("TSS2_FAPI_STATIC").is_some_and(parse_as_boolean);

    // Try to detect the TSS 2.0 library by invoking the `pkg-config` utility
    Config::new()
        .cargo_metadata(false)
        .atleast_version(LIBRARY_MIN_VERSION)
        .statik(statik)
        .probe(LIBRARY_NAME)
        .map(|config| (config.libs, config.link_paths, config.include_paths, config.version))
}

/// Detect all available FAPI functions
///
/// For each FAPI function that is available in the TSS 2.0 library, the corresponding `--cfg` flag will be set!
fn detect_fapi_functions(bindings: &Path) -> Result<(), IoError> {
    for line in BufReader::new(File::open(bindings)?).lines().map_while(|line| line.ok()) {
        for caps in REGEX_FUNCTION.captures_iter(&line) {
            if let Some(fn_name) = caps.get(1) {
                println!("cargo:rustc-cfg=fapi_sys_fn_{}", fn_name.as_str());
            }
        }
    }
    Ok(())
}

/// Persist the version string to output file, so that it can be evaluated in the code at runtime
fn write_version_string(path: &Path, version_string: &str) -> Result<(), IoError> {
    // Try to parse the given version string
    let version = REGEX_VERSION.captures(version_string.trim_ascii()).map_or("UNDEFINED", |caps| caps.get(0).unwrap().as_str());

    // Try to write the version string to the output file
    let mut file = File::create(path).expect("Failed to create output file for version!");
    writeln!(file, r#"pub const TSS2_FAPI_VERSION: &str = "{}";"#, version)
}

/// Parse the given 'flag' string as a boolean value
fn parse_as_boolean(str: &str) -> bool {
    match str.trim_ascii() {
        "" | "false" | "no" | "0" => false,
        "true" | "yes" | "1" => true,
        value => value.parse::<usize>().is_ok_and(|num| num > 0usize),
    }
}
