/* SPDX-License-Identifier: BSD-3-Clause */
/***********************************************************************************************
 * Copyright 2024-2026 Fraunhofer SIT, sponsored by the ELISA and ProSeCA research projects.
 * All rights reserved.
 **********************************************************************************************/

//! [![Rust](https://img.shields.io/badge/rust-1.82.0+-orchid?logo=rust)](https://www.rust-lang.org/)
//! [![Crates.io](https://img.shields.io/crates/v/tss2-fapi-rs.svg)](https://crates.io/crates/tss2-fapi-rs)
//! [![Docs.rs](https://img.shields.io/docsrs/tss2-fapi-rs.svg)](https://docs.rs/tss2-fapi-rs/latest/tss2_fapi_rs/)
//! [![License](https://img.shields.io/crates/l/tss2-fapi-rs)](https://opensource.org/licenses/BSD-3-Clause)
//!
//! # TSS 2.0 FAPI Rust Wrapper
//!
//! The **`tss2-fapi-rs`** Rust crate provides an interface to the [**TCG TSS 2.0 Feature API (FAPI)**](https://trustedcomputinggroup.org/resource/tss-fapi/).
//!
//! *Architectural overview:*  
//! ![Overview](https://raw.githubusercontent.com/tpm2-software/rust-tss-fapi/main/docs/images/tss2-fapi-rs.svg)
//!
//! ### Disclaimer
//!
//! The current version of the API does not offer any security or code safety guarantees. The implementation that is provided is suitable for exploratory testing and experimentation only. This test implementation does not offer any tangible security benefits and therefore is not suitable for use in production. Documentation pages may be incomplete and are subject to change without notice. Interfaces may change in such a way as to break compatibility with client code.
//!
//! ### Getting started
//!
//! The following example illustrates how to use the TSS 2.0 FAPI in Rust:
//!
//! ```rust no_run
//! use log::{error, info, warn};
//! use std::num::NonZeroUsize;
//! use tss2_fapi_rs::FapiContext;
//!
//! fn main() {
//!     // Create a new FAPI context
//!     info!("Creating FAPI context, please wait...");
//!     let mut context = match FapiContext::new() {
//!         Ok(fpai_ctx) => fpai_ctx,
//!         Err(error) => panic!("Failed to create context: {:?}", error),
//!     };
//!
//!     // Perform the provisioning, if it has not been done yet
//!     info!("Provisioning, please wait...");
//!     match context.provision(None, None, None) {
//!         Ok(_) => info!("Success."),
//!         Err(error) => warn!("Provisioning has failed: {:?}", error),
//!     }
//!
//!     // Generate random
//!     info!("Generating random data...");
//!     for _i in 0..8 {
//!         match context.get_random(NonZeroUsize::new(32).unwrap()) {
//!             Ok(random) => info!("Random data: {}", hex::encode(&random[..])),
//!             Err(error) => error!("get_random() failed: {:?}", error),
//!         }
//!     }
//! }
//! ```
//!
//! In this example, it is assumed that a valid [FAPI configuration](https://github.com/tpm2-software/tpm2-tss/blob/master/doc/fapi-config.md) has already been set up on the target system.
//!
//! Please see the **[`FapiContext`]** documentation for more details!
//!
//! #### Callback functions
//!
//! Various use-cases of the FAPI require implementing and installing ***callback functions***, for example:
//!
//! ```rust no_run
//! use log::info;
//! use std::borrow::Cow;
//! use tss2_fapi_rs::{Callbacks, FapiContext};
//!
//! fn main() {
//!     // Create a new FAPI context
//!     let mut context = FapiContext::new().expect("Failed to create context!");
//!
//!     // Register "auth" callback function
//!     match context.set_callbacks(Callbacks::with_auth(|_| Some(Cow::from("my_password")))) {
//!         Ok(_) => info!("Success."),
//!         Err(error) => panic!("Failed to set up AUTH callback function: {:?}", error),
//!     }
//! }
//! ```
//!
//! Please see the **[`FapiCallbacks`]** documentation for more details!
//!
//! ### Usage instructions
//!
//! In order to use the **`tss2-fapi-rs`** library in your Rust project, simply add it to your `Cargo.toml` file:
//!
//! ```toml
//! [dependencies]
//! tss2-fapi-rs = "0.10.0"
//! ```
//!
//! **Note:** Please also consider the [prerequisites](#prerequisites) that are required to use the `tss2-fapi-rs` library!
//!
//! #### Features
//!
//! Optional [features](https://doc.rust-lang.org/cargo/reference/features.html) that can be enabled/disabled for the `tss2-fapi-rs` library:
//!
//! Feature        | Description
//! -------------- | ----------------------------------------------------------------------------------------------------------------
//! `locking`      | Use an [R/W Lock](std::sync::RwLock) to serialize the invocations of certain "critical" FAPI functions (default)
//! `full_locking` | Similar to feature `locking`, but serializes **all** FAPI function invocations
//!
//! ### Build instructions
//!
//! In order to build **`tss2-fapi-rs`** from the sources, run the following command in the project root directory:
//!
//! ```sh
//! $ cargo build --release
//! ```
//!
//! Alternatively, the provided `Makefile`, in the project root directory, may be invoked for building the library:
//!
//! ```sh
//! $ make build
//! ```
//!
//! **Note:** Please also consider the [prerequisites](#prerequisites) that are required to build the `tss2-fapi-rs` library!
//!
//! #### Building with Docker
//!
//! Building **`tss2-fapi-rs`** in the fully self-contained [Docker environment](#docker-environment) (see below) has the advantage that the library can be built *without* the need to install any of the prerequisites &ndash; except for Docker and the Compose V2 plug-in &ndash; on the "host" system.
//!
//! With Docker Compose V2 installed, simply run the following `make` command in the project root directory:
//!
//! ```sh
//! $ make docker.build
//! ```
//!
//! ### Examples
//!
//! Some examples demonstrating how to use the `tss2-fapi-rs` library are provided in the **`examples`** sub-directory.
//!
//! In order to build and run an example, simply run the following command in the project root directory:
//!
//! ```sh
//! $ cargo run --example <example_name>
//! ```
//!
//! **Note:** Please also consider the [prerequisites](#prerequisites) that are required to use the `tss2-fapi-rs` library!
//!
//! #### Configuration
//!
//! An example *FAPI configuration* is provided in the **`examples/data`** sub-directory. It can be applied as follows:
//!
//! * Copy the configuration files to the "home" directory:
//!   ```sh
//!   $ mkdir ~/my-fapi-config
//!   $ cp -r examples/data/* ~/my-fapi-config
//!   ```
//!
//! * Run the example with the desired FAPI configuration:
//!   ```sh
//!   $ TSS2_FAPICONF=~/my-fapi-config/fapi-config.json cargo run --example [...]
//!   ```
//!
//! ### Prerequisites
//!
//! The following prerequisites are required for building or using the `tss2-fapi-rs` library:
//!
//! ##### *libtss2‑fapi*
//!
//! The native **`libtss2‑fapi`** library, version 3.2.0 or later, and its associated header files must be available:
//!
//! - On Ubuntu 22.04 (Jammy), Debian 12.0 (Bookworm) or later:
//!   * Install the TSS 2.0 FAPI library with the packet manager via the `libtss2-dev` package.
//!   * Furthermore, it may be necessary to additionally install the following *transitive* dependencies:  
//!     `uuid-dev`, `libjson-c-dev`, `libcrypt-dev` and `libcurl4-openssl-dev`
//!
//! - On older OS versions or other platforms:
//!   * It may be necessary to compile and install the TSS 2.0 FAPI library manually from the source code.
//!   * Please refer to the official build and installation instructions for the TSS libraries at:  
//!     <https://github.com/tpm2-software/tpm2-tss/blob/master/INSTALL.md>
//!
//! **Note:** By default, the native FAPI library is detected automatically, using the [pkg-config](https://en.wikipedia.org/wiki/Pkg-config) utility. If the required metadata file `tss2-fapi.pc` can *not* be found, please set or update your `PKG_CONFIG_PATH` as needed! Alternatively, the location of the native FAPI library and its associated header files can be specified explicitly via the *environment variables* described below.
//!
//! ##### *C compiler*
//!
//! A working **C compiler** (`cc`) is required for Rust/Cargo to build some of the required dependencies.
//!
//! On Ubuntu 22.04 (Jammy), Debian 12.0 (Bookworm) or later, it can be installed via the `build-essential` package.
//!
//! ##### *libclang*
//!
//! Rust's [`bindgen`](https://github.com/rust-lang/rust-bindgen?tab=readme-ov-file) tool requires that **`libclang`** is available on the system.
//!
//! On Ubuntu 22.04 (Jammy), Debian 12.0 (Bookworm) or later, it can be installed via the `libclang-dev` package.
//!
//! #### Environment
//!
//! The following environment variables may specify the location of the native FAPI library during the *build* process:
//!
//! * **`TSS2_FAPI_STATIC`**  
//!   If set to `true` (or `yes`), instruct the *pkg-config* to link with the **static** FAPI library.
//!
//! * **`TSS2_INCLUDE_PATH`**  
//!   Location of the TSS 2.0 header files. If specified, this path shall contain the `tss2_fapi.h` header file.  
//!   This variable must be set in conjunction with `TSS2_LIBRARY_PATH` to be effective!
//!
//! * **`TSS2_LIBRARY_PATH`**  
//!   Location of the TSS 2.0 library files. If specified, this path shall contain the `libtss2-fapi.so` file.  
//!   This variable must be set in conjunction with `TSS2_INCLUDE_PATH` to be effective!
//!
//! * **`TSS2_LIBRARY_VERS`**  
//!   Version of the TSS 2.0 library. If specified, the version string shall have the `"major.minor.patch"` format.
//!
//! The following environment variables can be used to control the *runtime* behavior:
//!
//! * **`LD_LIBRARY_PATH`**  
//!   On Linux/Unix systems, this can be set to control the location to load the native FAPI library from.
//!
//! ### Testing
//!
//! Integration tests for *all* the supported FAPI functions are provided in the **`tests`** sub-directory.
//!
//! These tests also serve as additional usage examples for the respective functions.
//!
//! In order to execute the integration tests, simply run the following command in the project root directory:
//!
//! ```sh
//! $ cargo test --release [<test_name>]
//! ```
//!
//! If a test name is **not** specified, then *all* available (non-ignored) tests will be executed.
//!
//! Alternatively, the provided `Makefile`, in the project root directory, may be invoked for running the tests:
//!
//! ```sh
//! $ make tests
//! ```
//!
//! #### Test Prerequisites
//!
//! The integration tests require that a working TPM is available. Using a TPM emulator is recommended for testing!
//!
//! ##### *Software TPM Emulator*
//!
//! The *Software TPM Emulator* (SWTPM) created by Stefan Berger can be used testing purposes:  
//! <https://github.com/stefanberger/swtpm>
//!
//! In order to use the SWTPM, the TCTI needs to be configured as follows, specifying the proper IP address and port number:
//! ```sh
//! $ export FAPI_RS_TEST_TCTI="swtpm:host=<ip-address>,port=<port-number>"
//! ```
//!
//! ##### *Docker Environment*
//!
//! A fully self-contained [Docker Compose](https://docs.docker.com/compose/) (V2) setup for running the tests, based on SWTPM, is provided at **`tools/docker`**.
//!
//! The following prerequisites are required for using the Docker environment:
//!
//! * On Ubuntu 22.04 (Jammy) or later:
//!   - Docker Compose V2 can be installed via the `docker-compose-v2` package.
//!
//! * On Debian 12.0 (Bookworm) or later:
//!   - Please set up the Docker.io repository as described here:  
//!     <https://docs.docker.com/engine/install/debian/#install-using-the-repository>
//!   - Finally, install the following packages:  
//!     `docker-ce`, `docker-ce-cli`, `containerd.io` and `docker-compose-plugin`.
//!
//! With Docker Compose V2 installed, you can run the following `make` commands in the project root directory:
//!
//! * Runs the test suite completely in the Docker environment:
//!   ```sh
//!   $ make docker.tests
//!   ```
//!
//! * Starts just the SWTPM container, e.g. if you want to run `cargo test` natively:
//!   ```sh
//!   $ make docker.swtpm
//!   ```
//!
//! ##### *libtpms*
//!
//! As a more lightweight alternative to SWTPM, the integration tests may also be run using the *libtpms* library:  
//! <https://github.com/stefanberger/libtpms>
//!
//! On Ubuntu 24.04 (Noble), Debian 12.0 (Bookworm) or later, *libtpms* can be installed via the `libtpms-dev` package.
//!
//! In order to use the *libtpms* library, the TCTI needs to be configured as follows:
//! ```sh
//! $ export FAPI_RS_TEST_TCTI="libtpms:tpm_state.dat"
//! ```
//!
//! Be aware that it is necessary to save the state to the filesystem by specifying a file name when using *libtpms* for testing!
//!
//! With the *libtpms* installed, you can run the following `make` commands in the project root directory:
//!
//! * Runs the test suite by using *libtpms* as its TPM emulator:
//!   ```sh
//!   $ make libtpms
//!   ```
//!
//! #### Environment
//!
//! The following environment variables can be set as needed:
//!
//! * **`FAPI_RS_TEST_TCTI`**  
//!   The TCTI connection string to be used for testing. By default, `swtpm:host=127.0.0.1,port=2321` is used.  
//!   *See also:* <https://github.com/tpm2-software/tpm2-tss/blob/master/doc/tcti.md>
//!
//! * **`FAPI_RS_TEST_PROF`**  
//!   The FAPI profile to be used for testing. By default, `RSA2048SHA256` is used. May be set to `ECCP256SHA256`.
//!
//! * **`FAPI_RS_TEST_LOOP`**  
//!   The number of times to repeat each test. Default is **3**.
//!
//! * **`RUST_LOG`**  
//!   Controls the logging level. Set to, for example, `debug` in order to enable additional logging outputs.
//!
//! * **`TSS2_LOG`**  
//!   Controls the logging level of the underlying native TSS2 libraries. This can be set to `all+none` in order to silence all outputs from the native TSS2 libraries. It can also be set `all+debug` in order to enable some additional debug outputs.
//!
//! * **`LD_LIBRARY_PATH`**  
//!   On Linux/Unix systems, this can be set to control the location to load the native `libtss2-fapi.so` library from. This is useful if you want to test with a "custom" build of `tpm2-tss` instead of using the version provided by the operating system.
//!
//! #### Configuration
//!
//! The integration tests automatically create and use a temporary FAPI configuration. It is generated from the template at:  
//! **`tests/data/fapi-config.json.template`**
//!
//! The FAPI profiles that are intended to be used by the integration tests are stored at:  
//! **`tests/data/profiles/*.json`**
//!
//! ## Troubleshooting
//!
//! * **Error message:**
//!   ```txt
//!   pkg_config: Required library "tss2-fapi" not found!
//!   The system library `tss2-fapi` required by crate `tss2-fapi-rs` was not found.
//!   ```
//!   *Solution:*  
//!   The native TSS 2.0 FAPI library, or one of its dependencies, can not be found by `pkg-config`. Please make sure that the required library and all of its dependencies are installed! If the `tss2-fapi.pc` resides at a non-standard location, set `PKG_CONFIG_PATH` accordingly. Also, the command `pkg-config --libs tss2-fapi` may be useful for debugging.
//!
//! * **Error message:**
//!   ```txt
//!   error: linker `cc` not found
//!   note: No such file or directory (os error 2)
//!   ```
//!   *Solution:*  
//!   The C compiler could not be found. Please install a working C compiler (e.g. `gcc` or `clang`) and then try again.
//!
//! * **Error message:**
//!   ```txt
//!   error: failed to run custom build command for `tss2-fapi-rs`
//!   Unable to generate bindings: "fatal error: 'tss2_fapi.h' file not found"
//!   ```
//!   *Solution:*  
//!   The header file for the native TSS 2.0 FAPI library is missing. Make sure that the native TSS 2.0 FAPI library and its header files are installed. If the `tss2_fapi.h` is installed at a non-standard location, set `TSS2_INCLUDE_PATH` as needed.  
//!   Be aware that the "include" directory shall contain a sub-directory named `tss2` containing the actual `tss2_fapi.h` file.
//!
//! * **Error message:**
//!   ```txt
//!   error: failed to run custom build command for `tss2-fapi-rs`
//!   Unable to generate bindings: "fatal error: 'stddef.h' file not found"
//!   ```
//!   *Solution:*  
//!   The C Standard Library header files can not be found. This usually indicates an incomplete/broken installation of the Clang compiler, as used by Rust's `bindgen` tool. Can be fixed, e.g., by (re)installing the `clang` or `libclang-dev` package.
//!
//! * **Error message:**
//!   ```txt
//!   error: linking with `cc` failed: exit status: 1
//!   /usr/bin/ld: cannot find -ltss2-fapi: No such file or directory
//!   ```
//!   *Solution:*  
//!   The native TSS 2.0 FAPI library is missing. Make sure that the native TSS 2.0 FAPI library is actually installed (or has been built from the sources). If the `libtss2-fapi.so` resides at a non-standard location, set `TSS2_LIBRARY_PATH` as needed.
//!
//! * **Error message:**
//!   ```txt
//!   error: failed to run custom build command for `tss2-fapi-rs`
//!   Unable to find libclang: "couldn't find any valid shared libraries matching ..."
//!   ```
//!   *Solution:*  
//!   Indicates that Rust's `bindgen` tool was unable to load the required Clang library. This is usually fixed, e.g., by installing the `libclang-dev` package. If the `libclang.so` resides at a non-standard location, set `LIBCLANG_PATH` as needed.
//!
//! * **Error message:**
//!   ```txt
//!   error while loading shared libraries: libtss2-fapi.so.1:
//!   cannot open shared object file: No such file or directory
//!   ```
//!   *Solution:*  
//!   The native TSS 2.0 FAPI library could not be loaded at runtime. Make sure that the native TSS 2.0 FAPI library is actually installed, and that it is located in one of the directories where the dynamic linker/loader is looking for shared libraries. If the `libtss2-fapi.so.1` resides at a non-standard location, you may update the `LD_LIBRARY_PATH` as needed.
//!
//! * **Error message:**
//!   ```txt
//!   ERROR:tcti:src/tss2-tcti/tcti-swtpm.c:617:Tss2_Tcti_Swtpm_Init()
//!   Cannot connect to swtpm TPM socket
//!   Failed to create context: OtherError(IoError)
//!   ```
//!   ```txt
//!   Failed to connect to the software TPM! Is the software TPM running?
//!   Connection refused
//!   ```
//!   *Solution:*  
//!   If this message appears at runtime, e.g. when trying to run the test cases, it indicates that the connection to the software TPM could not be established. Make sure that the software TPM is actually running and ready for incoming connections! One simple way to get a running software TPM is by using the Docker environment provided in the `etc/docker/swtpm` directory.
//!
//! * **Error message:**
//!   ```txt
//!   socket_connect() Failed to connect to host 10.0.0.1, port 2321:
//!   errno 99: Cannot assign requested address
//!   ```
//!   *Solution:*  
//!   The native TSS 2.0 FAPI library was unable to connect to the software TPM. This error may occur, after some time, when too many TPM commands are sent to the software TPM at a high rate. There currently is **no** known solution, but a possible workaround is to simply slow down the sequence of TPM commands, e.g., by adding an artificial delay after each command. Furthermore, adding the `disconnect` option to the SWTPM `--server` parameter seems to attenuate the problem.
//!
//! ### Source Code
//!
//! The `tss2-fapi-rs` source code can be found at the official GitHub repository:  
//! <https://github.com/tpm2-software/rust-tss-fapi/>
//!
//! ### Contact
//!
//! For bug reports, feature requests, etc., please refer to the issue tracker at:  
//! <https://github.com/tpm2-software/rust-tss-fapi/issues/>
//!
//! #### Security Reporting
//!
//! Security vulnerabilities *should be emailed* to **all** members of the [MAINTAINERS](https://github.com/tpm2-software/rust-tss-fapi/blob/main/MAINTAINERS.md) file.
//!
//! ### License
//!
//! Copyright &copy; 2024-2026 [Fraunhofer SIT](https://www.sit.fraunhofer.de/en/), sponsored by the [ELISA and ProSeCA](https://novomotive.de/) research projects.  
//! All rights reserved.
//!
//! This work is released under the [**3-Clause BSD License**](https://opensource.org/license/bsd-3-clause) (SPDX short identifier: `BSD-3-Clause`).

#![doc(html_no_source)]

mod algorithm_id;
mod callback;
mod context;
mod error;
mod fapi_sys;
mod flags;
mod locking;
mod marshal;
mod memory;
mod types;
mod version;

pub use algorithm_id::HashAlgorithm;
pub use callback::{AsAny, AuthCbParam, BranchCbParam, Callbacks, FapiCallbacks, PolicyActionCbParam, SignCbParam};
pub use context::FapiContext;
pub use error::{BaseErrorCode, ErrorCode, InternalError, Tpm2ErrFmt0, Tpm2ErrFmt1, Tpm2ErrorCode, Tpm2Warning};
pub use flags::{BlobType, KeyFlags, NvFlags, PaddingFlags, QuoteFlags, SealFlags};
pub use types::{ImportData, QuoteResult, SignResult, TpmBlobs};
pub use version::{FapiVersion, VersionInfo, get_version};

// Re-export JSON module
pub use ::json;
