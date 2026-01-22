# Change Log

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/).

## [0.12.0] - 2026-01-22

### Changed

- Improved `FapiContext::create_seal()` to accept either a non-empty `&[u8]` slice or a `NonZeroUsize` value.
- Various improvements to internal memory handling.

## [0.11.0] - 2026-01-21

### Changed

- The first parameter of all `FapiCallbacks` functions have been changed from `&self` to `&mut self`.

### Added

- Added the `FapiCallbacks::downcast()` and `FapiCallbacks::downcast_mut()` functions.

## [0.10.0] - 2026-01-21

### Added

- Added the `Callbacks` struct, as a simple generic implementation of the `FapiCallbacks` trait.

### Changed

- The `FapiCallbacks` trait **no** longer has the `Debug` trait bound.

## [0.9.0] - 2026-01-20

### Added

- Added the `FapiContext::set_callbacks()` function, which can be used to set or replace all callback functions at once.
- Added the `FapiContext::clear_callbacks()` function, which can be used to unset all callback functions.
- Added the `FapiCallbacks` trait, which represents the set of application-defined callback functions that the FAPI invokes.

### Changed

- Function `get_version()` now returns a `FapiVersion` struct.
- Functions `FapiContext::set_callbacks()` and `FapiContext::clear_callbacks()` now return the previous callbacks.

### Removed

- Removed the `FapiContext::set_auth_callback` function; superseded by `set_callbacks()`.
- Removed the `FapiContext::set_sign_callback` function; superseded by `set_callbacks()`.
- Removed the `FapiContext::set_branch_callback` function; superseded by `set_callbacks()`.
- Removed the `FapiContext::set_policy_action_callback` function; superseded by `set_callbacks()`.

## [0.8.1] - 2026-01-15

### Added

- Re-exported the `json` crate from this crate, because it is used in the public interface.

### Changed

- Simplified some public data types by using `#[non_exhaustive]` attribute where applicable.
- Various improvements to the validation of "flag" parameters.

## [0.8.0] - 2026-01-15

### Added

- Added constructor functions `from_json()` and `from_pem` to the `ImportData` struct.

### Changed

- Function `FapiContext::sign()` now returns a `SignResult` struct on success.
- Function `FapiContext::quote()` now returns a `QuoteResult` struct on success.
- Function `FapiContext::get_tpm_blobs()` now returns a `TpmBlobs` struct on success.

## [0.7.0] - 2026-01-14

### Changed

- Improved `FapiContext::import()` to support the import of either a JSON object (e.g. TPM policy) or a PEM encoded key.
- Updated the Docker images used for building/testing.
- Various dependencies have been updated to the latest version.

## [0.6.2] - 2025-12-12

### Changed

- Various dependencies have been updated to the latest version.
- Updated the Docker images used for building/testing.

## [0.6.1] - 2025-11-07

### Changed

- Various dependencies have been updated to the latest version.
- Updated the Docker images used for building/testing.

## [0.6.0] - 2025-10-06

### Changed

- Rust edition has been changed to 2024.
- Various dependencies have been updated to the latest version.

### Added

- Added support for environment variable `TSS2_FAPI_STATIC` to the `build.rs` file, which allows the *static* version of the TSS2 FAPI library to be linked via pkg-config.

### Fixed

- Improved parsing of the TSS2 FAPI library version in the `build.rs` file, fixing possible errors with "custom" builds.

## [0.5.8] - 2025-04-24

### Changed

- Various dependencies have been updated to the latest version.
- Implemented workaround to make the test code compile with the new version of `rand` crate.

### Added

- GitHub Actions: Run the tests also with the `nightly` toolchain.

## [0.5.7] - 2025-04-22

### Changed

- Various dependencies have been updated to the latest version.
- Incremented minimum supported Rust version to `1.82` in order to build with newer dependency versions.

## [0.5.6] - 2025-01-23

### Fixed

- GitHub Actions: Workaround for our actions being aborted because of an outdated version of `actions/upload-artifact`. We did *not* use the "problematic" version directly, but it was used implicitely via an old version of `awalsh128/cache-apt-pkgs-action`.

### Changed

- Updated funding information in source files and documentation.

## [0.5.5] - 2025-01-17

### Added

- Introduced the `locking` and `full_locking` features to make the serialization of FAPI calls optional.

## [0.5.4] - 2025-01-17

### Added

- Implemented workaround to ensure that calls to `FAPI_Provision()` are serialized across all FAPI contexts and that they are *not* executed concurrently to other FAPI functions, because that function apparently is *not* thread-safe in the underlying TSS 2.0 library.

### Changed

- Updated Docker images for SWTPM and build/test environment to the latest versions.

## [0.5.3] - 2024-10-15

#### Changed

- GitHub repository has been moved to the new official location at: <https://github.com/tpm2-software/rust-tss-fapi>

## [0.5.2] - 2024-10-10

### Added

- Added a job for running/testing the usage examples to the GitHub CI pipeline.

### Changed

- Some improvements to the provided usage examples and the associated documentation.


## [0.5.1] - 2024-10-07

### Changed

- Updated Docker images for SWTPM and build/test environment to the latest versions.
- `build.rs`: Removed workaround for [Docs.rs](https://docs.rs/) build process, now that they have added support for the TSS 2.0 libraries.


## [0.5.0] - 2024-09-22

### Added

- This is the first public release of this project.
