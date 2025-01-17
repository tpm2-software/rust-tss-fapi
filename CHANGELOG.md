# Change Log

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/).

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
