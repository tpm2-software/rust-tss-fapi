[![Rust](https://img.shields.io/badge/rust-1.79.0+-orchid?logo=rust)](https://www.rust-lang.org/)
[![Crates.io](https://img.shields.io/crates/v/tss2-fapi-rs.svg)](https://crates.io/crates/tss2-fapi-rs)
[![Docs.rs](https://img.shields.io/docsrs/tss2-fapi-rs.svg)](https://docs.rs/tss2-fapi-rs/latest/tss2_fapi_rs/)
[![License](https://img.shields.io/crates/l/tss2-fapi-rs)](https://opensource.org/licenses/BSD-3-Clause)
[![CI](https://github.com/tpm2-software/rust-tss-fapi/actions/workflows/ci.yaml/badge.svg)](https://github.com/tpm2-software/rust-tss-fapi/actions/workflows/ci.yaml)
[![Codecov](https://codecov.io/github/danieltrick/tss2-fapi-rs/graph/badge.svg?token=c3Jw6d2ZAk)](https://codecov.io/github/danieltrick/tss2-fapi-rs)

# TSS 2.0 FAPI Rust Wrapper

The **`tss2-fapi-rs`** Rust crate provides an interface to the [**TSS2.0 Feature API (FAPI)**](https://tpm2-tss.readthedocs.io/en/latest/group__fapi.html).

*Architectural overview:*  
![tss2-fapi-rs Overview](docs/images/tss2-fapi-rs-overview.png)

## Layout

The **`tss2-fapi-rs`** project is organized as follows:

```
tss2-fapi-rs
├── Cargo.toml      The "manifest" file for Cargo
├── build.rs        Build script (for pkg-config + bindgen)
├── docs            Various bits of documentation
├── examples        Usage examples
│   └── data        Example FAPI configuration
├── src             Source code of the "tss2-fapi-rs" library
│   └── fapi_sys    Low-level FFI bindings for FAPI
├── tests           Integration tests
│   └── data        Test configuration files
└── tools           Build tools
    ├── codecov     Code coverage analysis script (llvm-cov)
    ├── docker      Docker test/build environment
    │   ├── build   Build container
    │   ├── swtpm   Software TPM container
    │   └── tests   Test container
    └── libtpms     Test driver script for using libtpms
```

## Documentation

The documentation for **`tss2-fapi-rs`** is created with [`rustdoc`](https://doc.rust-lang.org/rustdoc/what-is-rustdoc.html) and can be viewed online at:

* **<https://tpm2-software.github.io/rust-tss-fapi/tss2_fapi_rs/>**

* **<https://docs.rs/tss2-fapi-rs/latest/>**

## Disclaimer

The current version of the API does not offer any security or code safety guarantees. The implementation that is provided is suitable for exploratory testing and experimentation only. This test implementation does not offer any tangible security benefits and therefore is not suitable for use in production. Documentation pages may be incomplete and are subject to change without notice. Interfaces may change in such a way as to break compatibility with client code. Contributions from the developer community are welcome.

## License

Copyright 2024, Fraunhofer SIT sponsored by the ELISA research project  
All rights reserved.

This work is released under the [**3-Clause BSD License**](https://opensource.org/license/bsd-3-clause) (SPDX short identifier: `BSD-3-Clause`).
