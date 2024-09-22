#!/bin/bash
set -eo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.."

# ----------------------------------------------------------------------------
# Check prerequisites
# ----------------------------------------------------------------------------

pkg-config --cflags --libs libtpms tss2-tcti-libtpms

# ----------------------------------------------------------------------------
# Run tests using libtpms
# ----------------------------------------------------------------------------

readonly WORKING_DIR="$(mktemp -d)"
trap "rm -rf \"${WORKING_DIR}\"" EXIT ERR

cargo clean

RUST_LOG=info TSS2_LOG="all+none" \
RUST_BACKTRACE=1 \
CARGO_PROFILE_RELEASE_DEBUG=true \
FAPI_RS_TEST_TCTI="libtpms:libtpms_state.dat" \
FAPI_RS_TEST_DIR="${WORKING_DIR}" \
cargo test --tests --release -- "${@}"
