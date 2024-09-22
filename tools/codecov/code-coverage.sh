#!/bin/bash
set -eo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.."

# ----------------------------------------------------------------------------
# Check parameters
# ----------------------------------------------------------------------------

if [ "$#" -lt 1 ]; then
	echo "Usage: code-coverage.sh <format> [<output_file>]"
	exit 1
fi

readonly DEST_FORMAT="${1}"
readonly OUTPUT_FILE="${2}"

case "${DEST_FORMAT}" in
	html)
		true;;
	json|text|lcov|ccov)
		if [ -z "${OUTPUT_FILE}" ]; then
			echo "ERROR: Output file must be specified for the selected target format!"
			exit 1
		fi;;
	*)
		echo "ERROR: The specified target format \"${DEST_FORMAT}\" is *not* supported!"
		exit 1
esac



# ----------------------------------------------------------------------------
# Check prerequisites
# ----------------------------------------------------------------------------

if ! which cargo >/dev/null 2>&1; then
	echo "ERROR: Cargo program could not be found. Please make sure that Rust/Cargo is installed!"
	exit 1
fi

if [[ -z "$(cargo --list | grep 'llvm-cov')" ]]; then
	echo "ERROR: It appears that the required command 'cargo-llvm-cov' is *not* currently installed."
	echo "Please run \"cargo +stable install cargo-llvm-cov --locked\" to install!"
	exit 1
fi

# ----------------------------------------------------------------------------
# Instrumentation and profiling
# ----------------------------------------------------------------------------

cargo clean
cargo llvm-cov clean

if [[ "${DEST_FORMAT}" != "html" && "$(dirname -- ${OUTPUT_FILE})" != "." ]]; then
	mkdir -p "$(dirname -- ${OUTPUT_FILE})"
fi

case "${DEST_FORMAT}" in
	html)
		cargo llvm-cov --release --locked --html;;
	json)
		cargo llvm-cov --release --locked --json    --output-path "${OUTPUT_FILE}";;
	text)
		cargo llvm-cov --release --locked --text    --output-path "${OUTPUT_FILE}";;
	lcov)
		cargo llvm-cov --release --locked --lcov    --output-path "${OUTPUT_FILE}";;
	ccov)
		cargo llvm-cov --release --locked --codecov --output-path "${OUTPUT_FILE}";;
esac
