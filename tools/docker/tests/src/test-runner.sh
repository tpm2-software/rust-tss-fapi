#!/bin/bash
set -eo pipefail

readonly logfile="/var/log/tss2-fapi-rs/test-bench.$(date +'%s')"

. "${CARGO_HOME}/env"

if [[ -n "${TEST_KEEP_RUNNING}" && "${TEST_KEEP_RUNNING}" -gt 0 ]]; then
	trap "sleep inf" EXIT
fi

function trace() {
	local -
	set -o xtrace
	"$@"
}

function test_profile() {
	echo "========================================================"
	echo "Test profile: ${1}"
	echo "========================================================"
	local my_target="$(mktemp --tmpdir="/var/tmp/rust" -d)"
	local test_opts="--test-threads=1"
	if [[ -n "${TEST_INCL_IGNORED}" && "${TEST_INCL_IGNORED}" -gt 0 ]]; then
		local test_opts="${test_opts} --include-ignored"
	fi
	export CARGO_PROFILE_RELEASE_DEBUG=true
	export RUST_BACKTRACE=1
	export FAPI_RS_TEST_PROF="${1}"
	trace cargo test --release --tests --target-dir="${my_target}" ${FAPI_RS_TEST_NAME:-test} -- ${test_opts}
	rm -rf "${my_target}"
}

unset result

for profile_name in "${@:-RSA2048SHA256}"; do
	test_profile "${profile_name}" 2>&1 | tee "${logfile}.${profile_name}.log"
	result=$(cat "${logfile}.${profile_name}.log" | grep -F 'test result:' | grep -Po '\d+ passed' | awk '{s+=$1}END{print s}')
	printf "SUMMARY: %d tests completed successfully.\n\n" "${result}"
	/opt/shutdown_swtpm "${SWTPM_CTRL_ADDR:-127.0.0.1}" "${SWTPM_CTRL_PORT:-2322}"
done
