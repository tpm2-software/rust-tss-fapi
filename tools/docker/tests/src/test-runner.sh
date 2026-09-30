#!/bin/bash
set -eo pipefail

readonly EXPECTED_TEST_COUNT=79

. "${CARGO_HOME}/env"

if [[ -n "${TEST_KEEP_RUNNING}" && "${TEST_KEEP_RUNNING}" -gt 0 ]]; then
	trap "sleep inf" EXIT
fi

( . /etc/os-release && printf '%s %s ["%s"]\n' "${NAME:-Linux}" "${VERSION:-${VERSION_CODENAME:-Unknown}}" "${PRETTY_NAME:-Unknown}" )
cargo version || true
printf 'tss2-fapi: %s\n' "$(pkgconf --modversion tss2-fapi)" || true

function test_profile() {
	echo "========================================================"
	echo "Test profile: ${1}"
	echo "========================================================"
	local my_target="$(mktemp --tmpdir="/var/tmp/rust" -d)"
	local test_opts="--test-threads=1"
	if [[ -n "${TEST_INCL_IGNORED}" && "${TEST_INCL_IGNORED}" -gt 0 ]]; then
		local test_opts="${test_opts} --include-ignored"
	fi
	$BASH -x <<-EOF
		CARGO_PROFILE_RELEASE_DEBUG=true \
		RUST_BACKTRACE=1 \
		FAPI_RS_TEST_PROF="${1}" \
		cargo test --release --tests --target-dir="${my_target}" ${FAPI_RS_TEST_NAME:-test} -- ${test_opts}
	EOF
	rm -rf "${my_target}"
}

for profile_name in "${@:-RSA2048SHA256}"; do
	log_file="$(mktemp --suffix=.log)"
	n_global=0
	test_profile "${profile_name}" 2>&1 | tee "${log_file}"
	while IFS= read -r line; do
		n_passed=$(grep -Po '\b\d+\s+passed' <<< "${line}" | tr -s '[:space:]' ';' | cut -d';' -f1)
		n_failed=$(grep -Po '\b\d+\s+failed' <<< "${line}" | tr -s '[:space:]' ';' | cut -d';' -f1)
		if [[ -z "${n_passed}" || "${n_passed}" -lt 1 || "${n_failed}" -ne 0 ]]; then
			printf "ERROR: At least one test has failed! (profile: %s, passed: %d, failed: %d)\n" "${profile_name}" "${n_passed}" "${n_failed}"
			exit 1
		fi
		(( n_global += n_passed ))
	done < <(grep -P '^test result:' "${log_file}")
	rm -f "${log_file}"
	printf "SUMMARY: %d/%d tests completed successfully.\n\n" "${n_global}" "${EXPECTED_TEST_COUNT}"
	if [[ "${n_global}" -lt "${EXPECTED_TEST_COUNT}" ]]; then
		printf "ERROR: The total number of passed tests is insufficient! (total: %d, expected: %d)\n" "${n_global}" "${EXPECTED_TEST_COUNT}"
		exit 1
	fi
	/opt/shutdown_swtpm "${SWTPM_CTRL_ADDR:-127.0.0.1}" "${SWTPM_CTRL_PORT:-2322}"
done
