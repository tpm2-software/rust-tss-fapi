include tools/docker/docker.mk

.SHELLFLAGS = -e -c

DOCKER := $(foreach target,$(DOCKER_TARGETS),docker.$(target))

.PHONY: all bench build check clean clippy codecov docs examples fmt libtpms package publish tests upgrade $(DOCKER)

all: clean check build

fmt:
	cargo fmt --all

check:
	cargo fmt --all --check
	cargo check --no-default-features
	cargo check --release --all-features --all-targets

clippy: check
	cargo clippy --no-default-features -- -D warnings
	cargo clippy --all-features --all-targets -- -D warnings

upgrade:
	cargo upgrade -i
	cargo update

tests:
	CARGO_PROFILE_RELEASE_DEBUG=true RUST_BACKTRACE=1 RUST_LOG=info TSS2_LOG="all+none" \
	cargo test --release --tests --locked -- --test-threads=1

build:
	cargo build --release --locked

examples:
	for i in $(basename $(notdir $(wildcard examples/*.rs))); do \
		cargo run --example $$i; \
	done

bench:
	TSS2_LOG="all+error" cargo bench --bench fapi_benchmark $(if $(QUICK_MODE),-- --quick)

docs:
	cargo doc --no-deps --locked

format:
	cargo fmt --all $(if $(APPLY_FMT),,--check)

package:
	cargo package --locked

publish:
	cargo publish --locked

clean:
	rm -rf target $(if $(CARGO_TARGET_DIR),"$(CARGO_TARGET_DIR)")

libtpms:
	./tools/libtpms/libtpms-test-runner.sh --include-ignored

codecov:
	./tools/codecov/code-coverage.sh ccov target/llvm-cov/codecov-output.json

$(DOCKER): docker.%:
	$(MAKE) -C tools/docker $*
