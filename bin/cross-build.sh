#!/bin/bash
set -eo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"

readonly TARGET_DIR="${PWD}/target"
readonly BUILD_DIR="${PWD}/build"
rm -rf "${TARGET_DIR}" "${BUILD_DIR}"

if [ -e "${TARGET_DIR}" ] || [ -e "${BUILD_DIR}" ]; then
    echo "Error: Faild to remove the existing build directory!"
    exit 1
fi

mkdir -p "${TARGET_DIR}" "${BUILD_DIR}"
cd -- "${BUILD_DIR}"

export PKG_CONFIG_SYSROOT_DIR="${TARGET_DIR}"
export PKG_CONFIG_PATH="${PKG_CONFIG_SYSROOT_DIR}/lib/pkgconfig"
export PKG_CONFIG_LIBDIR="${PKG_CONFIG_PATH}"

git config --global advice.detachedHead false

# ----------------------------
# zlib
# ----------------------------

git clone --branch v1.3.1 --single-branch --depth=1 https://github.com/madler/zlib.git
pushd zlib
CC=aarch64-linux-gnu-gcc ./configure --prefix="${TARGET_DIR}" --prefix="${TARGET_DIR}" --static
make install
popd

# ----------------------------
# libuuid
# ----------------------------

git clone --branch v2.41.2 --single-branch --depth=1 https://github.com/util-linux/util-linux.git
pushd util-linux
./autogen.sh
./configure --host=aarch64-linux-gnu --prefix="${TARGET_DIR}" --disable-shared --enable-static --disable-all-programs --enable-libuuid
make install
popd

# ----------------------------
# OpenSSL
# ----------------------------

git clone --branch openssl-3.6.0 --single-branch --depth=1 https://github.com/openssl/openssl.git
pushd openssl
./Configure linux-aarch64 --prefix="${TARGET_DIR}" --cross-compile-prefix=aarch64-linux-gnu- --openssldir="${TARGET_DIR}/etc/ssl" no-tests no-shared
make install_sw
popd

# ----------------------------
# json-c
# ----------------------------

git clone --branch json-c-0.18-20240915 --single-branch --depth=1 https://github.com/json-c/json-c.git
pushd json-c
mkdir build
pushd build
CC=aarch64-linux-gnu-gcc ../cmake-configure --prefix="${TARGET_DIR}" --disable-shared --enable-static
make install
popd && popd

# ----------------------------
# libpsl 
# ----------------------------

git clone --branch 0.21.5 --single-branch --depth=1  https://github.com/rockdaboot/libpsl.git
pushd libpsl
curl -fLo list/public_suffix_list.dat https://publicsuffix.org/list/public_suffix_list.dat
autoreconf -fi
./configure --host=aarch64-linux-gnu --prefix="${TARGET_DIR}" --disable-shared --enable-static --disable-runtime
make install
popd

# ----------------------------
# cURL
# ----------------------------

git clone --branch curl-8_16_0 --single-branch --depth=1  https://github.com/curl/curl.git
pushd curl
autoreconf -fi
./configure --host=aarch64-linux-gnu --prefix="${TARGET_DIR}" --disable-shared --enable-static --with-openssl="${TARGET_DIR}" --without-zstd --without-brotli --disable-docs
make install
popd

# ----------------------------
# TPM 2.0 Software Stack
# ----------------------------

git clone --depth=1 https://github.com/tpm2-software/tpm2-tss.git
pushd tpm2-tss
./bootstrap
./configure --host=aarch64-linux-gnu --prefix="${TARGET_DIR}" --disable-shared --enable-static
make install-libLTLIBRARIES install-tss2HEADERS install-pkgconfigDATA
popd

# ----------------------------
# Rust FAPI-Wrapper
# ----------------------------

export RUSTFLAGS=-Clinker=aarch64-linux-gnu-gcc
export TSS2_FAPI_STATIC=1

git clone --branch 0.6.0 --single-branch https://github.com/tpm2-software/rust-tss-fapi.git
pushd rust-tss-fapi
patch -p1 < "${BUILD_DIR}/../rust-tss-fapi-patch.diff"
cargo build --target=aarch64-unknown-linux-gnu
cargo build --example 1_get_random --target aarch64-unknown-linux-gnu --release
