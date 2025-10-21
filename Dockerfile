FROM debian:13-slim
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update -qq && \
    apt-get install -y --no-install-recommends \
        autoconf \
        autoconf-archive \
        automake \
        autopoint \
        bison \
        build-essential \
        ca-certificates \
        cmake \
        crossbuild-essential-arm64 \
        curl \
        flex \
        gettext \
        git \
        libtool \
        pkg-config && \
    rm -rf /var/lib/apt/lists && \
    rm -rf /var/cache/apt/archives

RUN curl https://sh.rustup.rs -sSf | bash -s -- -y && \
    . /root/.cargo/env && \
    rustup target add aarch64-unknown-linux-gnu

COPY bin/cross-build.sh /app/cross-build.sh
COPY bin/rust-tss-fapi-patch.diff /app/rust-tss-fapi-patch.diff
RUN chmod +x /app/cross-build.sh

ENV PATH="/root/.cargo/bin:${PATH}"
WORKDIR /app
CMD ["./cross-build.sh"]
