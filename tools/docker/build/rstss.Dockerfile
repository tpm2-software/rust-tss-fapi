# Define default Rust-TSS2 base image version
ARG IMAGE_VERSION_RSTSS=0000000000000000000000000000000000000000000000000000000000000000

# Docker file for build-env
FROM danieltrick/rust-tss2-docker@sha256:${IMAGE_VERSION_RSTSS}

# Default command
CMD ["rebuild", "--release"]
