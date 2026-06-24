# Define default Rust-TSS2 base image version
ARG IMAGE_VERSION_RSTSS=UNDEFINED

# Docker file for build-env
FROM danieltrick/rust-tss2-docker@${IMAGE_VERSION_RSTSS}

# Default command
CMD ["rebuild", "--release"]
