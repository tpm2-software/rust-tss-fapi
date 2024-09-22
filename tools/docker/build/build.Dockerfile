# Define default base image version
ARG BASE_VERSION=UNDEFINED

# Docker file for build-env
FROM danieltrick/rust-tss2-docker:${BASE_VERSION}

# Default command
CMD ["rebuild", "--release"]
