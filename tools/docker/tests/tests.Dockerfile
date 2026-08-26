# Define default Rust-TSS2 base image version
ARG IMAGE_VERSION_RSTSS=0000000000000000000000000000000000000000000000000000000000000000

# Docker file for build-env
FROM danieltrick/rust-tss2-docker@sha256:${IMAGE_VERSION_RSTSS}

# Copy source files
COPY src/test-runner.sh src/shutdown_swtpm.c /opt/

# Build tool
RUN gcc -O2 -Wall -DNDEBUG -o /opt/shutdown_swtpm /opt/shutdown_swtpm.c \
    && rm -rvf /opt/shutdown_swtpm.c

# Entry point
ENTRYPOINT ["/opt/test-runner.sh"]
