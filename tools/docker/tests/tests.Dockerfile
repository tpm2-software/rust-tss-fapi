# Define default base image version
ARG BASE_VERSION=UNDEFINED

# Docker file for build-env
FROM danieltrick/rust-tss2-docker:${BASE_VERSION}

# Copy source files
COPY src/test-runner.sh src/shutdown_swtpm.c /opt/

# Build tool
RUN gcc -O2 -Wall -DNDEBUG -o /opt/shutdown_swtpm /opt/shutdown_swtpm.c \
    && rm -rvf /opt/shutdown_swtpm.c

# Entry point
ENTRYPOINT ["/opt/test-runner.sh"]
