# Define default SWTPM base image version
ARG IMAGE_VERSION_SWTPM=0000000000000000000000000000000000000000000000000000000000000000

# Docker file for SWTPM
FROM danieltrick/swtpm-docker@sha256:${IMAGE_VERSION_SWTPM}

# Copy source files
COPY src/entry-point.sh /opt/

# Start SWTPM Server
ENTRYPOINT ["/opt/entry-point.sh"]
