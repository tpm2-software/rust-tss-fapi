# Define default SWTPM base image version
ARG IMAGE_VERSION_SWTPM=UNDEFINED

# Docker file for SWTPM
FROM danieltrick/swtpm-docker@${IMAGE_VERSION_SWTPM}

# Copy source files
COPY src/entry-point.sh /opt/

# Start SWTPM Server
ENTRYPOINT ["/opt/entry-point.sh"]
