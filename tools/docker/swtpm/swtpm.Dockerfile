# Define default base image version
ARG BASE_VERSION=UNDEFINED

# Docker file for SWTPM
FROM danieltrick/swtpm-docker:${BASE_VERSION}

# Copy source files
COPY src/entry-point.sh /opt/

# Start SWTPM Server
ENTRYPOINT ["/opt/entry-point.sh"]
