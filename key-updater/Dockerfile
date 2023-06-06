FROM ubuntu:22.04
# https://www.docker.com/blog/faster-multi-platform-builds-dockerfile-cross-compilation-guide/
ARG TARGETPLATFORM

# see https://docs.docker.com/develop/develop-images/dockerfile_best-practices/
RUN apt-get update && apt-get install -y \
	ca-certificates \
 && rm -rf /var/lib/apt/lists/*
RUN update-ca-certificates

COPY bin/$TARGETPLATFORM/keys-updater /usr/local/bin/warp-keys-updater

RUN mkdir -p /root/keys
COPY $WARP_KEYS_HOME/$WARP_ENV/ /root/keys/${WARP_VERSION}/
CMD ["/usr/local/bin/warp-keys-updater", "/root/keys/${WARP_VERSION}"]
