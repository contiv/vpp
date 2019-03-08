FROM ubuntu:18.04

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
    # general tools
    sudo wget git ca-certificates \
    # build tools
    make \
    # required for disabling TCP checksum offload in containers
    ethtool \
    # network tools
    iproute2 iputils-ping inetutils-traceroute \
    # ability to run vpptrace.sh
    netcat-openbsd \
 && apt-get remove -y --purge gcc \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /opt/vpp-agent/dev/vpp /opt/vpp-agent/plugin

# install Go
ENV GOLANG_VERSION 1.11.5
RUN wget -O go.tgz "https://golang.org/dl/go$GOLANG_VERSION.linux-amd64.tar.gz" \
 && tar -C /usr/local -xzf go.tgz \
 && rm go.tgz

# input arguments
ARG VPP_REPO_URL
ARG VPP_BRANCH_NAME
ARG VPP_COMMIT_ID

# optional argument - skips debug build
ARG SKIP_DEBUG_BUILD=0

# set work directory
WORKDIR /root/

# Path to VPP ws root directory
ENV VPP_DIR /opt/vpp-agent/dev/vpp
ENV VPP_BUILD_DIR $VPP_DIR/build-root
ENV VPP_BIN_DIR $VPP_DIR/build-root/install-vpp_debug-native/vpp/bin
ENV VPP_LIB_DIR $VPP_DIR/build-root/install-vpp_debug-native/vpp/lib64
ENV VPP_BIN $VPP_BIN_DIR/vpp
ENV LD_PRELOAD_LIB_DIR $VPP_LIB_DIR

ENV VPP_PATCH_DIR /opt/vpp-agent/dev/vpp-patches
COPY ./patches $VPP_PATCH_DIR

COPY ./build-vpp.sh /
RUN /build-vpp.sh

