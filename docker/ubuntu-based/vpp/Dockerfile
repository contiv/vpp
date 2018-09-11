FROM ubuntu:16.04

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
    sudo wget git gdb nano python \
    iproute2 iputils-ping inetutils-traceroute libapr1 supervisor \
    telnet netcat software-properties-common \
    make autoconf automake libtool curl unzip \
    ethtool\
 && apt-get remove -y --purge gcc \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /opt/vpp-agent/dev/vpp /opt/vpp-agent/plugin

# install Go
ENV GOLANG_VERSION 1.9.3
RUN wget -O go.tgz "https://golang.org/dl/go$GOLANG_VERSION.linux-amd64.tar.gz" \
 && tar -C /usr/local -xzf go.tgz \
 && rm go.tgz

# install ETCD
ENV ETCD_VER=v3.3.9
ENV GOOGLE_URL=https://storage.googleapis.com/etcd
ENV GITHUB_URL=https://github.com/coreos/etcd/releases/download
ENV DOWNLOAD_URL=${GOOGLE_URL}

RUN curl -L ${DOWNLOAD_URL}/${ETCD_VER}/etcd-${ETCD_VER}-linux-amd64.tar.gz -o /tmp/etcd-${ETCD_VER}-linux-amd64.tar.gz
RUN tar xzvf /tmp/etcd-${ETCD_VER}-linux-amd64.tar.gz -C /tmp/etcd --strip-components=1
RUN rm -f /tmp/etcd-${ETCD_VER}-linux-amd64.tar.gz

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
ENV VPP_BIN_DIR $VPP_DIR/build-root/install-vpp_debug-native/vpp/bin
ENV VPP_LIB_DIR $VPP_DIR/build-root/install-vpp_debug-native/vpp/lib64
ENV VPP_BIN $VPP_BIN_DIR/vpp
ENV LD_PRELOAD_LIB_DIR $VPP_LIB_DIR

ENV VPP_PATCH_DIR /opt/vpp-agent/dev/vpp-patches
COPY ./patches $VPP_PATCH_DIR

COPY ./build-vpp.sh /
RUN /build-vpp.sh

