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

# optional argument - a specific VPP commit ID
ARG VPP_COMMIT_ID="xxx"

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

COPY docker/ubuntu-based/dev/build-vpp.sh /
RUN /build-vpp.sh

# copy source files to the container
COPY / /root/go/src/github.com/contiv/vpp

# set env. variables required for go build
ENV GOROOT /usr/local/go
ENV GOPATH /root/go
ENV PATH $PATH:$GOROOT/bin:$GOPATH/bin

# build
RUN cd $GOPATH/src/github.com/contiv/vpp \
 && make \
 && make install

# add supervisord config file
COPY docker/ubuntu-based/dev/supervisord.conf /etc/supervisord.conf

# add debug govpp.conf with larger timeouts
COPY docker/ubuntu-based/dev/govpp.conf /opt/vpp-agent/dev/govpp.conf

# run supervisord as the default executable
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf"]
