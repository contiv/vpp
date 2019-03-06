ARG VPP_IMAGE
FROM ${VPP_IMAGE}

# install deps
RUN apt-get update && apt-get install -y \
 make \
 wget \
 git \
 gcc

# install vpp
WORKDIR $VPP_BUILD_DIR
ARG VPP_INSTALL_PKG
RUN if [ -n "$VPP_INSTALL_PKG" ]; then \
 apt-get install -y ./*.deb; \
 fi

# copy source files to the container
COPY / /root/go/src/github.com/contiv/vpp

# install Go
ENV GOLANG_VERSION 1.10.7
RUN if [ -n "$VPP_INSTALL_PKG" ]; then \
 wget -O go.tgz "https://golang.org/dl/go$GOLANG_VERSION.linux-amd64.tar.gz" \
 && tar -C /usr/local -xzf go.tgz \
 && rm go.tgz; \
 fi

# set env. variables required for go build
ENV GOROOT /usr/local/go
ENV GOPATH /root/go
ENV PATH $PATH:$GOROOT/bin:$GOPATH/bin

# build
RUN cd $GOPATH/src/github.com/contiv/vpp \
 && make contiv-init \
 && make contiv-agent

# add debug govpp.conf with larger timeouts
COPY docker/vpp-vswitch/dev/govpp.conf /opt/vpp-agent/dev/govpp.conf

# add vppctl script
COPY docker/vpp-vswitch/prod/vswitch/vppctl /usr/local/bin/vppctl

# run contiv-init as the default executable
CMD ["/root/go/src/github.com/contiv/vpp/cmd/contiv-init/contiv-init", "-vpp-bin=/opt/vpp-agent/dev/vpp/build-root/install-vpp_debug-native/vpp/bin/vpp", "-agent-bin=/root/go/src/github.com/contiv/vpp/cmd/contiv-agent/contiv-agent"]
