FROM golang:1.10.7-alpine3.8 as builder

# we want a static binary
ENV CGO_ENABLED=0

RUN apk add --update wget git make gcc linux-headers libc-dev

COPY . /go/src/github.com/contiv/vpp

# we need the loopback binary from CNI
# this binary can be obtained from the cni tarball
RUN export CNI_VERSION=0.3.0 \
 && wget https://github.com/containernetworking/cni/releases/download/v$CNI_VERSION/cni-v$CNI_VERSION.tgz -O /cni.tgz \
 && mkdir /cni \
 && tar -xvf /cni.tgz -C /cni

# Build a custom version of the portmap plugin, modified for VPP-based networking.
RUN export CNI_PLUGIN_VERSION=0.7 \
 && mkdir -p /go/src/github.com/containernetworking \
 && cd /go/src/github.com/containernetworking \
 && git clone https://github.com/containernetworking/plugins.git -b v$CNI_PLUGIN_VERSION \
 && cd plugins/plugins/meta/portmap/ \
 && git apply /go/src/github.com/contiv/vpp/docker/vpp-cni/portmap.diff \
 && go build -ldflags '-s -w' -o /portmap

WORKDIR /go/src/github.com/contiv/vpp

# build contiv-cni
RUN make contiv-cni

# we collect & store all files in one folder to make the resulting
# image smaller when we copy them all in one single operation
RUN mkdir -p /output/cni/bin && mkdir -p /output/cni/cfg \
 && cp cmd/contiv-cni/contiv-cni /output/cni/bin/ \
 && cp /cni/loopback /output/cni/bin/ \
 && cp /portmap /output/cni/bin/ \
 && cp /go/src/github.com/contiv/vpp/docker/vpp-cni/install.sh /output/cni/ \
 && cp /go/src/github.com/contiv/vpp/docker/vpp-cni/10-contiv-vpp.conflist /output/cni/cfg/

FROM alpine:3.8

COPY --from=builder /output/cni /cni

# run install script by default
CMD ["/cni/install.sh"]
