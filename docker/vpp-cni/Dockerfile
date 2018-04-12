FROM golang:1.9.3-alpine3.7 as builder

# we need the loopback binary from CNI
# this binary can be obtained from the cni tarball
RUN apk add --update wget \
 && export CNI_VERSION=0.3.0 \
 && wget https://github.com/containernetworking/cni/releases/download/v$CNI_VERSION/cni-v$CNI_VERSION.tgz \
    -O /cni.tgz \
 && mkdir /cni \
 && tar -xvf /cni.tgz -C /cni \
 && rm /cni.tgz
COPY . /go/src/github.com/contiv/vpp

# Build a custom version of the portmap plugin, modified for VPP-based networking.
RUN apk add --update git gcc linux-headers libc-dev \
 && export CGO_ENABLED=0 \
 && export CNI_PLUGIN_VERSION=0.7 \
 && mkdir -p /go/src/github.com/containernetworking \
 && cd /go/src/github.com/containernetworking \
 && git clone https://github.com/containernetworking/plugins.git -b v$CNI_PLUGIN_VERSION \
 && cd plugins/plugins/meta/portmap/ \
 && git apply /go/src/github.com/contiv/vpp/docker/vpp-cni/portmap.diff \
 && go build -ldflags '-s -w' -o /portmap

WORKDIR /go/src/github.com/contiv/vpp/cmd/contiv-cni

# we collect & store all files in one folder to make the resulting
# image smaller when we copy them all in one single operation
RUN export CGO_ENABLED=0 \
 && mkdir /output/ \
 && cp /cni/loopback /output/ \
 && cp /go/src/github.com/contiv/vpp/docker/vpp-cni/10-contiv-vpp.conflist /output/ \
 && cp /go/src/github.com/contiv/vpp/docker/vpp-cni/install.sh /output/ \
 && cp /portmap /output/ \
 && go build -ldflags '-s -w' -o /output/contiv-cni contiv_cni.go


FROM alpine:3.7

# set work directory
WORKDIR /root/

COPY --from=builder /output/* /root/

# run install script by default
CMD ["/root/install.sh"]
