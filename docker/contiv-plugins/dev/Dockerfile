FROM golang:1.9.0-alpine3.6

# set work directory
WORKDIR /root/

# dependencies required for build
RUN apk add --update \
    wget git build-base make gcc linux-headers

# download CNI binaries
RUN wget https://github.com/containernetworking/cni/releases/download/v0.3.0/cni-v0.3.0.tgz
RUN mkdir cni
RUN tar xvf cni-v0.3.0.tgz -C cni

# copy source files to the container
COPY / /root/go/src/github.com/contiv/vpp

# set env. variables required for go build
ENV GOROOT /usr/local/go
ENV GOPATH /root/go
ENV PATH $PATH:$GOROOT/bin:$GOPATH/bin

# build
RUN cd $GOPATH/src/github.com/contiv/vpp && \
    make contiv-cni && \
    make contiv-ksr && \
    make contiv-cri

# run shell by default
CMD ["/bin/sh"]