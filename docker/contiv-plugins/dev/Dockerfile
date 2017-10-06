FROM golang:1.9.0-alpine3.6

RUN apk add --update \
    wget git build-base make gcc linux-headers

# set work directory
WORKDIR /root/

# download CNI binaries
RUN wget https://github.com/containernetworking/cni/releases/download/v0.3.0/cni-v0.3.0.tgz
RUN mkdir cni
RUN tar xvf cni-v0.3.0.tgz -C cni

# copy source files to the container
COPY / /root/go/src/github.com/contiv/vpp

# env. variables required for go build
ENV GOROOT /usr/local/go
ENV GOPATH /root/go
ENV PATH $PATH:$GOROOT/bin:$GOPATH/bin

# build
RUN cd $GOPATH/src/github.com/contiv/vpp && \
    make contiv-cni && \
    make contiv-ksr

# run shell by default
CMD ["/bin/sh"]