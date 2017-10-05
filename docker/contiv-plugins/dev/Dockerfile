FROM golang:1.9.0-alpine3.6

RUN apk add --update \
    git build-base make gcc linux-headers

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

# set work directory
WORKDIR /root/

# run shell by default
CMD ["/bin/sh"]