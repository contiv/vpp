FROM golang:1.10.5-alpine3.8 as builder

# we want a static binary
ENV CGO_ENABLED=0

# contiv-crd depends on govppmux transitively, but only because it reads some constants from vpp-agent plugins
ENV GO_BUILD_TAGS=mockvpp

RUN apk add --update git make

COPY . /go/src/github.com/contiv/vpp

WORKDIR /go/src/github.com/contiv/vpp

RUN make contiv-crd && make contiv-netctl

FROM alpine:3.8

COPY --from=builder /go/src/github.com/contiv/vpp/cmd/contiv-crd/contiv-crd /contiv-crd
COPY --from=builder /go/src/github.com/contiv/vpp/cmd/contiv-netctl/contiv-netctl /contiv-netctl

ENTRYPOINT ["/contiv-crd"]
