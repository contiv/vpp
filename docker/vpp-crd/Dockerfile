FROM golang:1.9.3-alpine3.7 as builder

# we want a static binary
ENV CGO_ENABLED=0

COPY . /go/src/github.com/contiv/vpp

WORKDIR /go/src/github.com/contiv/vpp

RUN make contiv-crd && make contiv-netctl

FROM scratch

COPY --from=builder /go/src/github.com/contiv/vpp/cmd/contiv-crd/contiv-crd /contiv-crd
COPY --from=builder /go/src/github.com/contiv/vpp/cmd/contiv-netctl/contiv-netctl /contiv-netctl

ENTRYPOINT ["/contiv-crd"]
