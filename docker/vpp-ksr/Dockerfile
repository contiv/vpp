FROM golang:1.10.5-alpine3.8 as builder

# we want a static binary
ENV CGO_ENABLED=0

RUN apk add --update git make

COPY . /go/src/github.com/contiv/vpp

WORKDIR /go/src/github.com/contiv/vpp

RUN make contiv-ksr

FROM scratch

COPY --from=builder /go/src/github.com/contiv/vpp/cmd/contiv-ksr/contiv-ksr /contiv-ksr

ENTRYPOINT ["/contiv-ksr"]
