FROM golang:1.9.3-alpine3.7 as builder

# we want a static binary
ENV CGO_ENABLED=0

RUN apk add --update git make

COPY . /go/src/github.com/contiv/vpp

WORKDIR /go/src/github.com/contiv/vpp

RUN make contiv-stn

FROM scratch

COPY --from=builder /go/src/github.com/contiv/vpp/cmd/contiv-stn/contiv-stn /contiv-stn

ENTRYPOINT ["/contiv-stn"]
