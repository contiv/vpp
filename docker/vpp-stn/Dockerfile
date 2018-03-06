FROM golang:1.9.3-alpine3.7 as builder

# we want a static binary
ENV CGO_ENABLED=0

COPY . /go/src/github.com/contiv/vpp

WORKDIR /go/src/github.com/contiv/vpp/cmd/contiv-stn

RUN go build -o /stn .

FROM scratch

COPY --from=builder /stn /stn

ENTRYPOINT ["/stn"]
