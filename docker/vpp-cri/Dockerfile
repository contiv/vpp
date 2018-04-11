FROM golang:1.9.3-alpine3.7 as builder

# we want a static binary
ENV CGO_ENABLED=0

COPY . /go/src/github.com/contiv/vpp

WORKDIR /go/src/github.com/contiv/vpp/cmd/contiv-cri

RUN go build -ldflags '-s -w' -o /cri main.go

FROM alpine:3.7

RUN apk --no-cache add iproute2

COPY --from=builder /cri /cri

ENTRYPOINT ["/cri"]
