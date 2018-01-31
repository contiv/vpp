FROM golang:1.9.3-alpine3.7 as builder

# we want a static binary
ENV CGO_ENABLED=0

COPY . /go/src/github.com/contiv/vpp

WORKDIR /go/src/github.com/contiv/vpp/cmd/contiv-cri

RUN go build -o /cri main.go

FROM ubuntu:16.04

# install iproute2 - required by dockershim
RUN apt-get update && \
	apt-get install -y --allow-unauthenticated iproute2 && \
	rm -rf /var/lib/apt/lists/*

COPY --from=builder /cri /cri

ENTRYPOINT ["/cri"]
