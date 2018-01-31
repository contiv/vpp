FROM golang:1.9.3-alpine3.7 as builder

# we want a static binary
ENV CGO_ENABLED=0

COPY . /go/src/github.com/contiv/vpp

WORKDIR /go/src/github.com/contiv/vpp/cmd/contiv-ksr

RUN go build -o /ksr main.go

FROM scratch

COPY --from=builder /ksr /ksr

ENTRYPOINT ["/ksr"]
