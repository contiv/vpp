# compile vpp-agent needs vpp libs
# Update contiv/vpp-base version below if contiv/vpp-base-builder is changed
FROM contiv/vpp-base-builder:b59bd659 as builder

ENV GOLANG_VERSION 1.9.3
ENV GOPATH /root/go
ENV PATH $PATH:/usr/local/go/bin:$GOPATH/bin

RUN apt-get update \
    && apt-get install -y curl git make \
    && rm -rf /var/lib/apt/lists/* \
    && curl -L "https://golang.org/dl/go$GOLANG_VERSION.linux-amd64.tar.gz" | tar -C /usr/local -xzf - \
    && go get -u github.com/golang/lint/golint

COPY . $GOPATH/src/github.com/contiv/vpp

# lint and only build vpp-agent
RUN cd $GOPATH/src/github.com/contiv/vpp \
    && make lint agent contiv-init

FROM contiv/vpp-base:b59bd659

RUN apt-get update \
    && apt-get install -y ethtool supervisor \
    && rm -rf /var/lib/apt/lists/*

# copy binaries
COPY --from=builder /root/go/src/github.com/contiv/vpp/cmd/contiv-agent/contiv-agent /usr/bin/contiv-agent
COPY --from=builder /root/go/src/github.com/contiv/vpp/cmd/contiv-init/contiv-init /usr/bin/contiv-init

COPY docker/vpp-vswitch/contiv-vswitch.conf /etc/vpp/contiv-vswitch.conf
COPY docker/vpp-vswitch/govpp.conf /etc/govpp/govpp.conf
COPY docker/vpp-vswitch/supervisord.conf /etc/supervisord.conf

# run supervisord as the default executable
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf"]
