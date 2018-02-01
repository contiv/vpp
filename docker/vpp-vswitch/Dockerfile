# compile vpp-agent needs vpp libs
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
    && make lint agent

FROM contiv/vpp-base:b59bd659

RUN apt-get update \
    && apt-get install -y ethtool supervisor

# copy binaries
COPY --from=builder /root/go/src/github.com/contiv/vpp/cmd/contiv-agent/contiv-agent /usr/bin/contiv-agent

# add contiv-vswitch.conf
COPY docker/vpp-vsvswitch/contiv-vswitch.conf /etc/vpp/contiv-vswitch.conf

# add supervisord config file
COPY docker/vpp-vsvswitch/supervisord.conf /etc/supervisord.conf

# add govpp config file
COPY docker/vpp-vsvswitch/govpp.conf /etc/govpp/govpp.conf

# run supervisord as the default executable
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf"]
