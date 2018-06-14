ARG VPP_IMAGE
FROM ${VPP_IMAGE}

# copy source files to the container
COPY / /root/go/src/github.com/contiv/vpp

# set env. variables required for go build
ENV GOROOT /usr/local/go
ENV GOPATH /root/go
ENV PATH $PATH:$GOROOT/bin:$GOPATH/bin

# build
RUN cd $GOPATH/src/github.com/contiv/vpp \
 && make \
 && make install

# add supervisord config file
COPY docker/ubuntu-based/dev/supervisord.conf /etc/supervisord.conf

# add debug govpp.conf with larger timeouts
COPY docker/ubuntu-based/dev/govpp.conf /opt/vpp-agent/dev/govpp.conf

# add vppctl script
COPY docker/ubuntu-based/prod/vswitch/vppctl /usr/local/bin/vppctl

# run supervisord as the default executable
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf"]
