# update the version tag when moving to a new version of the vpp-agent
FROM ligato/dev-vpp-agent:v1.0.5

# set work directory
WORKDIR /root/

# copy source files to the container
COPY / /root/go/src/github.com/contiv/vpp

# set env. variables required for go build
ENV GOROOT /usr/local/go
ENV GOPATH /root/go
ENV PATH $PATH:$GOROOT/bin:$GOPATH/bin

# build
RUN cd $GOPATH/src/github.com/contiv/vpp && \
    make && \
    make install

# add supervisord config file
COPY docker/contiv-vswitch/dev/supervisord.conf /etc/supervisord.conf

# run supervisord as the default executable
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf"]
