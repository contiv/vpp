FROM ligato/dev-vpp-agent

# copy source files to the container
COPY / /root/go/src/github.com/contiv/vpp

# env. variables required for go build
ENV GOROOT /usr/local/go
ENV GOPATH /root/go
ENV PATH $PATH:$GOROOT/bin:$GOPATH/bin

# build
RUN cd $GOPATH/src/github.com/contiv/vpp && \
    make && \
    make install

# add supervisor config file
COPY docker/contiv-vswitch/dev/supervisord.conf /etc/supervisord.conf

# set work directory
WORKDIR /root/

# run supervisor as the default executable
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf"]
