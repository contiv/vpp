# update the version tag when moving to a new version of the vpp-agent
FROM ligato/dev-vpp-agent:pantheon-dev

# optional argument - a specific VPP commit ID
ARG VPP_COMMIT_ID="xxx"

# install ethtool - required for disabling TCP checksum offload in containers
RUN apt-get update && apt-get install -y ethtool

# set work directory
WORKDIR /root/

# Path to VPP ws root directory
ENV VPP_DIR /opt/vpp-agent/dev/vpp
ENV VPP_BIN_DIR $VPP_DIR/build-root/install-vpp-native/vpp/bin
ENV VPP_LIB_DIR $VPP_DIR/build-root/install-vpp-native/vpp/lib64
ENV VPP_BIN $VPP_BIN_DIR/vpp
ENV LD_PRELOAD_LIB_DIR $VPP_LIB_DIR

# if VPP comit ID is specified, update to specific VPP commit ID
#RUN /bin/bash -c "if [ '${VPP_COMMIT_ID}' != 'xxx' ]; then \
#        cd ${VPP_DIR} && \
#        git checkout master && \
#        git pull && \
#        git checkout ${VPP_COMMIT_ID} && \
#        rm -rf build-root/ && \
#        git reset --hard HEAD && \
#        yes | make install-dep && \
#        make bootstrap && \
#        make build && \
#        make pkg-deb && \
#        cd build-root && \
#        yes | apt remove vpp vpp-plugins vpp-lib vpp-dev || true && \
#        dpkg -i vpp_*.deb vpp-dev_*.deb vpp-lib_*.deb vpp-plugins_*.deb ; \
#    fi"

RUN rm -rf /opt/vpp-agent/dev/vpp && \
    cd /opt/vpp-agent/dev && \
    git clone https://github.com/vpp-dev/vpp.git && \
    cd vpp && \
    yes | make install-dep && \
    make bootstrap && \
    make build && \
    make pkg-deb && \
    cd build-root && \
    yes | apt remove vpp vpp-plugins vpp-lib vpp-dev || true && \
    dpkg -i vpp_*.deb vpp-dev_*.deb vpp-lib_*.deb vpp-plugins_*.deb ;

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
COPY docker/ubuntu-based/dev/supervisord.conf /etc/supervisord.conf

# add debug govpp.conf with larger timeouts
COPY docker/ubuntu-based/dev/govpp.conf /opt/vpp-agent/dev/govpp.conf

# run supervisord as the default executable
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf"]
