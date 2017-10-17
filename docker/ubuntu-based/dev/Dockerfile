# update the version tag when moving to a new version of the vpp-agent
FROM ligato/dev-vpp-agent:v1.0.5-4-gd26bfb8

# optional argument - a specific VPP commit ID
ARG VPP_COMMIT_ID="xxx"

# set work directory
WORKDIR /root/

ENV VPP_DIR /opt/vpp-agent/dev/vpp
ENV LDP_DIR $VPP_DIR/extras
ENV VCL_LDPRELOAD_LIB_DIR $LDP_DIR/vcl-ldpreload/src/.libs
ENV LD_PRELOAD_INSTALL /opt/ldpreload

# if VPP comit ID is specified, update to specific VPP commit ID
RUN /bin/bash -c "if [ '${VPP_COMMIT_ID}' != 'xxx' ]; then \
        cd ${VPP_DIR} && \
        git checkout master && \
        git pull && \
        git checkout ${VPP_COMMIT_ID} && \
        rm -rf build-root/ && \
        git reset --hard HEAD ; \
    fi"

# build vcl-ldpreload and uri dependency
RUN /bin/bash -c " \
    cd ${VPP_DIR} && \
    perl -pi -e 's/noinst_PROGRAMS/bin_PROGRAMS/g' $VPP_DIR/src/uri.am && \
    yes | make install-dep && \
    make bootstrap && \
    make pkg-deb && \
    cd build-root && \
    dpkg -i vpp_*.deb vpp-dev_*.deb vpp-lib_*.deb vpp-plugins_*.deb && \
    cd $LDP_DIR/vcl-ldpreload/src && \
    autoreconf -i -f && \
    ./configure VPP_DIR=$VPP_DIR && \
    make"

# copy vcl-ldpreload
RUN /bin/bash -c " \
    mkdir -p $LD_PRELOAD_INSTALL/vpp && \
    mkdir -p $LD_PRELOAD_INSTALL/vpp-lib64 && \
    mkdir -p $LD_PRELOAD_INSTALL/vcl-ldpreload && \
    cp -r $VPP_DIR/build-root/install-vpp-native/vpp/bin/* $LD_PRELOAD_INSTALL/vpp && \
    cp -r $VPP_DIR/build-root/install-vpp-native/vpp/lib64/* $LD_PRELOAD_INSTALL/vpp-lib64 && \
    cp -r $VCL_LDPRELOAD_LIB_DIR/* $LD_PRELOAD_INSTALL/vcl-ldpreload"

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

# run supervisord as the default executable
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf"]
