# update the version tag when moving to a new version of the vpp-agent
FROM ligato/dev-vpp-agent:v1.0.6

# optional argument - a specific VPP commit ID
ARG VPP_COMMIT_ID="xxx"

# set work directory
WORKDIR /root/

# Path to VPP ws root directory
ENV VPP_DIR /opt/vpp-agent/dev/vpp

# if VPP comit ID is specified, update to specific VPP commit ID
RUN /bin/bash -c "if [ '${VPP_COMMIT_ID}' != 'xxx' ]; then \
        cd ${VPP_DIR} && \
        git checkout master && \
        git pull && \
        git checkout ${VPP_COMMIT_ID} && \
        rm -rf build-root/ && \
        git reset --hard HEAD ; \
    fi"

# Path to LDPRELOAD root directory
ENV LDP_DIR $VPP_DIR/extras/vcl-ldpreload
# Path where the builded lib is
ENV VCL_LDPRELOAD_LIB_DIR $LDP_DIR/src/.libs
ENV LD_PRELOAD_INSTALL_DIR /opt/ldpreload

# build uri dependency
# ldpreload requires URI to be enabled, so vpp must be recopiled and relinked
# if not needed building of the packages should be doing only if VPP_COMMIT_ID specified
RUN /bin/bash -c " \
    cd ${VPP_DIR} && \
    perl -pi -e 's/noinst_PROGRAMS/bin_PROGRAMS/g' $VPP_DIR/src/uri.am && \
    yes | make install-dep && \
    make bootstrap && \
    make pkg-deb && \
    cd build-root && \
    dpkg -i vpp_*.deb vpp-dev_*.deb vpp-lib_*.deb vpp-plugins_*.deb"

# build vcl-ldpreload
RUN /bin/bash -c " \
    cd $LDP_DIR/src && \
    autoreconf -i -f && \
    ./configure VPP_DIR=$VPP_DIR && \
    make"

# copy vcl-ldpreload
# vpp - vpp binaries, also contains socket_test tool
# vpp-lib64 - libs for vpp
# vcl-ldpreload - ldpreload library
RUN /bin/bash -c " \
    mkdir -p $LD_PRELOAD_INSTALL_DIR/vpp && \
    mkdir -p $LD_PRELOAD_INSTALL_DIR/vpp-lib64 && \
    mkdir -p $LD_PRELOAD_INSTALL_DIR/vcl-ldpreload && \
    cp -r $VPP_DIR/build-root/install-vpp-native/vpp/bin/* $LD_PRELOAD_INSTALL_DIR/vpp && \
    cp -r $VPP_DIR/build-root/install-vpp-native/vpp/lib64/* $LD_PRELOAD_INSTALL_DIR/vpp-lib64 && \
    cp -r $VCL_LDPRELOAD_LIB_DIR/* $LD_PRELOAD_INSTALL_DIR/vcl-ldpreload"

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
