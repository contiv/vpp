FROM ligato/dev-vpp-agent

# copy source files to the container
COPY /vpp /opt/ld_preload/vpp

ENV VCL_BASE /opt/ld_preload
ENV VPP_DIR $VCL_BASE/vpp
ENV LDP_DIR $VCL_BASE/vpp/extras
ENV WS_ROOT $VCL_BASE/vpp
ENV VCL_LDPRELOAD_LIB_DIR $LDP_DIR/vcl-ldpreload/src/.libs

RUN cd $VPP_DIR && \
    perl -pi -e 's/noinst_PROGRAMS/bin_PROGRAMS/g' $VPP_DIR/src/uri.am

RUN cd $VPP_DIR && \
    yes | make install-dep

#RUN cd $VPP_DIR && \
#    make wipe-release

RUN cd $VPP_DIR && \
    make bootstrap

RUN cd $VPP_DIR && \
    make build-release

RUN cd $LDP_DIR/vcl-ldpreload/src && \
    autoreconf -i -f && \
    ./configure VPP_DIR=$VPP_DIR && \
    make
