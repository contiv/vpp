FROM ubuntu:18.04

# set work directory
ENV VPP_BUILD_DIR /opt/vpp-agent/dev/vpp/build-root
WORKDIR $VPP_BUILD_DIR

# add VPP binaries (add also extracts from .tar.gz)
ADD binaries/vpp.tar.gz .
