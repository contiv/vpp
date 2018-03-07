#!/bin/bash

set -euo pipefail

cd /opt/vpp-agent/dev/
git clone https://gerrit.fd.io/r/vpp
cd ${VPP_DIR}
git checkout master
git pull
# check out a specific commit if specified
# continue and ignore the error if the commit ID isn't specified
git checkout ${VPP_COMMIT_ID} || true
rm -rf build-root/
git reset --hard HEAD
UNATTENDED=y make vpp_configure_args_vpp='--disable-japi --disable-vom' install-dep
apt-get remove --purge -y gcc gcc-5 g++ cpp-5
add-apt-repository -y ppa:ubuntu-toolchain-r/test
apt-get update
apt-get install -y gcc-7 g++-7
cd /usr/bin/
ln -s gcc-7 gcc
ln -s g++-7 g++
ln -s cpp-7 cpp
rm -rf /var/lib/apt/lists/*
cd ${VPP_DIR}
UNATTENDED=y make vpp_configure_args_vpp='--disable-japi --disable-vom' bootstrap dpdk-install-dev pkg-deb
add-apt-repository -y ppa:ubuntu-toolchain-r/test
cd build-root
rm -rf .ccache \
	build-vpp-native/vpp/vpp-api/vom \
	build-vpp_debug-native/vpp/vpp-api/vom \
	build-vpp_debug-native/vpp/vpp-api/java
rm *java*.deb
dpkg -i vpp_*.deb vpp-dev_*.deb vpp-lib_*.deb vpp-plugins_*.deb vpp-dbg_*.deb
# run the debug build too if:
# VPP commit ID is specified AND
# the SKIP_DEBUG_BUILD env var is 0
if [ '${VPP_COMMIT_ID}' != 'xxx' ] && [ '${SKIP_DEBUG_BUILD}' -eq 0 ]; then
	cd ${VPP_DIR}
	make build
fi
cd ${VPP_DIR}
cd build-root
rm -rf .ccache \
	build-vpp-native/vpp/vpp-api/vom \
	build-vpp_debug-native/vpp/vpp-api/vom \
	build-vpp_debug-native/vpp/vpp-api/java
find . -name '*.o' -exec rm '{}' \;

apt-get remove --purge -y openjdk*
rm -rf /var/lib/apt/lists/*
