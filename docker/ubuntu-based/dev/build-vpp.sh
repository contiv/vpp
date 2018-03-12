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
rm -rf /var/lib/apt/lists/*
cd ${VPP_DIR}
UNATTENDED=y make vpp_configure_args_vpp='--disable-japi --disable-vom' bootstrap dpdk-install-dev pkg-deb
cd build-root
rm -rf .ccache \
	build-vpp-native/vpp/vpp-api/vom \
	build-vpp_debug-native/vpp/vpp-api/vom \
	build-vpp_debug-native/vpp/vpp-api/java
rm *java*.deb
dpkg -i vpp_*.deb vpp-dev_*.deb vpp-lib_*.deb vpp-plugins_*.deb vpp-dbg_*.deb
# run the debug build too if
# the SKIP_DEBUG_BUILD env var is 0
if [ "${SKIP_DEBUG_BUILD}" != "" ] && [ "${SKIP_DEBUG_BUILD}" -ne 0 ]; then
	cd ${VPP_DIR}
	make vpp_configure_args_vpp='--disable-japi --disable-vom' build
	# overwrite prod plugins with debug plugins
	rm -rf /usr/lib/{vpp_plugins,vpp_api_test_plugins}
	cp -r build-root/install-vpp_debug-native/vpp/lib64/{vpp_plugins,vpp_api_test_plugins} /usr/lib
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
