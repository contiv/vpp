#!/bin/bash

set -euo pipefail

cd /opt/vpp-agent/dev/

#git clone https://gerrit.fd.io/r/vpp
#cd ${VPP_DIR}
#git checkout master
git clone https://github.com/vpp-dev/vpp.git
cd ${VPP_DIR}
git checkout stable-1801-contiv
git pull

# check out a specific commit if specified
# continue and ignore the error if the commit ID isn't specified
git checkout ${VPP_COMMIT_ID} || true

# clean up old build root
rm -rf build-root/
git reset --hard HEAD

# apply VPP patches if present
cp ${VPP_PATCH_DIR}/*.diff . || true
git apply -v *.diff || true

# run the production build
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

# run the debug build too unless the SKIP_DEBUG_BUILD env var is set to non-0 value
if [ "${SKIP_DEBUG_BUILD}" == "" ] || [ "${SKIP_DEBUG_BUILD}" -eq 0 ]; then
	cd ${VPP_DIR}
	make vpp_configure_args_vpp='--disable-japi --disable-vom' build
	# overwrite prod plugins with debug plugins
	rm -rf /usr/lib/{vpp_plugins,vpp_api_test_plugins}
	cp -r build-root/install-vpp_debug-native/vpp/lib64/{vpp_plugins,vpp_api_test_plugins} /usr/lib
fi

# do some cleanup
cd ${VPP_DIR}
cd build-root
rm -rf .ccache \
	build-vpp-native/vpp/vpp-api/vom \
	build-vpp_debug-native/vpp/vpp-api/vom \
	build-vpp_debug-native/vpp/vpp-api/java
find . -name '*.o' -exec rm '{}' \;

apt-get remove --purge -y openjdk*
rm -rf /var/lib/apt/lists/*
