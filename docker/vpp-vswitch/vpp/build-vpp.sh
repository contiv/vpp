#!/bin/bash

set -euo pipefail

cd /opt/vpp-agent/dev/

# clone VPP
if [ "${VPP_REPO_URL}" == "" ]; then
    git clone --progress https://github.com/FDio/vpp
else
    git clone --progress "${VPP_REPO_URL}"
fi

cd ${VPP_DIR}

# checkout a specific branch if specified
if [ "${VPP_BRANCH_NAME}" != "" ]; then
    git checkout ${VPP_BRANCH_NAME}
    git pull
fi

# check out a specific commit if specified
if [ "${VPP_COMMIT_ID}" != "" ]; then
    git checkout ${VPP_COMMIT_ID}
fi

# clean up old build root
rm -rf build-root/
git reset --hard HEAD

# apply VPP patches if present
cp ${VPP_PATCH_DIR}/*.diff . || true
git apply -v *.diff || true

# do not build vom
sed -i -e 's/vpp vom japi/vpp/g' build-data/platforms/vpp.mk
cat build-data/platforms/vpp.mk

if [ "$(uname -m)" = "aarch64" ] ; then
  sed -i 's/lib\/x86_64-linux-gnu/lib\/aarch64-linux-gnu/g' build-data/platforms.mk
fi

# run the production build
UNATTENDED=y make vpp_configure_args_vpp='--disable-japi --disable-vom' install-dep dpdk-install-dev

if [ "$(uname -m)" = "aarch64" ] ; then
  apt-get install -y gcc-8 g++-8
  rm /usr/bin/gcc
  rm /usr/bin/g++
  ln -s /usr/bin/gcc-8 /usr/bin/gcc
  ln -s /usr/bin/g++-8 /usr/bin/g++
fi

rm -rf /var/lib/apt/lists/*
cd ${VPP_DIR}
UNATTENDED=y make vpp_configure_args_vpp='--disable-japi --disable-vom' build-release pkg-deb


# run the debug build too unless the SKIP_DEBUG_BUILD env var is set to non-0 value
if [ "${SKIP_DEBUG_BUILD}" == "" ] || [ "${SKIP_DEBUG_BUILD}" -eq 0 ]; then
    cd ${VPP_DIR}
    make vpp_configure_args_vpp='--disable-japi --disable-vom' build pkg-deb-debug
    cd build-root
    dpkg -i vpp_*.deb vpp-plugin-core_*.deb vpp-plugin-dpdk_*.deb libvppinfra_*.deb vpp-dev_*.deb libvppinfra-dev_*.deb
else
    cd build-root
    dpkg -i vpp_*.deb vpp-plugin-core_*.deb vpp-plugin-dpdk_*.deb libvppinfra_*.deb
fi

# do some cleanup
cd ${VPP_DIR}
cd build-root
find . -name '*.o' -exec rm '{}' \;

rm -rf /var/lib/apt/lists/*
