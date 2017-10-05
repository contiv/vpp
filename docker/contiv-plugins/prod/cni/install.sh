#!/bin/sh

# The host folders where CNI binaries and config files are located.
# Defaults can be overridden via environment variables.
HOST_CNI_BIN_DIR=${CNI_BIN_DIR:-/opt/cni/bin}
HOST_CNI_NET_DIR=${CNI_NET_DIR:-/etc/cni/net.d}

# Install loopback CNI binary if it does not exist yet.
if [ ! -e "${HOST_CNI_BIN_DIR}/loopback" ]
then
    echo "Installing loopback CNI binary to ${HOST_CNI_BIN_DIR}"
    cp /root/loopback ${HOST_CNI_BIN_DIR}
fi

# Install our CNI binary.
echo "Installing contiv CNI binary to ${HOST_CNI_BIN_DIR}"
cp /root/contiv-cni ${HOST_CNI_BIN_DIR}

# Erase all existing CNI config files.
echo "Erasing old CNI config in ${HOST_CNI_NET_DIR}"
rm -rf ${HOST_CNI_NET_DIR}/*

# Install our CNI config file.
echo "Installing new CNI config to ${HOST_CNI_NET_DIR}"
cp /root/10-contiv-vpp.conf ${HOST_CNI_NET_DIR}

# Unless told otherwise via SLEEP env. variable, sleep forever. This prevents k8s from restarting the pod repeatedly.
should_sleep=${SLEEP:-"true"}
echo "Done installing CNI. SLEEP=$should_sleep"
while [ "$should_sleep" == "true" ]; do
    sleep 10;
done