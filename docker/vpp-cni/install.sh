#!/bin/sh
# Copyright (c) 2017 Cisco and/or its affiliates.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# The host folders where CNI binaries and config files are located.
# Defaults can be overridden via environment variables.
HOST_CNI_BIN_DIR=${CNI_BIN_DIR:-/opt/cni/bin}
HOST_CNI_NET_DIR=${CNI_NET_DIR:-/etc/cni/net.d}
HOST_CNI_CONFIG_FILE=${CNI_CONFIG_FILE:-10-contiv-vpp.conflist}
HOST_LOG_FILE=${HOST_LOG_FILE:-/var/run/contiv/cni.log}

# Install loopback CNI binary if it does not exist yet.
if [ ! -e "${HOST_CNI_BIN_DIR}/loopback" ]
then
    echo "Installing loopback CNI binary to ${HOST_CNI_BIN_DIR}"
    cp /cni/bin/loopback ${HOST_CNI_BIN_DIR}
fi

# Install our CNI binary.
echo "Installing contiv CNI binary to ${HOST_CNI_BIN_DIR}"
cp /cni/bin/contiv-cni ${HOST_CNI_BIN_DIR}

# Install modified portmap plugin.
echo "Installing portmap plugin to ${HOST_CNI_BIN_DIR}"
cp /cni/bin/portmap ${HOST_CNI_BIN_DIR}

# Erase all existing CNI config files.
echo "Erasing old CNI config in ${HOST_CNI_NET_DIR}"
rm -f ${HOST_CNI_NET_DIR}/${HOST_CNI_CONFIG_FILE}

# Install our CNI config files.
echo "Installing new CNI config to ${HOST_CNI_NET_DIR}"
cp /cni/cfg/* ${HOST_CNI_NET_DIR}

# Delete old CNI log file.
echo "Deleting old contiv CNI logfile ${HOST_LOG_FILE}"
rm -f ${HOST_LOG_FILE}

# Unless told otherwise via SLEEP env. variable, sleep forever. This prevents k8s from restarting the pod repeatedly.
should_sleep=${SLEEP:-"true"}
echo "Done installing CNI. SLEEP=$should_sleep"
while [ "$should_sleep" == "true" ]; do
    sleep 10;
done

