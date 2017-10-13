#!/bin/bash
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

CONTIVSHIM_SOCKET_FILE="/var/run/contivshim.sock"

KUBELET_CFG_FILE="/etc/systemd/system/kubelet.service.d/10-kubeadm.conf"
KUBELET_CRI_CONFIG="--container-runtime=remote --container-runtime-endpoint=${CONTIVSHIM_SOCKET_FILE} --runtime-request-timeout=30m"

# Make sure only root can run this script
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root." 1>&2
   exit 1
fi

echo "Starting contiv-cri container."
docker run -dit --restart always --name contiv-cri \
    --privileged \
    --net=host \
    --pid=host \
    -v /dev:/dev \
    -v /sys:/sys:ro \
    -v /var/run:/var/run:rw \
    -v /var/lib/docker:/var/lib/docker:rw \
    -v /var/lib/kubelet:/var/lib/kubelet:shared \
    -v /var/log:/var/log:shared \
    -v /srv/kubernetes:/srv/kubernetes:ro \
    -v /etc/kubernetes:/etc/kubernetes:ro \
    -v /etc/cni:/etc/cni \
    -v /opt/cni/bin:/opt/cni/bin \
    dev-contiv-vswitch:0.0.1-68-ga8601bf \
    /root/go/bin/contiv-cri --etcd-endpoint "127.0.0.1:6666"


if [ -f "${KUBELET_CFG_FILE}" ]; then
   # Kubelet config file found
   echo "Processing Kubelet config in ${KUBELET_CFG_FILE}"

   if grep -q "${CONTIVSHIM_SOCKET_FILE}" "${KUBELET_CFG_FILE}"; then
        echo "Contiv CRI shim already configured."
    else
        echo "Configuring Contiv CRI shim."
        if grep -q "KUBELET_EXTRA_ARGS=" "${KUBELET_CFG_FILE}"; then
            echo "Modifying KUBELET_EXTRA_ARGS."
            sed -i 's|KUBELET_EXTRA_ARGS=|&'"${KUBELET_CRI_CONFIG}"' |' "${KUBELET_CFG_FILE}"
        else
            echo "Adding KUBELET_EXTRA_ARGS."
            sed -i '/Service/ a Environment="KUBELET_EXTRA_ARGS='"${KUBELET_CRI_CONFIG}"'"' "${KUBELET_CFG_FILE}"
        fi
        echo "Contiv CRI shim configured. Reloading systemctl daemon."
        systemctl daemon-reload
        #systemctl restart kubelet
    fi
else
    # Kubelet config file not found
   echo "File ${KUBELET_CFG_FILE} does not exist. Please manually configure Kubelet to start with the following arguments:"
   echo "${KUBELET_CRI_CONFIG}"
fi
