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

# Socket file where the Contiv CRI shim binds to.
CONTIVSHIM_SOCKET_FILE="/var/run/contivshim.sock"

# Directory where this script looks for systemd Kubelet config files.
KUBELET_CFG_DIR="/etc/systemd/system/kubelet.service.d/"

# The arguments that need to be passed to Kubelet executable when starting.
KUBELET_CRI_CONFIG="--container-runtime=remote --container-runtime-endpoint=${CONTIVSHIM_SOCKET_FILE} --runtime-request-timeout=30m"

# Make sure only root can run this script
if [[ $EUID -ne 0 ]]; then
   echo "ERROR: This script must be run as root." 1>&2
   exit 1
fi

# parse script arguments
UNINSTALL=0
while [ "$1" != "" ]; do
    case $1 in
        -u | --uninstall )
            shift
            UNINSTALL=1
            ;;
        -h | --help )
            echo "Use no arguments to install, -u or --uninstall to uninstall the Contiv CRI shim."
            exit 0
            ;;
        * )
            echo "Invalid argument: "$1
            exit 1
    esac
done

if [ ${UNINSTALL} == 0 ] ; then
    echo "Installing Contiv CRI shim."
else
    echo "Uninstalling Contiv CRI shim."
fi

if [ ${UNINSTALL} == 0 ] ; then
    # Install - start the Docker container with CRI, with autorestart turned on.
    echo "Starting contiv-cri Docker container:"
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
        contivvpp/cri \
        /root/contiv-cri --etcd-endpoint "127.0.0.1:6666"
else
    # Uninstall - stop the Docker container with CRI, disable autorestart.
    echo "Sopping contiv-cri Docker container:"
    docker update --restart=no contiv-cri
    docker stop contiv-cri
    docker rm contiv-cri
fi

# look for config files in KUBELET_CFG_DIR
KUBELET_CFG_FILE=""
for file in ${KUBELET_CFG_DIR}*
do
    if [[ -f ${file} ]]; then
        KUBELET_CFG_FILE=${file}
    fi
done

# modify the Kubelet config file
if [ -f "${KUBELET_CFG_FILE}" ]; then
   # Kubelet config file found
   echo "Processing Kubelet config in ${KUBELET_CFG_FILE}"

   if grep -q "${CONTIVSHIM_SOCKET_FILE}" "${KUBELET_CFG_FILE}"; then
        # already configured
        if [ ${UNINSTALL} == 0 ] ; then
            # Install - already done.
            echo "Contiv CRI shim already configured."
        else
            # Uninstall.
            echo "Unconfiguring Contiv CRI shim."
            sed -i 's|'"${KUBELET_CRI_CONFIG}"' ||' "${KUBELET_CFG_FILE}"
            echo "Contiv CRI shim unconfigured. Restarting Kubelet."
            systemctl daemon-reload
            systemctl restart kubelet
        fi
    else
        # not yet configured
        if [ ${UNINSTALL} == 0 ] ; then
            # Install.
            echo "Configuring Contiv CRI shim."
            if grep -q "KUBELET_EXTRA_ARGS=" "${KUBELET_CFG_FILE}"; then
                echo "Modifying KUBELET_EXTRA_ARGS."
                sed -i 's|KUBELET_EXTRA_ARGS=|&'"${KUBELET_CRI_CONFIG}"' |' "${KUBELET_CFG_FILE}"
            else
                echo "Adding KUBELET_EXTRA_ARGS."
                sed -i '/Service/ a Environment="KUBELET_EXTRA_ARGS='"${KUBELET_CRI_CONFIG}"'"' "${KUBELET_CFG_FILE}"
            fi
            echo "Contiv CRI shim configured. Restarting Kubelet."
            systemctl daemon-reload
            systemctl restart kubelet
        else
            # Uninstall - already done.
            echo "Contiv CRI shim already unconfigured."
        fi
    fi
else
    # Kubelet config file not found
    echo "Unable to find Kubelet config file in ${KUBELET_CFG_DIR}."
    if [ ${UNINSTALL} == 0 ] ; then
        echo "Please, manually configure Kubelet to start with the following arguments:"
    else
        echo "Please, manually configure Kubelet to NOT start with the following arguments:"
    fi
    echo "${KUBELET_CRI_CONFIG}"
fi

echo "Now, please continue with kubeadm init, or reboot the node."