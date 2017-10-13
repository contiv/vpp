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

# Make sure only root can run this script
if [[ $EUID -ne 0 ]]; then
   echo "ERROR: This script must be run as root." 1>&2
   exit 1
fi

docker update --restart=no contiv-cri
docker stop contiv-cri
docker rm contiv-cri

# TODO: unconfigure from Kubelet config file & restart Kubelet
echo "Please unconfigure the CRI shim from Kubelet config file in /etc/systemd/system/kubelet.service.d/ manually"

echo "Then, please continue with kubeadm init, or reboot the node."