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

# remove shrink container if it is running
set +e
sudo docker rm -f shrink 2>/dev/null
set -e

# obtain the current git tag for tagging the Docker images
TAG=`git describe --tags`

# shrink cni image and replace original one
sudo docker run -itd --name shrink prod-contiv-cni:${TAG} sh
sudo docker export shrink >shrink.tar
sudo docker rm -f shrink
sudo docker rmi prod-contiv-cni:${TAG}
sudo docker import -c "WORKDIR /root/" -c 'CMD ["/root/install.sh"]' shrink.tar prod-contiv-cni:${TAG}
rm shrink.tar

# shrink ksr image and replace original one
sudo docker run -itd --name shrink prod-contiv-ksr:${TAG} sh
sudo docker export shrink >shrink.tar
sudo docker rm -f shrink
sudo docker rmi prod-contiv-ksr:${TAG}
sudo docker import -c "WORKDIR /root/" -c 'CMD ["/root/contiv-ksr"]' shrink.tar prod-contiv-ksr:${TAG}
rm shrink.tar

# shrink cri image and replace original one
sudo docker run -itd --name shrink prod-contiv-cri:${TAG} bash
sudo docker export shrink >shrink.tar
sudo docker rm -f shrink
sudo docker rmi prod-contiv-cri:${TAG}
sudo docker import -c "WORKDIR /root/" -c 'CMD ["/root/contiv-cri"]' shrink.tar prod-contiv-cri:${TAG}
rm shrink.tar

# shrink vswitch image and replace original one
sudo docker run -itd --name shrink prod-contiv-vswitch:${TAG} bash
sudo docker export shrink >shrink.tar
sudo docker rm -f shrink
sudo docker rmi prod-contiv-vswitch:${TAG}
sudo docker import -c "WORKDIR /root/" -c "ENV LD_PRELOAD_LIB_DIR /opt/ldpreload/" -c 'CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf"]' shrink.tar prod-contiv-vswitch:${TAG}
rm shrink.tar

