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

# obtain branch name as an optional argument
BRANCH_NAME=${1:-master}

# obtain the current git tag for tagging the Docker images
TAG=`git describe --tags`

# list of images we are tagging & pushing
IMAGES=("vswitch" "cni" "ksr")

# tag and push each image
for IMAGE in "${IMAGES[@]}"
do
    if [ "${BRANCH_NAME}" == "master" ]
    then
        # master branch - tag with the git tag + "latest"
        sudo docker tag prod-contiv-${IMAGE} contivvpp/${IMAGE}:${TAG}
        sudo docker tag prod-contiv-${IMAGE} contivvpp/${IMAGE}:latest

        sudo docker push contivvpp/${IMAGE}:${TAG}
        sudo docker push contivvpp/${IMAGE}:latest
    else
        # other branch - tag with the branch name
        sudo docker tag prod-contiv-${IMAGE} contivvpp/${IMAGE}:${BRANCH_NAME}
        sudo docker push contivvpp/${IMAGE}:${BRANCH_NAME}
    fi
done
