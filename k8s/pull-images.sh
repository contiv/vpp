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

# set default values for pulling images
IMAGE_TAG="latest"

# override defaults from arguments
while [ "$1" != "" ]; do
    case $1 in
        -b | --branch )
            shift
            IMAGE_TAG=$1
            # strip "release-" prefix in IMAGE_TAG
            IMAGE_TAG=${IMAGE_TAG#release-}
            if [ "${IMAGE_TAG}" == "master" ]; then
              IMAGE_TAG="latest"
            fi
            ;;
        * )
            echo "Invalid parameter: "$1
            exit 1
    esac
    shift
done

echo "Using Images Tag: ${IMAGE_TAG}"

IMAGEARCH=""
BUILDARCH=`uname -m`

if [ ${BUILDARCH} = "aarch64" ] ; then
  IMAGEARCH="-arm64"
  BUILDARCH="arm64"
fi

docker pull contivvpp/vswitch${IMAGEARCH}:${IMAGE_TAG}
#docker pull contivvpp/cri${IMAGEARCH}:${IMAGE_TAG}
docker pull contivvpp/ksr${IMAGEARCH}:${IMAGE_TAG}
docker pull contivvpp/cni${IMAGEARCH}:${IMAGE_TAG}
docker pull contivvpp/stn${IMAGEARCH}:${IMAGE_TAG}
