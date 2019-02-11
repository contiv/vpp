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
SKIP_DELETE="false"

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
        -s | --skip-delete )
            SKIP_DELETE="true"
            echo "Images will not be deleted"
            ;;            
        * )
            echo "Invalid parameter: "$1
            exit 1
    esac
    shift
done

set -euo pipefail
echo "Using Images Tag: ${IMAGE_TAG}"

# this script exports the built images as a tarball to be loaded

IMAGEARCH=""
BUILDARCH=`uname -m`

if [ ${BUILDARCH} = "aarch64" ]; then
  IMAGEARCH="-arm64"
  echo "Using Images Arch: ${IMAGEARCH}"
fi

images="contivvpp/ksr${IMAGEARCH}:${IMAGE_TAG}"
images="${images} contivvpp/cni${IMAGEARCH}:${IMAGE_TAG}"
images="${images} contivvpp/stn${IMAGEARCH}:${IMAGE_TAG}"
images="${images} contivvpp/vswitch${IMAGEARCH}:${IMAGE_TAG}"
images="${images} contivvpp/crd${IMAGEARCH}:${IMAGE_TAG}"
#images="${images} contivvpp/ui${IMAGEARCH}:${IMAGE_TAG}"
echo $images

if [ -f ../vagrant/images.tar ]; then
  rm ../vagrant/images.tar
fi

docker save $images -o ../vagrant/images.tar

if [ "${SKIP_DELETE}" != "true" ]; then
  for img in $images; do
    docker rmi $img
  done
fi
