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

# fail in case of error
set -e

# obtain the tag for tagging the Docker images from the argument (if not passed in, default to "latest")
TAG=${1-latest}

DOCKERFILE_tag=""
BUILDARCH=`uname -m`
IMAGEARCH=""

if [ ${BUILDARCH} = "aarch64" ] ; then
  DOCKERFILE_tag=".arm64"
  BUILDARCH="arm64"
  IMAGEARCH="-arm64"
fi

if [ ${BUILDARCH} = "x86_64" ] ; then
  BUILDARCH="amd64"
fi

DOCKERFILE=Dockerfile${DOCKERFILE_tag}
#ALL_ARCH = amd64 arm64

# extract the binaries from the development image into the "binaries/" folder
./extract.sh dev-contiv-vswitch${IMAGEARCH}:${TAG}

# build the production images
docker build -t prod-contiv-vpp-binaries-${BUILDARCH}:${VPP_COMMIT_ID:0:7} ${DOCKER_BUILD_ARGS} --no-cache --force-rm=true -f ${DOCKERFILE} .

if [ ${BUILDARCH} = "amd64" ] ; then
  docker tag prod-contiv-vpp-binaries-${BUILDARCH}:${VPP_COMMIT_ID:0:7} prod-contiv-vpp-binaries:${VPP_COMMIT_ID:0:7}
fi

# delete the extracted binaries
rm -rf binaries/

