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

if [ ${BUILDARCH} = "aarch64" ] ; then
  DOCKERFILE_tag=".arm64"
  BUILDARCH="arm64"
fi

if [ ${BUILDARCH} = "x86_64" ] ; then
  BUILDARCH="amd64"
fi

DOCKERFILE=Dockerfile${DOCKERFILE_tag}

# determine extra vpp version based args
VPP_COMMIT_VERSION="latest"
if [ -n "${VPP_COMMIT_ID}" ]
then
  VPP_COMMIT_VERSION="${VPP_COMMIT_ID:0:7}"
fi

# extract the binaries from the development image into the "binaries/" folder
./extract.sh contivvpp/dev-vswitch-${BUILDARCH}:${TAG}

# build the production images
docker build -t contivvpp/vpp-binaries-${BUILDARCH}:${VPP_COMMIT_VERSION} ${DOCKER_BUILD_ARGS} -f ${DOCKERFILE} .

if [ ${BUILDARCH} = "amd64" ] ; then
  docker tag contivvpp/vpp-binaries-${BUILDARCH}:${VPP_COMMIT_VERSION} contivvpp/vpp-binaries:${VPP_COMMIT_VERSION}
fi

# delete the extracted binaries
rm -rf binaries/

