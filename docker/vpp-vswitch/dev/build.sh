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

# obtain the tag for tagging the Docker images from the 1st argument (if not passed in, default to "latest")
TAG=${1-latest}

DOCKERFILETAG=""

BUILDARCH=`uname -m`

if [ ${BUILDARCH} = "aarch64" ] ; then
  DOCKERFILETAG=".arm64"
  BUILDARCH="arm64"
fi

if [ ${BUILDARCH} = "x86_64" ] ; then
  BUILDARCH="amd64"
fi

DOCKERFILE=Dockerfile${DOCKERFILETAG}

# the build needs to be executed from the github repository root, so that we can add
# all the source files without the need of cloning them:
cd ../../../

# determine extra vpp version based args
VPP_COMMIT_VERSION="latest"
if [ -n "${VPP_COMMIT_ID}" ]
then
  VPP_COMMIT_VERSION="${VPP_COMMIT_ID}"
fi

VPP_IMAGE="contivvpp/vpp"
VPP_BUILD_ARGS=""
if [ "${SKIP_DEBUG_BUILD}" -eq 1 ]
then
  VPP_IMAGE="$VPP_IMAGE-binaries"
  VPP_BUILD_ARGS="--build-arg VPP_INSTALL_PKG=true"
fi

VPP="${VPP_COMMIT_VERSION}"

# check if build is really necessary
function validate_docker_tag() {
  out=$(curl --silent -lSL https://index.docker.io/v1/repositories/$1/tags/$2)
  if [ "${SKIP_DEBUG_BUILD}" -eq 1 ] && [ "${out}" = "[]" ]; then
    docker pull $1:$2
    echo "true"
  fi
}

if [ "${REBUILD_VPP}" -eq 1 ] || [ -z "$(validate_docker_tag contivvpp/dev-vswitch-${BUILDARCH} ${TAG}-${VPP})" ]; then
  # execute the build
  # use no cache and force rm because docker cannot handle dynamic FROM and so trying to use cache is useless
  docker build --no-cache=true --force-rm=true -f docker/vpp-vswitch/dev/${DOCKERFILE} -t contivvpp/dev-vswitch-${BUILDARCH}:${TAG}-${VPP} \
  --build-arg VPP_IMAGE=${VPP_IMAGE}-${BUILDARCH}:${VPP_COMMIT_VERSION} \
    ${VPP_BUILD_ARGS} \
    ${DOCKER_BUILD_ARGS} .
fi

docker tag contivvpp/dev-vswitch-${BUILDARCH}:${TAG}-${VPP} contivvpp/dev-vswitch-${BUILDARCH}:${TAG}

if [ ${BUILDARCH} = "amd64" ] ; then
   docker tag contivvpp/dev-vswitch-${BUILDARCH}:${TAG}-${VPP} contivvpp/dev-vswitch:${TAG}-${VPP}
   docker tag contivvpp/dev-vswitch:${TAG}-${VPP} contivvpp/dev-vswitch:${TAG}
fi
