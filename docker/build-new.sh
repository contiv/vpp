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
set -euo pipefail

# obtain the current git tag for tagging the Docker images
TAG=`git describe --tags`
DOCKER_BUILD_ARGS=${DOCKER_BUILD_ARGS-}

cd ..


#To prepare for future fat manifest image by multi-arch manifest,
#now build the docker image with its arch
#For fat manifest, please refer
#https://docs.docker.com/registry/spec/manifest-v2-2/#example-manifest-list

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
#ALL_ARCH = amd64 arm64


CNIDEFAULTIMG="prod-contiv-cni":${TAG}
KSRDEFAULTIMG="prod-contiv-ksr":${TAG}
CRIDEFAULTIMG="prod-contiv-cri":${TAG}
STNDEFAULTIMG="prod-contiv-stn":${TAG}

CNIBUILDIMG="prod-contiv-cni"-${BUILDARCH}:${TAG}
KSRBUILDIMG="prod-contiv-ksr"-${BUILDARCH}:${TAG}
CRIBUILDIMG="prod-contiv-cri"-${BUILDARCH}:${TAG}
STNBUILDIMG="prod-contiv-stn"-${BUILDARCH}:${TAG}



docker build -t ${CNIBUILDIMG} ${DOCKER_BUILD_ARGS} --no-cache --force-rm -f docker/vpp-cni/${DOCKERFILE} .
docker build -t ${KSRBUILDIMG} ${DOCKER_BUILD_ARGS} --no-cache --force-rm -f docker/vpp-ksr/${DOCKERFILE} .
docker build -t ${CRIBUILDIMG} ${DOCKER_BUILD_ARGS} --no-cache --force-rm -f docker/vpp-cri/${DOCKERFILE} .
docker build -t ${STNBUILDIMG} ${DOCKER_BUILD_ARGS} --no-cache --force-rm -f docker/vpp-stn/${DOCKERFILE} .



if [ ${BUILDARCH} = "amd64" ] ; then
  docker tag  ${CNIBUILDIMG} ${CNIDEFAULTIMG}
  docker tag  ${KSRBUILDIMG} ${KSRDEFAULTIMG}
  docker tag  ${CRIBUILDIMG} ${CRIDEFAULTIMG}
  docker tag  ${STNBUILDIMG} ${STNDEFAULTIMG}
fi

