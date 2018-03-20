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

# the build needs to be executed from the github repository root, so that we can add
# all the source files without the need of cloning them:
cd ../../../

# execute the build
if [ -z "${VPP_COMMIT_ID}" ]
then
    # no specific VPP commit ID
    docker build -f docker/ubuntu-based/dev/Dockerfile -t dev-contiv-vswitch:${TAG} --build-arg VPP_IMAGE=dev-contiv-vpp:latest ${DOCKER_BUILD_ARGS} --force-rm=true .
else
    # specific VPP commit ID
    docker build -f docker/ubuntu-based/dev/Dockerfile -t dev-contiv-vswitch:${TAG} --build-arg VPP_IMAGE=dev-contiv-vpp:${VPP_COMMIT_ID} ${DOCKER_BUILD_ARGS} --force-rm=true .
fi

VPP=$(docker run --rm dev-contiv-vswitch:${TAG} bash -c "cd \$VPP_DIR && git rev-parse --short HEAD")
docker tag dev-contiv-vswitch:${TAG} dev-contiv-vswitch:${TAG}-${VPP}
