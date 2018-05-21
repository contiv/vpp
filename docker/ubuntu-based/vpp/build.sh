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

# execute the build
if [ -z "${VPP_COMMIT_ID}" ]
then
    # no specific VPP commit ID
    docker build -t dev-contiv-vpp:latest \
        --build-arg VPP_REPO_URL=${VPP_REPO_URL} \
        --build-arg VPP_BRANCH_NAME=${VPP_BRANCH_NAME} \
        --build-arg SKIP_DEBUG_BUILD=${SKIP_DEBUG_BUILD} \
        ${DOCKER_BUILD_ARGS} --force-rm=true .
else
    # specific VPP commit ID
    docker build -t dev-contiv-vpp:${VPP_COMMIT_ID} \
        --build-arg VPP_REPO_URL=${VPP_REPO_URL} \
        --build-arg VPP_BRANCH_NAME=${VPP_BRANCH_NAME} \
        --build-arg VPP_COMMIT_ID=${VPP_COMMIT_ID} \
        --build-arg SKIP_DEBUG_BUILD=${SKIP_DEBUG_BUILD} \
        ${DOCKER_BUILD_ARGS} --force-rm=true .
fi
