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

# default values for build args and VPP commit ID
export DOCKER_BUILD_ARGS=""
export VPP_COMMIT_ID="6f2ac420511c0c3c03fe4d64a5aa8a92cd46f9ce"
export SKIP_DEBUG_BUILD=0

# override defaults from arguments
while [ "$1" != "" ]; do
    case $1 in
        -d | --docker-build-args )
            shift
            export DOCKER_BUILD_ARGS=$1
            echo "Using Docker build args: ${DOCKER_BUILD_ARGS}"
            ;;
        -v | --vpp )
            shift
            export VPP_COMMIT_ID=$1
            echo "Using VPP commit ID: ${VPP_COMMIT_ID}"
            ;;
        -s | --skip-debug )
            export SKIP_DEBUG_BUILD=1
            echo "Using SKIP_DEBUG_BUILD=1"
            ;;
        * )
            echo "Invalid parameter: "$1
            exit 1
    esac
    shift
done

# builds all Ubuntu -based images
cd ubuntu-based
./build.sh

# builds the new images (vpp-cni, vpp-ksr, vpp-cri)
cd ..
./build-new.sh

# remove dangling images
set +e
docker rmi `docker images --filter=dangling=true -q` 2>/dev/null
set -e

