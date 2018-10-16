#!/bin/bash
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

# default values for "skip dev-upload"
DEV_UPLOAD="false"

# list of images we are tagging & pushing
IMAGES=()
IMAGES_VPP=("cni" "ksr" "stn" "crd" "vswitch")
IMAGES_BIN=("vpp-binaries")

# override defaults from arguments
while [ "$1" != "" ]; do
    case $1 in
        -d | --dev-upload )
            DEV_UPLOAD="true"
            echo "Using dev upload: ${DEV_UPLOAD}"
            ;;
        * )
            echo "Invalid parameter: "$1
            exit 1
    esac
    shift
done


ARCHES="amd64 arm64"
platforms="linux/amd64,linux/arm64"

# Please install manifest-tool first by the script 'install-manifest-tool.sh'
# Do 'docker login' first to get the correct $(HOME)/.docker/config.json

# Just multi-arch the latest image now

for IMAGE in "${IMAGES[@]}"
do
    /usr/bin/manifest-tool push from-args --platforms ${platforms} --template contivvpp/${IMAGE}-ARCH:latest --target contivvpp/${IMAGE}:latest
done

for IMAGE in "${IMAGES_VPP[@]}"
do
    /usr/bin/manifest-tool push from-args --platforms ${platforms} --template contivvpp/${IMAGE}-ARCH:latest --target contivvpp/${IMAGE}:latest
done

for IMAGE in "${IMAGES_BIN[@]}"
do
    /usr/bin/manifest-tool push from-args --platforms ${platforms} --template contivvpp/${IMAGE}-ARCH:latest --target contivvpp/${IMAGE}:latest
done

if [ "${DEV_UPLOAD}" == "true" ]
then
    /usr/bin/manifest-tool push from-args --platforms ${platforms} --template contivvpp/dev-vswitch-ARCH:latest --target contivvpp/dev-vswitch:latest
fi

