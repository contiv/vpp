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

# default values for "branch name" and "skip upload"
BRANCH_NAME="master"
SKIP_UPLOAD="false"
DEV_UPLOAD="false"
CLEANUP="false"

# list of images we are tagging & pushing
IMAGES=("cni" "ksr" "cri")
IMAGES_VPP=("vswitch")

# override defaults from arguments
while [ "$1" != "" ]; do
    case $1 in
        -b | --branch-name )
            shift
            BRANCH_NAME=$1
            echo "Using branch name: ${BRANCH_NAME}"
            ;;
        -s | --skip-upload )
            SKIP_UPLOAD="true"
            echo "Using skip upload: ${SKIP_UPLOAD}"
            ;;
        -d | --dev-upload )
            DEV_UPLOAD="true"
            echo "Using dev upload: ${DEV_UPLOAD}"
            ;;
        -c | --cleanup )
            CLEANUP="true"
            echo "Using cleanup: ${CLEANUP}"
            ;;
        * )
            echo "Invalid parameter: "$1
            exit 1
    esac
    shift
done

# obtain the current git tag for tagging the Docker images
export TAG=`git describe --tags`
echo "exported TAG=$TAG"
export VPP=$(docker run --rm dev-contiv-vswitch:$TAG bash -c "cd \$VPP_DIR && git rev-parse --short HEAD")
echo "exported VPP=$VPP"

# tag and push each image
for IMAGE in "${IMAGES[@]}"
do
    if [ "${BRANCH_NAME}" == "master" ]
    then
        # master branch - tag with the git tag + "latest"
        echo "Tagging as contivvpp/${IMAGE}:${TAG} + contivvpp/${IMAGE}:latest"
        sudo docker tag prod-contiv-${IMAGE}:${TAG} contivvpp/${IMAGE}:${TAG}
        sudo docker tag prod-contiv-${IMAGE}:${TAG} contivvpp/${IMAGE}:latest

        # push the images
        if [ "${SKIP_UPLOAD}" != "true" ]
        then
            sudo docker push contivvpp/${IMAGE}:${TAG}
            sudo docker push contivvpp/${IMAGE}:latest
        fi
    else
        # other branch - tag with the branch name
        echo "Tagging as contivvpp/${IMAGE}:${BRANCH_NAME}-${TAG} + contivvpp/${IMAGE}:${BRANCH_NAME}"
        sudo docker tag prod-contiv-${IMAGE}:${TAG} contivvpp/${IMAGE}:${BRANCH_NAME}
        sudo docker tag prod-contiv-${IMAGE}:${TAG} contivvpp/${IMAGE}:${BRANCH_NAME}-${TAG}

        # push the images
        if [ "${SKIP_UPLOAD}" != "true" ]
        then
            sudo docker push contivvpp/${IMAGE}:${BRANCH_NAME}-${TAG}
            sudo docker push contivvpp/${IMAGE}:${BRANCH_NAME}
        fi
    fi
done

for IMAGE in "${IMAGES_VPP[@]}"
do
    if [ "${BRANCH_NAME}" == "master" ]
    then
        # master branch - tag with the git tag + "latest"
        echo "Tagging as contivvpp/${IMAGE}:${TAG}-${VPP} + contivvpp/${IMAGE}:latest"
        sudo docker tag prod-contiv-${IMAGE}:${TAG} contivvpp/${IMAGE}:${TAG}-${VPP}
        sudo docker tag prod-contiv-${IMAGE}:${TAG} contivvpp/${IMAGE}:latest

        # push the images
        if [ "${SKIP_UPLOAD}" != "true" ]
        then
            sudo docker push contivvpp/${IMAGE}:${TAG}-${VPP}
            sudo docker push contivvpp/${IMAGE}:latest
        fi
    else
        # other branch - tag with the branch name
        echo "Tagging as contivvpp/${IMAGE}:${BRANCH_NAME}-${TAG}-${VPP} + contivvpp/${IMAGE}:${BRANCH_NAME}"
        sudo docker tag prod-contiv-${IMAGE}:${TAG} contivvpp/${IMAGE}:${BRANCH_NAME}
        sudo docker tag prod-contiv-${IMAGE}:${TAG} contivvpp/${IMAGE}:${BRANCH_NAME}-${TAG}-${VPP}

        # push the images
        if [ "${SKIP_UPLOAD}" != "true" ]
        then
            sudo docker push contivvpp/${IMAGE}:${BRANCH_NAME}
            sudo docker push contivvpp/${IMAGE}:${BRANCH_NAME}-${TAG}-${VPP}
        fi
    fi
done

if [ "${DEV_UPLOAD}" == "true" ]
then
    if [ "${BRANCH_NAME}" == "master" ]
    then
        # master branch - tag with the git tag + "latest"
        echo "Tagging as contivvpp/dev-vswitch:${TAG}-${VPP} + contivvpp/dev-vswitch:latest"
        sudo docker tag dev-contiv-vswitch:${TAG} contivvpp/dev-vswitch:${TAG}-${VPP}
        sudo docker tag dev-contiv-vswitch:${TAG} contivvpp/dev-vswitch:latest

        # push the images
        if [ "${SKIP_UPLOAD}" != "true" ]
        then
            sudo docker push contivvpp/dev-vswitch:${TAG}-${VPP}
            sudo docker push contivvpp/dev-vswitch:latest
        fi
    else
        # other branch - tag with the branch name
        echo "Tagging as contivvpp/dev-vswitch:${BRANCH_NAME}-${TAG}-${VPP} + contivvpp/dev-vswitch:${BRANCH_NAME}"
        sudo docker tag dev-contiv-vswitch:${TAG} contivvpp/dev-vswitch:${BRANCH_NAME}
        sudo docker tag dev-contiv-vswitch:${TAG} contivvpp/dev-vswitch:${BRANCH_NAME}-${TAG}-${VPP}

        # push the images
        if [ "${SKIP_UPLOAD}" != "true" ]
        then
            sudo docker push contivvpp/dev-vswitch:${BRANCH_NAME}
            sudo docker push contivvpp/dev-vswitch:${BRANCH_NAME}-${TAG}-${VPP}
        fi
    fi
fi

if [ "${CLEANUP}" == "true" ]
then
    sudo docker images | fgrep "${TAG}" | awk '{print $3}' | uniq | xargs sudo docker rmi || true
fi
