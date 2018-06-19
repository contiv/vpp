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
IMAGES=()
#IMAGES_VPP=("cni" "ksr" "cri" "stn" "vswitch")
IMAGES_VPP=("cni" "ksr" "stn" "vswitch")

IMAGEARCH=""
RUNARCH=""
BUILDARCH=`uname -m`

if [ ${BUILDARCH} = "aarch64" ] ; then
  IMAGEARCH="-arm64"
  BUILDARCH="arm64"
  RUNARCH="-arm64"
fi

if [ ${BUILDARCH} = "x86_64" ] ; then
  IMAGEARCH="-amd64"
  BUILDARCH="amd64"
fi

# override defaults from arguments
while [ "$1" != "" ]; do
    case $1 in
        -b | --branch-name )
            shift
            BRANCH_NAME=$1
            # strip "release-" prefix in BRANCH_NAME
            BRANCH_NAME=${BRANCH_NAME#release-}
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
export VPP=$(docker run --rm dev-contiv-vswitch${RUNARCH}:$TAG bash -c "cd \$VPP_DIR && git rev-parse --short HEAD")
echo "exported VPP=$VPP"

# tag and push each image
for IMAGE in "${IMAGES[@]}"
do
    if [ "${BRANCH_NAME}" == "master" ]
    then
        # master branch - tag with the git tag + "latest"
        echo "Tagging as contivvpp/${IMAGE}:${TAG} + contivvpp/${IMAGE}:latest"
        docker tag prod-contiv-${IMAGE}${IMAGEARCH}:${TAG} contivvpp/${IMAGE}${IMAGEARCH}:${TAG}
        docker tag prod-contiv-${IMAGE}${IMAGEARCH}:${TAG} contivvpp/${IMAGE}${IMAGEARCH}:latest
 
        if [ ${BUILDARCH} = "amd64" ] ; then
            echo "Tagging as contivvpp/${IMAGE}${IMAGEARCH}:${TAG} + contivvpp/${IMAGE}${IMAGEARCH}:latest as default"
            docker tag prod-contiv-${IMAGE}${IMAGEARCH}:${TAG} contivvpp/${IMAGE}:${TAG}
            docker tag prod-contiv-${IMAGE}${IMAGEARCH}:${TAG} contivvpp/${IMAGE}:latest
        fi

        # push the images
        if [ "${SKIP_UPLOAD}" != "true" ]
        then
            docker push contivvpp/${IMAGE}${IMAGEARCH}:${TAG}
            docker push contivvpp/${IMAGE}${IMAGEARCH}:latest
            if [ ${BUILDARCH} = "amd64" ] ; then
                docker push contivvpp/${IMAGE}:${TAG}
                docker push contivvpp/${IMAGE}:latest
            fi
        fi
    else
        # other branch - tag with the branch name
        echo "Tagging as contivvpp/${IMAGE}${IMAGEARCH}:${BRANCH_NAME}-${TAG} + contivvpp/${IMAGE}${IMAGEARCH}:${BRANCH_NAME}"
        docker tag prod-contiv-${IMAGE}${IMAGEARCH}:${TAG} contivvpp/${IMAGE}${IMAGEARCH}:${BRANCH_NAME}
        docker tag prod-contiv-${IMAGE}${IMAGEARCH}:${TAG} contivvpp/${IMAGE}${IMAGEARCH}:${BRANCH_NAME}-${TAG}
        if [ ${BUILDARCH} = "amd64" ] ; then
            echo "Tagging as contivvpp/${IMAGE}${IMAGEARCH}:${BRANCH_NAME}-${TAG} + contivvpp/${IMAGE}${IMAGEARCH}:${BRANCH_NAME} as default"
            docker tag prod-contiv-${IMAGE}${IMAGEARCH}:${TAG} contivvpp/${IMAGE}:${BRANCH_NAME}
            docker tag prod-contiv-${IMAGE}${IMAGEARCH}:${TAG} contivvpp/${IMAGE}:${BRANCH_NAME}-${TAG}
        fi

        # push the images
        if [ "${SKIP_UPLOAD}" != "true" ]
        then
            docker push contivvpp/${IMAGE}${IMAGEARCH}:${BRANCH_NAME}-${TAG}
            docker push contivvpp/${IMAGE}${IMAGEARCH}:${BRANCH_NAME}
            if [ ${BUILDARCH} = "amd64" ] ; then
                docker push contivvpp/${IMAGE}:${BRANCH_NAME}-${TAG}
                docker push contivvpp/${IMAGE}:${BRANCH_NAME}
            fi
        fi
    fi
done

for IMAGE in "${IMAGES_VPP[@]}"
do
    if [ "${BRANCH_NAME}" == "master" ]
    then
        # master branch - tag with the git tag + "latest"
        echo "Tagging as contivvpp/${IMAGE}${IMAGEARCH}:${TAG}-${VPP} + contivvpp/${IMAGE}${IMAGEARCH}:latest"
        docker tag prod-contiv-${IMAGE}${IMAGEARCH}:${TAG} contivvpp/${IMAGE}${IMAGEARCH}:${TAG}-${VPP}
        docker tag prod-contiv-${IMAGE}${IMAGEARCH}:${TAG} contivvpp/${IMAGE}${IMAGEARCH}:latest

        if [ ${BUILDARCH} = "amd64" ] ; then
            echo "Tagging as contivvpp/${IMAGE}${IMAGEARCH}:${TAG}-${VPP} + contivvpp/${IMAGE}${IMAGEARCH}:latest as default"
            docker tag prod-contiv-${IMAGE}${IMAGEARCH}:${TAG} contivvpp/${IMAGE}:${TAG}-${VPP}
            docker tag prod-contiv-${IMAGE}${IMAGEARCH}:${TAG} contivvpp/${IMAGE}:latest
        fi

        # push the images
        if [ "${SKIP_UPLOAD}" != "true" ]
        then
            docker push contivvpp/${IMAGE}${IMAGEARCH}:${TAG}-${VPP}
            docker push contivvpp/${IMAGE}${IMAGEARCH}:latest
            if [ ${BUILDARCH} = "amd64" ] ; then
                docker push contivvpp/${IMAGE}:${TAG}-${VPP}
                docker push contivvpp/${IMAGE}:latest
            fi
        fi
    else
        # other branch - tag with the branch name
        echo "Tagging as contivvpp/${IMAGE}${IMAGEARCH}:${BRANCH_NAME}-${TAG}-${VPP} + contivvpp/${IMAGE}${IMAGEARCH}:${BRANCH_NAME}"
        docker tag prod-contiv-${IMAGE}${IMAGEARCH}:${TAG} contivvpp/${IMAGE}${IMAGEARCH}:${BRANCH_NAME}
        docker tag prod-contiv-${IMAGE}${IMAGEARCH}:${TAG} contivvpp/${IMAGE}${IMAGEARCH}:${BRANCH_NAME}-${TAG}-${VPP}

        if [ ${BUILDARCH} = "amd64" ] ; then
            echo "Tagging as contivvpp/${IMAGE}${IMAGEARCH}:${BRANCH_NAME}-${TAG}-${VPP} + contivvpp/${IMAGE}${IMAGEARCH}:${BRANCH_NAME} as default"
            docker tag prod-contiv-${IMAGE}${IMAGEARCH}:${TAG} contivvpp/${IMAGE}:${BRANCH_NAME}
            docker tag prod-contiv-${IMAGE}${IMAGEARCH}:${TAG} contivvpp/${IMAGE}:${BRANCH_NAME}-${TAG}-${VPP}
        fi
        # push the images
        if [ "${SKIP_UPLOAD}" != "true" ]
        then
            docker push contivvpp/${IMAGE}${IMAGEARCH}:${BRANCH_NAME}
            docker push contivvpp/${IMAGE}${IMAGEARCH}:${BRANCH_NAME}-${TAG}-${VPP}
            if [ ${BUILDARCH} = "amd64" ] ; then
                docker push contivvpp/${IMAGE}:${BRANCH_NAME}
                docker push contivvpp/${IMAGE}:${BRANCH_NAME}-${TAG}-${VPP}
            fi
        fi
    fi
done

if [ "${DEV_UPLOAD}" == "true" ]
then
    if [ "${BRANCH_NAME}" == "master" ]
    then
        # master branch - tag with the git tag + "latest"
        echo "Tagging as contivvpp/dev-vswitch${IMAGEARCH}:${TAG}-${VPP} + contivvpp/dev-vswitch${IMAGEARCH}:latest"
        docker tag dev-contiv-vswitch${IMAGEARCH}:${TAG} contivvpp/dev-vswitch${IMAGEARCH}:${TAG}-${VPP}
        docker tag dev-contiv-vswitch${IMAGEARCH}:${TAG} contivvpp/dev-vswitch${IMAGEARCH}:latest
        if [ ${BUILDARCH} = "amd64" ] ; then
            docker tag dev-contiv-vswitch${IMAGEARCH}:${TAG} contivvpp/dev-vswitch:${TAG}-${VPP}
            docker tag dev-contiv-vswitch${IMAGEARCH}:${TAG} contivvpp/dev-vswitch:latest
        fi

        # push the images
        if [ "${SKIP_UPLOAD}" != "true" ]
        then
            docker push contivvpp/dev-vswitch${IMAGEARCH}:${TAG}-${VPP}
            docker push contivvpp/dev-vswitch${IMAGEARCH}:latest
            if [ ${BUILDARCH} = "amd64" ] ; then
                docker push contivvpp/dev-vswitch:${TAG}-${VPP}
                docker push contivvpp/dev-vswitch:latest
            fi
        fi
    else
        # other branch - tag with the branch name
        echo "Tagging as contivvpp/dev-vswitch${IMAGEARCH}:${BRANCH_NAME}-${TAG}-${VPP} + contivvpp/dev-vswitch${IMAGEARCH}:${BRANCH_NAME}"
        docker tag dev-contiv-vswitch${IMAGEARCH}:${TAG} contivvpp/dev-vswitch${IMAGEARCH}:${BRANCH_NAME}
        docker tag dev-contiv-vswitch${IMAGEARCH}:${TAG} contivvpp/dev-vswitch${IMAGEARCH}:${BRANCH_NAME}-${TAG}-${VPP}
        if [ ${BUILDARCH} = "amd64" ] ; then
            docker tag dev-contiv-vswitch${IMAGEARCH}:${TAG} contivvpp/dev-vswitch:${BRANCH_NAME}
            docker tag dev-contiv-vswitch${IMAGEARCH}:${TAG} contivvpp/dev-vswitch:${BRANCH_NAME}-${TAG}-${VPP}
        fi

        # push the images
        if [ "${SKIP_UPLOAD}" != "true" ]
        then
            docker push contivvpp/dev-vswitch${IMAGEARCH}:${BRANCH_NAME}
            docker push contivvpp/dev-vswitch${IMAGEARCH}:${BRANCH_NAME}-${TAG}-${VPP}
            if [ ${BUILDARCH} = "amd64" ] ; then
                docker push contivvpp/dev-vswitch:${BRANCH_NAME}
                docker push contivvpp/dev-vswitch:${BRANCH_NAME}-${TAG}-${VPP}
            fi
        fi
    fi
fi

if [ "${CLEANUP}" == "true" ]
then
    docker images | fgrep "${TAG}" | awk '{print $3}' | sort -u | xargs docker rmi -f || true
fi
