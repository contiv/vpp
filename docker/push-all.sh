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

# source VPP commit ID and repo URL
source ../vpp.env

# default values for "branch name" and "skip upload"
BRANCH_NAME="master"
SKIP_UPLOAD="false"
DEV_UPLOAD="false"
CLEANUP="false"
PUSH_MULTI_ARCH="false"

# list of images we are tagging & pushing
IMAGES=()
IMAGES_VPP=("cni" "ksr" "stn" "crd" "vswitch" "dev-vswitch" "ui")
IMAGES_BIN=("vpp-binaries")

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

#Supported platforms of multi-arch images are: amd64 arm64
LINUX_ARCH=(amd64 arm64)
PLATFORMS=linux/${LINUX_ARCH[0]}
for i in $(seq 1  $[${#LINUX_ARCH[@]}-1])
do
PLATFORMS=$PLATFORMS,linux/${LINUX_ARCH[$i]}
done

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
        -m | --multi_arch )
            PUSH_MULTI_ARCH="true"
            echo "Push multi-arch support for images: ${PUSH_MULTI_ARCH}"
            ;;
        * )
            echo "Invalid parameter: "$1
            exit 1
    esac
    shift
done

BRANCH_TAG="${BRANCH_NAME}"
BRANCH_ADV_TAG="${BRANCH_TAG}-"
if [ "${BRANCH_NAME}" == "master" ]; then
  BRANCH_TAG="latest"
  BRANCH_ADV_TAG=""
fi

VPP_COMMIT_VERSION="latest"
if [ -n "${VPP_COMMIT_ID}" ]
then
  VPP_COMMIT_VERSION="${VPP_COMMIT_ID}"
fi

# obtain the current git tag for tagging the Docker images
export TAG=`git describe --tags`
echo "exported TAG=$TAG"
export VPP="${VPP_COMMIT_VERSION}"
echo "exported VPP=$VPP"

# tag and push each image
for IMAGE in "${IMAGES_VPP[@]}"
do
	if [ "${DEV_UPLOAD}" != "true" ] && [ "$IMAGE" == contivvpp/dev* ]; then
		continue
	fi

	docker tag contivvpp/${IMAGE}${IMAGEARCH}:${TAG} contivvpp/${IMAGE}${IMAGEARCH}:${BRANCH_TAG}
	docker tag contivvpp/${IMAGE}${IMAGEARCH}:${TAG} contivvpp/${IMAGE}${IMAGEARCH}:${BRANCH_ADV_TAG}${TAG}-${VPP}

	if [ ${BUILDARCH} = "amd64" ] ; then
		docker tag contivvpp/${IMAGE}${IMAGEARCH}:${BRANCH_TAG} contivvpp/${IMAGE}:${BRANCH_TAG}
		docker tag contivvpp/${IMAGE}${IMAGEARCH}:${BRANCH_ADV_TAG}${TAG}-${VPP} contivvpp/${IMAGE}:${BRANCH_ADV_TAG}${TAG}-${VPP}
	fi

	# push the images
	if [ "${SKIP_UPLOAD}" != "true" ]
	then
		docker push contivvpp/${IMAGE}${IMAGEARCH}:${BRANCH_TAG}
		docker push contivvpp/${IMAGE}${IMAGEARCH}:${BRANCH_ADV_TAG}${TAG}-${VPP}
		if [ ${BUILDARCH} = "amd64" ] ; then
			docker push contivvpp/${IMAGE}:${BRANCH_TAG}
			docker push contivvpp/${IMAGE}:${BRANCH_ADV_TAG}${TAG}-${VPP}
		fi
	fi
done

for IMAGE in "${IMAGES_BIN[@]}"
do
    if [ "${SKIP_UPLOAD}" == "true" ]; then
		continue
	fi

	docker push contivvpp/${IMAGE}${IMAGEARCH}:${VPP}
	if [ ${BUILDARCH} = "amd64" ] ; then
		docker push contivvpp/${IMAGE}:${VPP}
	fi
done

if [ "${CLEANUP}" == "true" ]
then
    docker images | fgrep "${TAG}" | awk '{print $3}' | sort -u | xargs docker rmi -f || true
    docker images | fgrep "${VPP}" | awk '{print $3}' | sort -u | xargs docker rmi -f || true
fi

#Before push, 'docker login' is needed
push_multi_arch(){

       if [ ! -f "./manifest-tool" ]
       then
                sudo apt-get install -y jq
                wget https://github.com/estesp/manifest-tool/releases/download/v0.9.0/manifest-tool-linux-${BUILDARCH} \
                -O manifest-tool && \
                chmod +x ./manifest-tool
       fi

       for IMAGE in "${IMAGES_VPP[@]}"
       do
         if [ "${DEV_UPLOAD}" != "true" ] && [ "$IMAGE" == contivvpp/dev* ]; then
            continue
         fi
	 set -x
         ./manifest-tool push from-args --platforms ${PLATFORMS} --template contivvpp/${IMAGE}-ARCH:${BRANCH_TAG} \
                --target contivvpp/${IMAGE}:${BRANCH_TAG}
         ./manifest-tool push from-args --platforms $(PLATFORMS) --template contivvpp/${IMAGE}-ARCH:${BRANCH_ADV_TAG}${TAG}-${VPP} \
               --target contivvpp/${IMAGE}:${BRANCH_ADV_TAG}${TAG}-${VPP}
       done
}

if [ "${PUSH_MULTI_ARCH}" == "true" ]
then
       echo "Push fat manifest for multi-arch images:"
       push_multi_arch
fi
