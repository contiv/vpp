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

IMAGES=("cni" "ksr" "stn" "crd" "vswitch" "ui")

IMAGE_TAG_OLD="$1"
IMAGE_TAG_NEW="$2"

if [[ "$#" -ne 2 ]]; then
    echo "Illegal number of parameters, use: $0 <old-tag> <new-tag>"
    exit 1
fi

IMAGEARCH=""
BUILDARCH=`uname -m`

if [[ ${BUILDARCH} = "aarch64" ]] ; then
  IMAGEARCH="-arm64"
  BUILDARCH="arm64"
fi

echo "Tagging $IMAGE_TAG_OLD as $IMAGE_TAG_NEW"

# pull each image
for IMAGE in "${IMAGES[@]}"
do
    echo ""
    echo "Pulling contivvpp/${IMAGE}${IMAGEARCH}:${IMAGE_TAG_OLD} ..."

	docker pull contivvpp/${IMAGE}${IMAGEARCH}:${IMAGE_TAG_OLD}
done

# tag and push each image
for IMAGE in "${IMAGES[@]}"
do
	docker tag contivvpp/${IMAGE}${IMAGEARCH}:${IMAGE_TAG_OLD} contivvpp/${IMAGE}${IMAGEARCH}:${IMAGE_TAG_NEW}

	echo ""
	echo "Pushing contivvpp/${IMAGE}${IMAGEARCH}:${IMAGE_TAG_NEW} ..."

	docker push contivvpp/${IMAGE}${IMAGEARCH}:${IMAGE_TAG_NEW}
done
