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

# obtain the tag for tagging the Docker images from the argument (if not passed in, default to "latest")
TAG=${1-latest}

# extract the binaries from the development image into the "binaries/" folder
./extract.sh dev-contiv-plugins:${TAG}

# build the production images
sudo docker build -t prod-contiv-cni:${TAG} --no-cache --rm=true -f cni/Dockerfile .
sudo docker build -t prod-contiv-ksr:${TAG} --no-cache --rm=true -f ksr/Dockerfile .

# delete the extracted binaries
rm -rf binaries