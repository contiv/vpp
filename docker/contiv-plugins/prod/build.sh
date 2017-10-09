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

# delete the old prod container if it already exists
set +e
sudo docker rmi -f prod-contiv-plugins 2>/dev/null
set -e

# extract the binaries from the development image into the "binaries/" folder
./extract.sh

# build the production images
sudo docker build -t prod-contiv-cni --no-cache --rm=true -f cni/Dockerfile .
sudo docker build -t prod-contiv-ksr --no-cache --rm=true -f ksr/Dockerfile .

# delete the extracted binaries
rm -rf binaries