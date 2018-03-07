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

# uncomment to pull newest base images
#docker pull ligato/dev-vpp-agent:pantheon-dev
#docker pull ligato/vpp-agent:pantheon-dev

# obtain the current git tag for tagging the Docker images
TAG=`git describe --tags`

# build development image
cd dev
./build.sh ${TAG}

# build production images
cd ../prod
./build.sh ${TAG}
