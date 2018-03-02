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

# Custom scripts which shrink images should be avoided.
# Maintaining separate import commands and the Dockerfiles themselves
# is too much.
# This script does nothing now.
echo "shrink.sh: cowardly exiting and not shrinking images"
echo "shrink.sh: the size of the images can be reduced by tweaking the \
	relevant Dockerfile of each Docker image"
