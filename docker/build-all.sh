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

## builds contiv-vswitch
# development image
cd contiv-vswitch/dev
./build.sh
# production image
cd ../prod
./build.sh

## builds all contiv plugins
# development image
cd ../../contiv-plugins/dev
./build.sh
# all production images
cd ../prod
./build.sh
