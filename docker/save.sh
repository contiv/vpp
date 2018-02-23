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

set -euo pipefail

# this script exports the built images as a tarball to be loaded

tag=$(git describe --tags)

images='contivvpp/ksr:latest contivvpp/cni:latest contivvpp/cri:latest contivvpp/vswitch:latest'

docker tag prod-contiv-ksr:$tag contivvpp/ksr:latest
docker tag prod-contiv-cni:$tag contivvpp/cni:latest
docker tag prod-contiv-cri:$tag contivvpp/cri:latest
docker tag prod-contiv-vswitch:$tag contivvpp/vswitch:latest

if [ -f ../vagrant/images.tar ]; then
	rm ../vagrant/images.tar
fi

docker save $images -o ../vagrant/images.tar

for img in $images; do
	docker rmi $img
done
