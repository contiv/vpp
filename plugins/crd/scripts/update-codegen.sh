#!/bin/bash

# Copyright 2017 The Kubernetes Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
set -x
set -o errexit
set -o nounset
set -o pipefail

SCRIPT_ROOT=$(dirname ${BASH_SOURCE})/../../..
CODEGEN_PKG=${CODEGEN_PKG:-$(cd ${SCRIPT_ROOT}; ls -d -1 ./vendor/k8s.io/code-generator 2>/dev/null || echo ../code-generator)}

# generate the code with:
${CODEGEN_PKG}/generate-groups.sh "deepcopy,client,informer,lister" \
  github.com/contiv/vpp/plugins/crd/pkg/client \
  github.com/contiv/vpp/plugins/crd/pkg/apis \
  "telemetry:v1 nodeconfig:v1 contivppio:v1" \
  --go-header-file ${SCRIPT_ROOT}/plugins/crd/scripts/custom-boilerplate.go.txt