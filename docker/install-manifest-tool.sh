#!/bin/bash
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

#manifest-tool - inspect and push manifest list images to a registry

MANIFEST_TOOL_VERSION=v0.7.0
BUILDARCH=`uname -m`

if [ ${BUILDARCH} = "aarch64" ] ; then
  BUILDARCH="arm64"
fi

if [ ${BUILDARCH} = "x86_64" ] ; then
  BUILDARCH="amd64"
fi

curl -sSL https://github.com/estesp/manifest-tool/releases/download/${MANIFEST_TOOL_VERSION}/manifest-tool-linux-${BUILDARCH} > manifest-tool
chmod +x manifest-tool
mv manifest-tool /usr/bin/

