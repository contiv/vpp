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

# Make sure only root can run this script
if [[ $EUID -ne 0 ]]; then
   echo "ERROR: This script must be run as root." 1>&2
   exit 1
fi

# parse script arguments
UNINSTALL=0
while [ "$1" != "" ]; do
    case $1 in
        -u | --uninstall )
            shift
            UNINSTALL=1
            ;;
        -h | --help )
            echo "Use no arguments to install, -u or --uninstall to uninstall the Contiv STN daemon."
            exit 0
            ;;
        * )
            echo "Invalid argument: "$1
            exit 1
    esac
done

if [ ${UNINSTALL} == 0 ] ; then
    echo "Installing Contiv STN daemon."
else
    echo "Uninstalling Contiv STN daemon."
fi

if [ ${UNINSTALL} == 0 ] ; then
    # Install - start the Docker container with STN, with autorestart turned on.
    echo "Starting contiv-stn Docker container:"
    docker run -dit --restart always --name contiv-stn \
        --privileged \
        --net=host \
        --pid=host \
        -v /dev:/dev \
        -v /sys:/sys:rw \
        -v /var/run:/var/run:rw \
        -v /var/log:/var/log:shared \
        contivvpp/stn
else
    # Uninstall - stop the Docker container with STN, disable autorestart.
    echo "Stopping contiv-stn Docker container:"
    docker update --restart=no contiv-stn
    docker stop contiv-stn
    docker rm contiv-stn
fi
