#!/bin/bash

set +e
sudo docker rm -f extract 2>/dev/null
set -e

sudo docker run -itd --name extract dev-contiv-plugins sh

rm -rf binaries
mkdir -p binaries

sudo docker cp extract:/root/go/src/github.com/contiv/vpp/cmd/contiv-cni/contiv-cni binaries/
sudo docker cp extract:/root/cni/loopback binaries/

sudo docker rm -f extract
