#!/bin/bash

set -euo pipefail

echo "Building contivvpp agent binary..."
docker kill dev-contiv || true
docker run -v /home/vagrant/gopath/src/github.com/contiv/vpp/:/root/go/src/github.com/contiv/vpp/ -itd --name dev-contiv --rm dev-contiv-vswitch:latest bash
docker exec -it dev-contiv bash -c "cd /root/go/src/github.com/contiv/vpp; make agent" 
docker kill dev-contiv

echo "Building and saving contivvpp/vswitch image..."
cd /home/vagrant/gopath/src/github.com/contiv/vpp/docker/development; ./build.sh
docker save contivvpp/vswitch:latest > /vagrant/config/vswitch.tar
