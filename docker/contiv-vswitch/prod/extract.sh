#!/bin/bash

set +e
sudo docker rm -f extract 2>/dev/null
set -e

sudo docker run -itd --name extract dev-contiv-vswitch bash

rm -rf contiv
mkdir -p contiv
sudo docker cp extract:/root/go/bin/contiv-agent contiv/

tar -zcvf contiv.tar.gz contiv

sudo docker rm -f extract
rm -rf contiv
