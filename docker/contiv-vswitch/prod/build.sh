#!/bin/bash

set +e
sudo docker rmi -f prod-contiv-vswitch 2>/dev/null
set -e

./extract.sh

sudo docker build -t prod-contiv-vswitch --no-cache .

rm contiv.tar.gz