#!/bin/bash

set +e
sudo docker rmi -f prod-contiv-plugins 2>/dev/null
set -e

./extract.sh

sudo docker build -t prod-contiv-plugins --no-cache .

rm contiv.tar.gz