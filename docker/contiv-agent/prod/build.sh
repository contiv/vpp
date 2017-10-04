#!/bin/bash

set +e
sudo docker rmi -f prod-contiv-agent 2>/dev/null
set -e

./extract.sh

sudo docker build -t prod-contiv-agent --no-cache .

rm contiv.tar.gz