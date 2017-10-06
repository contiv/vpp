#!/bin/bash

cd ../../../
sudo docker build -f docker/contiv-vswitch/dev/Dockerfile -t dev-contiv-vswitch --no-cache .
