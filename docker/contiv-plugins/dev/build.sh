#!/bin/bash

cd ../../../
sudo docker build -f docker/contiv-plugins/dev/Dockerfile -t dev-contiv-plugins --no-cache .
