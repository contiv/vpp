#!/bin/bash

cd ../../../
sudo docker build -f docker/contiv-agent/dev/Dockerfile -t dev-contiv-agent --no-cache .
