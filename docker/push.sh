#!/bin/bash

sudo docker tag prod-contiv-agent contivvpp/contiv-agent
sudo docker tag prod-contiv-cni contivvpp/contiv-cni

sudo docker push contivvpp/contiv-agent
sudo docker push contivvpp/contiv-cni