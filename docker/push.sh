#!/bin/bash

sudo docker tag prod-contiv-vswitch contivvpp/vswitch
sudo docker tag prod-contiv-cni contivvpp/cni

sudo docker push contivvpp/vswitch
sudo docker push contivvpp/cni