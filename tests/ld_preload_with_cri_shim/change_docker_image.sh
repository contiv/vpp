#!/usr/bin/env bash

sed -i "s@contivvpp/cri@prod-contiv-cri:specific@g" ./k8s/cri-install.sh
sed -i "s@image: contivvpp/vswitch@image: prod-contiv-vswitch:specific@g" ./k8s/contiv-vpp.yaml
sed -i "s@image: contivvpp/cni@image: prod-contiv-cni:specific@g" ./k8s/contiv-vpp.yaml
sed -i "s@image: contivvpp/ksr@image: prod-contiv-ksr:specific@g" ./k8s/contiv-vpp.yaml
