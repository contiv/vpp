#!/usr/bin/env bash

make helm-yaml
git diff --exit-code k8s/contiv-vpp.yaml

if [ $? -ne 0 ]; then
    echo "ERROR: Change in the helm template detected, please re-generate the main manifest file using: make helm-yaml"
    exit 1
fi

make helm-yaml-arm64
git diff --exit-code k8s/contiv-vpp-arm64.yaml

if [ $? -ne 0 ]; then
    echo "ERROR: Change in the helm template detected, please re-generate the arm64 manifest file using: make helm-yaml-arm64"
    exit 1
fi
