#!/usr/bin/env bash

echo Args passed: [[ $@ ]]

sudo -E apt-get install -y python-pip \
                   python-dev \
                   python-virtualenv \
                   build-essential

#Install pip
sudo -E pip install --upgrade pip
sudo -E pip install --upgrade virtualenv

#Install helm
echo "Downloading and installing Helm..."
curl -sL https://storage.googleapis.com/kubernetes-helm/helm-v"${helm_version}"-linux-amd64.tar.gz > /tmp/helm.tgz
tar -zxvf /tmp/helm.tgz -C /tmp
mv /tmp/linux-amd64/helm /usr/local/bin/helm

echo "Pulling k8s images..."
echo "$(kubeadm config images pull --kubernetes-version=v"${k8s_version}")"
