#!/usr/bin/env bash
set -x

# Install base requirements
sudo -E apt-get update
sudo -E apt-get install -y apt-transport-https ca-certificates curl software-properties-common htop
curl -fsSL https://packages.cloud.google.com/apt/doc/apt-key.gpg | sudo -E apt-key add -
sudo -E add-apt-repository "deb http://apt.kubernetes.io/ kubernetes-xenial main"
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo -E apt-key add -
sudo -E add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu xenial stable"
sudo -E apt-get update
sudo -E apt-get install -qy kubelet=1.12.3-00 kubectl=1.12.3-00 kubeadm=1.12.3-00
sudo -E apt-get install -y docker-ce=18.03.0~ce-0~ubuntu

sudo -E systemctl stop docker
sudo -E modprobe overlay

echo '{"storage-driver": "overlay2"}' | sudo -E tee /etc/docker/daemon.json
sudo -E rm -rf /var/lib/docker/*
sudo -E systemctl start docker

# Install master-only requirements
sudo -E apt-get install -y python-dev python-virtualenv build-essential

export LC_ALL=C
curl -O https://bootstrap.pypa.io/get-pip.py
sudo -EH python ./get-pip.py
sudo -EH pip install --upgrade virtualenv

curl -sL https://storage.googleapis.com/kubernetes-helm/helm-v2.9.1-linux-amd64.tar.gz > /tmp/helm.tgz
tar -zxvf /tmp/helm.tgz -C /tmp
sudo -E mv /tmp/linux-amd64/helm /usr/local/bin/helm

# Pull kubernetes images
sudo -E kubeadm config images pull --kubernetes-version=v1.12.3

# disable apt daily services
sudo systemctl disable --now apt-daily.service apt-daily.timer

# restore vagrant default ssh key
wget https://raw.githubusercontent.com/mitchellh/vagrant/master/keys/vagrant.pub
mv vagrant.pub ~/.ssh/authorized_keys

# zero out the drive
sudo dd if=/dev/zero of=/EMPTY bs=1M
sleep 10
sudo rm -f /EMPTY

# clean bash history and exit
cat /dev/null > ~/.bash_history && history -c && exit
