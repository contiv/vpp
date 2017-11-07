#!/bin/bash

sudo docker ps -as
sudo docker images
sudo k8s/cri-install.sh -u
sudo kubeadm reset

sudo systemctl restart kubelet
sudo systemctl status kubelet

sudo k8s/cri-install.sh
sudo -E kubeadm init --token-ttl 0 --pod-network-cidr=192.168.0.0/16 --skip-preflight-checks

rm -rf $HOME/.kube
mkdir -p $HOME/.kube
sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
sudo chown $(id -u):$(id -g) $HOME/.kube/config

kubectl taint nodes --all node-role.kubernetes.io/master-

kubectl apply -f k8s/contiv-vpp.yaml
sleep 10

sleep_time=15
max=40
count=0
while [[ $(kubectl -n kube-system get pods | grep contiv-vswitch | grep Running -c) -eq 0 && $count -lt $max ]]
do
  echo "waiting for contiv-vswitch..."
  ((count++))
  sleep $sleep_time
done

count=0
while [[ $(kubectl -n kube-system get pods | grep kube-controller-manager | grep Running -c) -eq 0 && $count -lt $max ]]
do
  echo "waiting for kube-controller-manager..."
  ((count++))
  sleep $sleep_time
done

count=0
while [[ $(kubectl -n kube-system get pods | grep kube-scheduler | grep Running -c) -eq 0 && $count -lt $max ]]
do
  echo "waiting for kube-scheduler..."
  ((count++))
  sleep $sleep_time
done

if [[ $(kubectl -n kube-system get pods | grep contiv-vswitch | grep Running -c) -gt 0 ]]
then
  echo "contiv-vswitch Running"
else
  echo "contiv-vswitch not Running"
  exit 1
fi

if [[ $(kubectl -n kube-system get pods | grep kube-scheduler | grep Running -c) -gt 0 ]]
then
  echo "kube-scheduler Running"
else
  echo "kube-scheduler not Running"
  exit 1
fi

kubectl -n kube-system get pods
